use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use net2rust_core::{ExecutionMode, NetContext, NetError, NetResult};
use serde::{Deserialize, Serialize};

use crate::geoip_db::OfflineIpDb;
use crate::model::{plan_filter_query, split_target_list};
use crate::tools::ipnet::build_offline_transports;
use crate::transport::{RdapTransport, StdWhoisTransport, UreqRdapTransport, WhoisTransport};
use crate::whois::{
    IpNetRecord, infer_rir_from_host, parse_rdap_ip, parse_whois_ip, rir_whois_query_string, select_rir_for_ip,
};

pub const TOOL_ID: &str = "osint.whosip";
pub const DESCRIPTION: &str = "WhosIP equivalent: IP WHOIS/RDAP resolver with referral chasing and ASN mapping.";
pub const MAX_REFERRAL_HOPS: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhosipRecord {
    pub ip: String,
    pub asn: String,
    pub owner: String,
    pub country: String,
    pub net_block: String,
    pub rir: String,
    pub raw_record: String,
    pub referral_chain: Vec<String>,
}

pub fn schema() -> TableSchema {
    TableSchema::new(
        TOOL_ID,
        "WhosIP — IP WHOIS & Referral Chasing",
        vec![
            ColumnDef::new("IP", "IP", ColumnType::IpAddr).with_width_hint(140),
            ColumnDef::new("ASN", "ASN", ColumnType::Text).with_width_hint(100),
            ColumnDef::new("Owner", "Owner", ColumnType::Text).with_width_hint(220),
            ColumnDef::new("Country", "Country", ColumnType::Text).with_width_hint(80),
            ColumnDef::new("NetBlock", "Net Block", ColumnType::Text).with_width_hint(180),
            ColumnDef::new("RIR", "RIR", ColumnType::Text).with_width_hint(80),
            ColumnDef::new("RawRecord", "Raw Record", ColumnType::Text).with_width_hint(320),
        ],
    )
}

/// Resolves an IP via RDAP and/or TCP:43 WHOIS with multi-hop referral chasing,
/// cycle detection, and `MAX_REFERRAL_HOPS` cap.
pub fn lookup_whosip(
    ip: IpAddr,
    initial_whois_server: Option<&str>,
    whois: &dyn WhoisTransport,
    rdap: &dyn RdapTransport,
    geoip: &OfflineIpDb,
    timeout: Duration,
) -> NetResult<WhosipRecord> {
    let ep = select_rir_for_ip(ip);
    let mut referral_chain = Vec::new();

    let best: Option<IpNetRecord> = if initial_whois_server.is_none() {
        chase_rdap_ip(
            ip,
            ep.rir,
            &format!("{}{}", ep.rdap_base, ip),
            rdap,
            timeout,
            &mut referral_chain,
        )
    } else {
        None
    };

    let record = match best {
        Some(r) if !r.is_referral_stub && (!r.org_name.is_empty() || !r.net_range.is_empty()) => r,
        _ => {
            let start_host = initial_whois_server.unwrap_or(ep.whois_host);
            chase_whois_ip(ip, start_host, ep.rir, whois, timeout, &mut referral_chain)?
        }
    };

    let asn = record.asn.clone().unwrap_or_else(|| {
        geoip
            .lookup(ip)
            .asn
            .map(|n| format!("AS{n}"))
            .unwrap_or_else(|| "N/A".to_string())
    });

    let net_block = if !record.cidr.is_empty() {
        record.cidr.clone()
    } else {
        record.net_range.clone()
    };

    Ok(WhosipRecord {
        ip: ip.to_string(),
        asn,
        owner: record.org_name,
        country: record.country,
        net_block,
        rir: record.rir,
        raw_record: record.raw_record,
        referral_chain,
    })
}

fn chase_rdap_ip(
    ip: IpAddr,
    rir_hint: &str,
    start_url: &str,
    rdap: &dyn RdapTransport,
    timeout: Duration,
    chain: &mut Vec<String>,
) -> Option<IpNetRecord> {
    let mut visited = HashSet::new();
    let mut current_url = start_url.to_string();
    let mut last_good: Option<IpNetRecord> = None;

    for _hop in 0..MAX_REFERRAL_HOPS {
        let norm = normalize_rdap_key(&current_url);
        if !visited.insert(norm) {
            break;
        }
        chain.push(format!("rdap:{current_url}"));
        let Ok(resp) = rdap.get_rdap_json(&current_url, timeout) else {
            break;
        };
        let Ok(rec) = parse_rdap_ip(ip, rir_hint, &resp) else {
            break;
        };
        let next = rec.referral_rdap.clone();
        let should_follow = rec.is_referral_stub && next.is_some();
        last_good = Some(rec);
        if should_follow && let Some(next_url) = next {
            current_url = next_url;
        } else {
            break;
        }
    }
    last_good
}

pub fn chase_whois_ip(
    ip: IpAddr,
    start_server: &str,
    rir_hint: &str,
    whois: &dyn WhoisTransport,
    timeout: Duration,
    chain: &mut Vec<String>,
) -> NetResult<IpNetRecord> {
    let mut visited = HashSet::new();
    let mut current_host = start_server.to_string();
    let mut current_port = 43u16;
    let mut last_rec: Option<IpNetRecord> = None;

    for _hop in 0..MAX_REFERRAL_HOPS {
        if let Some((h, p)) = parse_host_port(&current_host) {
            current_host = h;
            current_port = p;
        }
        let key = (current_host.to_ascii_lowercase(), current_port);
        if !visited.insert(key) {
            break;
        }
        chain.push(format!("whois:{current_host}:{current_port}"));
        let query = rir_whois_query_string(&current_host, ip);
        let raw = match whois.query_whois(&current_host, current_port, &query, timeout) {
            Ok(r) => r,
            Err(e) => {
                if let Some(prev) = last_rec {
                    return Ok(prev);
                }
                return Err(e);
            }
        };
        let hint = infer_rir_from_host(&current_host);
        let eff_hint = if hint == current_host { rir_hint } else { hint.as_str() };
        let rec = parse_whois_ip(ip, eff_hint, &raw);
        let next_ref = rec.referral_whois.clone();
        last_rec = Some(rec);

        if let Some(next_srv) = next_ref {
            current_host = next_srv;
            current_port = 43;
        } else {
            break;
        }
    }

    last_rec.ok_or_else(|| NetError::NetworkError(format!("WHOIS lookup produced no records for {ip}")))
}

fn parse_host_port(spec: &str) -> Option<(String, u16)> {
    let trimmed = spec.trim().trim_end_matches('/');
    if let Some((h, p)) = trimmed.rsplit_once(':')
        && let Ok(port) = p.parse::<u16>()
    {
        return Some((h.to_string(), port));
    }
    None
}

fn normalize_rdap_key(url: &str) -> String {
    url.trim().trim_end_matches('/').to_ascii_lowercase()
}

pub struct WhosipProvider {
    ctx: NetContext,
    schema: TableSchema,
}

impl WhosipProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx, schema: schema() }
    }
}

impl TableProvider for WhosipProvider {
    fn tool_id(&self) -> &'static str {
        TOOL_ID
    }

    fn description(&self) -> &'static str {
        DESCRIPTION
    }

    fn schema(&self) -> TableSchema {
        self.schema.clone()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let plan = plan_filter_query(
            req.filter.as_ref(),
            &["IP"],
            |tok| tok.parse::<IpAddr>().is_ok(),
            |tok| tok.parse::<IpAddr>().ok().map(|ip| ip.to_string()),
        );
        let mut targets: Vec<IpAddr> = Vec::new();
        for token in plan.targets.iter().flat_map(|s| split_target_list(s)) {
            let ip: IpAddr = token
                .parse()
                .map_err(|_| TableError::from(NetError::InvalidInput(format!("invalid IP address '{token}'"))))?;
            if !targets.contains(&ip) {
                targets.push(ip);
            }
        }
        if plan.include_defaults || targets.is_empty() {
            for default_str in ["8.8.8.8", "1.1.1.1", "193.0.0.1"] {
                let ip: IpAddr = default_str.parse().expect("valid ip");
                if !targets.contains(&ip) {
                    targets.push(ip);
                }
            }
        }

        let mut geoip = OfflineIpDb::embedded();
        if let Some(cfg) = self.ctx.offline_config()
            && let Some(path) = &cfg.geoip_db_path
        {
            geoip.merge_csv_file(path)?;
        }

        let (whois_box, rdap_box): (Box<dyn WhoisTransport>, Box<dyn RdapTransport>) = match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => {
                let (w, r) = build_offline_transports(Some(cfg))?;
                (Box::new(w), Box::new(r))
            }
            ExecutionMode::Live => (Box::new(StdWhoisTransport::new()), Box::new(UreqRdapTransport::new())),
        };

        let mut rows = Vec::with_capacity(targets.len());
        for (idx, ip) in targets.into_iter().enumerate() {
            let rec = lookup_whosip(
                ip,
                None,
                whois_box.as_ref(),
                rdap_box.as_ref(),
                &geoip,
                self.ctx.timeout,
            )?;
            let detail = serde_json::to_value(&rec).unwrap_or(serde_json::Value::Null);
            rows.push(
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.ip),
                        CellValue::Text(rec.asn),
                        CellValue::Text(rec.owner),
                        CellValue::Text(rec.country),
                        CellValue::Text(rec.net_block),
                        CellValue::Text(rec.rir),
                        CellValue::Text(rec.raw_record),
                    ],
                )
                .with_detail_json(detail),
            );
        }

        let forwarded = TableQuery {
            filter: plan.remaining_filter,
            sort: req.sort.clone(),
            columns: req.columns.clone(),
            offset: req.offset,
            limit: req.limit,
        };
        let mut data = apply_query(&self.schema, &rows, &forwarded)?;
        if let Some(max) = self.ctx.max_rows {
            data.rows.truncate(max);
        }
        Ok(data)
    }
}

pub fn provider(ctx: &NetContext) -> Arc<dyn TableProvider> {
    Arc::new(WhosipProvider::new(ctx.clone()))
}
