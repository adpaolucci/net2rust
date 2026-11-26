use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use net2rust_core::{ExecutionMode, NetContext};
use serde::{Deserialize, Serialize};

use crate::geoip_db::OfflineIpDb;
use crate::model::{load_fixture_lines, plan_filter_query, split_target_list};
use crate::tools::ipnet::build_offline_transports;
use crate::tools::whois_domain::{build_offline_domain_transports, lookup_whois_domain};
use crate::tools::whosip::lookup_whosip;
use crate::transport::{
    MockRdapTransport, MockWhoisTransport, RdapTransport, StdWhoisTransport, UreqRdapTransport, WhoisTransport,
};
use crate::whois::normalize_domain;

pub const TOOL_ID: &str = "osint.whoiscl";
pub const DESCRIPTION: &str = "Deterministic batch CLI WHOIS query runner.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhoisClRecord {
    pub query: String,
    pub whois_server: String,
    pub registrar: String,
    pub expiry_date: String,
    pub raw_text: String,
    pub error: Option<String>,
}

pub fn schema() -> TableSchema {
    TableSchema::new(
        TOOL_ID,
        "Batch WHOIS Query Runner",
        vec![
            ColumnDef::new("Query", "Query", ColumnType::Text).with_width_hint(180),
            ColumnDef::new("WhoisServer", "WHOIS Server", ColumnType::Text).with_width_hint(180),
            ColumnDef::new("Registrar", "Registrar / Owner", ColumnType::Text).with_width_hint(220),
            ColumnDef::new("ExpiryDate", "Expiry Date", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("RawText", "Raw Text", ColumnType::Text).with_width_hint(320),
        ],
    )
}

/// Runs a batch of mixed IP/domain WHOIS queries with per-target error isolation.
pub fn run_whoiscl_batch(
    targets: &[String],
    whois: &dyn WhoisTransport,
    rdap: &dyn RdapTransport,
    geoip: &OfflineIpDb,
    timeout: Duration,
) -> Vec<WhoisClRecord> {
    targets
        .iter()
        .map(|target| {
            let trimmed = target.trim();
            if let Ok(ip) = trimmed.parse::<IpAddr>() {
                match lookup_whosip(ip, None, whois, rdap, geoip, timeout) {
                    Ok(rec) => {
                        let server = rec.referral_chain.last().cloned().unwrap_or_else(|| rec.rir.clone());
                        WhoisClRecord {
                            query: trimmed.to_string(),
                            whois_server: server,
                            registrar: rec.owner,
                            expiry_date: String::new(),
                            raw_text: rec.raw_record,
                            error: None,
                        }
                    }
                    Err(e) => WhoisClRecord {
                        query: trimmed.to_string(),
                        whois_server: "error".to_string(),
                        registrar: String::new(),
                        expiry_date: String::new(),
                        raw_text: format!("ERROR: {e}"),
                        error: Some(e.to_string()),
                    },
                }
            } else {
                match lookup_whois_domain(trimmed, whois, rdap, timeout) {
                    Ok(rec) => WhoisClRecord {
                        query: rec.domain,
                        whois_server: rec.whois_server,
                        registrar: rec.registrar,
                        expiry_date: rec.expiry_date,
                        raw_text: rec.raw_text,
                        error: None,
                    },
                    Err(e) => WhoisClRecord {
                        query: trimmed.to_string(),
                        whois_server: "error".to_string(),
                        registrar: String::new(),
                        expiry_date: String::new(),
                        raw_text: format!("ERROR: {e}"),
                        error: Some(e.to_string()),
                    },
                }
            }
        })
        .collect()
}

pub struct WhoisClProvider {
    ctx: NetContext,
    schema: TableSchema,
}

impl WhoisClProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx, schema: schema() }
    }
}

impl TableProvider for WhoisClProvider {
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
            &["Query"],
            |tok| tok.parse::<IpAddr>().is_ok() || (tok.contains('.') && normalize_domain(tok).is_ok()),
            |tok| {
                if let Ok(ip) = tok.parse::<IpAddr>() {
                    Some(ip.to_string())
                } else {
                    normalize_domain(tok).ok()
                }
            },
        );
        let norm_key = |tok: &str| -> String {
            if let Ok(ip) = tok.trim().parse::<IpAddr>() {
                ip.to_string()
            } else {
                normalize_domain(tok).unwrap_or_else(|_| tok.trim().to_ascii_lowercase())
            }
        };
        let mut seen = HashSet::new();
        let mut targets: Vec<String> = Vec::new();
        for tok in plan.targets.iter().flat_map(|s| split_target_list(s)) {
            if seen.insert(norm_key(&tok)) {
                targets.push(tok);
            }
        }

        if plan.include_defaults || targets.is_empty() {
            let defaults = if let Some(cfg) = self.ctx.offline_config()
                && let Some(lines) = load_fixture_lines(cfg, "whoiscl_targets.txt")?
            {
                lines
            } else {
                vec![
                    "8.8.8.8".to_string(),
                    "example.com".to_string(),
                    "example.org".to_string(),
                ]
            };
            for tok in defaults {
                if seen.insert(norm_key(&tok)) {
                    targets.push(tok);
                }
            }
        }

        let geoip = OfflineIpDb::embedded();
        let (whois_box, rdap_box): (Box<dyn WhoisTransport>, Box<dyn RdapTransport>) = match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => {
                // Combine IP + Domain offline fixtures into one transport pair
                let (w_ip, r_ip) = build_offline_transports(Some(cfg))?;
                let (w_dom, r_dom) = build_offline_domain_transports(Some(cfg))?;
                let combined_w = CombinedWhois { a: w_ip, b: w_dom };
                let combined_r = CombinedRdap { a: r_ip, b: r_dom };
                (Box::new(combined_w), Box::new(combined_r))
            }
            ExecutionMode::Live => (Box::new(StdWhoisTransport::new()), Box::new(UreqRdapTransport::new())),
        };

        let results = run_whoiscl_batch(
            &targets,
            whois_box.as_ref(),
            rdap_box.as_ref(),
            &geoip,
            self.ctx.timeout,
        );
        let rows: Vec<Row> = results
            .into_iter()
            .enumerate()
            .map(|(idx, rec)| {
                let detail = serde_json::to_value(&rec).unwrap_or(serde_json::Value::Null);
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.query),
                        CellValue::Text(rec.whois_server),
                        CellValue::Text(rec.registrar),
                        CellValue::Text(rec.expiry_date),
                        CellValue::Text(rec.raw_text),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

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

struct CombinedWhois {
    a: MockWhoisTransport,
    b: MockWhoisTransport,
}

impl WhoisTransport for CombinedWhois {
    fn query_whois(&self, server: &str, port: u16, query: &str, timeout: Duration) -> net2rust_core::NetResult<String> {
        self.a
            .query_whois(server, port, query, timeout)
            .or_else(|_| self.b.query_whois(server, port, query, timeout))
    }
}

struct CombinedRdap {
    a: MockRdapTransport,
    b: MockRdapTransport,
}

impl RdapTransport for CombinedRdap {
    fn get_rdap_json(
        &self,
        url: &str,
        timeout: Duration,
    ) -> net2rust_core::NetResult<crate::transport::RdapHttpResponse> {
        self.a
            .get_rdap_json(url, timeout)
            .or_else(|_| self.b.get_rdap_json(url, timeout))
    }
}

pub fn provider(ctx: &NetContext) -> Arc<dyn TableProvider> {
    Arc::new(WhoisClProvider::new(ctx.clone()))
}
