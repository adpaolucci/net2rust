use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use net2rust_core::{ExecutionMode, NetContext, NetError, NetResult, OfflineConfig};

use crate::model::{load_fixture_json, plan_filter_query, split_target_list};
use crate::transport::{
    MockRdapTransport, MockWhoisTransport, RdapTransport, StdWhoisTransport, UreqRdapTransport, WhoisTransport,
};
use crate::whois::{IpNetRecord, parse_rdap_ip, parse_whois_ip, rir_whois_query_string, select_rir_for_ip};

pub const TOOL_ID: &str = "osint.ipnet";
pub const DESCRIPTION: &str =
    "RIR WHOIS (TCP 43) and RDAP IP block, org, and abuse contact lookup.";

pub fn schema() -> TableSchema {
    TableSchema::new(
        TOOL_ID,
        "RIR WHOIS / RDAP IP Ownership",
        vec![
            ColumnDef::new("IPAddress", "IP Address", ColumnType::IpAddr).with_width_hint(140),
            ColumnDef::new("NetRange", "Net Range", ColumnType::Text).with_width_hint(200),
            ColumnDef::new("CIDR", "CIDR", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("OrgName", "Organization", ColumnType::Text).with_width_hint(220),
            ColumnDef::new("Country", "Country", ColumnType::Text).with_width_hint(80),
            ColumnDef::new("AbuseEmail", "Abuse Email", ColumnType::Text).with_width_hint(200),
            ColumnDef::new("RIR", "RIR", ColumnType::Text).with_width_hint(80),
            ColumnDef::new("Updated", "Updated", ColumnType::Text).with_width_hint(160),
        ],
    )
}

/// Queries RDAP first (or WHOIS TCP:43 fallback) for a single IP address using injected transports.
pub fn lookup_ipnet(
    ip: IpAddr,
    whois: &dyn WhoisTransport,
    rdap: &dyn RdapTransport,
    timeout: Duration,
) -> NetResult<IpNetRecord> {
    let ep = select_rir_for_ip(ip);
    let rdap_url = format!("{}{}", ep.rdap_base, ip);
    if let Ok(resp) = rdap.get_rdap_json(&rdap_url, timeout)
        && let Ok(mut rec) = parse_rdap_ip(ip, ep.rir, &resp)
    {
        if rec.org_name.is_empty() && rec.abuse_email.is_empty() {
            let query = rir_whois_query_string(ep.whois_host, ip);
            if let Ok(raw) = whois.query_whois(ep.whois_host, 43, &query, timeout) {
                let wrec = parse_whois_ip(ip, ep.rir, &raw);
                if !wrec.org_name.is_empty() || !wrec.abuse_email.is_empty() {
                    rec = wrec;
                }
            }
        }
        return Ok(rec);
    }

    let query = rir_whois_query_string(ep.whois_host, ip);
    let raw = whois.query_whois(ep.whois_host, 43, &query, timeout)?;
    Ok(parse_whois_ip(ip, ep.rir, &raw))
}

pub fn lookup_ipnet_whois_only(ip: IpAddr, whois: &dyn WhoisTransport, timeout: Duration) -> NetResult<IpNetRecord> {
    let ep = select_rir_for_ip(ip);
    let query = rir_whois_query_string(ep.whois_host, ip);
    let raw = whois.query_whois(ep.whois_host, 43, &query, timeout)?;
    Ok(parse_whois_ip(ip, ep.rir, &raw))
}

pub(crate) fn build_offline_transports(
    cfg: Option<&OfflineConfig>,
) -> NetResult<(MockWhoisTransport, MockRdapTransport)> {
    let mut whois = MockWhoisTransport::new();
    let mut rdap = MockRdapTransport::new();

    // Built-in deterministic RIR fixtures for offline mode
    whois.insert(
        "whois.arin.net",
        "n + 8.8.8.8",
        "NetRange:       8.8.8.0 - 8.8.8.255\nCIDR:           8.8.8.0/24\nNetName:        GOGL\nOrgName:        Google LLC\nCountry:        US\nRegDate:        2014-03-14\nUpdated:        2023-12-28\nOrgAbuseEmail:  network-abuse@google.com\nOriginAS:       AS15169\n",
    );
    whois.insert(
        "whois.apnic.net",
        "1.1.1.1",
        "inetnum:        1.1.1.0 - 1.1.1.255\nnetname:        APNIC-LABS\ndescr:          APNIC and Cloudflare DNS Resolver project\ncountry:        AU\norg:            ORG-APNIC1-AP\nlast-modified:  2023-07-01T00:00:00Z\nsource:         APNIC\n\norganisation:   ORG-APNIC1-AP\norg-name:       APNIC Research and Development\nabuse-mailbox:  helpdesk@apnic.net\n",
    );
    whois.insert(
        "whois.ripe.net",
        "-B 193.0.0.1",
        "inetnum:        193.0.0.0 - 193.0.7.255\nnetname:        RIPE-NCC\ncountry:        NL\norg:            ORG-RIPE1-RIPE\nlast-modified:  2024-02-15T10:00:00Z\nsource:         RIPE\n\norganisation:   ORG-RIPE1-RIPE\norg-name:       RIPE Network Coordination Centre\nabuse-mailbox:  abuse@ripe.net\n",
    );

    rdap.insert(
        "https://rdap.arin.net/registry/ip/8.8.8.8",
        serde_json::json!({
            "handle": "NET-8-8-8-0-2",
            "startAddress": "8.8.8.0",
            "endAddress": "8.8.8.255",
            "name": "GOGL",
            "country": "US",
            "port43": "whois.arin.net",
            "cidr0_cidrs": [{ "v4prefix": "8.8.8.0", "length": 24 }],
            "arin_originas0_originautnums": [15169],
            "events": [
                { "eventAction": "registration", "eventDate": "2014-03-14T00:00:00Z" },
                { "eventAction": "last changed", "eventDate": "2023-12-28T00:00:00Z" }
            ],
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]],
                    "entities": [
                        {
                            "roles": ["abuse"],
                            "vcardArray": ["vcard", [["email", {}, "text", "network-abuse@google.com"]]]
                        }
                    ]
                }
            ]
        }),
    );

    if let Some(cfg) = cfg
        && let Some(extra) = load_fixture_json::<serde_json::Value>(cfg, "ipnet_fixtures.json")?
        && let Some(entries) = extra.as_array()
    {
        for entry in entries {
            if let (Some(srv), Some(q), Some(raw)) = (
                entry.get("server").and_then(|v| v.as_str()),
                entry.get("query").and_then(|v| v.as_str()),
                entry.get("raw").and_then(|v| v.as_str()),
            ) {
                whois.insert(srv, q, raw);
            }
            if let (Some(url), Some(body)) = (entry.get("rdap_url").and_then(|v| v.as_str()), entry.get("rdap_body")) {
                rdap.insert(url, body.clone());
            }
        }
    }

    Ok((whois, rdap))
}

pub struct IpNetProvider {
    ctx: NetContext,
    schema: TableSchema,
}

impl IpNetProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx, schema: schema() }
    }
}

impl TableProvider for IpNetProvider {
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
            &["IPAddress", "IP"],
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

        let (whois_box, rdap_box): (Box<dyn WhoisTransport>, Box<dyn RdapTransport>) = match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => {
                let (w, r) = build_offline_transports(Some(cfg))?;
                (Box::new(w), Box::new(r))
            }
            ExecutionMode::Live => (Box::new(StdWhoisTransport::new()), Box::new(UreqRdapTransport::new())),
        };

        if plan.include_defaults || targets.is_empty() {
            for default_str in ["8.8.8.8", "1.1.1.1", "193.0.0.1"] {
                let ip: IpAddr = default_str.parse().expect("valid ip");
                if !targets.contains(&ip) {
                    targets.push(ip);
                }
            }
        }

        let mut rows = Vec::with_capacity(targets.len());
        for (idx, ip) in targets.into_iter().enumerate() {
            let rec = lookup_ipnet(ip, whois_box.as_ref(), rdap_box.as_ref(), self.ctx.timeout)?;
            let detail = serde_json::to_value(&rec).unwrap_or(serde_json::Value::Null);
            rows.push(
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.ip_address),
                        CellValue::Text(rec.net_range),
                        CellValue::Text(rec.cidr),
                        CellValue::Text(rec.org_name),
                        CellValue::Text(rec.country),
                        CellValue::Text(rec.abuse_email),
                        CellValue::Text(rec.rir),
                        CellValue::Text(rec.updated),
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
    Arc::new(IpNetProvider::new(ctx.clone()))
}
