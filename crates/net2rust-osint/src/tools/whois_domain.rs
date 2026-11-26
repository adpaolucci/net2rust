use std::collections::HashSet;
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
use crate::whois::{
    DomainWhoisRecord, merge_domain_records, normalize_domain, parse_rdap_domain, parse_whois_domain, rdap_domain_url,
    select_tld_whois_server,
};

pub const TOOL_ID: &str = "osint.whois-domain";
pub const DESCRIPTION: &str = "IANA and registrar WHOIS/RDAP domain registration lookup.";
pub const MAX_DOMAIN_REFERRAL_HOPS: usize = 4;

pub fn schema() -> TableSchema {
    TableSchema::new(
        TOOL_ID,
        "Domain WHOIS & RDAP",
        vec![
            ColumnDef::new("Domain", "Domain", ColumnType::Text).with_width_hint(180),
            ColumnDef::new("Registrar", "Registrar", ColumnType::Text).with_width_hint(220),
            ColumnDef::new("CreatedDate", "Created Date", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("UpdatedDate", "Updated Date", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("ExpiryDate", "Expiry Date", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("NameServers", "Name Servers", ColumnType::Text).with_width_hint(240),
            ColumnDef::new("Status", "Status", ColumnType::Text).with_width_hint(220),
        ],
    )
}

/// Resolves domain registration details via TLD/IANA WHOIS + thin-to-thick registrar chasing,
/// falling back to RDAP JSON when TCP:43 WHOIS fails or returns no structured data.
pub fn lookup_whois_domain(
    raw_domain: &str,
    whois: &dyn WhoisTransport,
    rdap: &dyn RdapTransport,
    timeout: Duration,
) -> NetResult<DomainWhoisRecord> {
    let domain = normalize_domain(raw_domain)?;

    if let Ok(rec) = resolve_via_whois(&domain, whois, timeout)
        && (!rec.registrar.is_empty() || !rec.name_servers.is_empty() || !rec.expiry_date.is_empty())
    {
        return Ok(rec);
    }

    let rdap_url = rdap_domain_url(&domain);
    match rdap.get_rdap_json(&rdap_url, timeout) {
        Ok(resp) => parse_rdap_domain(&domain, &resp),
        Err(rdap_err) => resolve_via_whois(&domain, whois, timeout).map_err(|whois_err| {
            NetError::NetworkError(format!(
                "domain lookup failed for '{domain}': WHOIS=({whois_err}); RDAP=({rdap_err})"
            ))
        }),
    }
}

fn resolve_via_whois(domain: &str, whois: &dyn WhoisTransport, timeout: Duration) -> NetResult<DomainWhoisRecord> {
    let (registry_host, registry_query) = match select_tld_whois_server(domain) {
        Some((host, qry)) => (host.to_string(), qry),
        None => {
            let tld = domain.rsplit('.').next().unwrap_or(domain);
            let iana_raw = whois.query_whois("whois.iana.org", 43, tld, timeout)?;
            let iana_rec = parse_whois_domain(domain, "whois.iana.org", &iana_raw);
            let refer = iana_rec.referral_server.ok_or_else(|| {
                NetError::NetworkError(format!("IANA WHOIS returned no referral server for TLD '.{tld}'"))
            })?;
            (refer, domain.to_string())
        }
    };

    let reg_raw = whois.query_whois(&registry_host, 43, &registry_query, timeout)?;
    let mut current = parse_whois_domain(domain, &registry_host, &reg_raw);

    let mut visited = HashSet::new();
    visited.insert(registry_host.to_ascii_lowercase());

    for _hop in 0..MAX_DOMAIN_REFERRAL_HOPS {
        let Some(ref_srv) = current.referral_server.clone() else {
            break;
        };
        let key = ref_srv.to_ascii_lowercase();
        if !visited.insert(key) {
            break;
        }
        let Ok(next_raw) = whois.query_whois(&ref_srv, 43, domain, timeout) else {
            break;
        };
        let next_rec = parse_whois_domain(domain, &ref_srv, &next_raw);
        let has_next_ref = next_rec.referral_server.clone();
        current = merge_domain_records(current, next_rec);
        current.referral_server = has_next_ref;
    }

    Ok(current)
}

pub(crate) fn build_offline_domain_transports(
    cfg: Option<&OfflineConfig>,
) -> NetResult<(MockWhoisTransport, MockRdapTransport)> {
    let mut whois = MockWhoisTransport::new();
    let mut rdap = MockRdapTransport::new();

    whois.insert(
        "whois.verisign-grs.com",
        "=example.com",
        "   Domain Name: EXAMPLE.COM\n   Registry Domain ID: 2336799_DOMAIN_COM-VRSN\n   Registrar WHOIS Server: whois.iana.org\n   Updated Date: 2024-08-14T07:01:34Z\n   Creation Date: 1995-08-14T04:00:00Z\n   Registry Expiry Date: 2025-08-13T04:00:00Z\n   Registrar: RESERVED-Internet Assigned Numbers Authority\n   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\n   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n   Name Server: A.IANA-SERVERS.NET\n   Name Server: B.IANA-SERVERS.NET\n",
    );
    whois.insert(
        "whois.iana.org",
        "example.com",
        "domain: EXAMPLE.COM\nregistrar: Internet Assigned Numbers Authority\ncreated: 1995-08-14\nchanged: 2024-08-14\nnserver: a.iana-servers.net\nnserver: b.iana-servers.net\nstatus: ACTIVE\n",
    );
    whois.insert(
        "whois.pir.org",
        "example.org",
        "Domain Name: example.org\nRegistrar: Public Interest Registry\nCreation Date: 1995-08-31T04:00:00Z\nUpdated Date: 2024-08-31T04:00:00Z\nRegistry Expiry Date: 2025-08-30T04:00:00Z\nName Server: a.iana-servers.net\nName Server: b.iana-servers.net\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n",
    );
    whois.insert(
        "whois.nic.uk",
        "example.co.uk",
        "Domain name:\n    example.co.uk\n\nRegistrar:\n    Nominet UK [Tag = NOMINET]\n\nRelevant dates:\n    Registered on: 01-Aug-1996\n    Expiry date:  01-Aug-2026\n    Last updated:  01-Aug-2024\n\nRegistration status:\n    Registered until expiry date.\n\nName servers:\n    ns1.example.co.uk\n    ns2.example.co.uk\n",
    );

    rdap.insert(
        "https://rdap.verisign.com/com/v1/domain/example.com",
        serde_json::json!({
            "ldhName": "example.com",
            "status": ["client transfer prohibited"],
            "events": [
                { "eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z" },
                { "eventAction": "last changed", "eventDate": "2024-08-14T07:01:34Z" },
                { "eventAction": "expiration", "eventDate": "2025-08-13T04:00:00Z" }
            ],
            "nameservers": [
                { "ldhName": "a.iana-servers.net" },
                { "ldhName": "b.iana-servers.net" }
            ],
            "entities": [
                { "roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "IANA"]]] }
            ]
        }),
    );

    if let Some(cfg) = cfg
        && let Some(extra) = load_fixture_json::<serde_json::Value>(cfg, "whois_domain_fixtures.json")?
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

pub struct WhoisDomainProvider {
    ctx: NetContext,
    schema: TableSchema,
}

impl WhoisDomainProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx, schema: schema() }
    }
}

impl TableProvider for WhoisDomainProvider {
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
            &["Domain"],
            |tok| tok.contains('.') && normalize_domain(tok).is_ok(),
            |tok| normalize_domain(tok).ok(),
        );
        let mut seen = HashSet::new();
        let mut targets: Vec<String> = Vec::new();
        for tok in plan.targets.iter().flat_map(|s| split_target_list(s)) {
            let key = normalize_domain(&tok).unwrap_or_else(|_| tok.to_ascii_lowercase());
            if seen.insert(key) {
                targets.push(tok);
            }
        }
        if plan.include_defaults || targets.is_empty() {
            for default_dom in ["example.com", "example.org", "example.co.uk"] {
                if seen.insert(default_dom.to_string()) {
                    targets.push(default_dom.to_string());
                }
            }
        }

        let (whois_box, rdap_box): (Box<dyn WhoisTransport>, Box<dyn RdapTransport>) = match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => {
                let (w, r) = build_offline_domain_transports(Some(cfg))?;
                (Box::new(w), Box::new(r))
            }
            ExecutionMode::Live => (Box::new(StdWhoisTransport::new()), Box::new(UreqRdapTransport::new())),
        };

        let mut rows = Vec::with_capacity(targets.len());
        for (idx, domain) in targets.into_iter().enumerate() {
            let rec = lookup_whois_domain(&domain, whois_box.as_ref(), rdap_box.as_ref(), self.ctx.timeout)?;
            let detail = serde_json::to_value(&rec).unwrap_or(serde_json::Value::Null);
            rows.push(
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.domain),
                        CellValue::Text(rec.registrar),
                        CellValue::Text(rec.created_date),
                        CellValue::Text(rec.updated_date),
                        CellValue::Text(rec.expiry_date),
                        CellValue::Text(rec.name_servers),
                        CellValue::Text(rec.status),
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
    Arc::new(WhoisDomainProvider::new(ctx.clone()))
}
