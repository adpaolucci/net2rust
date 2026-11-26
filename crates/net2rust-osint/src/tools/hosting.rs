use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use net2rust_core::{ExecutionMode, NetContext, NetError};
use serde::{Deserialize, Serialize};

use crate::dns_wire::DnsRecordType;
use crate::geoip_db::OfflineIpDb;
use crate::model::{plan_filter_query, split_target_list};
use crate::tools::dns::{DEFAULT_DNS_SERVER, build_synthetic_dns_reply, query_dns_records};
use crate::tools::ipnet::{build_offline_transports, lookup_ipnet};
use crate::tools::whois_domain::{build_offline_domain_transports, lookup_whois_domain};
use crate::transport::{
    DnsTransport, MockDnsTransport, RdapTransport, StdDnsTransport, StdWhoisTransport, UreqRdapTransport,
    WhoisTransport,
};
use crate::whois::normalize_domain;

pub const TOOL_ID: &str = "osint.hosting";
pub const DESCRIPTION: &str =
    "DomainHostingView equivalent: aggregated WHOIS, DNS, ASN, web host, and mail provider profiler.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainHostingProfile {
    pub domain: String,
    pub web_host_ip: String,
    pub web_host_org: String,
    pub mail_provider: String,
    pub dns_provider: String,
    pub registrar: String,
    pub country: String,
    pub ipv4_addrs: Vec<String>,
    pub ipv6_addrs: Vec<String>,
    pub mx_hosts: Vec<String>,
    pub ns_hosts: Vec<String>,
    pub ptr_hostname: Option<String>,
    pub asn: Option<u32>,
    pub warnings: Vec<String>,
}

pub fn schema() -> TableSchema {
    TableSchema::new(
        TOOL_ID,
        "DomainHostingView — Domain Infrastructure & Hosting Profiler",
        vec![
            ColumnDef::new("Domain", "Domain", ColumnType::Text).with_width_hint(180),
            ColumnDef::new("WebHostIP", "Web Host IP", ColumnType::IpAddr).with_width_hint(140),
            ColumnDef::new("WebHostOrg", "Web Host Org", ColumnType::Text).with_width_hint(200),
            ColumnDef::new("MailProvider", "Mail Provider", ColumnType::Text).with_width_hint(200),
            ColumnDef::new("DnsProvider", "DNS Provider", ColumnType::Text).with_width_hint(200),
            ColumnDef::new("Registrar", "Registrar", ColumnType::Text).with_width_hint(200),
            ColumnDef::new("Country", "Country", ColumnType::Text).with_width_hint(80),
        ],
    )
}

pub struct HostingDeps<'a> {
    pub dns_server: SocketAddr,
    pub dns: &'a dyn DnsTransport,
    pub whois: &'a dyn WhoisTransport,
    pub rdap: &'a dyn RdapTransport,
    pub geoip: &'a OfflineIpDb,
    pub timeout: Duration,
    pub use_live_ip_whois: bool,
}

/// Aggregates DNS (`A`, `AAAA`, `MX`, `NS`, `PTR`), domain WHOIS, IP WHOIS/RDAP, and GeoIP
/// for a domain with partial-failure resilience.
pub fn analyze_domain_hosting(raw_domain: &str, deps: &HostingDeps<'_>) -> DomainHostingProfile {
    let HostingDeps {
        dns_server,
        dns,
        whois,
        rdap,
        geoip,
        timeout,
        use_live_ip_whois,
    } = *deps;
    let mut warnings = Vec::new();
    let domain = match normalize_domain(raw_domain) {
        Ok(d) => d,
        Err(e) => {
            warnings.push(format!("invalid domain: {e}"));
            raw_domain.trim().to_string()
        }
    };

    let mut ipv4_addrs = Vec::new();
    let mut ipv6_addrs = Vec::new();
    let mut mx_hosts = Vec::new();
    let mut ns_hosts = Vec::new();

    match query_dns_records(
        &domain,
        &[
            DnsRecordType::A,
            DnsRecordType::AAAA,
            DnsRecordType::MX,
            DnsRecordType::NS,
        ],
        dns_server,
        dns,
        timeout,
    ) {
        Ok(records) => {
            for r in records {
                match r.record_type.as_str() {
                    "A" => ipv4_addrs.push(r.value),
                    "AAAA" => ipv6_addrs.push(r.value),
                    "MX" => mx_hosts.push(r.value),
                    "NS" => ns_hosts.push(r.value),
                    _ => {}
                }
            }
        }
        Err(e) => warnings.push(format!("DNS query failed: {e}")),
    }

    let web_host_ip = ipv4_addrs
        .first()
        .or_else(|| ipv6_addrs.first())
        .cloned()
        .unwrap_or_default();

    let mut ptr_hostname = None;
    let mut web_host_org = String::new();
    let mut country = String::new();
    let mut asn = None;

    if let Ok(ip) = web_host_ip.parse::<IpAddr>() {
        if let Ok(ptr_recs) = query_dns_records(&ip.to_string(), &[DnsRecordType::PTR], dns_server, dns, timeout)
            && let Some(first) = ptr_recs.first()
        {
            ptr_hostname = Some(first.value.clone());
        }

        let geo = geoip.lookup(ip);
        if geo.country_code != "ZZ" {
            country = geo.country_code.clone();
        }
        if geo.as_name != "UNKNOWN" {
            web_host_org = geo.as_name.clone();
        }
        asn = geo.asn;

        if (web_host_org.is_empty() || country.is_empty()) && use_live_ip_whois {
            match lookup_ipnet(ip, whois, rdap, timeout) {
                Ok(iprec) => {
                    if web_host_org.is_empty() && !iprec.org_name.is_empty() {
                        web_host_org = iprec.org_name;
                    }
                    if country.is_empty() && !iprec.country.is_empty() {
                        country = iprec.country;
                    }
                    if asn.is_none()
                        && let Some(as_str) = iprec.asn
                    {
                        asn = as_str.trim_start_matches("AS").parse().ok();
                    }
                }
                Err(e) => warnings.push(format!("IP WHOIS enrichment failed: {e}")),
            }
        }
    } else if web_host_ip.is_empty() {
        warnings.push("no A/AAAA web host IP resolved".to_string());
    }

    let registrar = match lookup_whois_domain(&domain, whois, rdap, timeout) {
        Ok(w) => w.registrar,
        Err(e) => {
            warnings.push(format!("domain WHOIS failed: {e}"));
            String::new()
        }
    };

    let mail_provider = classify_mail_provider(&mx_hosts);
    let dns_provider = classify_dns_provider(&ns_hosts);

    DomainHostingProfile {
        domain,
        web_host_ip,
        web_host_org,
        mail_provider,
        dns_provider,
        registrar,
        country,
        ipv4_addrs,
        ipv6_addrs,
        mx_hosts,
        ns_hosts,
        ptr_hostname,
        asn,
        warnings,
    }
}

pub fn classify_mail_provider(mx_hosts: &[String]) -> String {
    if mx_hosts.is_empty() {
        return "None".to_string();
    }
    let first = &mx_hosts[0];
    let lc = first.to_ascii_lowercase();
    let vendor = if lc.contains("google.com") || lc.contains("googlemail.com") {
        Some("Google Workspace")
    } else if lc.contains("protection.outlook.com") || lc.contains("mail.eo.outlook.com") {
        Some("Microsoft 365")
    } else if lc.contains("pphosted.com") {
        Some("Proofpoint")
    } else if lc.contains("mimecast.com") {
        Some("Mimecast")
    } else if lc.contains("mx.cloudflare.net") {
        Some("Cloudflare Email Routing")
    } else if lc.contains("protonmail.ch") {
        Some("Proton Mail")
    } else if lc.contains("fastmail.com") || lc.contains("messagingengine.com") {
        Some("Fastmail")
    } else {
        None
    };

    match vendor {
        Some(v) => format!("{v} ({first})"),
        None => first.clone(),
    }
}

pub fn classify_dns_provider(ns_hosts: &[String]) -> String {
    if ns_hosts.is_empty() {
        return "None".to_string();
    }
    let first = &ns_hosts[0];
    let lc = first.to_ascii_lowercase();
    let vendor = if lc.contains("ns.cloudflare.com") {
        Some("Cloudflare DNS")
    } else if lc.contains("awsdns-") {
        Some("Amazon Route 53")
    } else if lc.contains("googledomains.com") || lc.contains("ns-cloud-") {
        Some("Google Cloud DNS")
    } else if lc.contains("azure-dns.") {
        Some("Azure DNS")
    } else if lc.contains("iana-servers.net") {
        Some("IANA")
    } else if lc.contains("domaincontrol.com") {
        Some("GoDaddy DNS")
    } else {
        None
    };

    match vendor {
        Some(v) => format!("{v} ({first})"),
        None => first.clone(),
    }
}

pub struct HostingProvider {
    ctx: NetContext,
    schema: TableSchema,
}

impl HostingProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx, schema: schema() }
    }
}

impl TableProvider for HostingProvider {
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
            for default_dom in ["example.com", "example.org"] {
                if seen.insert(default_dom.to_string()) {
                    targets.push(default_dom.to_string());
                }
            }
        }

        let mut geoip = OfflineIpDb::embedded();
        if let Some(cfg) = self.ctx.offline_config()
            && let Some(path) = &cfg.geoip_db_path
        {
            geoip.merge_csv_file(path)?;
        }

        let dns_server: SocketAddr = DEFAULT_DNS_SERVER.parse().expect("valid default dns");
        let profiles: Vec<DomainHostingProfile> = match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => {
                let mock_dns = MockDnsTransport::new(|_srv, query, _tcp| {
                    let tx_id = u16::from_be_bytes([query[0], query[1]]);
                    let (qname, next) = crate::dns_wire::decode_name(query, 12)?;
                    let qtype = u16::from_be_bytes([query[next], query[next + 1]]);
                    Ok(build_synthetic_dns_reply(tx_id, &qname, qtype))
                });
                let (w_ip, r_ip) = build_offline_transports(Some(cfg))?;
                let (w_dom, r_dom) = build_offline_domain_transports(Some(cfg))?;
                let whois = MergedMockWhois(w_ip, w_dom);
                let rdap = MergedMockRdap(r_ip, r_dom);
                let deps = HostingDeps {
                    dns_server,
                    dns: &mock_dns,
                    whois: &whois,
                    rdap: &rdap,
                    geoip: &geoip,
                    timeout: self.ctx.timeout,
                    use_live_ip_whois: false,
                };
                targets.iter().map(|d| analyze_domain_hosting(d, &deps)).collect()
            }
            ExecutionMode::Live => {
                let dns = StdDnsTransport::new();
                let whois = StdWhoisTransport::new();
                let rdap = UreqRdapTransport::new();
                let deps = HostingDeps {
                    dns_server,
                    dns: &dns,
                    whois: &whois,
                    rdap: &rdap,
                    geoip: &geoip,
                    timeout: self.ctx.timeout,
                    use_live_ip_whois: true,
                };
                targets.iter().map(|d| analyze_domain_hosting(d, &deps)).collect()
            }
        };

        let rows: Vec<Row> = profiles
            .into_iter()
            .enumerate()
            .map(|(idx, p)| {
                let detail = serde_json::to_value(&p).unwrap_or(serde_json::Value::Null);
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(p.domain),
                        CellValue::Text(p.web_host_ip),
                        CellValue::Text(p.web_host_org),
                        CellValue::Text(p.mail_provider),
                        CellValue::Text(p.dns_provider),
                        CellValue::Text(p.registrar),
                        CellValue::Text(p.country),
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

struct MergedMockWhois(
    crate::transport::MockWhoisTransport,
    crate::transport::MockWhoisTransport,
);
impl WhoisTransport for MergedMockWhois {
    fn query_whois(&self, server: &str, port: u16, query: &str, timeout: Duration) -> Result<String, NetError> {
        self.1
            .query_whois(server, port, query, timeout)
            .or_else(|_| self.0.query_whois(server, port, query, timeout))
    }
}

struct MergedMockRdap(crate::transport::MockRdapTransport, crate::transport::MockRdapTransport);
impl RdapTransport for MergedMockRdap {
    fn get_rdap_json(&self, url: &str, timeout: Duration) -> Result<crate::transport::RdapHttpResponse, NetError> {
        self.1
            .get_rdap_json(url, timeout)
            .or_else(|_| self.0.get_rdap_json(url, timeout))
    }
}

pub fn provider(ctx: &NetContext) -> Arc<dyn TableProvider> {
    Arc::new(HostingProvider::new(ctx.clone()))
}
