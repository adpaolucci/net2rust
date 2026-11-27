use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use net2rust_core::{ExecutionMode, NetContext, NetError, NetResult, OfflineConfig};
use serde::{Deserialize, Serialize};

use crate::dns_wire::{
    DnsRecordType, decode_dns_response, ip_to_arpa_name, query_dns_with_fallback, rcode_description,
};
use crate::model::{
    extract_conjunctive_targets, load_fixture_json, normalize_filter_columns, plan_filter_query, split_target_list,
};
use crate::transport::{DnsTransport, MockDnsTransport, StdDnsTransport};
use crate::whois::normalize_domain;

pub const TOOL_ID: &str = "osint.dns";
pub const DESCRIPTION: &str = "Direct DNS A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV, CAA resolver.";
pub const DEFAULT_DNS_SERVER: &str = "1.1.1.1:53";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRowRecord {
    pub domain: String,
    pub record_type: String,
    pub ttl: u32,
    pub value: String,
    pub priority: Option<u16>,
    pub dns_server: String,
    pub rcode: String,
    pub used_tcp: bool,
}

pub fn schema() -> TableSchema {
    TableSchema::new(
        TOOL_ID,
        "RFC 1035 DNS Record Resolver",
        vec![
            ColumnDef::new("Domain", "Domain", ColumnType::Text).with_width_hint(180),
            ColumnDef::new("RecordType", "Record Type", ColumnType::Text).with_width_hint(90),
            ColumnDef::new("TTL", "TTL", ColumnType::Uint).with_width_hint(80),
            ColumnDef::new("Value", "Value", ColumnType::Text).with_width_hint(260),
            ColumnDef::new("Priority", "Priority", ColumnType::Uint).with_width_hint(80),
            ColumnDef::new("DnsServer", "DNS Server", ColumnType::Text).with_width_hint(140),
        ],
    )
}

/// Queries the requested `record_types` for `target` (auto-converting raw IP addresses to `.arpa` for `PTR`)
/// against `server` using the supplied `DnsTransport`.
pub fn query_dns_records(
    target: &str,
    record_types: &[DnsRecordType],
    server: SocketAddr,
    transport: &dyn DnsTransport,
    timeout: Duration,
) -> NetResult<Vec<DnsRowRecord>> {
    let mut out = Vec::new();
    let trimmed = target.trim().trim_end_matches('.');
    let parsed_ip = trimmed.parse::<IpAddr>().ok();

    for (idx, &rr_type) in record_types.iter().enumerate() {
        let qname = if let Some(ip) = parsed_ip {
            if rr_type == DnsRecordType::PTR {
                ip_to_arpa_name(ip)
            } else {
                continue;
            }
        } else {
            trimmed.to_string()
        };

        let tx_id = 0x4200u16.wrapping_add(idx as u16);
        let msg = query_dns_with_fallback(transport, server, &qname, rr_type, tx_id, timeout)?;
        let rcode_name = rcode_description(msg.rcode).to_string();
        for ans in msg.answers {
            out.push(DnsRowRecord {
                domain: qname.clone(),
                record_type: ans.record_type,
                ttl: ans.ttl,
                value: ans.value,
                priority: ans.priority,
                dns_server: server.to_string(),
                rcode: rcode_name.clone(),
                used_tcp: msg.used_tcp,
            });
        }
    }

    Ok(out)
}

fn parse_dns_server_addr(raw: &str) -> NetResult<SocketAddr> {
    let trimmed = raw.trim();
    if let Ok(sa) = trimmed.parse::<SocketAddr>() {
        return Ok(sa);
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(NetError::InvalidInput(format!("invalid DNS server address '{raw}'")))
}

fn build_offline_dns_records(cfg: Option<&OfflineConfig>, server: SocketAddr) -> NetResult<Vec<DnsRowRecord>> {
    if let Some(cfg) = cfg
        && let Some(custom) = load_fixture_json::<Vec<DnsRowRecord>>(cfg, "dns_records.json")?
    {
        return Ok(custom);
    }
    // Use the real RFC 1035 wire encoder + MockDnsTransport + decode_dns_response so offline mode
    // also exercises the wire parser end-to-end!
    let mock = MockDnsTransport::new(|_srv, query, _tcp| {
        if query.len() < 12 {
            return Err(NetError::ParseError("short query".into()));
        }
        let tx_id = u16::from_be_bytes([query[0], query[1]]);
        let (qname, next) = crate::dns_wire::decode_name(query, 12)?;
        let qtype = u16::from_be_bytes([query[next], query[next + 1]]);
        Ok(build_synthetic_dns_reply(tx_id, &qname, qtype))
    });

    let mut rows = Vec::new();
    let types = [
        DnsRecordType::A,
        DnsRecordType::AAAA,
        DnsRecordType::MX,
        DnsRecordType::NS,
        DnsRecordType::TXT,
        DnsRecordType::SOA,
        DnsRecordType::CAA,
    ];
    rows.extend(query_dns_records(
        "example.com",
        &types,
        server,
        &mock,
        Duration::from_secs(2),
    )?);
    rows.extend(query_dns_records(
        "93.184.216.34",
        &[DnsRecordType::PTR],
        server,
        &mock,
        Duration::from_secs(2),
    )?);
    Ok(rows)
}

/// Builds a valid RFC 1035 wire reply packet for offline/unit-test fixtures.
pub fn build_synthetic_dns_reply(tx_id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let encoded_qname = crate::dns_wire::encode_dns_name(qname).unwrap_or_else(|_| vec![0]);
    let mut rdata = Vec::new();
    let mut has_answer = true;

    match qtype {
        // A -> 93.184.216.34
        1 => rdata.extend_from_slice(&[93, 184, 216, 34]),
        // AAAA -> 2606:2800:220:1:248:1893:25c8:1946
        28 => rdata.extend_from_slice(&[
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46,
        ]),
        // NS -> a.iana-servers.net
        2 => rdata.extend_from_slice(&crate::dns_wire::encode_dns_name("a.iana-servers.net").unwrap()),
        // CNAME -> example.com
        5 => rdata.extend_from_slice(&crate::dns_wire::encode_dns_name("example.com").unwrap()),
        // PTR -> example.com
        12 => rdata.extend_from_slice(&crate::dns_wire::encode_dns_name("example.com").unwrap()),
        // MX -> 10 mail.example.com
        15 => {
            rdata.extend_from_slice(&10u16.to_be_bytes());
            rdata.extend_from_slice(&crate::dns_wire::encode_dns_name("mail.example.com").unwrap());
        }
        // TXT -> v=spf1 -all
        16 => {
            let txt = b"v=spf1 -all";
            rdata.push(txt.len() as u8);
            rdata.extend_from_slice(txt);
        }
        // SOA
        6 => {
            rdata.extend_from_slice(&crate::dns_wire::encode_dns_name("ns.icann.org").unwrap());
            rdata.extend_from_slice(&crate::dns_wire::encode_dns_name("noc.dns.icann.org").unwrap());
            rdata.extend_from_slice(&2024081401u32.to_be_bytes());
            rdata.extend_from_slice(&7200u32.to_be_bytes());
            rdata.extend_from_slice(&3600u32.to_be_bytes());
            rdata.extend_from_slice(&1209600u32.to_be_bytes());
            rdata.extend_from_slice(&3600u32.to_be_bytes());
        }
        // SRV -> 10 5 443 sip.example.com
        33 => {
            rdata.extend_from_slice(&10u16.to_be_bytes());
            rdata.extend_from_slice(&5u16.to_be_bytes());
            rdata.extend_from_slice(&443u16.to_be_bytes());
            rdata.extend_from_slice(&crate::dns_wire::encode_dns_name("sip.example.com").unwrap());
        }
        // CAA -> 0 issue "letsencrypt.org"
        257 => {
            rdata.push(0);
            rdata.push(5);
            rdata.extend_from_slice(b"issue");
            rdata.extend_from_slice(b"letsencrypt.org");
        }
        _ => {
            has_answer = false;
        }
    }

    let mut pkt = Vec::new();
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    pkt.extend_from_slice(&(if has_answer { 1u16 } else { 0u16 }).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&encoded_qname);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());

    if has_answer {
        // Compression pointer to question name at offset 12 (0xC00C)
        pkt.extend_from_slice(&0xC00Cu16.to_be_bytes());
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // IN
        pkt.extend_from_slice(&3600u32.to_be_bytes()); // TTL
        pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&rdata);
    }
    let _ = decode_dns_response(&pkt, tx_id);
    pkt
}

pub struct DnsProvider {
    ctx: NetContext,
    schema: TableSchema,
}

impl DnsProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx, schema: schema() }
    }
}

impl TableProvider for DnsProvider {
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
        let domain_plan = plan_filter_query(
            req.filter.as_ref(),
            &["Domain"],
            |tok| tok.parse::<IpAddr>().is_ok() || (tok.contains('.') && normalize_domain(tok).is_ok()),
            |tok| {
                if let Ok(ip) = tok.parse::<IpAddr>() {
                    Some(ip_to_arpa_name(ip))
                } else {
                    Some(tok.trim().trim_end_matches('.').to_string())
                }
            },
        );
        let domain_targets: Vec<String> = domain_plan
            .targets
            .into_iter()
            .flat_map(|s| split_target_list(&s))
            .collect();
        let rr_targets: Vec<String> = extract_conjunctive_targets(req.filter.as_ref(), &["RecordType"], |tok| {
            DnsRecordType::from_str(tok).is_ok()
        })
        .into_iter()
        .flat_map(|s| split_target_list(&s))
        .collect();
        let server_targets = extract_conjunctive_targets(req.filter.as_ref(), &["DnsServer"], |tok| {
            parse_dns_server_addr(tok).is_ok()
        });

        let server_addr = if let Some(raw_srv) = server_targets.first() {
            parse_dns_server_addr(raw_srv)?
        } else {
            DEFAULT_DNS_SERVER.parse().expect("valid default dns")
        };

        let mut rr_types = Vec::new();
        for tok in &rr_targets {
            rr_types.push(DnsRecordType::from_str(tok)?);
        }
        if rr_types.is_empty() {
            rr_types = vec![
                DnsRecordType::A,
                DnsRecordType::AAAA,
                DnsRecordType::MX,
                DnsRecordType::NS,
                DnsRecordType::TXT,
                DnsRecordType::SOA,
                DnsRecordType::CAA,
            ];
        }

        let mut records: Vec<DnsRowRecord> = match &self.ctx.mode {
            ExecutionMode::Offline(cfg) if domain_targets.is_empty() => {
                build_offline_dns_records(Some(cfg), server_addr)?
            }
            ExecutionMode::Offline(cfg) => {
                let mock = MockDnsTransport::new(|_srv, query, _tcp| {
                    let tx_id = u16::from_be_bytes([query[0], query[1]]);
                    let (qname, next) = crate::dns_wire::decode_name(query, 12)?;
                    let qtype = u16::from_be_bytes([query[next], query[next + 1]]);
                    Ok(build_synthetic_dns_reply(tx_id, &qname, qtype))
                });
                let mut all = Vec::new();
                for target in &domain_targets {
                    let mut types_for_target = rr_types.clone();
                    if target.parse::<IpAddr>().is_ok() && rr_targets.is_empty() {
                        types_for_target = vec![DnsRecordType::PTR];
                    }
                    all.extend(query_dns_records(
                        target,
                        &types_for_target,
                        server_addr,
                        &mock,
                        self.ctx.timeout,
                    )?);
                }
                if domain_plan.include_defaults {
                    all.extend(build_offline_dns_records(Some(cfg), server_addr)?);
                }
                all
            }
            ExecutionMode::Live => {
                let mut seen_doms = HashSet::new();
                let mut live_targets = Vec::new();
                for t in domain_targets {
                    if seen_doms.insert(t.to_ascii_lowercase()) {
                        live_targets.push(t);
                    }
                }
                if (domain_plan.include_defaults || live_targets.is_empty())
                    && seen_doms.insert("example.com".to_string())
                {
                    live_targets.push("example.com".to_string());
                }
                let transport = StdDnsTransport::new();
                let mut all = Vec::new();
                for target in &live_targets {
                    let mut types_for_target = rr_types.clone();
                    if target.parse::<IpAddr>().is_ok() && rr_targets.is_empty() {
                        types_for_target = vec![DnsRecordType::PTR];
                    }
                    all.extend(query_dns_records(
                        target,
                        &types_for_target,
                        server_addr,
                        &transport,
                        self.ctx.timeout,
                    )?);
                }
                all
            }
        };

        let mut seen_rows = HashSet::new();
        records.retain(|rec| {
            seen_rows.insert((
                rec.domain.clone(),
                rec.record_type.clone(),
                rec.ttl,
                rec.value.clone(),
                rec.priority,
                rec.dns_server.clone(),
            ))
        });

        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, rec)| {
                let detail = serde_json::to_value(&rec).unwrap_or(serde_json::Value::Null);
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.domain),
                        CellValue::Text(rec.record_type),
                        CellValue::Uint(rec.ttl as u64),
                        CellValue::Text(rec.value),
                        rec.priority
                            .map(|p| CellValue::Uint(p as u64))
                            .unwrap_or(CellValue::Null),
                        CellValue::Text(rec.dns_server),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        // Normalize RecordType and DnsServer predicates (e.g., "MX, A" -> Or(MX, A), "mx" -> "MX",
        // "1.1.1.1" -> "1.1.1.1:53") without stripping them so multi-value Or/And filters evaluate accurately.
        let normalized_rr = normalize_filter_columns(
            domain_plan.remaining_filter.as_ref(),
            &["RecordType"],
            |tok| DnsRecordType::from_str(tok).is_ok(),
            |tok| DnsRecordType::from_str(tok).ok().map(|t| t.as_str().to_string()),
        );
        let remaining_filter = normalize_filter_columns(
            normalized_rr.as_ref(),
            &["DnsServer"],
            |tok| parse_dns_server_addr(tok).is_ok(),
            |tok| parse_dns_server_addr(tok).ok().map(|sa| sa.to_string()),
        );
        let forwarded = TableQuery {
            filter: remaining_filter,
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
    Arc::new(DnsProvider::new(ctx.clone()))
}
