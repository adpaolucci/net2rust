//! `capture.dns` TableProvider supporting UDP 53 and TCP 53 (2-byte length prefix).

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use net2rust_core::NetContext;
use serde_json::json;

use crate::capture::{CaptureRequest, capture_packets};
use crate::decode::dns_wire::{
    DnsMessage, parse_dns_message, parse_dns_tcp_frames_with_offsets, qtype_name, rcode_name,
};
use crate::decode::l2_l4::{L4Header, decode_packet};
use crate::decode::tcp_stream::TcpStreamReassembler;
use crate::tools::finalize_table_query;

pub struct DnsProvider {
    ctx: NetContext,
}

impl DnsProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

fn build_schema() -> TableSchema {
    TableSchema::new(
        "capture.dns",
        "DNS Queries & Responses",
        vec![
            ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(180),
            ColumnDef::new("tx_id", "TxID", ColumnType::Text).with_width_hint(80),
            ColumnDef::new("query_name", "QueryName", ColumnType::Text).with_width_hint(220),
            ColumnDef::new("query_type", "QueryType", ColumnType::Text).with_width_hint(80),
            ColumnDef::new("response_code", "ResponseCode", ColumnType::Text).with_width_hint(110),
            ColumnDef::new("answers", "Answers", ColumnType::Text).with_width_hint(260),
            ColumnDef::new("ttl", "TTL", ColumnType::Uint).with_width_hint(70),
            ColumnDef::new("src_ip", "SrcIP", ColumnType::IpAddr).with_width_hint(140),
            ColumnDef::new("dst_ip", "DstIP", ColumnType::IpAddr).with_width_hint(140),
            ColumnDef::new("latency_ms", "LatencyMs", ColumnType::Float).with_width_hint(95),
        ],
    )
    .with_default_sort(0, SortDirection::Asc)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PendingKey {
    client_ip: IpAddr,
    server_ip: IpAddr,
    tx_id: u16,
    qname_lower: String,
}

struct PendingQuery {
    timestamp: Option<DateTime<Utc>>,
    tx_id: u16,
    qname: String,
    qtype: String,
    client_ip: IpAddr,
    server_ip: IpAddr,
    transport: &'static str,
}

struct DnsRowEntry {
    timestamp: Option<DateTime<Utc>>,
    tx_id: String,
    query_name: String,
    query_type: String,
    response_code: String,
    answers: Option<String>,
    ttl: Option<u32>,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    latency_ms: Option<f64>,
    transport: &'static str,
}

struct RawDnsItem {
    timestamp: Option<DateTime<Utc>>,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    transport: &'static str,
    parsed: Result<DnsMessage, String>,
}

fn process_dns_item(
    item: RawDnsItem,
    pending: &mut HashMap<PendingKey, VecDeque<PendingQuery>>,
    pending_order: &mut Vec<PendingKey>,
    rows: &mut Vec<DnsRowEntry>,
) {
    let msg = match item.parsed {
        Ok(m) => m,
        Err(err) => {
            rows.push(DnsRowEntry {
                timestamp: item.timestamp,
                tx_id: "0x0000".to_string(),
                query_name: format!("<malformed: {err}>"),
                query_type: "UNKNOWN".to_string(),
                response_code: "MALFORMED".to_string(),
                answers: None,
                ttl: None,
                src_ip: item.src_ip,
                dst_ip: item.dst_ip,
                latency_ms: None,
                transport: item.transport,
            });
            return;
        }
    };

    let q0 = msg.questions.first();
    let qname = q0.map(|q| q.name.clone()).unwrap_or_else(|| ".".to_string());
    let qtype = q0.map(|q| qtype_name(q.qtype)).unwrap_or_else(|| "ANY".to_string());

    if !msg.is_response {
        let key = PendingKey {
            client_ip: item.src_ip,
            server_ip: item.dst_ip,
            tx_id: msg.tx_id,
            qname_lower: qname.to_ascii_lowercase(),
        };
        if !pending.contains_key(&key) {
            pending_order.push(key.clone());
        }
        pending.entry(key).or_default().push_back(PendingQuery {
            timestamp: item.timestamp,
            tx_id: msg.tx_id,
            qname,
            qtype,
            client_ip: item.src_ip,
            server_ip: item.dst_ip,
            transport: item.transport,
        });
        return;
    }

    let key = PendingKey {
        client_ip: item.dst_ip,
        server_ip: item.src_ip,
        tx_id: msg.tx_id,
        qname_lower: qname.to_ascii_lowercase(),
    };
    let matched_query = pending.get_mut(&key).and_then(|q| q.pop_front());

    let (row_ts, client_ip, server_ip, latency_ms) = match matched_query {
        Some(q) => {
            let lat = match (q.timestamp, item.timestamp) {
                (Some(t0), Some(t1)) => {
                    let us = (t1 - t0).num_microseconds().unwrap_or(-1);
                    if us >= 0 { Some(us as f64 / 1000.0) } else { None }
                }
                _ => None,
            };
            (q.timestamp.or(item.timestamp), q.client_ip, q.server_ip, lat)
        }
        None => (item.timestamp, item.dst_ip, item.src_ip, None),
    };

    let mut ans_list = Vec::new();
    let mut min_ttl: Option<u32> = None;
    for rr in &msg.answers {
        ans_list.push(rr.rdata.display_value());
        min_ttl = Some(min_ttl.map(|t| t.min(rr.ttl)).unwrap_or(rr.ttl));
    }
    if ans_list.is_empty() {
        for rr in &msg.authorities {
            ans_list.push(rr.rdata.display_value());
            min_ttl = Some(min_ttl.map(|t| t.min(rr.ttl)).unwrap_or(rr.ttl));
        }
    }

    rows.push(DnsRowEntry {
        timestamp: row_ts,
        tx_id: format!("0x{:04X}", msg.tx_id),
        query_name: qname,
        query_type: qtype,
        response_code: rcode_name(msg.rcode),
        answers: if ans_list.is_empty() {
            None
        } else {
            Some(ans_list.join("; "))
        },
        ttl: min_ttl,
        src_ip: client_ip,
        dst_ip: server_ip,
        latency_ms,
        transport: item.transport,
    });
}

impl TableProvider for DnsProvider {
    fn tool_id(&self) -> &'static str {
        "capture.dns"
    }

    fn description(&self) -> &'static str {
        "RFC 1035 UDP/TCP DNS queries, answers, TTLs, and latency"
    }

    fn schema(&self) -> TableSchema {
        build_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let packets = capture_packets(&self.ctx, &CaptureRequest::default()).map_err(TableError::from)?;
        let mut raw_items = Vec::new();
        let mut tcp_reassembler = TcpStreamReassembler::new();

        for pkt in &packets {
            let Ok(dec) = decode_packet(pkt) else {
                continue;
            };
            let (Some(src_ip), Some(dst_ip)) = (dec.src_ip, dec.dst_ip) else {
                continue;
            };
            match &dec.l4 {
                Some(L4Header::Udp(udp)) if udp.src_port == 53 || udp.dst_port == 53 => {
                    let parsed = parse_dns_message(dec.payload, false).map_err(|e| e.to_string());
                    raw_items.push(RawDnsItem {
                        timestamp: dec.timestamp,
                        src_ip,
                        dst_ip,
                        transport: "UDP",
                        parsed,
                    });
                }
                Some(L4Header::Tcp(tcp)) if tcp.src_port == 53 || tcp.dst_port == 53 => {
                    let key = crate::decode::tcp_stream::StreamKey {
                        src_ip,
                        src_port: tcp.src_port,
                        dst_ip,
                        dst_port: tcp.dst_port,
                    };
                    tcp_reassembler.ingest_segment(key, tcp.seq, tcp.flags, dec.timestamp, dec.payload);
                }
                _ => {}
            }
        }

        for stream in tcp_reassembler.finalize() {
            let msgs = parse_dns_tcp_frames_with_offsets(&stream.data, false);
            for (offset, res) in msgs {
                raw_items.push(RawDnsItem {
                    timestamp: stream.timestamp_at(offset),
                    src_ip: stream.key.src_ip,
                    dst_ip: stream.key.dst_ip,
                    transport: "TCP",
                    parsed: res.map_err(|e| e.to_string()),
                });
            }
        }

        let mut pending: HashMap<PendingKey, VecDeque<PendingQuery>> = HashMap::new();
        let mut pending_order: Vec<PendingKey> = Vec::new();
        let mut entries: Vec<DnsRowEntry> = Vec::new();

        for item in raw_items {
            process_dns_item(item, &mut pending, &mut pending_order, &mut entries);
        }

        // Remaining unanswered queries
        for key in pending_order {
            if let Some(mut queue) = pending.remove(&key) {
                while let Some(q) = queue.pop_front() {
                    entries.push(DnsRowEntry {
                        timestamp: q.timestamp,
                        tx_id: format!("0x{:04X}", q.tx_id),
                        query_name: q.qname,
                        query_type: q.qtype,
                        response_code: "NO_RESPONSE".to_string(),
                        answers: None,
                        ttl: None,
                        src_ip: q.client_ip,
                        dst_ip: q.server_ip,
                        latency_ms: None,
                        transport: q.transport,
                    });
                }
            }
        }

        let rows: Vec<Row> = entries
            .into_iter()
            .enumerate()
            .map(|(idx, e)| {
                let detail = json!({
                    "transport": e.transport,
                    "tx_id": e.tx_id,
                    "response_code": e.response_code,
                });
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        e.timestamp.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Text(e.tx_id),
                        CellValue::Text(e.query_name),
                        CellValue::Text(e.query_type),
                        CellValue::Text(e.response_code),
                        e.answers.map(CellValue::Text).unwrap_or(CellValue::Null),
                        e.ttl.map(|t| CellValue::Uint(u64::from(t))).unwrap_or(CellValue::Null),
                        CellValue::Text(e.src_ip.to_string()),
                        CellValue::Text(e.dst_ip.to_string()),
                        e.latency_ms.map(CellValue::Float).unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        finalize_table_query(&build_schema(), rows, req, &self.ctx)
    }
}
