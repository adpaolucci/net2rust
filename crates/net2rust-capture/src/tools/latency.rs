//! `capture.latency` TableProvider with Karn's retransmission exclusion.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use net2rust_core::NetContext;
use serde_json::json;

use crate::capture::{CaptureRequest, capture_packets};
use crate::decode::l2_l4::{L4Header, decode_packet};
use crate::tools::finalize_table_query;

pub struct LatencyProvider {
    ctx: NetContext,
}

impl LatencyProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

fn build_schema() -> TableSchema {
    TableSchema::new(
        "capture.latency",
        "Passive TCP Handshake RTT",
        vec![
            ColumnDef::new("src_ip", "SrcIP", ColumnType::IpAddr).with_width_hint(150),
            ColumnDef::new("dst_ip", "DstIP", ColumnType::IpAddr).with_width_hint(150),
            ColumnDef::new("dst_port", "DstPort", ColumnType::Uint).with_width_hint(85),
            ColumnDef::new("min_latency_ms", "MinLatencyMs", ColumnType::Float).with_width_hint(110),
            ColumnDef::new("avg_latency_ms", "AvgLatencyMs", ColumnType::Float).with_width_hint(110),
            ColumnDef::new("max_latency_ms", "MaxLatencyMs", ColumnType::Float).with_width_hint(110),
            ColumnDef::new("sample_count", "SampleCount", ColumnType::Uint).with_width_hint(100),
            ColumnDef::new("last_seen", "LastSeen", ColumnType::Timestamp).with_width_hint(180),
        ],
    )
    .with_default_sort(4, SortDirection::Desc)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct HandshakeKey {
    client_ip: IpAddr,
    client_port: u16,
    server_ip: IpAddr,
    server_port: u16,
}

#[derive(Debug, Clone, Copy)]
struct PendingSyn {
    seq: u32,
    timestamp: DateTime<Utc>,
    retransmitted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EndpointKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    dst_port: u16,
}

#[derive(Default)]
struct RttAggregate {
    samples_ms: Vec<f64>,
    last_seen: Option<DateTime<Utc>>,
    excluded_retransmissions: u64,
}

impl TableProvider for LatencyProvider {
    fn tool_id(&self) -> &'static str {
        "capture.latency"
    }

    fn description(&self) -> &'static str {
        "Passive TCP SYN -> SYN-ACK RTT with Karn's retransmission exclusion"
    }

    fn schema(&self) -> TableSchema {
        build_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let packets = capture_packets(&self.ctx, &CaptureRequest::default()).map_err(TableError::from)?;
        let mut pending: HashMap<HandshakeKey, PendingSyn> = HashMap::new();
        let mut aggregates: BTreeMap<EndpointKey, RttAggregate> = BTreeMap::new();

        for pkt in &packets {
            let Ok(dec) = decode_packet(pkt) else {
                continue;
            };
            let (Some(src_ip), Some(dst_ip), Some(ts)) = (dec.src_ip, dec.dst_ip, dec.timestamp) else {
                continue;
            };
            let Some(L4Header::Tcp(tcp)) = dec.l4 else {
                continue;
            };

            let is_pure_syn = (tcp.flags & 0x0002) != 0 && (tcp.flags & 0x0010) == 0;
            let is_syn_ack = (tcp.flags & 0x0012) == 0x0012;

            if is_pure_syn {
                let hkey = HandshakeKey {
                    client_ip: src_ip,
                    client_port: tcp.src_port,
                    server_ip: dst_ip,
                    server_port: tcp.dst_port,
                };
                match pending.get_mut(&hkey) {
                    Some(prev) if prev.seq == tcp.seq => {
                        // Karn's algorithm: retransmitted SYN renders RTT ambiguous -> mark & exclude.
                        prev.retransmitted = true;
                        let ekey = EndpointKey {
                            src_ip,
                            dst_ip,
                            dst_port: tcp.dst_port,
                        };
                        aggregates.entry(ekey).or_default().excluded_retransmissions += 1;
                    }
                    _ => {
                        pending.insert(
                            hkey,
                            PendingSyn {
                                seq: tcp.seq,
                                timestamp: ts,
                                retransmitted: false,
                            },
                        );
                    }
                }
            } else if is_syn_ack {
                let hkey = HandshakeKey {
                    client_ip: dst_ip,
                    client_port: tcp.dst_port,
                    server_ip: src_ip,
                    server_port: tcp.src_port,
                };
                if let Some(syn) = pending.remove(&hkey)
                    && tcp.ack == syn.seq.wrapping_add(1)
                    && !syn.retransmitted
                {
                    let delta_us = (ts - syn.timestamp).num_microseconds().unwrap_or(-1);
                    if delta_us >= 0 {
                        let rtt_ms = delta_us as f64 / 1000.0;
                        let ekey = EndpointKey {
                            src_ip: dst_ip,
                            dst_ip: src_ip,
                            dst_port: tcp.src_port,
                        };
                        let agg = aggregates.entry(ekey).or_default();
                        agg.samples_ms.push(rtt_ms);
                        agg.last_seen = Some(agg.last_seen.map(|p| p.max(ts)).unwrap_or(ts));
                    }
                }
            }
        }

        let mut rows = Vec::new();
        for (ekey, agg) in aggregates {
            if agg.samples_ms.is_empty() {
                continue;
            }
            let min_ms = agg.samples_ms.iter().copied().fold(f64::INFINITY, f64::min);
            let max_ms = agg.samples_ms.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            let avg_ms = agg.samples_ms.iter().sum::<f64>() / agg.samples_ms.len() as f64;
            let count = agg.samples_ms.len() as u64;

            let detail = json!({
                "excluded_retransmissions": agg.excluded_retransmissions,
                "samples_ms": agg.samples_ms,
            });

            let row_id = (rows.len() + 1) as u64;
            rows.push(
                Row::new(
                    row_id,
                    vec![
                        CellValue::Text(ekey.src_ip.to_string()),
                        CellValue::Text(ekey.dst_ip.to_string()),
                        CellValue::Uint(u64::from(ekey.dst_port)),
                        CellValue::Float(min_ms),
                        CellValue::Float(avg_ms),
                        CellValue::Float(max_ms),
                        CellValue::Uint(count),
                        agg.last_seen.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(detail),
            );
        }

        finalize_table_query(&build_schema(), rows, req, &self.ctx)
    }
}
