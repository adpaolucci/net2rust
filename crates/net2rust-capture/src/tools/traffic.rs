//! `capture.traffic` TableProvider.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use net2rust_core::NetContext;
use serde_json::json;

use crate::capture::{CaptureRequest, capture_packets};
use crate::decode::l2_l4::decode_packet;
use crate::tools::finalize_table_query;

pub struct TrafficProvider {
    ctx: NetContext,
}

impl TrafficProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FlowKey {
    ethernet_type: String,
    protocol: String,
    src_addr: String,
    dst_addr: String,
    src_port: Option<u16>,
    dst_port: Option<u16>,
}

struct FlowStats {
    packets_count: u64,
    total_bytes: u64,
    first_seen: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
    src_mac: Option<String>,
    dst_mac: Option<String>,
    vlan_id: Option<u16>,
}

fn build_schema() -> TableSchema {
    TableSchema::new(
        "capture.traffic",
        "Aggregated Traffic Flows",
        vec![
            ColumnDef::new("ethernet_type", "EthernetType", ColumnType::Text).with_width_hint(100),
            ColumnDef::new("protocol", "Protocol", ColumnType::Text).with_width_hint(80),
            ColumnDef::new("src_addr", "SrcAddr", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("dst_addr", "DstAddr", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("src_port", "SrcPort", ColumnType::Uint).with_width_hint(80),
            ColumnDef::new("dst_port", "DstPort", ColumnType::Uint).with_width_hint(80),
            ColumnDef::new("packets_count", "PacketsCount", ColumnType::Uint).with_width_hint(100),
            ColumnDef::new("total_bytes", "TotalBytes", ColumnType::BytesSize).with_width_hint(110),
            ColumnDef::new("avg_packet_size", "AvgPacketSize", ColumnType::Float).with_width_hint(110),
            ColumnDef::new("bps", "Bps", ColumnType::Float).with_width_hint(110),
        ],
    )
    .with_default_sort(7, SortDirection::Desc)
}

impl TableProvider for TrafficProvider {
    fn tool_id(&self) -> &'static str {
        "capture.traffic"
    }

    fn description(&self) -> &'static str {
        "Aggregated traffic flows by protocol, endpoint, port, and byte volume"
    }

    fn schema(&self) -> TableSchema {
        build_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let packets = capture_packets(&self.ctx, &CaptureRequest::default()).map_err(TableError::from)?;
        let mut flows: BTreeMap<FlowKey, FlowStats> = BTreeMap::new();

        for pkt in &packets {
            let Ok(dec) = decode_packet(pkt) else {
                continue;
            };
            let src_addr = dec
                .src_ip
                .map(|ip| ip.to_string())
                .or_else(|| dec.src_mac.map(|m| m.to_colon_string()))
                .unwrap_or_else(|| "unknown".to_string());
            let dst_addr = dec
                .dst_ip
                .map(|ip| ip.to_string())
                .or_else(|| dec.dst_mac.map(|m| m.to_colon_string()))
                .unwrap_or_else(|| "unknown".to_string());

            let key = FlowKey {
                ethernet_type: dec.ethernet_type_label,
                protocol: dec.protocol_label,
                src_addr,
                dst_addr,
                src_port: dec.src_port,
                dst_port: dec.dst_port,
            };

            let entry = flows.entry(key).or_insert_with(|| FlowStats {
                packets_count: 0,
                total_bytes: 0,
                first_seen: dec.timestamp,
                last_seen: dec.timestamp,
                src_mac: dec.src_mac.map(|m| m.to_colon_string()),
                dst_mac: dec.dst_mac.map(|m| m.to_colon_string()),
                vlan_id: dec.vlan_id,
            });
            entry.packets_count += 1;
            entry.total_bytes += u64::from(dec.original_len);
            if let Some(ts) = dec.timestamp {
                entry.first_seen = Some(entry.first_seen.map(|p| p.min(ts)).unwrap_or(ts));
                entry.last_seen = Some(entry.last_seen.map(|p| p.max(ts)).unwrap_or(ts));
            }
        }

        let mut rows = Vec::with_capacity(flows.len());
        for (idx, (key, stats)) in flows.into_iter().enumerate() {
            let avg_pkt = if stats.packets_count > 0 {
                stats.total_bytes as f64 / stats.packets_count as f64
            } else {
                0.0
            };

            let bps = match (stats.first_seen, stats.last_seen) {
                (Some(first), Some(last)) => {
                    let us = (last - first).num_microseconds().unwrap_or(0);
                    if us <= 0 {
                        0.0
                    } else {
                        (stats.total_bytes as f64 * 8.0) / (us as f64 / 1_000_000.0)
                    }
                }
                _ => 0.0,
            };

            let detail = json!({
                "first_seen": stats.first_seen.map(|t| t.to_rfc3339()),
                "last_seen": stats.last_seen.map(|t| t.to_rfc3339()),
                "src_mac": stats.src_mac,
                "dst_mac": stats.dst_mac,
                "vlan_id": stats.vlan_id,
            });

            rows.push(
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(key.ethernet_type),
                        CellValue::Text(key.protocol),
                        CellValue::Text(key.src_addr),
                        CellValue::Text(key.dst_addr),
                        key.src_port
                            .map(|p| CellValue::Uint(u64::from(p)))
                            .unwrap_or(CellValue::Null),
                        key.dst_port
                            .map(|p| CellValue::Uint(u64::from(p)))
                            .unwrap_or(CellValue::Null),
                        CellValue::Uint(stats.packets_count),
                        CellValue::Bytes(stats.total_bytes),
                        CellValue::Float(avg_pkt),
                        CellValue::Float(bps),
                    ],
                )
                .with_detail_json(detail),
            );
        }

        finalize_table_query(&build_schema(), rows, req, &self.ctx)
    }
}
