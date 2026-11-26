//! `capture.sniff` (`SmartSniff`) TableProvider.

use std::collections::HashSet;
use std::net::IpAddr;

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use net2rust_core::NetContext;
use serde_json::json;

use crate::capture::{CaptureRequest, capture_packets};
use crate::decode::l2_l4::{L4Header, decode_packet};
use crate::r4_guard::{
    is_cleartext_auth_initiation, safe_payload_summary, safe_tainted_flow_summary, should_omit_raw_bytes,
};
use crate::tools::finalize_table_query;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct BidirectionalTcpFlow {
    ep_a: (IpAddr, u16),
    ep_b: (IpAddr, u16),
}

impl BidirectionalTcpFlow {
    fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        let a = (src_ip, src_port);
        let b = (dst_ip, dst_port);
        if a <= b {
            Self { ep_a: a, ep_b: b }
        } else {
            Self { ep_a: b, ep_b: a }
        }
    }
}

pub struct SniffProvider {
    ctx: NetContext,
}

impl SniffProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

fn build_schema() -> TableSchema {
    TableSchema::new(
        "capture.sniff",
        "SmartSniff — Packet & Stream Summary",
        vec![
            ColumnDef::new("packet_no", "PacketNo", ColumnType::Uint).with_width_hint(80),
            ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(180),
            ColumnDef::new("protocol", "Protocol", ColumnType::Text).with_width_hint(90),
            ColumnDef::new("src_ip", "SrcIP", ColumnType::IpAddr).with_width_hint(150),
            ColumnDef::new("src_port", "SrcPort", ColumnType::Uint).with_width_hint(80),
            ColumnDef::new("dst_ip", "DstIP", ColumnType::IpAddr).with_width_hint(150),
            ColumnDef::new("dst_port", "DstPort", ColumnType::Uint).with_width_hint(80),
            ColumnDef::new("length", "Length", ColumnType::BytesSize).with_width_hint(90),
            ColumnDef::new("tcp_flags", "TcpFlags", ColumnType::Text).with_width_hint(120),
            ColumnDef::new("summary", "Summary", ColumnType::Text).with_width_hint(280),
        ],
    )
    .with_default_sort(0, SortDirection::Asc)
}

impl TableProvider for SniffProvider {
    fn tool_id(&self) -> &'static str {
        "capture.sniff"
    }

    fn description(&self) -> &'static str {
        "SmartSniff — IPv4/IPv6/TCP/UDP/ICMP/ARP packet summary (R4 credential-free)"
    }

    fn schema(&self) -> TableSchema {
        build_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let packets = capture_packets(&self.ctx, &CaptureRequest::default()).map_err(TableError::from)?;
        let mut rows = Vec::with_capacity(packets.len());
        let mut tainted_tcp_flows: HashSet<BidirectionalTcpFlow> = HashSet::new();

        for pkt in &packets {
            let Ok(dec) = decode_packet(pkt) else {
                continue;
            };

            let tcp_flow = if matches!(dec.l4, Some(L4Header::Tcp(_))) {
                match (dec.src_ip, dec.src_port, dec.dst_ip, dec.dst_port) {
                    (Some(si), Some(sp), Some(di), Some(dp)) => Some(BidirectionalTcpFlow::new(si, sp, di, dp)),
                    _ => None,
                }
            } else {
                None
            };
            let flow_already_tainted = tcp_flow.is_some_and(|f| tainted_tcp_flows.contains(&f));
            let initiates_auth = matches!(dec.l4, Some(L4Header::Tcp(_)))
                && is_cleartext_auth_initiation(dec.src_port, dec.dst_port, dec.payload);
            if initiates_auth && let Some(flow) = tcp_flow {
                tainted_tcp_flows.insert(flow);
            }

            let summary = if let Some(arp) = dec.arp {
                let op_name = if arp.oper == 1 {
                    "Request"
                } else if arp.oper == 2 {
                    "Reply"
                } else {
                    "Op"
                };
                format!("ARP {op_name} {} ({}) -> {}", arp.spa, arp.sha, arp.tpa)
            } else if dec.is_non_initial_fragment {
                format!("{} non-initial fragment ({}B)", dec.protocol_label, dec.payload.len())
            } else {
                match &dec.l4 {
                    Some(L4Header::Icmpv4(icmp)) => {
                        let id = u16::from_be_bytes([icmp.rest[0], icmp.rest[1]]);
                        let seq = u16::from_be_bytes([icmp.rest[2], icmp.rest[3]]);
                        format!(
                            "ICMP type={} code={} id=0x{id:04x} seq={seq}",
                            icmp.icmp_type, icmp.code
                        )
                    }
                    Some(L4Header::Icmpv6(icmp)) => {
                        format!("ICMPv6 type={} code={}", icmp.icmp_type, icmp.code)
                    }
                    Some(L4Header::Tcp(_)) => {
                        if flow_already_tainted {
                            safe_tainted_flow_summary(&dec.protocol_label, dec.payload.len())
                        } else {
                            safe_payload_summary(dec.src_port, dec.dst_port, dec.payload, &dec.protocol_label)
                        }
                    }
                    Some(L4Header::Udp(_)) => {
                        safe_payload_summary(dec.src_port, dec.dst_port, dec.payload, &dec.protocol_label)
                    }
                    None => format!("{} {}B", dec.protocol_label, dec.payload.len()),
                }
            };

            let omit_raw = flow_already_tainted
                || initiates_auth
                || should_omit_raw_bytes(dec.src_port, dec.dst_port, dec.payload);
            let raw_bytes = if omit_raw {
                None
            } else {
                let cap = dec.raw_frame.len().min(512);
                Some(dec.raw_frame[..cap].to_vec())
            };

            let detail_json = json!({
                "packet_no": dec.packet_no,
                "ethernet_type": dec.ethernet_type_label,
                "vlan_id": dec.vlan_id,
                "src_mac": dec.src_mac.map(|m| m.to_colon_string()),
                "dst_mac": dec.dst_mac.map(|m| m.to_colon_string()),
                "payload_offset": dec.payload_offset,
                "payload_len": dec.payload.len(),
                "r4_raw_omitted": omit_raw,
            });

            let cells = vec![
                CellValue::Uint(dec.packet_no),
                dec.timestamp.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                CellValue::Text(dec.protocol_label),
                dec.src_ip
                    .map(|ip| CellValue::Text(ip.to_string()))
                    .unwrap_or(CellValue::Null),
                dec.src_port
                    .map(|p| CellValue::Uint(u64::from(p)))
                    .unwrap_or(CellValue::Null),
                dec.dst_ip
                    .map(|ip| CellValue::Text(ip.to_string()))
                    .unwrap_or(CellValue::Null),
                dec.dst_port
                    .map(|p| CellValue::Uint(u64::from(p)))
                    .unwrap_or(CellValue::Null),
                CellValue::Bytes(u64::from(dec.original_len)),
                dec.tcp_flags_text.map(CellValue::Text).unwrap_or(CellValue::Null),
                CellValue::Text(summary),
            ];

            let mut row = Row::new(dec.packet_no, cells).with_detail_json(detail_json);
            if let Some(rb) = raw_bytes {
                row = row.with_raw_bytes(rb);
            }
            rows.push(row);
        }

        finalize_table_query(&build_schema(), rows, req, &self.ctx)
    }
}
