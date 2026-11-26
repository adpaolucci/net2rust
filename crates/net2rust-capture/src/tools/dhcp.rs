//! `capture.dhcp` (`DHCPLogView`) TableProvider.

use std::net::IpAddr;

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use net2rust_core::NetContext;
use serde_json::json;

use crate::capture::{CaptureRequest, capture_packets};
use crate::decode::dhcp::parse_dhcp;
use crate::decode::l2_l4::{L4Header, decode_packet};
use crate::tools::finalize_table_query;

pub struct DhcpProvider {
    ctx: NetContext,
}

impl DhcpProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

fn build_schema() -> TableSchema {
    TableSchema::new(
        "capture.dhcp",
        "DHCPLogView — DHCPv4 Transactions",
        vec![
            ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(180),
            ColumnDef::new("message_type", "MessageType", ColumnType::Text).with_width_hint(110),
            ColumnDef::new("client_mac", "ClientMAC", ColumnType::MacAddr).with_width_hint(140),
            ColumnDef::new("requested_ip", "RequestedIP", ColumnType::IpAddr).with_width_hint(130),
            ColumnDef::new("assigned_ip", "AssignedIP", ColumnType::IpAddr).with_width_hint(130),
            ColumnDef::new("subnet_mask", "SubnetMask", ColumnType::IpAddr).with_width_hint(130),
            ColumnDef::new("gateway", "Gateway", ColumnType::IpAddr).with_width_hint(130),
            ColumnDef::new("dhcp_server", "DhcpServer", ColumnType::IpAddr).with_width_hint(130),
            ColumnDef::new("hostname", "Hostname", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("lease_sec", "LeaseSec", ColumnType::Uint).with_width_hint(90),
        ],
    )
    .with_default_sort(0, SortDirection::Asc)
}

impl TableProvider for DhcpProvider {
    fn tool_id(&self) -> &'static str {
        "capture.dhcp"
    }

    fn description(&self) -> &'static str {
        "DHCPLogView — BOOTP/DHCPv4 Discover/Offer/Request/Ack lease transactions"
    }

    fn schema(&self) -> TableSchema {
        build_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let packets = capture_packets(&self.ctx, &CaptureRequest::default()).map_err(TableError::from)?;
        let mut rows = Vec::new();

        for pkt in &packets {
            let Ok(dec) = decode_packet(pkt) else {
                continue;
            };
            let Some(L4Header::Udp(udp)) = dec.l4 else {
                continue;
            };
            if !matches!(udp.src_port, 67 | 68) && !matches!(udp.dst_port, 67 | 68) {
                continue;
            }
            let src_v4 = dec.src_ip.and_then(|ip| match ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            });
            let Ok(dhcp) = parse_dhcp(dec.payload, src_v4) else {
                continue;
            };

            let detail = json!({
                "xid": format!("0x{:08x}", dhcp.xid),
                "gateways": dhcp.gateways.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
                "dns_servers": dhcp.dns_servers.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
                "vendor_class": dhcp.vendor_class,
                "param_request_list": dhcp.param_request_list,
                "client_id_hex": dhcp.client_id_hex,
            });

            let row_id = (rows.len() + 1) as u64;
            rows.push(
                Row::new(
                    row_id,
                    vec![
                        dec.timestamp.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Text(dhcp.message_type),
                        dhcp.client_mac
                            .map(|m| CellValue::Text(m.to_colon_string()))
                            .unwrap_or(CellValue::Null),
                        dhcp.requested_ip
                            .map(|ip| CellValue::Text(ip.to_string()))
                            .unwrap_or(CellValue::Null),
                        dhcp.assigned_ip
                            .map(|ip| CellValue::Text(ip.to_string()))
                            .unwrap_or(CellValue::Null),
                        dhcp.subnet_mask
                            .map(|ip| CellValue::Text(ip.to_string()))
                            .unwrap_or(CellValue::Null),
                        dhcp.gateways
                            .first()
                            .map(|ip| CellValue::Text(ip.to_string()))
                            .unwrap_or(CellValue::Null),
                        dhcp.dhcp_server
                            .map(|ip| CellValue::Text(ip.to_string()))
                            .unwrap_or(CellValue::Null),
                        dhcp.hostname.map(CellValue::Text).unwrap_or(CellValue::Null),
                        dhcp.lease_sec
                            .map(|s| CellValue::Uint(u64::from(s)))
                            .unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(detail),
            );
        }

        finalize_table_query(&build_schema(), rows, req, &self.ctx)
    }
}
