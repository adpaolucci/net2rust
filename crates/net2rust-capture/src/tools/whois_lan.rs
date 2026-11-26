//! `capture.whois-lan` TableProvider.

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use net2rust_core::NetContext;
use serde_json::json;

use crate::capture::{CaptureRequest, capture_packets};
use crate::decode::lan_discovery::discover_lan_hosts;
use crate::tools::finalize_table_query;

pub struct WhoisLanProvider {
    ctx: NetContext,
}

impl WhoisLanProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

fn build_schema() -> TableSchema {
    TableSchema::new(
        "capture.whois-lan",
        "Passive LAN Host Discovery",
        vec![
            ColumnDef::new("ip_address", "IPAddress", ColumnType::IpAddr).with_width_hint(140),
            ColumnDef::new("mac_address", "MACAddress", ColumnType::MacAddr).with_width_hint(140),
            ColumnDef::new("host_name", "HostName", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("vendor_oui", "VendorOUI", ColumnType::Text).with_width_hint(180),
            ColumnDef::new("discovery_protocol", "DiscoveryProtocol", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("os_hint", "OSHint", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("first_seen", "FirstSeen", ColumnType::Timestamp).with_width_hint(180),
            ColumnDef::new("last_seen", "LastSeen", ColumnType::Timestamp).with_width_hint(180),
        ],
    )
    .with_default_sort(0, SortDirection::Asc)
}

impl TableProvider for WhoisLanProvider {
    fn tool_id(&self) -> &'static str {
        "capture.whois-lan"
    }

    fn description(&self) -> &'static str {
        "Passive ARP/DHCP/mDNS/NetBIOS/SSDP LAN host inventory with OUI lookup"
    }

    fn schema(&self) -> TableSchema {
        build_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let packets = capture_packets(&self.ctx, &CaptureRequest::default()).map_err(TableError::from)?;
        let oui_path = self.ctx.offline_config().and_then(|c| c.oui_db_path.as_deref());
        let hosts = discover_lan_hosts(&packets, oui_path);

        let rows: Vec<Row> = hosts
            .into_iter()
            .enumerate()
            .map(|(idx, h)| {
                let protos: Vec<String> = h.protocols.into_iter().collect();
                let proto_str = protos.join(",");
                let detail = json!({
                    "protocols": protos,
                    "oui_hex": h.mac_address.map(|m| m.oui_hex()),
                });

                Row::new(
                    (idx + 1) as u64,
                    vec![
                        h.ip_address
                            .map(|ip| CellValue::Text(ip.to_string()))
                            .unwrap_or(CellValue::Null),
                        h.mac_address
                            .map(|m| CellValue::Text(m.to_colon_string()))
                            .unwrap_or(CellValue::Null),
                        h.host_name.map(CellValue::Text).unwrap_or(CellValue::Null),
                        h.vendor_oui.map(CellValue::Text).unwrap_or(CellValue::Null),
                        CellValue::Text(proto_str),
                        h.os_hint.map(CellValue::Text).unwrap_or(CellValue::Null),
                        h.first_seen.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        h.last_seen.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        finalize_table_query(&build_schema(), rows, req, &self.ctx)
    }
}
