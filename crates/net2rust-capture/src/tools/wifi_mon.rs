//! `capture.wifi-mon` TableProvider.

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use net2rust_core::NetContext;
use serde_json::json;

use crate::capture::{CaptureRequest, capture_packets};
use crate::decode::radiotap::parse_wifi_management_packet;
use crate::tools::finalize_table_query;

pub struct WifiMonProvider {
    ctx: NetContext,
}

impl WifiMonProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

fn build_schema() -> TableSchema {
    TableSchema::new(
        "capture.wifi-mon",
        "802.11 RadioTap & Beacon Monitor",
        vec![
            ColumnDef::new("ssid", "SSID", ColumnType::Text).with_width_hint(180),
            ColumnDef::new("bssid", "BSSID", ColumnType::MacAddr).with_width_hint(140),
            ColumnDef::new("channel", "Channel", ColumnType::Uint).with_width_hint(80),
            ColumnDef::new("frequency_mhz", "FrequencyMHz", ColumnType::Uint).with_width_hint(105),
            ColumnDef::new("rssi", "RSSI", ColumnType::Int).with_width_hint(75),
            ColumnDef::new("phy_type", "PhyType", ColumnType::Text).with_width_hint(110),
            ColumnDef::new("security_mode", "SecurityMode", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("beacon_interval", "BeaconInterval", ColumnType::Uint).with_width_hint(115),
            ColumnDef::new("vendor_oui", "VendorOUI", ColumnType::Text).with_width_hint(180),
        ],
    )
    .with_default_sort(4, SortDirection::Desc)
}

impl TableProvider for WifiMonProvider {
    fn tool_id(&self) -> &'static str {
        "capture.wifi-mon"
    }

    fn description(&self) -> &'static str {
        "802.11 RadioTap/Beacon/Probe channel, RSSI, PHY, and security analyzer"
    }

    fn schema(&self) -> TableSchema {
        build_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let cap_req = CaptureRequest {
            monitor_mode: true,
            prefer_npcap: true,
            ..Default::default()
        };
        let packets = capture_packets(&self.ctx, &cap_req).map_err(TableError::from)?;
        let mut rows = Vec::new();

        for pkt in &packets {
            let Ok(Some(info)) = parse_wifi_management_packet(pkt) else {
                continue;
            };
            let detail = json!({
                "frame_subtype": info.frame_subtype,
                "oui_hex": info.bssid.oui_hex(),
                "packet_no": pkt.packet_no,
            });
            let row_id = (rows.len() + 1) as u64;
            rows.push(
                Row::new(
                    row_id,
                    vec![
                        CellValue::Text(info.ssid),
                        CellValue::Text(info.bssid.to_colon_string()),
                        info.channel
                            .map(|c| CellValue::Uint(u64::from(c)))
                            .unwrap_or(CellValue::Null),
                        info.frequency_mhz
                            .map(|f| CellValue::Uint(u64::from(f)))
                            .unwrap_or(CellValue::Null),
                        info.rssi_dbm
                            .map(|r| CellValue::Int(i64::from(r)))
                            .unwrap_or(CellValue::Null),
                        CellValue::Text(info.phy_type),
                        CellValue::Text(info.security_mode),
                        info.beacon_interval
                            .map(|b| CellValue::Uint(u64::from(b)))
                            .unwrap_or(CellValue::Null),
                        info.vendor_oui.map(CellValue::Text).unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(detail),
            );
        }

        finalize_table_query(&build_schema(), rows, req, &self.ctx)
    }
}
