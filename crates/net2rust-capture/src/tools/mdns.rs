//! `capture.mdns` (`mDNSView`) TableProvider.

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use net2rust_core::NetContext;
use serde_json::json;

use crate::capture::{CaptureRequest, capture_packets};
use crate::decode::mdns::extract_mdns_services;
use crate::tools::finalize_table_query;

pub struct MdnsProvider {
    ctx: NetContext,
}

impl MdnsProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

fn build_schema() -> TableSchema {
    TableSchema::new(
        "capture.mdns",
        "mDNSView — Multicast DNS & DNS-SD Services",
        vec![
            ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(180),
            ColumnDef::new("service_name", "ServiceName", ColumnType::Text).with_width_hint(200),
            ColumnDef::new("service_type", "ServiceType", ColumnType::Text).with_width_hint(170),
            ColumnDef::new("host_name", "HostName", ColumnType::Text).with_width_hint(170),
            ColumnDef::new("ip_addresses", "IPAddresses", ColumnType::Text).with_width_hint(180),
            ColumnDef::new("port", "Port", ColumnType::Uint).with_width_hint(75),
            ColumnDef::new("txt_records", "TxtRecords", ColumnType::Text).with_width_hint(240),
            ColumnDef::new("ttl", "TTL", ColumnType::Uint).with_width_hint(75),
        ],
    )
    .with_default_sort(0, SortDirection::Asc)
}

impl TableProvider for MdnsProvider {
    fn tool_id(&self) -> &'static str {
        "capture.mdns"
    }

    fn description(&self) -> &'static str {
        "mDNSView — Multicast DNS (UDP 5353) and DNS-SD service discovery"
    }

    fn schema(&self) -> TableSchema {
        build_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let packets = capture_packets(&self.ctx, &CaptureRequest::default()).map_err(TableError::from)?;
        let services = extract_mdns_services(&packets);

        let rows: Vec<Row> = services
            .into_iter()
            .enumerate()
            .map(|(idx, svc)| {
                let ips_str = if svc.ip_addresses.is_empty() {
                    None
                } else {
                    Some(
                        svc.ip_addresses
                            .iter()
                            .map(|ip| ip.to_string())
                            .collect::<Vec<_>>()
                            .join(", "),
                    )
                };
                let txt_str = if svc.txt_records.is_empty() {
                    None
                } else {
                    Some(svc.txt_records.join("; "))
                };

                let detail = json!({
                    "cache_flush": svc.cache_flush,
                    "ip_count": svc.ip_addresses.len(),
                    "txt_count": svc.txt_records.len(),
                });

                Row::new(
                    (idx + 1) as u64,
                    vec![
                        svc.timestamp.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Text(svc.service_name),
                        svc.service_type.map(CellValue::Text).unwrap_or(CellValue::Null),
                        svc.host_name.map(CellValue::Text).unwrap_or(CellValue::Null),
                        ips_str.map(CellValue::Text).unwrap_or(CellValue::Null),
                        svc.port
                            .map(|p| CellValue::Uint(u64::from(p)))
                            .unwrap_or(CellValue::Null),
                        txt_str.map(CellValue::Text).unwrap_or(CellValue::Null),
                        svc.ttl
                            .map(|t| CellValue::Uint(u64::from(t)))
                            .unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        finalize_table_query(&build_schema(), rows, req, &self.ctx)
    }
}
