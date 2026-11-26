//! `capture.http` TableProvider with strict R4 header/URL/raw_bytes redaction.

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use net2rust_core::NetContext;
use serde_json::{Map, Value, json};

use crate::capture::{CaptureRequest, capture_packets};
use crate::decode::http::extract_http_transactions;
use crate::tools::finalize_table_query;

pub struct HttpProvider {
    ctx: NetContext,
}

impl HttpProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

fn build_schema() -> TableSchema {
    TableSchema::new(
        "capture.http",
        "HTTP Header Metadata",
        vec![
            ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(180),
            ColumnDef::new("method", "Method", ColumnType::Text).with_width_hint(80),
            ColumnDef::new("host", "Host", ColumnType::Text).with_width_hint(180),
            ColumnDef::new("path", "Path", ColumnType::Text).with_width_hint(220),
            ColumnDef::new("status_code", "StatusCode", ColumnType::Uint).with_width_hint(90),
            ColumnDef::new("content_type", "ContentType", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("content_length", "ContentLength", ColumnType::BytesSize).with_width_hint(110),
            ColumnDef::new("user_agent", "UserAgent", ColumnType::Text).with_width_hint(200),
            ColumnDef::new("server", "Server", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("src_ip", "SrcIP", ColumnType::IpAddr).with_width_hint(140),
            ColumnDef::new("dst_ip", "DstIP", ColumnType::IpAddr).with_width_hint(140),
        ],
    )
    .with_default_sort(0, SortDirection::Asc)
}

impl TableProvider for HttpProvider {
    fn tool_id(&self) -> &'static str {
        "capture.http"
    }

    fn description(&self) -> &'static str {
        "HTTP request/response header metadata (R4 credential-free)"
    }

    fn schema(&self) -> TableSchema {
        build_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let packets = capture_packets(&self.ctx, &CaptureRequest::default()).map_err(TableError::from)?;
        let txns = extract_http_transactions(&packets, self.ctx.redact_sensitive_headers);

        let mut rows = Vec::with_capacity(txns.len());
        for (idx, txn) in txns.into_iter().enumerate() {
            let method = txn
                .request
                .as_ref()
                .map(|r| CellValue::Text(r.method.clone()))
                .unwrap_or(CellValue::Null);
            let host = txn
                .request
                .as_ref()
                .and_then(|r| r.host.as_ref())
                .map(|h| CellValue::Text(h.clone()))
                .unwrap_or(CellValue::Null);
            let path = txn
                .request
                .as_ref()
                .map(|r| CellValue::Text(r.path.clone()))
                .unwrap_or(CellValue::Null);
            let status_code = txn
                .response
                .as_ref()
                .map(|r| CellValue::Uint(u64::from(r.status_code)))
                .unwrap_or(CellValue::Null);
            let content_type = txn
                .response
                .as_ref()
                .and_then(|r| r.content_type.as_ref())
                .map(|ct| CellValue::Text(ct.clone()))
                .unwrap_or(CellValue::Null);
            let content_length = txn
                .response
                .as_ref()
                .map(|r| CellValue::Bytes(r.decoded_body_len as u64))
                .unwrap_or(CellValue::Null);
            let user_agent = txn
                .request
                .as_ref()
                .and_then(|r| r.user_agent.as_ref())
                .map(|ua| CellValue::Text(ua.clone()))
                .unwrap_or(CellValue::Null);
            let server = txn
                .response
                .as_ref()
                .and_then(|r| r.server.as_ref())
                .map(|s| CellValue::Text(s.clone()))
                .unwrap_or(CellValue::Null);

            let mut req_hdrs = Map::new();
            if let Some(ref rq) = txn.request {
                for h in &rq.headers {
                    req_hdrs.insert(h.name.clone(), Value::String(h.sanitized_value.clone()));
                }
            }
            let mut resp_hdrs = Map::new();
            if let Some(ref rs) = txn.response {
                for h in &rs.headers {
                    resp_hdrs.insert(h.name.clone(), Value::String(h.sanitized_value.clone()));
                }
            }

            let detail = json!({
                "src_port": txn.src_port,
                "dst_port": txn.dst_port,
                "request_headers": req_hdrs,
                "response_headers": resp_hdrs,
                "r4_redacted": txn.had_sensitive_material,
            });

            let mut row = Row::new(
                (idx + 1) as u64,
                vec![
                    txn.timestamp.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                    method,
                    host,
                    path,
                    status_code,
                    content_type,
                    content_length,
                    user_agent,
                    server,
                    CellValue::Text(txn.src_ip.to_string()),
                    CellValue::Text(txn.dst_ip.to_string()),
                ],
            )
            .with_detail_json(detail);

            if !txn.had_sensitive_material
                && let Some(ref rq) = txn.request
            {
                row = row.with_raw_bytes(rq.raw_sanitized_headers.clone());
            }

            rows.push(row);
        }

        finalize_table_query(&build_schema(), rows, req, &self.ctx)
    }
}
