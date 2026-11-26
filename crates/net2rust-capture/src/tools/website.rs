//! `capture.website` (`WebSiteSniffer`) TableProvider (strictly read-only, virtual SavedPath + SHA-256).

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use net2rust_core::NetContext;
use serde_json::json;

use crate::capture::{CaptureRequest, capture_packets};
use crate::decode::http::extract_http_transactions;
use crate::r4_guard::{contains_url_userinfo, scrub_url_credentials};
use crate::sha256::sha256_hex;
use crate::tools::finalize_table_query;

const MAX_RAW_PREVIEW_BYTES: usize = 64 * 1024;

pub struct WebsiteProvider {
    ctx: NetContext,
}

impl WebsiteProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

fn build_schema() -> TableSchema {
    TableSchema::new(
        "capture.website",
        "WebSiteSniffer — Reconstructed HTTP Assets",
        vec![
            ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(180),
            ColumnDef::new("host", "Host", ColumnType::Text).with_width_hint(170),
            ColumnDef::new("url", "URL", ColumnType::Text).with_width_hint(260),
            ColumnDef::new("content_type", "ContentType", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("size_bytes", "SizeBytes", ColumnType::BytesSize).with_width_hint(100),
            ColumnDef::new("status_code", "StatusCode", ColumnType::Uint).with_width_hint(85),
            ColumnDef::new("saved_path", "SavedPath", ColumnType::Text).with_width_hint(220),
        ],
    )
    .with_default_sort(0, SortDirection::Asc)
}

fn mime_category(mime: Option<&str>) -> &'static str {
    let lower = mime.unwrap_or("").to_ascii_lowercase();
    if lower.contains("text/html") || lower.contains("xhtml") {
        "HTML"
    } else if lower.contains("text/css") {
        "CSS"
    } else if lower.contains("javascript") || lower.contains("ecmascript") {
        "JS"
    } else if lower.starts_with("image/") {
        "Image"
    } else if lower.starts_with("font/") || lower.contains("woff") {
        "Font"
    } else if lower.contains("json") {
        "JSON"
    } else {
        "Other"
    }
}

fn sanitize_rel_path(raw_path: &str) -> String {
    let path_part = if let Some((_, after_scheme)) = raw_path.split_once("://") {
        match after_scheme.find('/') {
            Some(slash) => &after_scheme[slash..],
            None => "/",
        }
    } else {
        raw_path
    };
    let without_query = path_part.split('?').next().unwrap_or("/");
    let trimmed = without_query.trim_start_matches('/');
    let safe_segments: Vec<&str> = trimmed
        .split('/')
        .filter(|seg| !seg.is_empty() && *seg != "." && *seg != "..")
        .collect();
    if safe_segments.is_empty() {
        "index.html".to_string()
    } else {
        safe_segments.join("/")
    }
}

impl TableProvider for WebsiteProvider {
    fn tool_id(&self) -> &'static str {
        "capture.website"
    }

    fn description(&self) -> &'static str {
        "WebSiteSniffer — read-only HTTP static asset reconstruction with SHA-256 digests"
    }

    fn schema(&self) -> TableSchema {
        build_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let packets = capture_packets(&self.ctx, &CaptureRequest::default()).map_err(TableError::from)?;
        let txns = extract_http_transactions(&packets, self.ctx.redact_sensitive_headers);
        let mut rows = Vec::new();

        for txn in txns {
            let Some(ref resp) = txn.response else {
                continue;
            };
            let raw_host = txn
                .request
                .as_ref()
                .and_then(|r| r.host.clone())
                .unwrap_or_else(|| txn.dst_ip.to_string());
            let host_had_userinfo = contains_url_userinfo(&format!("http://{raw_host}/"));
            let host = if host_had_userinfo {
                scrub_url_credentials(&format!("http://{raw_host}"))
                    .trim_start_matches("http://")
                    .to_string()
            } else {
                raw_host
            };
            let path = txn
                .request
                .as_ref()
                .map(|r| scrub_url_credentials(&r.path))
                .unwrap_or_else(|| "/".to_string());
            let url = if path.contains("://") {
                scrub_url_credentials(&path)
            } else {
                scrub_url_credentials(&format!("http://{host}{path}"))
            };

            let normalized_mime = resp
                .content_type
                .as_deref()
                .and_then(|ct| ct.split(';').next())
                .map(|s| s.trim().to_string());
            let category = mime_category(normalized_mime.as_deref());
            let digest = sha256_hex(&resp.body);
            let rel_path = sanitize_rel_path(&path);
            let saved_path = scrub_url_credentials(&format!("virtual://{host}/{rel_path}"));
            let r4_redacted = txn.had_sensitive_material || host_had_userinfo;

            let detail = json!({
                "sha256": digest,
                "mime_category": category,
                "full_content_type": resp.content_type,
                "content_encoding": resp.content_encoding,
                "truncated": resp.body_truncated,
                "r4_redacted": r4_redacted,
            });

            let row_id = (rows.len() + 1) as u64;
            let mut row = Row::new(
                row_id,
                vec![
                    resp.timestamp
                        .or(txn.timestamp)
                        .map(CellValue::Timestamp)
                        .unwrap_or(CellValue::Null),
                    CellValue::Text(host),
                    CellValue::Text(url),
                    normalized_mime.map(CellValue::Text).unwrap_or(CellValue::Null),
                    CellValue::Bytes(resp.decoded_body_len as u64),
                    CellValue::Uint(u64::from(resp.status_code)),
                    CellValue::Text(saved_path),
                ],
            )
            .with_detail_json(detail);

            if !r4_redacted && !matches!(resp.status_code, 401 | 407) && !resp.body.is_empty() {
                let preview_len = resp.body.len().min(MAX_RAW_PREVIEW_BYTES);
                row = row.with_raw_bytes(resp.body[..preview_len].to_vec());
            }

            rows.push(row);
        }

        finalize_table_query(&build_schema(), rows, req, &self.ctx)
    }
}
