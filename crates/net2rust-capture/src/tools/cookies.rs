//! `capture.cookies` (`WebCookiesSniffer`) TableProvider with mandatory R4 auth/session redaction.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery, TableSchema,
};
use net2rust_core::NetContext;
use serde_json::json;

use crate::capture::{CaptureRequest, capture_packets};
use crate::decode::http::{HttpHeader, extract_http_transactions};
use crate::r4_guard::{REDACTED_MARKER, sanitize_cookie_pair_value};
use crate::tools::finalize_table_query;

pub struct CookiesProvider {
    ctx: NetContext,
}

impl CookiesProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

fn build_schema() -> TableSchema {
    TableSchema::new(
        "capture.cookies",
        "WebCookiesSniffer — HTTP Cookie Metadata",
        vec![
            ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(180),
            ColumnDef::new("host", "Host", ColumnType::Text).with_width_hint(170),
            ColumnDef::new("cookie_name", "CookieName", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("value", "Value", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("domain", "Domain", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("path", "Path", ColumnType::Text).with_width_hint(110),
            ColumnDef::new("flags", "Flags", ColumnType::Text).with_width_hint(180),
            ColumnDef::new("src_ip", "SrcIP", ColumnType::IpAddr).with_width_hint(140),
            ColumnDef::new("dst_ip", "DstIP", ColumnType::IpAddr).with_width_hint(140),
        ],
    )
    .with_default_sort(0, SortDirection::Asc)
}

#[allow(clippy::too_many_arguments)]
fn emit_cookie_header_rows(
    hdr: &HttpHeader,
    is_set_cookie: bool,
    ts: Option<DateTime<Utc>>,
    host: Option<&str>,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    redact_sensitive_headers: bool,
    rows: &mut Vec<Row>,
) {
    let raw_val = hdr.raw_cookie_value.as_deref().unwrap_or(&hdr.sanitized_value);
    if !is_set_cookie {
        // Request `Cookie:` may hold multiple `name=value` pairs separated by ';'
        for pair in raw_val.split(';') {
            let trimmed = pair.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Some((cname, cval)) = trimmed.split_once('=') else {
                continue;
            };
            let clean_name = cname.trim().to_string();
            let safe_val = sanitize_cookie_pair_value(&clean_name, cval.trim(), redact_sensitive_headers);
            let is_redacted = safe_val == REDACTED_MARKER;
            let row_id = (rows.len() + 1) as u64;
            rows.push(
                Row::new(
                    row_id,
                    vec![
                        ts.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        host.map(|h| CellValue::Text(h.to_string())).unwrap_or(CellValue::Null),
                        CellValue::Text(clean_name),
                        CellValue::Text(safe_val),
                        CellValue::Null,
                        CellValue::Null,
                        CellValue::Text("RequestCookie".to_string()),
                        CellValue::Text(src_ip.to_string()),
                        CellValue::Text(dst_ip.to_string()),
                    ],
                )
                .with_detail_json(json!({
                    "header": hdr.name,
                    "direction": "request",
                    "r4_redacted": is_redacted,
                })),
            );
        }
        return;
    }

    // Response `Set-Cookie:` / `Set-Cookie2:` -> single `name=value` + `; attributes`
    let mut parts = raw_val.split(';');
    let Some(first_pair) = parts.next().map(str::trim).filter(|s| !s.is_empty()) else {
        return;
    };
    let Some((cname, cval)) = first_pair.split_once('=') else {
        return;
    };
    let clean_name = cname.trim().to_string();
    let safe_val = sanitize_cookie_pair_value(&clean_name, cval.trim(), redact_sensitive_headers);
    let is_redacted = safe_val == REDACTED_MARKER;

    let mut domain: Option<String> = None;
    let mut path: Option<String> = None;
    let mut flags: Vec<String> = Vec::new();

    for attr in parts {
        let t = attr.trim();
        if t.is_empty() {
            continue;
        }
        if let Some((ak, av)) = t.split_once('=') {
            let ak_l = ak.trim().to_ascii_lowercase();
            let av_t = av.trim();
            if ak_l == "domain" {
                domain = Some(av_t.to_string());
            } else if ak_l == "path" {
                path = Some(av_t.to_string());
            } else {
                flags.push(format!("{}={av_t}", ak.trim()));
            }
        } else {
            flags.push(t.to_string());
        }
    }

    let flags_str = if flags.is_empty() { None } else { Some(flags.join("; ")) };
    let row_id = (rows.len() + 1) as u64;
    rows.push(
        Row::new(
            row_id,
            vec![
                ts.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                host.map(|h| CellValue::Text(h.to_string())).unwrap_or(CellValue::Null),
                CellValue::Text(clean_name),
                CellValue::Text(safe_val),
                domain.map(CellValue::Text).unwrap_or(CellValue::Null),
                path.map(CellValue::Text).unwrap_or(CellValue::Null),
                flags_str.map(CellValue::Text).unwrap_or(CellValue::Null),
                CellValue::Text(src_ip.to_string()),
                CellValue::Text(dst_ip.to_string()),
            ],
        )
        .with_detail_json(json!({
            "header": hdr.name,
            "direction": "response",
            "r4_redacted": is_redacted,
        })),
    );
}

impl TableProvider for CookiesProvider {
    fn tool_id(&self) -> &'static str {
        "capture.cookies"
    }

    fn description(&self) -> &'static str {
        "WebCookiesSniffer — HTTP Cookie/Set-Cookie metadata with mandatory R4 auth/session redaction"
    }

    fn schema(&self) -> TableSchema {
        build_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let packets = capture_packets(&self.ctx, &CaptureRequest::default()).map_err(TableError::from)?;
        let txns = extract_http_transactions(&packets, self.ctx.redact_sensitive_headers);
        let mut rows = Vec::new();

        for txn in &txns {
            let host = txn.request.as_ref().and_then(|r| r.host.as_deref());
            if let Some(ref rq) = txn.request {
                for hdr in &rq.headers {
                    if hdr.name.eq_ignore_ascii_case("cookie") {
                        emit_cookie_header_rows(
                            hdr,
                            false,
                            rq.timestamp.or(txn.timestamp),
                            host,
                            txn.src_ip,
                            txn.dst_ip,
                            self.ctx.redact_sensitive_headers,
                            &mut rows,
                        );
                    }
                }
            }
            if let Some(ref rs) = txn.response {
                for hdr in &rs.headers {
                    if hdr.name.eq_ignore_ascii_case("set-cookie") || hdr.name.eq_ignore_ascii_case("set-cookie2") {
                        emit_cookie_header_rows(
                            hdr,
                            true,
                            rs.timestamp.or(txn.timestamp),
                            host,
                            txn.dst_ip,
                            txn.src_ip,
                            self.ctx.redact_sensitive_headers,
                            &mut rows,
                        );
                    }
                }
            }
        }

        finalize_table_query(&build_schema(), rows, req, &self.ctx)
    }
}
