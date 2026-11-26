//! Shared `TableProvider` helpers and provider factory for all 11 `net2rust-capture` tools.

pub mod cookies;
pub mod dhcp;
pub mod dns;
pub mod http;
pub mod latency;
pub mod mdns;
pub mod sniff;
pub mod traffic;
pub mod website;
pub mod whois_lan;
pub mod wifi_mon;

use std::sync::Arc;

use guap_table::{Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query};
use net2rust_core::NetContext;

pub fn providers(ctx: &NetContext) -> Vec<Arc<dyn TableProvider>> {
    vec![
        Arc::new(sniff::SniffProvider::new(ctx.clone())),
        Arc::new(traffic::TrafficProvider::new(ctx.clone())),
        Arc::new(http::HttpProvider::new(ctx.clone())),
        Arc::new(dns::DnsProvider::new(ctx.clone())),
        Arc::new(dhcp::DhcpProvider::new(ctx.clone())),
        Arc::new(mdns::MdnsProvider::new(ctx.clone())),
        Arc::new(whois_lan::WhoisLanProvider::new(ctx.clone())),
        Arc::new(cookies::CookiesProvider::new(ctx.clone())),
        Arc::new(website::WebsiteProvider::new(ctx.clone())),
        Arc::new(latency::LatencyProvider::new(ctx.clone())),
        Arc::new(wifi_mon::WifiMonProvider::new(ctx.clone())),
    ]
}

pub fn finalize_table_query(
    schema: &TableSchema,
    mut rows: Vec<Row>,
    req: &TableQuery,
    ctx: &NetContext,
) -> Result<TableData, TableError> {
    ctx.apply_row_limit(&mut rows);
    apply_query(schema, &rows, req)
}
