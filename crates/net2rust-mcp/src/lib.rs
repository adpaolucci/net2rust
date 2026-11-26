#![forbid(unsafe_code)]

//! Policy-gated MCP JSON-RPC 2.0 (`2024-11-05`) server registry for `net2rust`.
//!
//! Exposes all 55 read-only `TableProvider`s and all 13 mutating `ActionCommand`s
//! across `-sockets`, `-capture`, `-lan`, `-osint`, and `-radio`.

use std::io::{BufRead, Write};
use std::sync::Arc;

use guap_table::TableProvider;
use net2rust_core::{NetContext, ToolDescriptor};

pub use guap_mcp::{
    ActionCommand, ActionRiskLevel, JsonRpcError, MCP_PROTOCOL_VERSION, McpServerRegistry, McpToolError, PolicyMode,
};

pub const EXPECTED_PROVIDER_COUNT: usize = 55;
pub const EXPECTED_ACTION_COUNT: usize = 13;
pub const EXPECTED_TOTAL_TOOLS: usize = EXPECTED_PROVIDER_COUNT + EXPECTED_ACTION_COUNT;

pub fn all_tool_descriptors() -> Vec<ToolDescriptor> {
    net2rust_sockets::tool_descriptors()
        .into_iter()
        .chain(net2rust_capture::tool_descriptors())
        .chain(net2rust_lan::tool_descriptors())
        .chain(net2rust_osint::tool_descriptors())
        .chain(net2rust_radio::tool_descriptors())
        .collect()
}

pub fn all_providers(ctx: &NetContext) -> Vec<Arc<dyn TableProvider>> {
    net2rust_sockets::providers(ctx)
        .into_iter()
        .chain(net2rust_capture::providers(ctx))
        .chain(net2rust_lan::providers(ctx))
        .chain(net2rust_osint::providers(ctx))
        .chain(net2rust_radio::providers(ctx))
        .collect()
}

pub fn all_actions(ctx: &NetContext) -> Vec<Arc<dyn ActionCommand>> {
    net2rust_sockets::actions(ctx)
        .into_iter()
        .chain(net2rust_capture::actions(ctx))
        .chain(net2rust_lan::actions(ctx))
        .chain(net2rust_osint::actions(ctx))
        .chain(net2rust_radio::actions(ctx))
        .collect()
}

pub fn build_registry(ctx: &NetContext, policy: PolicyMode) -> McpServerRegistry {
    let mut registry = McpServerRegistry::new(policy).with_server_info("net2rust-mcp", env!("CARGO_PKG_VERSION"));
    for provider in all_providers(ctx) {
        registry.register_table(provider);
    }
    for action in all_actions(ctx) {
        registry.register_action(action);
    }
    registry
}

pub fn run_stdio_with<R: BufRead, W: Write>(
    ctx: &NetContext,
    policy: PolicyMode,
    reader: R,
    writer: W,
) -> anyhow::Result<()> {
    let registry = build_registry(ctx, policy);
    registry.serve_reader_writer(reader, writer)?;
    Ok(())
}
