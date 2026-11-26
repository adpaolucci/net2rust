#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::Parser;
use guap_mcp::PolicyMode;
use net2rust_core::{NetContext, OfflineConfig};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "net2rust-mcp", version, about = "net2rust MCP JSON-RPC 2.0 stdio server")]
struct Args {
    /// Allow mutating ActionCommands (defaults to read-only policy mode; still requires confirm_destructive=true)
    #[arg(long)]
    allow_mutating: bool,

    /// Print registered MCP tools as JSON and exit
    #[arg(long)]
    tools: bool,

    /// Run in deterministic offline fixture mode
    #[arg(long)]
    offline: bool,

    /// Optional fixture directory override (activates offline mode)
    #[arg(long, value_name = "PATH")]
    fixture_dir: Option<PathBuf>,

    /// Optional PCAP/PCAPNG file path for offline capture tools (activates offline mode)
    #[arg(long, value_name = "PATH")]
    pcap: Option<PathBuf>,
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn build_context(args: &Args) -> NetContext {
    if args.offline || args.fixture_dir.is_some() || args.pcap.is_some() {
        NetContext::offline(OfflineConfig {
            fixture_dir: args.fixture_dir.clone(),
            pcap_path: args.pcap.clone(),
            ..OfflineConfig::default()
        })
    } else {
        NetContext::live()
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_tracing();

    let policy = if args.allow_mutating {
        PolicyMode::AllowMutating
    } else {
        PolicyMode::ReadOnlyOnly
    };
    let ctx = build_context(&args);
    let registry = net2rust_mcp::build_registry(&ctx, policy);
    if args.tools {
        println!("{}", serde_json::to_string_pretty(&registry.list_tools())?);
        return Ok(());
    }
    registry.serve_stdio()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_cli_flags_and_context_mode() {
        let args = Args::try_parse_from(["net2rust-mcp", "--offline", "--allow-mutating", "--tools"]).unwrap();
        assert!(args.offline);
        assert!(args.allow_mutating);
        assert!(args.tools);
        let ctx = build_context(&args);
        assert!(ctx.is_offline());

        let registry = net2rust_mcp::build_registry(&ctx, PolicyMode::ReadOnlyOnly);
        assert_eq!(registry.policy(), PolicyMode::ReadOnlyOnly);
        assert_eq!(
            registry.list_tools().as_array().unwrap().len(),
            net2rust_mcp::EXPECTED_TOTAL_TOOLS
        );
    }
}
