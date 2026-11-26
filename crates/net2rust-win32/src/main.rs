#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use guap_gui_win32::{Win32TableHostConfig, run_win32_suite};
use guap_mcp::ActionCommand;
use guap_table::TableProvider;
use net2rust_core::{NetContext, OfflineConfig};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchArgs {
    pub offline: bool,
    pub fixture_dir: Option<PathBuf>,
    pub pcap: Option<PathBuf>,
    pub light: bool,
    pub tool: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchAction {
    Help,
    Version,
    Run(LaunchArgs),
}

pub fn parse_launch_args_from<I>(args: I) -> Result<LaunchAction, String>
where
    I: IntoIterator<Item = String>,
{
    let mut parsed = LaunchArgs::default();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => return Ok(LaunchAction::Help),
            "--version" | "-V" => return Ok(LaunchAction::Version),
            "--offline" => parsed.offline = true,
            "--light" => parsed.light = true,
            "--tool" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value after --tool <TOOL_ID>".to_string())?;
                if value.trim().is_empty() {
                    return Err("--tool value must not be empty".to_string());
                }
                parsed.tool = Some(value);
            }
            "--fixture-dir" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value after --fixture-dir <PATH>".to_string())?;
                parsed.fixture_dir = Some(PathBuf::from(value));
            }
            "--pcap" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value after --pcap <PATH>".to_string())?;
                parsed.pcap = Some(PathBuf::from(value));
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    Ok(LaunchAction::Run(parsed))
}

fn help_text() -> &'static str {
    "net2rust-win32 — Native Win32 GUI for the 55-tool net2rust suite\n\n\
     USAGE:\n    net2rust-win32 [OPTIONS]\n\n\
     OPTIONS:\n    \
     --offline              Use deterministic offline synthetic fixtures\n    \
     --fixture-dir <PATH>   Load offline fixtures from directory (implies --offline)\n    \
     --pcap <PATH>          Open PCAP/PCAPNG capture offline (implies --offline)\n    \
     --light                Start with light theme instead of dark mode\n    \
     --tool <TOOL_ID>       Select initial tool (e.g. sockets.ports, capture.http)\n    \
     -h, --help             Print help and exit\n    \
     -V, --version          Print version and exit"
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn build_context(args: &LaunchArgs) -> NetContext {
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

fn default_host_config(dark_mode: bool) -> Win32TableHostConfig {
    Win32TableHostConfig {
        app_title: "Net2Rust — Network Diagnostics Console (Win32)".to_string(),
        dark_mode,
        show_hex_pane: true,
        default_export_dir: None,
    }
}

type ProvidersAndActions = (Vec<Arc<dyn TableProvider>>, Vec<Arc<dyn ActionCommand>>);

fn collect_providers_and_actions(ctx: &NetContext, initial_tool: Option<&str>) -> anyhow::Result<ProvidersAndActions> {
    let mut providers: Vec<Arc<dyn TableProvider>> = net2rust_sockets::providers(ctx)
        .into_iter()
        .chain(net2rust_capture::providers(ctx))
        .chain(net2rust_lan::providers(ctx))
        .chain(net2rust_osint::providers(ctx))
        .chain(net2rust_radio::providers(ctx))
        .collect();

    if let Some(id) = initial_tool {
        let pos = providers
            .iter()
            .position(|p| p.tool_id() == id)
            .ok_or_else(|| anyhow::anyhow!("unknown tool_id '{id}'"))?;
        providers.swap(0, pos);
    }

    let actions: Vec<Arc<dyn ActionCommand>> = net2rust_sockets::actions(ctx)
        .into_iter()
        .chain(net2rust_capture::actions(ctx))
        .chain(net2rust_lan::actions(ctx))
        .chain(net2rust_osint::actions(ctx))
        .chain(net2rust_radio::actions(ctx))
        .collect();

    Ok((providers, actions))
}

fn main() -> anyhow::Result<()> {
    let action = match parse_launch_args_from(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(err) => {
            eprintln!("{err}\n\n{}", help_text());
            std::process::exit(2);
        }
    };

    match action {
        LaunchAction::Help => {
            println!("{}", help_text());
            Ok(())
        }
        LaunchAction::Version => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        LaunchAction::Run(args) => {
            init_tracing();
            let ctx = build_context(&args);
            let (providers, actions) = collect_providers_and_actions(&ctx, args.tool.as_deref())?;
            let cfg = default_host_config(!args.light);
            run_win32_suite(cfg, providers, actions)
        }
    }
}

#[cfg(test)]
mod tests {
    use guap_gui_win32::Win32GridState;

    use super::*;

    #[test]
    fn test_parse_launch_args_help_version_flags_and_errors() {
        assert_eq!(
            parse_launch_args_from(["--help".to_string()]).unwrap(),
            LaunchAction::Help
        );
        assert_eq!(parse_launch_args_from(["-h".to_string()]).unwrap(), LaunchAction::Help);
        assert_eq!(
            parse_launch_args_from(["--version".to_string()]).unwrap(),
            LaunchAction::Version
        );
        assert_eq!(
            parse_launch_args_from(["-V".to_string()]).unwrap(),
            LaunchAction::Version
        );

        let parsed = parse_launch_args_from([
            "--offline".to_string(),
            "--light".to_string(),
            "--tool".to_string(),
            "sockets.routes".to_string(),
            "--fixture-dir".to_string(),
            "fixtures".to_string(),
            "--pcap".to_string(),
            "trace.pcap".to_string(),
        ])
        .unwrap();
        assert_eq!(
            parsed,
            LaunchAction::Run(LaunchArgs {
                offline: true,
                fixture_dir: Some(PathBuf::from("fixtures")),
                pcap: Some(PathBuf::from("trace.pcap")),
                light: true,
                tool: Some("sockets.routes".to_string()),
            })
        );

        assert!(parse_launch_args_from(["--bogus".to_string()]).is_err());
        assert!(parse_launch_args_from(["--tool".to_string()]).is_err());
        assert!(parse_launch_args_from(["--fixture-dir".to_string()]).is_err());
        assert!(parse_launch_args_from(["--pcap".to_string()]).is_err());
    }

    #[test]
    fn test_win32_grid_state_loads_all_55_providers_and_13_actions() {
        let ctx = NetContext::offline(OfflineConfig::default());
        let (providers, actions) = collect_providers_and_actions(&ctx, Some("capture.http")).unwrap();
        assert_eq!(providers.len(), 55);
        assert_eq!(actions.len(), 13);
        assert_eq!(providers[0].tool_id(), "capture.http");

        let tool_ids: Vec<String> = providers.iter().map(|p| p.tool_id().to_string()).collect();
        let mut state = Win32GridState::new(default_host_config(true), providers, actions);
        assert_eq!(state.active_tool_id(), Some("capture.http"));

        for id in &tool_ids {
            assert!(state.select_tool_by_id(id), "failed to select '{id}'");
            assert_eq!(state.active_tool_id(), Some(id.as_str()));
            assert!(state.last_error.is_none(), "'{id}' query error: {:?}", state.last_error);
            assert!(!state.columns().is_empty(), "'{id}' has empty columns");
            assert!(state.row_count() > 0, "'{id}' returned 0 offline rows");
        }

        // Exercise filtering, regex filtering, sorting, and CRLF inspector formatting.
        assert!(state.select_tool_by_id("sockets.ports"));
        state.set_filter("443".to_string());
        assert!(state.last_error.is_none());
        state.set_use_regex(true);
        state.set_filter(".*".to_string());
        assert!(state.last_error.is_none());
        state.set_use_regex(false);
        state.set_filter(String::new());

        let _ = state.toggle_sort(0);
        assert!(state.last_error.is_none());

        state.selected_row = Some(0);
        let inspector = state.format_inspector_crlf();
        assert!(inspector.contains("\r\n"));
        assert!(inspector.contains("Row ID:"));

        // Verify real run_win32_suite symbol linkage (without launching GUI loop).
        type RunSuiteFn =
            fn(Win32TableHostConfig, Vec<Arc<dyn TableProvider>>, Vec<Arc<dyn ActionCommand>>) -> anyhow::Result<()>;
        let _fn_ptr: RunSuiteFn = run_win32_suite;
    }
}
