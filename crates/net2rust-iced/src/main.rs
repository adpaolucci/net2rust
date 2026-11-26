#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use guap_gui_iced::{IcedSuiteConfig, run_iced_suite};
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
    "net2rust-iced — Cross-platform Iced 0.14 GUI for the 55-tool net2rust suite\n\n\
     USAGE:\n    net2rust-iced [OPTIONS]\n\n\
     OPTIONS:\n    \
     --offline              Use deterministic offline synthetic fixtures\n    \
     --fixture-dir <PATH>   Load offline fixtures from directory (implies --offline)\n    \
     --pcap <PATH>          Open PCAP/PCAPNG capture offline (implies --offline)\n    \
     --light                Start with light theme instead of dark mode\n    \
     --tool <TOOL_ID>       Select initial tool (e.g. sockets.ports, radio.ble)\n    \
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

fn default_suite_config(dark_mode: bool) -> IcedSuiteConfig {
    IcedSuiteConfig {
        app_title: "Net2Rust — Network Diagnostics Console (Iced)".to_string(),
        dark_mode,
        window_size: (1360.0, 820.0),
    }
}

fn collect_providers(ctx: &NetContext, initial_tool: Option<&str>) -> Result<Vec<Arc<dyn TableProvider>>, String> {
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
            .ok_or_else(|| format!("unknown tool_id '{id}'"))?;
        providers.swap(0, pos);
    }

    Ok(providers)
}

fn main() -> iced::Result {
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
            let providers = match collect_providers(&ctx, args.tool.as_deref()) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("{err}");
                    std::process::exit(2);
                }
            };
            run_iced_suite(default_suite_config(!args.light), providers)
        }
    }
}

#[cfg(test)]
mod tests {
    use guap_gui_iced::{DataGridMessage, IcedDataGrid};

    use super::*;

    #[test]
    fn test_parse_launch_args_help_version_and_options() {
        assert_eq!(
            parse_launch_args_from(["--help".to_string()]).unwrap(),
            LaunchAction::Help
        );
        assert_eq!(
            parse_launch_args_from(["--version".to_string()]).unwrap(),
            LaunchAction::Version
        );

        let parsed = parse_launch_args_from([
            "--offline".to_string(),
            "--light".to_string(),
            "--tool".to_string(),
            "radio.ble".to_string(),
        ])
        .unwrap();
        assert_eq!(
            parsed,
            LaunchAction::Run(LaunchArgs {
                offline: true,
                fixture_dir: None,
                pcap: None,
                light: true,
                tool: Some("radio.ble".to_string()),
            })
        );

        assert!(parse_launch_args_from(["--invalid".to_string()]).is_err());
        assert!(parse_launch_args_from(["--tool".to_string()]).is_err());
    }

    #[test]
    fn test_iced_data_grid_switches_across_all_55_providers_headless() {
        let ctx = NetContext::offline(OfflineConfig::default());
        let providers = collect_providers(&ctx, Some("radio.ble")).unwrap();
        assert_eq!(providers.len(), 55);
        assert_eq!(providers[0].tool_id(), "radio.ble");

        let tool_ids: Vec<String> = providers.iter().map(|p| p.tool_id().to_string()).collect();
        let mut grid = IcedDataGrid::new(providers).with_dark_mode(true).with_page_size(50);
        assert_eq!(grid.active_tool_id(), Some("radio.ble"));

        for id in &tool_ids {
            let _ = grid.update(DataGridMessage::SelectTool(id.clone()));
            assert_eq!(grid.active_tool_id(), Some(id.as_str()));
            assert!(grid.last_error().is_none(), "'{id}' error: {:?}", grid.last_error());
            assert!(!grid.columns().is_empty(), "'{id}' has empty columns");
            assert!(grid.total_rows() > 0, "'{id}' returned 0 offline rows");
        }

        let _ = grid.update(DataGridMessage::SelectTool("sockets.ports".to_string()));
        let _ = grid.update(DataGridMessage::SelectRow(0));
        assert!(grid.selected_row().is_some());

        let _ = grid.update(DataGridMessage::FilterChanged("443".to_string()));
        assert!(grid.last_error().is_none());
        let _ = grid.update(DataGridMessage::ToggleRegex);
        let _ = grid.update(DataGridMessage::FilterChanged(".*".to_string()));
        assert!(grid.last_error().is_none());
        let _ = grid.update(DataGridMessage::ToggleRegex);
        let _ = grid.update(DataGridMessage::FilterChanged(String::new()));

        let _ = grid.update(DataGridMessage::SortColumn(0));
        let _ = grid.update(DataGridMessage::SetPage(0));
        let _ = grid.update(DataGridMessage::SetPageSize(10));
        let _ = grid.update(DataGridMessage::ToggleHex);
        assert!(!grid.show_hex_pane());
        let _ = grid.update(DataGridMessage::ToggleDarkMode);
        assert!(!grid.dark_mode());
        let _ = grid.update(DataGridMessage::Refresh);
        assert!(grid.last_error().is_none());
    }
}
