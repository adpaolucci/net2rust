#![forbid(unsafe_code)]

//! Unified CLI library (`net2rust`) exposing all 55 tools across
//! `sockets`, `capture`, `lan`, `osint`, and `radio`, plus `mcp`, `export`,
//! `list-tools`, `gui`, and `action`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use guap_mcp::{ActionCommand, McpServerRegistry, PolicyMode};
use guap_table::{GuapQuery, SortDirection, TableData, TableProvider, TableQuery, TableSchema};
use net2rust_core::{NetContext, OfflineConfig, ToolCategory, ToolDescriptor};
use net2rust_report::{
    CustodyManifestBuilder, ExportFormat, ReportOptions, format_file_extension, render_report,
    write_single_report_with_custody,
};
use serde_json::{Map, Value, json};

#[derive(Debug, Parser)]
#[command(
    name = "net2rust",
    version,
    about = "Pure-Rust network diagnostics, ETW capture, LAN, OSINT, and Wi-Fi/BLE suite",
    arg_required_else_help = true
)]
pub struct Cli {
    /// Run in deterministic offline synthetic fixture mode
    #[arg(long, global = true)]
    pub offline: bool,

    /// Directory containing offline JSON fixtures (activates offline mode)
    #[arg(long, global = true, value_name = "PATH")]
    pub fixture_dir: Option<PathBuf>,

    /// Path to offline PCAP/PCAPNG file for capture tools (activates offline mode)
    #[arg(long, global = true, value_name = "PATH")]
    pub pcap: Option<PathBuf>,

    /// Path to offline ETL trace file (activates offline mode)
    #[arg(long, global = true, value_name = "PATH")]
    pub etl: Option<PathBuf>,

    /// Named offline fixture scenario (activates offline mode)
    #[arg(long, global = true, value_name = "NAME")]
    pub scenario: Option<String>,

    /// Maximum rows returned after filtering and sorting
    #[arg(long, global = true, visible_alias = "limit", value_name = "N")]
    pub max_rows: Option<usize>,

    /// Output format: csv, tsv, json, jsonl, html, html-vertical, markdown
    #[arg(long, global = true, default_value = "markdown", value_name = "FMT")]
    pub format: String,

    /// Write formatted report to file (or directory for batch export)
    #[arg(long, global = true, visible_aliases = ["output", "export"], value_name = "PATH")]
    pub out: Option<PathBuf>,

    /// Write SHA-256/SHA-512 Merkle custody manifest JSON to file
    #[arg(long, global = true, visible_alias = "custody", value_name = "PATH")]
    pub custody_out: Option<PathBuf>,

    /// Tabular filter expression (e.g. "protocol == TCP AND local_port >= 443")
    #[arg(long, global = true, allow_hyphen_values = true, value_name = "EXPR")]
    pub filter: Option<String>,

    /// Sort specification (e.g. "port:desc", "-port", "~port", "a:asc,b:desc")
    #[arg(long, global = true, allow_hyphen_values = true, value_name = "SPEC")]
    pub sort: Option<String>,

    /// Permit policy-gated mutating ActionCommands (required for non-read-only actions)
    #[arg(short = 'y', long, global = true)]
    pub allow_mutating: bool,

    /// Preview mutating ActionCommands without applying OS/network changes
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Tracing log level written to stderr (trace, debug, info, warn, error)
    #[arg(long, global = true, default_value = "warn", value_name = "LEVEL")]
    pub log_level: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Socket, route, neighbor, interface, and ETW network tools (13 tools)
    Sockets {
        #[command(subcommand)]
        sub: SocketsSub,
    },
    /// Packet capture & protocol dissectors (11 tools, R4 credential-free)
    Capture {
        #[command(subcommand)]
        sub: CaptureSub,
    },
    /// LAN diagnostics, scanning, Wake-on-LAN, NetBIOS, SMB, and speedtest (11 tools)
    Lan {
        #[command(subcommand)]
        sub: LanSub,
    },
    /// OSINT, WHOIS/RDAP, offline GeoIP/OUI, DNS, and profile tools (10 tools)
    Osint {
        #[command(subcommand)]
        sub: OsintSub,
    },
    /// Wi-Fi BSS/profile and Bluetooth/BLE radio tools (10 tools, zero key extraction)
    Radio {
        #[command(subcommand)]
        sub: RadioSub,
    },
    /// Start policy-gated MCP JSON-RPC 2.0 stdio server (or dump --tools manifest)
    Mcp(McpArgs),
    /// Export single tool or batch category/all tools with Merkle custody manifest
    Export(ExportArgs),
    /// List all 55 tools and 13 mutating ActionCommands
    #[command(name = "list-tools", visible_aliases = ["list", "catalog"])]
    ListTools(ListToolsArgs),
    /// Launch native Win32 or cross-platform Iced GUI binary
    Gui(GuiArgs),
    /// Invoke a policy-gated mutating ActionCommand directly by ID
    Action(ActionArgs),
}

#[derive(Debug, Subcommand)]
pub enum SocketsSub {
    /// Active TCP/UDP sockets & owning processes (optional --close)
    Ports(PortsArgs),
    /// TCP socket open/close/listen transition log
    Tcplog,
    /// Live ETW Kernel-Network TCP/UDP activity
    Live,
    /// Per-application TCP/UDP byte counters
    #[command(name = "app-net")]
    AppNet,
    /// Per-process TCP state counts & throughput
    #[command(name = "proc-tcp")]
    ProcTcp,
    /// TCP timeouts, refusals, and retransmissions
    #[command(name = "tcp-errors")]
    TcpErrors,
    /// DNS client lookup telemetry
    #[command(name = "dns-log")]
    DnsLog,
    /// IPv4/IPv6/TCP/UDP/ICMP stack counters
    Counters,
    /// Adapter link speed, throughput, errors, discards
    #[command(name = "adapter-watch")]
    AdapterMonitor,
    /// Full interface, IP, gateway, DNS, DHCP view
    Interfaces,
    /// IPv4/IPv6 routing table (optional --add / --delete)
    Routes(RoutesArgs),
    /// ARP and IPv6 NDP neighbor cache
    Neighbors,
    /// OS IP path table, next-hop RTT, MTU
    Paths,
}

#[derive(Debug, Args)]
pub struct PortsArgs {
    /// Close matching IPv4 TCP connection via sockets.ports.close (policy-gated)
    #[arg(long)]
    pub close: bool,
    #[arg(long)]
    pub local_addr: Option<String>,
    #[arg(long)]
    pub local_port: Option<u16>,
    #[arg(long)]
    pub remote_addr: Option<String>,
    #[arg(long)]
    pub remote_port: Option<u16>,
}

#[derive(Debug, Args)]
pub struct RoutesArgs {
    /// Add route via sockets.routes.add (policy-gated)
    #[arg(long, conflicts_with = "delete")]
    pub add: bool,
    /// Delete route via sockets.routes.delete (policy-gated)
    #[arg(long, conflicts_with = "add")]
    pub delete: bool,
    #[arg(long)]
    pub destination: Option<String>,
    #[arg(long)]
    pub prefix_length: Option<u8>,
    #[arg(long)]
    pub next_hop: Option<String>,
    #[arg(long)]
    pub interface_index: Option<u32>,
    #[arg(long)]
    pub interface_alias: Option<String>,
    #[arg(long)]
    pub metric: Option<u32>,
}

#[derive(Debug, Subcommand)]
pub enum CaptureSub {
    /// IPv4/IPv6 TCP/UDP/ICMP stream summary
    Sniff,
    /// Aggregated traffic flows
    Traffic,
    /// HTTP request/response metadata (R4 credential-free)
    Http,
    /// DNS queries, answers, TTLs, latency
    Dns,
    /// BOOTP/DHCPv4 lease transactions
    Dhcp,
    /// Multicast DNS / DNS-SD listener
    Mdns,
    /// Passive LAN host discovery
    #[command(name = "whois-lan")]
    WhoisLan,
    /// Cookie/Set-Cookie metadata with R4 token redaction
    Cookies,
    /// Static asset URL & content-type reconstruction
    Website,
    /// Passive TCP SYN to SYN-ACK latency
    Latency,
    /// 802.11 RadioTap/beacon/probe channel analyzer
    #[command(name = "wifi-mon")]
    WifiMon,
}

#[derive(Debug, Subcommand)]
pub enum LanSub {
    /// Concurrent ICMP/TCP ping monitor
    Ping,
    /// ICMP traceroute with offline GeoIP enrichment
    Trace,
    /// Concurrent ARP/ICMP/NetBIOS/port scanner
    Scan,
    /// Active subnet ARP sweep
    Wnetwatcher,
    /// LAN host arrival/departure diff logger
    #[command(name = "connect-log")]
    ConnectLog,
    /// LAN host inventory (optional --send magic packet)
    Wol(WolArgs),
    /// UDP 137 NetBIOS node status scanner
    Netbios,
    /// SMB/WNet shared folder enumerator
    Shares,
    /// SMB open-file inspector (optional --close-id)
    Openfiles(OpenfilesArgs),
    /// Parallel DNS and MAC OUI resolver
    Resolve,
    /// Multi-target HTTP/HTTPS download throughput benchmark
    Speedtest,
}

#[derive(Debug, Args)]
pub struct WolArgs {
    /// Transmit Wake-on-LAN magic packet via lan.wol.send (policy-gated)
    #[arg(long)]
    pub send: bool,
    #[arg(long)]
    pub mac: Option<String>,
    #[arg(long)]
    pub broadcast_ip: Option<String>,
    #[arg(long)]
    pub port: Option<u16>,
    #[arg(long)]
    pub repeat_count: Option<u32>,
}

#[derive(Debug, Args)]
pub struct OpenfilesArgs {
    /// Close open SMB file handle ID via lan.openfiles.close (policy-gated)
    #[arg(long, value_name = "ID")]
    pub close_id: Option<u32>,
    #[arg(long)]
    pub server: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum OsintSub {
    /// RIR WHOIS/RDAP IP block lookup
    Ipnet,
    /// IP WHOIS/RDAP referral & ASN resolver
    Whosip,
    /// Embedded offline IPv4/IPv6 CIDR to country & ASN
    Ipoffline,
    /// IANA & registrar domain WHOIS/RDAP
    #[command(name = "whois-domain")]
    WhoisDomain,
    /// Batch WHOIS query runner
    Whoiscl,
    /// Direct DNS record resolver
    Dns,
    /// Aggregated WHOIS/DNS/ASN/hosting profiler
    Hosting,
    /// Embedded offline IEEE MAC OUI vendor lookup
    Oui,
    /// Interface DNS inspector (optional --apply)
    #[command(name = "set-dns")]
    SetDns(SetDnsArgs),
    /// NetworkList profile inspector (optional --connect / --disconnect)
    #[command(name = "net-profiles")]
    NetProfiles(NetProfilesArgs),
}

#[derive(Debug, Args)]
pub struct SetDnsArgs {
    /// Apply DNS settings via osint.set-dns.apply (policy-gated)
    #[arg(long)]
    pub apply: bool,
    #[arg(long)]
    pub interface: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub servers: Vec<String>,
    #[arg(long)]
    pub ipv6: bool,
}

#[derive(Debug, Args)]
pub struct NetProfilesArgs {
    /// Connect network profile via osint.net-profiles.connect (policy-gated)
    #[arg(long, conflicts_with = "disconnect")]
    pub connect: bool,
    /// Disconnect network profile via osint.net-profiles.disconnect (policy-gated)
    #[arg(long, conflicts_with = "connect")]
    pub disconnect: bool,
    #[arg(long)]
    pub profile_id: Option<String>,
    #[arg(long)]
    pub profile_name: Option<String>,
    #[arg(long)]
    pub interface: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum RadioSub {
    /// 802.11 BSS/IE scanner (zero key extraction)
    #[command(name = "wifi-info")]
    WifiInfo,
    /// Wi-Fi availability & signal monitor
    #[command(name = "wifi-scan")]
    WifiScan,
    /// Streaming Wi-Fi scan table
    #[command(name = "wifi-console")]
    WifiConsole,
    /// Active Wi-Fi PHY/channel/RSSI
    #[command(name = "wifi-conn")]
    WifiConn,
    /// Saved WLAN profile metadata (optional --set-order / --delete / --toggle-auto)
    #[command(name = "wifi-profiles")]
    WifiProfiles(WifiProfilesArgs),
    /// SoftAP status (optional --start / --stop)
    #[command(name = "wifi-hosted")]
    WifiHosted(WifiHostedArgs),
    /// Bluetooth Classic discovery
    #[command(name = "bt-view")]
    BtView,
    /// Bluetooth arrival/departure log
    #[command(name = "bt-log")]
    BtLog,
    /// Deterministic Bluetooth Classic enumeration
    #[command(name = "bt-cl")]
    BtCl,
    /// BLE advertisement & GATT UUID scanner
    Ble,
}

#[derive(Debug, Args)]
pub struct WifiProfilesArgs {
    /// Reorder WLAN profile via radio.wifi-profiles.set-order (policy-gated)
    #[arg(long, conflicts_with_all = ["delete", "toggle_auto"])]
    pub set_order: bool,
    /// Delete WLAN profile via radio.wifi-profiles.delete (policy-gated)
    #[arg(long, conflicts_with_all = ["set_order", "toggle_auto"])]
    pub delete: bool,
    /// Toggle auto-connect via radio.wifi-profiles.toggle-auto (policy-gated)
    #[arg(long, conflicts_with_all = ["set_order", "delete"])]
    pub toggle_auto: bool,
    #[arg(long)]
    pub profile_name: Option<String>,
    #[arg(long)]
    pub interface_guid: Option<String>,
    #[arg(long)]
    pub interface_name: Option<String>,
    #[arg(long)]
    pub position: Option<u32>,
    #[arg(long)]
    pub auto_connect: Option<bool>,
}

#[derive(Debug, Args)]
pub struct WifiHostedArgs {
    /// Start hosted network via radio.wifi-hosted.start (policy-gated)
    #[arg(long, conflicts_with = "stop")]
    pub start: bool,
    /// Stop hosted network via radio.wifi-hosted.stop (policy-gated)
    #[arg(long, conflicts_with = "start")]
    pub stop: bool,
    #[arg(long)]
    pub ssid: Option<String>,
    #[arg(long)]
    pub max_peers: Option<u32>,
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct McpArgs {
    /// Print all 68 MCP tool definitions as JSON and exit
    #[arg(long)]
    pub tools: bool,
    /// Allow mutating ActionCommands (still requires confirm_destructive=true per call)
    #[arg(long)]
    pub allow_mutating: bool,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Export a single tool by ID (e.g. sockets.ports)
    #[arg(long, conflicts_with_all = ["all", "category"])]
    pub tool: Option<String>,
    /// Batch-export all 55 tools into --out directory (default: ./net2rust-export)
    #[arg(long, conflicts_with = "tool")]
    pub all: bool,
    /// Export all tools in a single category (sockets, capture, lan, osint, radio)
    #[arg(long, conflicts_with = "tool")]
    pub category: Option<String>,
}

#[derive(Debug, Args)]
pub struct ListToolsArgs {
    /// Output machine-readable JSON catalog
    #[arg(long)]
    pub json: bool,
    /// Filter by category (sockets, capture, lan, osint, radio)
    #[arg(long)]
    pub category: Option<String>,
}

#[derive(Debug, Args)]
pub struct GuiArgs {
    /// Launch cross-platform Iced 0.14 GUI instead of native Win32 GUI
    #[arg(long)]
    pub iced: bool,
}

#[derive(Debug, Args)]
pub struct ActionArgs {
    /// ActionCommand ID (e.g. lan.wol.send)
    #[arg(long, value_name = "COMMAND_ID")]
    pub id: Option<String>,
    /// JSON object payload for the ActionCommand
    #[arg(long, default_value = "{}", value_name = "JSON")]
    pub args: String,
    /// List all 13 mutating ActionCommands and exit
    #[arg(long)]
    pub list: bool,
}

pub fn build_context(cli: &Cli) -> NetContext {
    if cli.offline || cli.fixture_dir.is_some() || cli.pcap.is_some() || cli.etl.is_some() || cli.scenario.is_some() {
        NetContext::offline(OfflineConfig {
            fixture_dir: cli.fixture_dir.clone(),
            pcap_path: cli.pcap.clone(),
            etl_path: cli.etl.clone(),
            scenario: cli.scenario.clone(),
            ..OfflineConfig::default()
        })
    } else {
        NetContext::live()
    }
}

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

pub fn build_mcp_registry(ctx: &NetContext, policy: PolicyMode) -> McpServerRegistry {
    let mut registry = McpServerRegistry::new(policy).with_server_info("net2rust-mcp", env!("CARGO_PKG_VERSION"));
    for p in all_providers(ctx) {
        registry.register_table(p);
    }
    for a in all_actions(ctx) {
        registry.register_action(a);
    }
    registry
}

pub fn parse_sort_compat(spec: Option<&str>) -> anyhow::Result<Vec<(String, SortDirection)>> {
    let Some(raw) = spec else {
        return Ok(Vec::new());
    };
    let rewritten: Vec<String> = raw
        .split(',')
        .map(|part| {
            let trimmed = part.trim();
            if let Some(rest) = trimmed.strip_prefix('~') {
                format!("-{}", rest.trim())
            } else {
                trimmed.to_string()
            }
        })
        .collect();
    let joined = rewritten.join(",");
    Ok(GuapQuery::parse_sort(&joined)?)
}

pub fn build_table_query(cli: &Cli, schema: &TableSchema) -> anyhow::Result<TableQuery> {
    let sort = parse_sort_compat(cli.sort.as_deref())?;
    let gq = GuapQuery {
        columns: None,
        filter_expr: cli.filter.clone(),
        sort,
        offset: 0,
        limit: cli.max_rows,
    };
    Ok(gq.to_table_query(schema)?)
}

fn find_provider<'a>(
    providers: &'a [Arc<dyn TableProvider>],
    tool_id: &str,
) -> anyhow::Result<&'a Arc<dyn TableProvider>> {
    providers
        .iter()
        .find(|p| p.tool_id() == tool_id)
        .ok_or_else(|| anyhow::anyhow!("unknown tool '{tool_id}'"))
}

fn query_tool(cli: &Cli, ctx: &NetContext, tool_id: &str) -> anyhow::Result<TableData> {
    let providers = all_providers(ctx);
    let provider = find_provider(&providers, tool_id)?;
    let schema = provider.schema();
    let query = build_table_query(cli, &schema)?;
    let mut data = provider.query(&query)?;
    // Defense-in-depth: ensure max_rows is respected post-query even if a provider ignores limit.
    if let Some(limit) = cli.max_rows
        && data.rows.len() > limit
    {
        data.rows.truncate(limit);
    }
    Ok(data)
}

fn emit_table_output(cli: &Cli, data: &TableData) -> anyhow::Result<()> {
    let fmt = ExportFormat::parse(&cli.format)?;
    let opts = ReportOptions::default();

    if let Some(out_path) = &cli.out {
        let manifest = write_single_report_with_custody(data, out_path, fmt, cli.custody_out.as_deref(), &opts)?;
        println!(
            "Wrote {} rows ({}) to {} (sha256: {})",
            data.rows.len(),
            fmt,
            out_path.display(),
            manifest.leaves[0].sha256
        );
    } else {
        let bytes = render_report(data, fmt, &opts)?;
        if let Some(custody_path) = &cli.custody_out {
            let mut builder = CustodyManifestBuilder::new(&data.schema.tool_id, &opts.export.tool_version);
            builder.add_artifact(Path::new("<stdout>"), &bytes);
            builder.write_to(custody_path)?;
        }
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&bytes)?;
        if !bytes.ends_with(b"\n") {
            stdout.write_all(b"\n")?;
        }
    }
    Ok(())
}

fn dispatch_mutating_action(
    cli: &Cli,
    ctx: &NetContext,
    cmd_id: &str,
    mut args: Map<String, Value>,
) -> anyhow::Result<()> {
    let policy = if cli.allow_mutating {
        PolicyMode::AllowMutating
    } else {
        PolicyMode::ReadOnlyOnly
    };
    if cli.allow_mutating {
        args.insert("confirm_destructive".to_string(), json!(true));
    }
    if cli.dry_run {
        args.insert("dry_run".to_string(), json!(true));
    }

    let registry = build_mcp_registry(ctx, policy);
    match registry.dispatch(cmd_id, &Value::Object(args)) {
        Ok(val) => {
            println!("{}", serde_json::to_string_pretty(&val)?);
            Ok(())
        }
        Err(err) => bail!("MCP policy/execution error ({}): {}", err.code, err.message),
    }
}

fn run_sockets(cli: &Cli, ctx: &NetContext, sub: &SocketsSub) -> anyhow::Result<()> {
    match sub {
        SocketsSub::Ports(p) if p.close => {
            let mut args = Map::new();
            if let Some(v) = &p.local_addr {
                args.insert("local_addr".to_string(), json!(v));
            }
            if let Some(v) = p.local_port {
                args.insert("local_port".to_string(), json!(v));
            }
            if let Some(v) = &p.remote_addr {
                args.insert("remote_addr".to_string(), json!(v));
            }
            if let Some(v) = p.remote_port {
                args.insert("remote_port".to_string(), json!(v));
            }
            dispatch_mutating_action(cli, ctx, "sockets.ports.close", args)
        }
        SocketsSub::Routes(r) if r.add || r.delete => {
            let mut args = Map::new();
            if let Some(v) = &r.destination {
                args.insert("destination".to_string(), json!(v));
            }
            if let Some(v) = r.prefix_length {
                args.insert("prefix_length".to_string(), json!(v));
            }
            if let Some(v) = &r.next_hop {
                args.insert("next_hop".to_string(), json!(v));
            }
            if let Some(v) = r.interface_index {
                args.insert("interface_index".to_string(), json!(v));
            }
            if let Some(v) = &r.interface_alias {
                args.insert("interface_alias".to_string(), json!(v));
            }
            if r.add
                && let Some(v) = r.metric
            {
                args.insert("metric".to_string(), json!(v));
            }
            let cmd = if r.add {
                "sockets.routes.add"
            } else {
                "sockets.routes.delete"
            };
            dispatch_mutating_action(cli, ctx, cmd, args)
        }
        _ => {
            let tool_id = match sub {
                SocketsSub::Ports(_) => "sockets.ports",
                SocketsSub::Tcplog => "sockets.tcplog",
                SocketsSub::Live => "sockets.live",
                SocketsSub::AppNet => "sockets.app-net",
                SocketsSub::ProcTcp => "sockets.proc-tcp",
                SocketsSub::TcpErrors => "sockets.tcp-errors",
                SocketsSub::DnsLog => "sockets.dns-log",
                SocketsSub::Counters => "sockets.counters",
                SocketsSub::AdapterMonitor => "sockets.adapter-watch",
                SocketsSub::Interfaces => "sockets.interfaces",
                SocketsSub::Routes(_) => "sockets.routes",
                SocketsSub::Neighbors => "sockets.neighbors",
                SocketsSub::Paths => "sockets.paths",
            };
            let data = query_tool(cli, ctx, tool_id)?;
            emit_table_output(cli, &data)
        }
    }
}

fn run_capture(cli: &Cli, ctx: &NetContext, sub: &CaptureSub) -> anyhow::Result<()> {
    let tool_id = match sub {
        CaptureSub::Sniff => "capture.sniff",
        CaptureSub::Traffic => "capture.traffic",
        CaptureSub::Http => "capture.http",
        CaptureSub::Dns => "capture.dns",
        CaptureSub::Dhcp => "capture.dhcp",
        CaptureSub::Mdns => "capture.mdns",
        CaptureSub::WhoisLan => "capture.whois-lan",
        CaptureSub::Cookies => "capture.cookies",
        CaptureSub::Website => "capture.website",
        CaptureSub::Latency => "capture.latency",
        CaptureSub::WifiMon => "capture.wifi-mon",
    };
    let data = query_tool(cli, ctx, tool_id)?;
    emit_table_output(cli, &data)
}

fn run_lan(cli: &Cli, ctx: &NetContext, sub: &LanSub) -> anyhow::Result<()> {
    match sub {
        LanSub::Wol(w) if w.send => {
            let mut args = Map::new();
            if let Some(v) = &w.mac {
                args.insert("mac".to_string(), json!(v));
            }
            if let Some(v) = &w.broadcast_ip {
                args.insert("broadcast_ip".to_string(), json!(v));
            }
            if let Some(v) = w.port {
                args.insert("port".to_string(), json!(v));
            }
            if let Some(v) = w.repeat_count {
                args.insert("repeat_count".to_string(), json!(v));
            }
            dispatch_mutating_action(cli, ctx, "lan.wol.send", args)
        }
        LanSub::Openfiles(o) if o.close_id.is_some() => {
            let mut args = Map::new();
            if let Some(id) = o.close_id {
                args.insert("file_id".to_string(), json!(id));
            }
            if let Some(v) = &o.server {
                args.insert("server".to_string(), json!(v));
            }
            dispatch_mutating_action(cli, ctx, "lan.openfiles.close", args)
        }
        _ => {
            let tool_id = match sub {
                LanSub::Ping => "lan.ping",
                LanSub::Trace => "lan.trace",
                LanSub::Scan => "lan.scan",
                LanSub::Wnetwatcher => "lan.wnetwatcher",
                LanSub::ConnectLog => "lan.connect-log",
                LanSub::Wol(_) => "lan.wol",
                LanSub::Netbios => "lan.netbios",
                LanSub::Shares => "lan.shares",
                LanSub::Openfiles(_) => "lan.openfiles",
                LanSub::Resolve => "lan.resolve",
                LanSub::Speedtest => "lan.speedtest",
            };
            let data = query_tool(cli, ctx, tool_id)?;
            emit_table_output(cli, &data)
        }
    }
}

fn run_osint(cli: &Cli, ctx: &NetContext, sub: &OsintSub) -> anyhow::Result<()> {
    match sub {
        OsintSub::SetDns(s) if s.apply => {
            let mut args = Map::new();
            if let Some(v) = &s.interface {
                args.insert("interface".to_string(), json!(v));
            }
            args.insert("servers".to_string(), json!(s.servers));
            args.insert("ipv6".to_string(), json!(s.ipv6));
            dispatch_mutating_action(cli, ctx, "osint.set-dns.apply", args)
        }
        OsintSub::NetProfiles(np) if np.connect || np.disconnect => {
            let mut args = Map::new();
            if let Some(v) = &np.profile_id {
                args.insert("profile_id".to_string(), json!(v));
            }
            if let Some(v) = &np.profile_name {
                args.insert("profile_name".to_string(), json!(v));
            }
            if let Some(v) = &np.interface {
                args.insert("interface".to_string(), json!(v));
            }
            let cmd = if np.connect {
                "osint.net-profiles.connect"
            } else {
                "osint.net-profiles.disconnect"
            };
            dispatch_mutating_action(cli, ctx, cmd, args)
        }
        _ => {
            let tool_id = match sub {
                OsintSub::Ipnet => "osint.ipnet",
                OsintSub::Whosip => "osint.whosip",
                OsintSub::Ipoffline => "osint.ipoffline",
                OsintSub::WhoisDomain => "osint.whois-domain",
                OsintSub::Whoiscl => "osint.whoiscl",
                OsintSub::Dns => "osint.dns",
                OsintSub::Hosting => "osint.hosting",
                OsintSub::Oui => "osint.oui",
                OsintSub::SetDns(_) => "osint.set-dns",
                OsintSub::NetProfiles(_) => "osint.net-profiles",
            };
            let data = query_tool(cli, ctx, tool_id)?;
            emit_table_output(cli, &data)
        }
    }
}

fn run_radio(cli: &Cli, ctx: &NetContext, sub: &RadioSub) -> anyhow::Result<()> {
    match sub {
        RadioSub::WifiProfiles(wp) if wp.set_order || wp.delete || wp.toggle_auto => {
            let mut args = Map::new();
            if let Some(v) = &wp.profile_name {
                args.insert("profile_name".to_string(), json!(v));
            }
            if let Some(v) = &wp.interface_guid {
                args.insert("interface_guid".to_string(), json!(v));
            }
            if let Some(v) = &wp.interface_name {
                args.insert("interface_name".to_string(), json!(v));
            }
            if let Some(v) = wp.position {
                args.insert("position".to_string(), json!(v));
            }
            if let Some(v) = wp.auto_connect {
                args.insert("auto_connect".to_string(), json!(v));
            }
            let cmd = if wp.set_order {
                "radio.wifi-profiles.set-order"
            } else if wp.delete {
                "radio.wifi-profiles.delete"
            } else {
                "radio.wifi-profiles.toggle-auto"
            };
            dispatch_mutating_action(cli, ctx, cmd, args)
        }
        RadioSub::WifiHosted(wh) if wh.start || wh.stop => {
            let mut args = Map::new();
            if wh.start {
                if let Some(v) = &wh.ssid {
                    args.insert("ssid".to_string(), json!(v));
                }
                if let Some(v) = wh.max_peers {
                    args.insert("max_peers".to_string(), json!(v));
                }
                dispatch_mutating_action(cli, ctx, "radio.wifi-hosted.start", args)
            } else {
                args.insert("force".to_string(), json!(wh.force));
                dispatch_mutating_action(cli, ctx, "radio.wifi-hosted.stop", args)
            }
        }
        _ => {
            let tool_id = match sub {
                RadioSub::WifiInfo => "radio.wifi-info",
                RadioSub::WifiScan => "radio.wifi-scan",
                RadioSub::WifiConsole => "radio.wifi-console",
                RadioSub::WifiConn => "radio.wifi-conn",
                RadioSub::WifiProfiles(_) => "radio.wifi-profiles",
                RadioSub::WifiHosted(_) => "radio.wifi-hosted",
                RadioSub::BtView => "radio.bt-view",
                RadioSub::BtLog => "radio.bt-log",
                RadioSub::BtCl => "radio.bt-cl",
                RadioSub::Ble => "radio.ble",
            };
            let data = query_tool(cli, ctx, tool_id)?;
            emit_table_output(cli, &data)
        }
    }
}

fn run_mcp(cli: &Cli, ctx: &NetContext, args: &McpArgs) -> anyhow::Result<()> {
    let policy = if cli.allow_mutating || args.allow_mutating {
        PolicyMode::AllowMutating
    } else {
        PolicyMode::ReadOnlyOnly
    };
    let registry = build_mcp_registry(ctx, policy);
    if args.tools {
        println!("{}", serde_json::to_string_pretty(&registry.list_tools())?);
        return Ok(());
    }
    registry.serve_stdio()?;
    Ok(())
}

fn run_export(cli: &Cli, ctx: &NetContext, args: &ExportArgs) -> anyhow::Result<()> {
    if let Some(tool_id) = &args.tool {
        let data = query_tool(cli, ctx, tool_id)?;
        return emit_table_output(cli, &data);
    }

    if !args.all && args.category.is_none() {
        bail!("specify either --tool <TOOL_ID>, --category <CAT>, or --all");
    }

    let filter_cat = args.category.as_deref().map(str::parse::<ToolCategory>).transpose()?;
    let descriptors = all_tool_descriptors();
    let providers = all_providers(ctx);
    let fmt = ExportFormat::parse(&cli.format)?;
    let opts = ReportOptions::default();

    let out_dir = cli.out.clone().unwrap_or_else(|| PathBuf::from("net2rust-export"));
    std::fs::create_dir_all(&out_dir)?;

    let mut builder = CustodyManifestBuilder::new("net2rust.export", env!("CARGO_PKG_VERSION"));
    let mut exported_count = 0usize;

    for desc in descriptors {
        if let Some(cat) = filter_cat
            && desc.category != cat
        {
            continue;
        }
        let provider = find_provider(&providers, desc.id)?;
        let schema = provider.schema();
        let query = build_table_query(cli, &schema)?;
        let mut data = provider.query(&query)?;
        if let Some(limit) = cli.max_rows
            && data.rows.len() > limit
        {
            data.rows.truncate(limit);
        }
        let bytes = render_report(&data, fmt, &opts)?;
        let ext = format_file_extension(fmt);
        let file_name = format!("{}.{}", desc.id.replace('.', "_"), ext);
        let file_path = out_dir.join(file_name);
        std::fs::write(&file_path, &bytes)?;
        builder.add_artifact(&file_path, &bytes);
        exported_count += 1;
    }

    let custody_path = cli
        .custody_out
        .clone()
        .unwrap_or_else(|| out_dir.join("custody_manifest.json"));
    let manifest = builder.write_to(&custody_path)?;
    println!(
        "Exported {exported_count} tools ({fmt}) to {} with Merkle custody manifest {} (sha256_root: {})",
        out_dir.display(),
        custody_path.display(),
        manifest.merkle_root_sha256
    );
    Ok(())
}

fn run_list_tools(ctx: &NetContext, args: &ListToolsArgs) -> anyhow::Result<()> {
    let filter_cat = args.category.as_deref().map(str::parse::<ToolCategory>).transpose()?;
    let descriptors: Vec<ToolDescriptor> = all_tool_descriptors()
        .into_iter()
        .filter(|d| filter_cat.is_none_or(|c| d.category == c))
        .collect();
    let actions = all_actions(ctx);

    if args.json {
        let action_list: Vec<Value> = actions
            .iter()
            .map(|a| {
                json!({
                    "id": a.command_id(),
                    "description": a.description(),
                    "risk_level": format!("{:?}", a.risk_level()),
                })
            })
            .collect();
        let payload = json!({
            "tool_count": descriptors.len(),
            "action_count": action_list.len(),
            "tools": descriptors,
            "actions": action_list,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!(
            "net2rust catalog ({} TableProviders, {} ActionCommands):\n",
            descriptors.len(),
            actions.len()
        );
        for d in &descriptors {
            let mut_tag = if d.has_mutating_action {
                " [mutating-action]"
            } else {
                ""
            };
            println!("  {:<22} {:<40} {}{}", d.id, d.display_name, d.description, mut_tag);
        }
    }
    Ok(())
}

fn resolve_sibling_gui_binary(bin_stem: &str) -> PathBuf {
    let exe_name = if cfg!(windows) {
        format!("{bin_stem}.exe")
    } else {
        bin_stem.to_string()
    };
    if let Ok(curr) = std::env::current_exe()
        && let Some(dir) = curr.parent()
    {
        let candidate = dir.join(&exe_name);
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from(exe_name)
}

fn run_gui(cli: &Cli, args: &GuiArgs) -> anyhow::Result<()> {
    let bin_stem = if args.iced || !cfg!(windows) {
        "net2rust-iced"
    } else {
        "net2rust-win32"
    };
    let bin = resolve_sibling_gui_binary(bin_stem);
    let mut cmd = Command::new(&bin);
    if cli.offline {
        cmd.arg("--offline");
    }
    if let Some(dir) = &cli.fixture_dir {
        cmd.arg("--fixture-dir").arg(dir);
    }
    if let Some(pcap) = &cli.pcap {
        cmd.arg("--pcap").arg(pcap);
    }
    let status = cmd.status().with_context(|| {
        format!(
            "failed to launch GUI binary '{}'; build it with `cargo build -p {bin_stem}`",
            bin.display()
        )
    })?;
    if !status.success() {
        bail!("GUI process '{}' exited with status {status}", bin.display());
    }
    Ok(())
}

fn run_action(cli: &Cli, ctx: &NetContext, args: &ActionArgs) -> anyhow::Result<()> {
    if args.list {
        for action in all_actions(ctx) {
            println!(
                "{:<32} [{:?}] {}",
                action.command_id(),
                action.risk_level(),
                action.description()
            );
        }
        return Ok(());
    }
    let cmd_id = args
        .id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing --id <COMMAND_ID> (or pass --list)"))?;
    let val: Value =
        serde_json::from_str(&args.args).with_context(|| format!("invalid JSON passed to --args: {}", args.args))?;
    let map = val
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("--args must parse to a JSON object"))?;
    dispatch_mutating_action(cli, ctx, cmd_id, map)
}

pub fn run_cli(cli: Cli) -> anyhow::Result<()> {
    let ctx = build_context(&cli);
    match &cli.command {
        Commands::Sockets { sub } => run_sockets(&cli, &ctx, sub),
        Commands::Capture { sub } => run_capture(&cli, &ctx, sub),
        Commands::Lan { sub } => run_lan(&cli, &ctx, sub),
        Commands::Osint { sub } => run_osint(&cli, &ctx, sub),
        Commands::Radio { sub } => run_radio(&cli, &ctx, sub),
        Commands::Mcp(args) => run_mcp(&cli, &ctx, args),
        Commands::Export(args) => run_export(&cli, &ctx, args),
        Commands::ListTools(args) => run_list_tools(&ctx, args),
        Commands::Gui(args) => run_gui(&cli, args),
        Commands::Action(args) => run_action(&cli, &ctx, args),
    }
}
