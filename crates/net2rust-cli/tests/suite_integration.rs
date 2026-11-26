#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use clap::CommandFactory;
use clap::Parser;
use guap_mcp::PolicyMode;
use net2rust_cli::{
    Cli, ExportArgs, all_actions, all_providers, all_tool_descriptors, build_context, build_mcp_registry,
    build_table_query, run_cli,
};
use net2rust_report::{ExportFormat, ReportOptions, verify_custody_manifest_file, write_single_report_with_custody};
use serde_json::{Value, json};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("net2rust_cli_e2e_{prefix}_{pid}_{seq}"));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn minimal_pcap_bytes() -> Vec<u8> {
    // Classic little-endian PCAP global header (24 bytes) + 1 minimal Ethernet/IPv4/TCP packet (54 bytes).
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
    out.extend_from_slice(&2u16.to_le_bytes()); // major
    out.extend_from_slice(&4u16.to_le_bytes()); // minor
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET

    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 64, 6, 0x00, 0x00, 192, 168, 1, 10, 93, 184, 216, 34,
    ]);
    frame.extend_from_slice(&[
        0xd4, 0x31, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xfa, 0xf0, 0x00, 0x00,
        0x00, 0x00,
    ]);

    let len = frame.len() as u32;
    out.extend_from_slice(&1700000000u32.to_le_bytes()); // ts_sec
    out.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    out.extend_from_slice(&len.to_le_bytes()); // incl_len
    out.extend_from_slice(&len.to_le_bytes()); // orig_len
    out.extend_from_slice(&frame);
    out
}

#[test]
fn test_clap_debug_assert_and_all_55_subcommands_offline() {
    Cli::command().debug_assert();

    let descriptors = all_tool_descriptors();
    assert_eq!(descriptors.len(), 55);

    let dir = TempDirGuard::new("all55");
    for desc in &descriptors {
        let out_file = dir.path().join(format!("{}.json", desc.id.replace('.', "_")));
        let args = [
            "net2rust",
            "--offline",
            "--max-rows",
            "2",
            "--format",
            "json",
            "--out",
            out_file.to_str().unwrap(),
            desc.category.as_str(),
            desc.subcommand,
        ];
        let cli = Cli::try_parse_from(args).unwrap_or_else(|e| panic!("failed to parse '{}': {e}", desc.id));
        run_cli(cli).unwrap_or_else(|e| panic!("failed to execute '{}': {e}", desc.id));
        let json_val: Value = serde_json::from_slice(&fs::read(&out_file).unwrap()).unwrap();
        assert!(json_val.as_array().unwrap().len() <= 2);
    }
}

#[test]
fn test_filter_sort_max_rows_and_implicit_offline_flags() {
    let dir = TempDirGuard::new("query_flags");
    let pcap_path = dir.path().join("sample.pcap");
    fs::write(&pcap_path, minimal_pcap_bytes()).unwrap();

    // Passing --pcap or --fixture-dir without --offline must activate ExecutionMode::Offline.
    let cli_pcap = Cli::try_parse_from([
        "net2rust",
        "--pcap",
        pcap_path.to_str().unwrap(),
        "--format",
        "json",
        "capture",
        "sniff",
    ])
    .unwrap();
    let ctx_pcap = build_context(&cli_pcap);
    assert!(ctx_pcap.is_offline());
    assert_eq!(
        ctx_pcap.offline_config().unwrap().pcap_path.as_deref(),
        Some(pcap_path.as_path())
    );
    run_cli(cli_pcap).unwrap();

    let cli_fixture = Cli::try_parse_from([
        "net2rust",
        "--fixture-dir",
        dir.path().to_str().unwrap(),
        "sockets",
        "ports",
    ])
    .unwrap();
    assert!(build_context(&cli_fixture).is_offline());

    // Verify --filter, --sort (with ~ and - prefixes), and --max-rows composition.
    let cli_query = Cli::try_parse_from([
        "net2rust",
        "--offline",
        "--filter",
        "local_port >= 1",
        "--sort",
        "~local_port",
        "--max-rows",
        "1",
        "sockets",
        "ports",
    ])
    .unwrap();
    let cli_query_hyphen = Cli::try_parse_from([
        "net2rust",
        "--offline",
        "--filter",
        "-1 != local_port",
        "--sort",
        "-local_port",
        "--max-rows",
        "1",
        "sockets",
        "ports",
    ])
    .unwrap();
    assert_eq!(cli_query_hyphen.sort.as_deref(), Some("-local_port"));
    assert_eq!(cli_query_hyphen.filter.as_deref(), Some("-1 != local_port"));
    let ctx = build_context(&cli_query);
    let providers = all_providers(&ctx);
    let ports = providers.iter().find(|p| p.tool_id() == "sockets.ports").unwrap();
    let query = build_table_query(&cli_query, &ports.schema()).unwrap();
    assert_eq!(query.limit, Some(1));
    assert!(query.filter.is_some());
    assert_eq!(query.sort.len(), 1);
    let data = ports.query(&query).unwrap();
    assert_eq!(data.rows.len(), 1);

    let query_hyphen = build_table_query(&cli_query_hyphen, &ports.schema()).unwrap();
    assert_eq!(query_hyphen.sort, query.sort);
}

#[test]
fn test_report_formats_custody_and_batch_export() {
    let dir = TempDirGuard::new("export_custody");
    let ctx = net2rust_core::NetContext::offline(Default::default());
    let providers = all_providers(&ctx);
    let ports = providers.iter().find(|p| p.tool_id() == "sockets.ports").unwrap();
    let data = ports.query(&Default::default()).unwrap();

    let formats = [
        ExportFormat::Csv,
        ExportFormat::Tsv,
        ExportFormat::Json,
        ExportFormat::Jsonl,
        ExportFormat::Html,
        ExportFormat::HtmlVertical,
        ExportFormat::Markdown,
    ];
    for fmt in formats {
        let out_file = dir.path().join(format!("ports_{fmt}.{}", fmt.extension()));
        let custody_file = dir.path().join(format!("ports_{fmt}.custody.json"));
        let manifest =
            write_single_report_with_custody(&data, &out_file, fmt, Some(&custody_file), &ReportOptions::default())
                .unwrap();
        assert_eq!(manifest.merkle_root_sha256.len(), 64);
        assert_eq!(manifest.merkle_root_sha512.len(), 128);
        verify_custody_manifest_file(&custody_file).unwrap();
    }

    // Batch export via CLI `export --all`
    let batch_dir = dir.path().join("batch");
    let batch_custody = dir.path().join("batch_custody.json");
    let cli = Cli::try_parse_from([
        "net2rust",
        "--offline",
        "--max-rows",
        "1",
        "--format",
        "jsonl",
        "--out",
        batch_dir.to_str().unwrap(),
        "--custody-out",
        batch_custody.to_str().unwrap(),
        "export",
        "--all",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        net2rust_cli::Commands::Export(ExportArgs { all: true, .. })
    ));
    run_cli(cli).unwrap();
    let verified = verify_custody_manifest_file(&batch_custody).unwrap();
    assert_eq!(verified.artifact_count, 55);
}

#[test]
fn test_metadata_smithery_and_mcp_json_parity() {
    let root = workspace_root();
    let metadata_raw = fs::read_to_string(root.join("metadata.json")).unwrap();
    let metadata: Value = serde_json::from_str(&metadata_raw).unwrap();
    let smithery_raw = fs::read_to_string(root.join("smithery.yaml")).unwrap();
    let mcp_raw = fs::read_to_string(root.join("mcp.json")).unwrap();
    let mcp_json: Value = serde_json::from_str(&mcp_raw).unwrap();

    assert_eq!(mcp_json["mcpServers"]["net2rust"]["command"], json!("net2rust-mcp"));

    let descriptors = all_tool_descriptors();
    let ctx = net2rust_core::NetContext::offline(Default::default());
    let providers = all_providers(&ctx);
    let actions = all_actions(&ctx);
    let registry = build_mcp_registry(&ctx, PolicyMode::ReadOnlyOnly);
    let mcp_tools = registry.list_tools();
    let mcp_names: BTreeSet<String> = mcp_tools
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(mcp_names.len(), 68);

    // metadata.json tools (55) + actions (13)
    let meta_tools = metadata["tools"].as_array().unwrap();
    assert_eq!(meta_tools.len(), 55);
    let meta_tool_ids: BTreeSet<String> = meta_tools
        .iter()
        .map(|t| t["id"].as_str().unwrap().to_string())
        .collect();
    let descriptor_ids: BTreeSet<String> = descriptors.iter().map(|d| d.id.to_string()).collect();
    let provider_ids: BTreeSet<String> = providers.iter().map(|p| p.tool_id().to_string()).collect();
    assert_eq!(meta_tool_ids, descriptor_ids);
    assert_eq!(meta_tool_ids, provider_ids);

    let meta_actions = metadata["actions"].as_array().unwrap();
    assert_eq!(meta_actions.len(), 13);
    let meta_action_ids: BTreeSet<String> = meta_actions
        .iter()
        .map(|a| a["id"].as_str().unwrap().to_string())
        .collect();
    let action_ids: BTreeSet<String> = actions.iter().map(|a| a.command_id().to_string()).collect();
    assert_eq!(meta_action_ids, action_ids);

    // smithery.yaml lists all 68 endpoints (`- name: <id>`) and includes toggle-auto description.
    assert!(smithery_raw.contains("toggle-auto"));
    let smithery_names: BTreeSet<String> = smithery_raw
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            trimmed.strip_prefix("- name:").map(|rest| rest.trim().to_string())
        })
        .collect();
    assert_eq!(smithery_names.len(), 68);
    assert_eq!(smithery_names, mcp_names);
}

#[test]
fn test_net2rust_binary_cli_mcp_and_policy_subprocesses() {
    let bin = env!("CARGO_BIN_EXE_net2rust");

    let help = Command::new(bin).arg("--help").output().unwrap();
    assert!(help.status.success());
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help_text.contains("sockets"));
    assert!(help_text.contains("radio"));

    let gui_help = Command::new(bin).args(["gui", "--help"]).output().unwrap();
    assert!(gui_help.status.success());
    assert!(String::from_utf8_lossy(&gui_help.stdout).contains("--iced"));

    let list_json = Command::new(bin).args(["list-tools", "--json"]).output().unwrap();
    assert!(list_json.status.success());
    let list_val: Value = serde_json::from_slice(&list_json.stdout).unwrap();
    assert_eq!(list_val["tool_count"], json!(55));
    assert_eq!(list_val["action_count"], json!(13));

    let mcp_tools = Command::new(bin)
        .args(["mcp", "--tools", "--offline"])
        .output()
        .unwrap();
    assert!(mcp_tools.status.success());
    let tools_arr: Value = serde_json::from_slice(&mcp_tools.stdout).unwrap();
    assert_eq!(tools_arr.as_array().unwrap().len(), 68);

    // Mutating CLI flag rejected without -y / --allow-mutating (-32003), allowed with -y --dry-run
    let denied = Command::new(bin)
        .args([
            "--offline",
            "--dry-run",
            "lan",
            "wol",
            "--send",
            "--mac",
            "00:11:22:33:44:55",
        ])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    let denied_err = String::from_utf8_lossy(&denied.stderr);
    assert!(
        denied_err.contains("-32003"),
        "expected -32003 in stderr, got: {denied_err}"
    );

    let allowed = Command::new(bin)
        .args([
            "--offline",
            "-y",
            "--dry-run",
            "lan",
            "wol",
            "--send",
            "--mac",
            "00:11:22:33:44:55",
        ])
        .output()
        .unwrap();
    assert!(
        allowed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let allowed_val: Value = serde_json::from_slice(&allowed.stdout).unwrap();
    assert_eq!(allowed_val["dry_run"], json!(true));

    // Live `--sort -local_port` two-token CLI invocation
    let sorted = Command::new(bin)
        .args([
            "--offline",
            "--sort",
            "-local_port",
            "--max-rows",
            "1",
            "--format",
            "json",
            "sockets",
            "ports",
        ])
        .output()
        .unwrap();
    assert!(
        sorted.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&sorted.stderr)
    );
    let sorted_rows: Value = serde_json::from_slice(&sorted.stdout).unwrap();
    assert_eq!(sorted_rows.as_array().unwrap().len(), 1);

    // Live stdio JSON-RPC through `net2rust mcp --offline`
    let reqs = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}).to_string(),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}).to_string(),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"lan.wol.send","arguments":{"mac":"00:11:22:33:44:55","confirm_destructive":true,"dry_run":true}}}).to_string(),
        json!({"jsonrpc":"1.0","id":4,"method":"ping"}).to_string(),
        json!({"id":5,"method":"ping"}).to_string(),
    ]
    .join("\n")
        + "\n";

    let mut child = Command::new(bin)
        .args(["mcp", "--offline"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(reqs.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let lines: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 5);
    assert_eq!(lines[0]["result"]["protocolVersion"], json!("2024-11-05"));
    assert_eq!(lines[1]["result"]["tools"].as_array().unwrap().len(), 68);
    assert_eq!(lines[2]["error"]["code"], json!(-32003));
    assert_eq!(lines[3]["error"]["code"], json!(-32600));
    assert_eq!(lines[4]["error"]["code"], json!(-32600));
}
