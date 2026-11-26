#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::io::{BufReader, Cursor, Write};
use std::process::{Command, Stdio};

use guap_mcp::{JsonRpcError, MCP_PROTOCOL_VERSION, PolicyMode};
use net2rust_core::{NetContext, OfflineConfig};
use net2rust_mcp::{
    EXPECTED_ACTION_COUNT, EXPECTED_PROVIDER_COUNT, EXPECTED_TOTAL_TOOLS, all_actions, all_providers,
    all_tool_descriptors, build_registry, run_stdio_with,
};
use serde_json::{Value, json};

fn mutating_sample_args() -> Vec<(&'static str, Value)> {
    vec![
        (
            "sockets.ports.close",
            json!({
                "local_addr": "192.168.1.50",
                "local_port": 51234,
                "remote_addr": "93.184.216.34",
                "remote_port": 443
            }),
        ),
        (
            "sockets.routes.add",
            json!({
                "destination": "10.20.0.0/16",
                "next_hop": "192.168.1.1",
                "interface_index": 1,
                "metric": 25
            }),
        ),
        (
            "sockets.routes.delete",
            json!({
                "destination": "10.20.0.0/16",
                "next_hop": "192.168.1.1",
                "interface_index": 1
            }),
        ),
        (
            "lan.wol.send",
            json!({
                "mac": "00:11:22:33:44:55",
                "broadcast_ip": "192.168.1.255",
                "port": 9,
                "repeat_count": 1
            }),
        ),
        (
            "lan.openfiles.close",
            json!({
                "file_id": 101
            }),
        ),
        (
            "osint.set-dns.apply",
            json!({
                "interface": "Ethernet",
                "servers": ["1.1.1.1", "9.9.9.9"],
                "ipv6": false
            }),
        ),
        (
            "osint.net-profiles.connect",
            json!({
                "profile_name": "CorpNet.internal"
            }),
        ),
        (
            "osint.net-profiles.disconnect",
            json!({
                "profile_name": "CorpNet.internal"
            }),
        ),
        (
            "radio.wifi-profiles.set-order",
            json!({
                "profile_name": "CorpNet-5G",
                "position": 0
            }),
        ),
        (
            "radio.wifi-profiles.delete",
            json!({
                "profile_name": "CorpNet-5G"
            }),
        ),
        (
            "radio.wifi-profiles.toggle-auto",
            json!({
                "profile_name": "CorpNet-5G",
                "auto_connect": false
            }),
        ),
        (
            "radio.wifi-hosted.start",
            json!({
                "ssid": "Net2RustTestAP",
                "max_peers": 8
            }),
        ),
        (
            "radio.wifi-hosted.stop",
            json!({
                "force": false
            }),
        ),
    ]
}

#[test]
fn test_registry_has_all_68_unique_tools_and_proper_annotations() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let providers = all_providers(&ctx);
    let actions = all_actions(&ctx);
    let descriptors = all_tool_descriptors();

    assert_eq!(providers.len(), EXPECTED_PROVIDER_COUNT);
    assert_eq!(actions.len(), EXPECTED_ACTION_COUNT);
    assert_eq!(descriptors.len(), EXPECTED_PROVIDER_COUNT);

    let registry = build_registry(&ctx, PolicyMode::ReadOnlyOnly);
    let tools_val = registry.list_tools();
    let tools = tools_val.as_array().expect("tools list must be JSON array");
    assert_eq!(tools.len(), EXPECTED_TOTAL_TOOLS);

    let provider_names: BTreeSet<&str> = providers.iter().map(|p| p.tool_id()).collect();
    let action_names: BTreeSet<&str> = actions.iter().map(|a| a.command_id()).collect();
    assert_eq!(provider_names.len(), EXPECTED_PROVIDER_COUNT);
    assert_eq!(action_names.len(), EXPECTED_ACTION_COUNT);

    let mut seen = BTreeSet::new();
    for tool in tools {
        let name = tool["name"].as_str().expect("tool name");
        assert!(seen.insert(name.to_string()), "duplicate MCP tool '{name}'");

        if provider_names.contains(name) {
            assert_eq!(tool["annotations"]["readOnlyHint"], json!(true), "{name}");
            assert_eq!(tool["annotations"]["destructiveHint"], json!(false), "{name}");
        } else if action_names.contains(name) {
            assert_eq!(tool["annotations"]["destructiveHint"], json!(true), "{name}");
            let props = &tool["inputSchema"]["properties"];
            assert!(
                props.get("confirm_destructive").is_some(),
                "action '{name}' missing confirm_destructive"
            );
            assert!(props.get("dry_run").is_some(), "action '{name}' missing dry_run");
        } else {
            panic!("unexpected tool '{name}' in MCP registry");
        }
    }

    let sample_ids: BTreeSet<&str> = mutating_sample_args().into_iter().map(|(id, _)| id).collect();
    assert_eq!(sample_ids, action_names);
}

#[test]
fn test_all_55_read_only_providers_execute_offline() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let providers = all_providers(&ctx);
    let registry = build_registry(&ctx, PolicyMode::ReadOnlyOnly);

    for provider in providers {
        let id = provider.tool_id();
        let res = registry
            .dispatch(id, &json!({ "limit": 2 }))
            .unwrap_or_else(|e| panic!("offline dispatch for '{id}' failed: {e:?}"));
        let rows = res["rows"].as_array().unwrap_or_else(|| panic!("'{id}' missing rows"));
        let cols = res["columns"]
            .as_array()
            .unwrap_or_else(|| panic!("'{id}' missing columns"));
        assert!(!cols.is_empty(), "'{id}' returned empty columns");
        assert!(rows.len() <= 2, "'{id}' exceeded limit=2 (got {})", rows.len());
    }
}

#[test]
fn test_all_13_mutating_actions_enforce_policy_gates_and_dry_run() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let read_only = build_registry(&ctx, PolicyMode::ReadOnlyOnly);
    let allow_mutating = build_registry(&ctx, PolicyMode::AllowMutating);

    for (cmd_id, base_args) in mutating_sample_args() {
        // 1. ReadOnlyOnly blocks even when confirm_destructive=true and dry_run=true.
        let mut ro_args = base_args.clone();
        ro_args["confirm_destructive"] = json!(true);
        ro_args["dry_run"] = json!(true);
        let err = read_only.dispatch(cmd_id, &ro_args).unwrap_err();
        assert_eq!(
            err.code,
            JsonRpcError::POLICY_DENIED,
            "ReadOnlyOnly must return -32003 for '{cmd_id}', got {err:?}"
        );

        // 2. AllowMutating without confirm_destructive=true must still return -32003.
        let mut unconfirmed_args = base_args.clone();
        unconfirmed_args["dry_run"] = json!(true);
        let err2 = allow_mutating.dispatch(cmd_id, &unconfirmed_args).unwrap_err();
        assert_eq!(
            err2.code,
            JsonRpcError::POLICY_DENIED,
            "AllowMutating without confirm_destructive must return -32003 for '{cmd_id}', got {err2:?}"
        );

        // 3. AllowMutating + confirm_destructive=true + dry_run=true must succeed cleanly.
        let mut ok_args = base_args;
        ok_args["confirm_destructive"] = json!(true);
        ok_args["dry_run"] = json!(true);
        let out = allow_mutating
            .dispatch(cmd_id, &ok_args)
            .unwrap_or_else(|e| panic!("AllowMutating dry_run failed for '{cmd_id}': {e:?}"));
        assert_eq!(out["dry_run"], json!(true), "'{cmd_id}' did not echo dry_run=true");
    }
}

#[test]
fn test_in_process_stdio_jsonrpc_2024_11_05_roundtrip() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let reqs = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}).to_string(),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string(),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}).to_string(),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sockets.ports","arguments":{"limit":2}}})
            .to_string(),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"lan.wol.send","arguments":{"mac":"00:11:22:33:44:55","confirm_destructive":true,"dry_run":true}}}).to_string(),
        "{malformed-json".to_string(),
    ]
    .join("\n")
        + "\n";

    let mut out = Vec::new();
    run_stdio_with(
        &ctx,
        PolicyMode::ReadOnlyOnly,
        BufReader::new(Cursor::new(reqs.as_bytes())),
        &mut out,
    )
    .unwrap();

    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    // notification emits zero response lines -> 5 responses
    assert_eq!(lines.len(), 5, "expected 5 JSON-RPC responses, got: {text}");

    let r1: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(r1["result"]["protocolVersion"], json!(MCP_PROTOCOL_VERSION));
    assert!(r1["result"]["capabilities"]["tools"].is_object());

    let r2: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(r2["result"]["tools"].as_array().unwrap().len(), EXPECTED_TOTAL_TOOLS);

    let r3: Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(r3["result"]["isError"], json!(false));

    let r4: Value = serde_json::from_str(lines[3]).unwrap();
    assert_eq!(r4["error"]["code"], json!(JsonRpcError::POLICY_DENIED));

    let r5: Value = serde_json::from_str(lines[4]).unwrap();
    assert_eq!(r5["error"]["code"], json!(JsonRpcError::PARSE_ERROR));
}

#[test]
fn test_jsonrpc_rejects_wrong_or_missing_version_with_32600() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let reqs = [
        json!({"jsonrpc":"1.0","id":2,"method":"ping"}).to_string(),
        json!({"id":3,"method":"ping"}).to_string(),
    ]
    .join("\n")
        + "\n";

    let mut out = Vec::new();
    run_stdio_with(
        &ctx,
        PolicyMode::ReadOnlyOnly,
        BufReader::new(Cursor::new(reqs.as_bytes())),
        &mut out,
    )
    .unwrap();

    let text = String::from_utf8(out).unwrap();
    let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["error"]["code"], json!(JsonRpcError::INVALID_REQUEST));
    assert_eq!(lines[0]["id"], json!(2));
    assert_eq!(lines[1]["error"]["code"], json!(JsonRpcError::INVALID_REQUEST));
    assert_eq!(lines[1]["id"], json!(3));

    let bin = env!("CARGO_BIN_EXE_net2rust-mcp");
    let mut child = Command::new(bin)
        .args(["--offline"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(reqs.as_bytes()).unwrap();
    let proc_out = child.wait_with_output().unwrap();
    assert!(proc_out.status.success());
    let proc_lines: Vec<Value> = String::from_utf8(proc_out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(proc_lines.len(), 2);
    assert_eq!(proc_lines[0]["error"]["code"], json!(-32600));
    assert_eq!(proc_lines[1]["error"]["code"], json!(-32600));
}

#[test]
fn test_live_mcp_binary_tools_and_stdio_policy_gates() {
    let bin = env!("CARGO_BIN_EXE_net2rust-mcp");

    let tools_out = Command::new(bin)
        .args(["--tools", "--offline"])
        .output()
        .expect("spawn net2rust-mcp --tools --offline");
    assert!(tools_out.status.success());
    let tools_json: Value = serde_json::from_slice(&tools_out.stdout).expect("valid JSON from --tools");
    assert_eq!(tools_json.as_array().unwrap().len(), EXPECTED_TOTAL_TOOLS);

    let payload = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}).to_string(),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}).to_string(),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"lan.wol.send","arguments":{"mac":"00:11:22:33:44:55","confirm_destructive":true,"dry_run":true}}}).to_string(),
    ]
    .join("\n")
        + "\n";

    // Read-only mode must deny lan.wol.send with -32003
    let mut ro_child = Command::new(bin)
        .args(["--offline"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn net2rust-mcp --offline");
    ro_child.stdin.as_mut().unwrap().write_all(payload.as_bytes()).unwrap();
    let ro_out = ro_child.wait_with_output().unwrap();
    assert!(ro_out.status.success());
    let ro_lines: Vec<Value> = String::from_utf8(ro_out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(ro_lines.len(), 3);
    assert_eq!(ro_lines[0]["result"]["protocolVersion"], json!("2024-11-05"));
    assert_eq!(
        ro_lines[1]["result"]["tools"].as_array().unwrap().len(),
        EXPECTED_TOTAL_TOOLS
    );
    assert_eq!(ro_lines[2]["error"]["code"], json!(-32003));

    // Allow-mutating mode + confirm_destructive + dry_run succeeds
    let mut mut_child = Command::new(bin)
        .args(["--offline", "--allow-mutating"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn net2rust-mcp --offline --allow-mutating");
    mut_child.stdin.as_mut().unwrap().write_all(payload.as_bytes()).unwrap();
    let mut_out = mut_child.wait_with_output().unwrap();
    assert!(mut_out.status.success());
    let mut_lines: Vec<Value> = String::from_utf8(mut_out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(mut_lines.len(), 3);
    assert_eq!(mut_lines[2]["result"]["isError"], json!(false));
}
