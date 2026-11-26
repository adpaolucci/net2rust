use std::sync::Arc;

use guap_mcp::{JsonRpcError, McpServerRegistry, PolicyMode};
use guap_table::{CellValue, TableProvider, TableQuery};
use net2rust_core::{NetContext, NetError, OfflineConfig};
use net2rust_osint::actions::{
    ACTION_NET_PROFILES_CONNECT, ACTION_NET_PROFILES_DISCONNECT, ACTION_SET_DNS_APPLY, NetProfileToggleAction,
    SetDnsApplyAction,
};
use net2rust_osint::tools::net_profiles::{
    MockNetProfilesBackend, NetProfilesBackend, NetProfilesProvider, build_net_profiles_backend,
};
use net2rust_osint::tools::set_dns::{DnsBackend, MockDnsBackend, SetDnsProvider, build_dns_backend};
use net2rust_osint::{actions, providers};
use serde_json::json;

fn build_registry(policy: PolicyMode) -> McpServerRegistry {
    let ctx = NetContext::offline(OfflineConfig::default());
    let mut reg = McpServerRegistry::new(policy);
    for p in providers(&ctx) {
        reg.register_table(p);
    }
    for a in actions(&ctx) {
        reg.register_action(a);
    }
    reg
}

#[test]
fn test_mcp_tool_discovery_and_policy_gates_read_only_and_confirm() {
    let reg_ro = build_registry(PolicyMode::ReadOnlyOnly);
    let tools = reg_ro.list_tools();
    let arr = tools.as_array().expect("tools array");
    assert_eq!(arr.len(), 13);

    // Read-only TableProvider queries succeed in ReadOnlyOnly mode
    let ok_res = reg_ro
        .dispatch("osint.ipoffline", &json!({ "filter": "IPAddress = 1.1.1.1" }))
        .expect("read-only provider succeeds");
    assert_eq!(ok_res["returned_rows"], 1);

    // All 3 mutating actions MUST return -32003 in ReadOnlyOnly mode
    for (name, args) in [
        (
            ACTION_SET_DNS_APPLY,
            json!({ "interface": "Ethernet", "servers": ["9.9.9.9"], "confirm_destructive": true }),
        ),
        (
            ACTION_NET_PROFILES_CONNECT,
            json!({ "profile_name": "HomeLab-LAN", "confirm_destructive": true }),
        ),
        (
            ACTION_NET_PROFILES_DISCONNECT,
            json!({ "profile_name": "CorpNet.internal", "confirm_destructive": true }),
        ),
    ] {
        let err = reg_ro.dispatch(name, &args).unwrap_err();
        assert_eq!(err.code, JsonRpcError::POLICY_DENIED, "expected -32003 for {name}");
    }

    // PolicyMode::AllowMutating without confirm_destructive=true MUST ALSO return -32003
    let reg_mut = build_registry(PolicyMode::AllowMutating);
    for (name, args) in [
        (
            ACTION_SET_DNS_APPLY,
            json!({ "interface": "Ethernet", "servers": ["9.9.9.9"] }),
        ),
        (
            ACTION_NET_PROFILES_CONNECT,
            json!({ "profile_name": "HomeLab-LAN", "confirm_destructive": false }),
        ),
        (
            ACTION_NET_PROFILES_DISCONNECT,
            json!({ "profile_name": "CorpNet.internal" }),
        ),
    ] {
        let err = reg_mut.dispatch(name, &args).unwrap_err();
        assert_eq!(err.code, JsonRpcError::POLICY_DENIED, "expected -32003 for {name}");
    }
}

#[test]
fn test_set_dns_action_validation_dry_run_and_apply_on_mock_backend() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let backend = Arc::new(MockDnsBackend::default());
    let provider = Arc::new(SetDnsProvider::new(ctx, Arc::clone(&backend) as Arc<dyn DnsBackend>));
    let action = Arc::new(SetDnsApplyAction::new(Arc::clone(&backend) as Arc<dyn DnsBackend>));

    let mut reg = McpServerRegistry::new(PolicyMode::AllowMutating);
    reg.register_table(provider.clone() as Arc<dyn TableProvider>);
    reg.register_action(action);

    // Invalid inputs -> -32602 (INVALID_PARAMS)
    let err_empty = reg
        .dispatch(
            ACTION_SET_DNS_APPLY,
            &json!({ "interface": "  ", "servers": ["1.1.1.1"], "confirm_destructive": true }),
        )
        .unwrap_err();
    assert_eq!(err_empty.code, JsonRpcError::INVALID_PARAMS);

    let err_bad_ip = reg
        .dispatch(
            ACTION_SET_DNS_APPLY,
            &json!({ "interface": "Ethernet", "servers": ["not-an-ip;rm -rf"], "confirm_destructive": true }),
        )
        .unwrap_err();
    assert_eq!(err_bad_ip.code, JsonRpcError::INVALID_PARAMS);

    let err_mixed = reg
        .dispatch(
            ACTION_SET_DNS_APPLY,
            &json!({ "interface": "Ethernet", "servers": ["1.1.1.1", "2001:4860:4860::8888"], "confirm_destructive": true }),
        )
        .unwrap_err();
    assert_eq!(err_mixed.code, JsonRpcError::INVALID_PARAMS);

    let err_unspec = reg
        .dispatch(
            ACTION_SET_DNS_APPLY,
            &json!({ "interface": "Ethernet", "servers": ["0.0.0.0"], "confirm_destructive": true }),
        )
        .unwrap_err();
    assert_eq!(err_unspec.code, JsonRpcError::INVALID_PARAMS);

    // Missing interface -> -32601 (METHOD_NOT_FOUND via HardwareNotFound -> NotFound)
    let err_missing = reg
        .dispatch(
            ACTION_SET_DNS_APPLY,
            &json!({ "interface": "NoSuchAdapter99", "servers": ["8.8.8.8"], "confirm_destructive": true }),
        )
        .unwrap_err();
    assert_eq!(err_missing.code, JsonRpcError::METHOD_NOT_FOUND);

    // dry_run: true does NOT mutate mock state
    let dry = reg
        .dispatch(
            ACTION_SET_DNS_APPLY,
            &json!({
                "interface": "Ethernet",
                "servers": ["9.9.9.9", "149.112.112.112"],
                "dry_run": true,
                "confirm_destructive": true
            }),
        )
        .expect("dry_run succeeds");
    assert_eq!(dry["applied"], false);
    assert_eq!(dry["dry_run"], true);

    let before = provider.query(&TableQuery::default()).unwrap();
    assert_eq!(before.rows[0].cells[2], CellValue::Text("1.1.1.1, 1.0.0.1".into()));

    // dry_run: false applies static IPv4 DNS
    let applied = reg
        .dispatch(
            ACTION_SET_DNS_APPLY,
            &json!({
                "interface": "Ethernet",
                "servers": ["9.9.9.9", "149.112.112.112"],
                "dry_run": false,
                "confirm_destructive": true
            }),
        )
        .expect("apply succeeds");
    assert_eq!(applied["applied"], true);
    assert_eq!(applied["mode"], "static");

    let after = provider.query(&TableQuery::default()).unwrap();
    assert_eq!(
        after.rows[0].cells[2],
        CellValue::Text("9.9.9.9, 149.112.112.112".into())
    );

    // Reset to DHCP (servers: [])
    let dhcp_res = reg
        .dispatch(
            ACTION_SET_DNS_APPLY,
            &json!({
                "interface": "{11111111-2222-3333-4444-555555555555}",
                "servers": [],
                "confirm_destructive": true
            }),
        )
        .expect("dhcp reset succeeds");
    assert_eq!(dhcp_res["mode"], "dhcp");
    let after_dhcp = provider.query(&TableQuery::default()).unwrap();
    assert_eq!(after_dhcp.rows[0].cells[2], CellValue::Null);
    assert!(after_dhcp.rows[0].cells[4].to_string().starts_with("DHCP"));
}

#[test]
fn test_net_profiles_actions_dry_run_and_state_mutation() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let backend = Arc::new(MockNetProfilesBackend::default());
    let provider = Arc::new(NetProfilesProvider::new(
        ctx,
        Arc::clone(&backend) as Arc<dyn NetProfilesBackend>,
    ));

    let mut reg = McpServerRegistry::new(PolicyMode::AllowMutating);
    reg.register_table(provider.clone() as Arc<dyn TableProvider>);
    reg.register_action(Arc::new(NetProfileToggleAction::new(
        Arc::clone(&backend) as Arc<dyn NetProfilesBackend>,
        true,
    )));
    reg.register_action(Arc::new(NetProfileToggleAction::new(
        Arc::clone(&backend) as Arc<dyn NetProfilesBackend>,
        false,
    )));

    // Missing both profile_id and profile_name -> -32602
    let err_missing_args = reg
        .dispatch(ACTION_NET_PROFILES_CONNECT, &json!({ "confirm_destructive": true }))
        .unwrap_err();
    assert_eq!(err_missing_args.code, JsonRpcError::INVALID_PARAMS);

    // dry_run: true leaves HomeLab-LAN disconnected
    let dry_conn = reg
        .dispatch(
            ACTION_NET_PROFILES_CONNECT,
            &json!({
                "profile_name": "HomeLab-LAN",
                "dry_run": true,
                "confirm_destructive": true
            }),
        )
        .unwrap();
    assert_eq!(dry_conn["applied"], false);
    assert_eq!(dry_conn["dry_run"], true);
    assert_eq!(
        provider.query(&TableQuery::default()).unwrap().rows[1].cells[5],
        CellValue::Bool(false)
    );

    // dry_run: false connects HomeLab-LAN
    let conn = reg
        .dispatch(
            ACTION_NET_PROFILES_CONNECT,
            &json!({
                "profile_name": "HomeLab-LAN",
                "dry_run": false,
                "confirm_destructive": true
            }),
        )
        .unwrap();
    assert_eq!(conn["applied"], true);
    assert_eq!(
        provider.query(&TableQuery::default()).unwrap().rows[1].cells[5],
        CellValue::Bool(true)
    );

    // Disconnect CorpNet.internal by GUID (without braces)
    let disc = reg
        .dispatch(
            ACTION_NET_PROFILES_DISCONNECT,
            &json!({
                "profile_id": "10101010-2020-3030-4040-505050505050",
                "confirm_destructive": true
            }),
        )
        .unwrap();
    assert_eq!(disc["applied"], true);
    assert_eq!(disc["action"], "disconnect");
    assert_eq!(
        provider.query(&TableQuery::default()).unwrap().rows[0].cells[5],
        CellValue::Bool(false)
    );
}

#[test]
fn test_r4_compliance_no_forbidden_apis_or_shell_injection() {
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let forbidden_tokens = [
        "WLAN_PROFILE_GET_PLAINTEXT_KEY",
        "0x0000_0004",
        "0x00000004",
        "CreateRemoteThread",
        "WriteProcessMemory",
        "SetWindowsHookEx",
        "CryptUnprotectData",
        "CredEnumerate",
        "cmd /c",
        "cmd.exe",
    ];

    fn scan_dir(dir: &std::path::Path, forbidden: &[&str]) {
        for entry in std::fs::read_dir(dir).expect("read src dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                scan_dir(&path, forbidden);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let text = std::fs::read_to_string(&path).expect("read rs file");
                let lower = text.to_ascii_lowercase();
                for token in forbidden {
                    assert!(
                        !lower.contains(&token.to_ascii_lowercase()),
                        "R4 forbidden token '{token}' found in {}",
                        path.display()
                    );
                }
            }
        }
    }

    scan_dir(&src_dir, &forbidden_tokens);

    // Also assert Tools 1-8 and shared non-Win32 modules contain zero `unsafe` blocks
    for rel in [
        "lib.rs",
        "model.rs",
        "transport.rs",
        "whois.rs",
        "dns_wire.rs",
        "geoip_db.rs",
        "oui_db.rs",
        "actions.rs",
        "tools/mod.rs",
        "tools/ipnet.rs",
        "tools/whosip.rs",
        "tools/ipoffline.rs",
        "tools/whois_domain.rs",
        "tools/whoiscl.rs",
        "tools/dns.rs",
        "tools/hosting.rs",
        "tools/oui.rs",
    ] {
        let text = std::fs::read_to_string(src_dir.join(rel)).expect("read pure-rust source");
        assert!(
            !text.contains("unsafe ") && !text.contains("unsafe{"),
            "unexpected unsafe code in {rel}"
        );
    }
}

#[test]
fn test_regression_profile_id_precedence_and_malformed_fixture_fallback() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let backend = Arc::new(MockNetProfilesBackend::default());
    let mut reg = McpServerRegistry::new(PolicyMode::AllowMutating);
    reg.register_action(Arc::new(NetProfileToggleAction::new(
        Arc::clone(&backend) as Arc<dyn NetProfilesBackend>,
        true,
    )));

    // Unknown profile_id + existing profile_name must fail with -32601 (profile_id takes exclusive precedence)
    let err = reg
        .dispatch(
            ACTION_NET_PROFILES_CONNECT,
            &json!({
                "profile_id": "{99999999-9999-9999-9999-999999999999}",
                "profile_name": "HomeLab-LAN",
                "confirm_destructive": true
            }),
        )
        .unwrap_err();
    assert_eq!(err.code, JsonRpcError::METHOD_NOT_FOUND);

    // Malformed fixture files surface ParseError from build_*_backend while providers()/actions() fall back cleanly
    let unique = format!(
        "osint_bad_fixture_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let dir = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("set_dns_interfaces.json"), "{not-valid-json").unwrap();
    std::fs::write(dir.join("net_profiles.json"), "{not-valid-json").unwrap();

    let bad_ctx = NetContext::offline(OfflineConfig {
        fixture_dir: Some(dir.clone()),
        ..Default::default()
    });
    assert!(matches!(build_dns_backend(&bad_ctx), Err(NetError::ParseError(_))));
    assert!(matches!(
        build_net_profiles_backend(&bad_ctx),
        Err(NetError::ParseError(_))
    ));
    assert_eq!(providers(&bad_ctx).len(), 10);
    assert_eq!(actions(&bad_ctx).len(), 3);
    assert!(
        !providers(&bad_ctx)[8]
            .query(&TableQuery::default())
            .unwrap()
            .rows
            .is_empty()
    );
    assert!(
        !providers(&bad_ctx)[9]
            .query(&TableQuery::default())
            .unwrap()
            .rows
            .is_empty()
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = ctx;
}
