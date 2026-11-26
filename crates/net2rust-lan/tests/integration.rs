use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::time::Duration;

use guap_mcp::{JsonRpcError, McpServerRegistry, PolicyMode};
use guap_table::{SortDirection, TableProvider, TableQuery};
use net2rust_core::{DomainCrateExport, MacAddr, NetContext, NetError, OfflineConfig, ToolCategory};
use net2rust_lan::netbios::{build_nbstat_query, encode_netbios_name, query_nbstat_udp_socket};
use net2rust_lan::speedtest::DownTesterProvider;
use net2rust_lan::wol::build_magic_packet;
use net2rust_lan::{LanDomain, actions, providers, tool_descriptors};
use serde_json::json;

fn offline_ctx() -> NetContext {
    NetContext::offline(OfflineConfig::default())
}

#[test]
fn test_all_11_offline_providers_and_schemas() {
    let ctx = offline_ctx();
    let descs = tool_descriptors();
    let provs = providers(&ctx);
    assert_eq!(LanDomain::category(), ToolCategory::Lan);
    assert_eq!(descs.len(), 11);
    assert_eq!(provs.len(), 11);

    let expected_ids = [
        "lan.ping",
        "lan.trace",
        "lan.scan",
        "lan.wnetwatcher",
        "lan.connect-log",
        "lan.wol",
        "lan.netbios",
        "lan.shares",
        "lan.openfiles",
        "lan.resolve",
        "lan.speedtest",
    ];

    for (idx, expected_id) in expected_ids.iter().enumerate() {
        assert_eq!(descs[idx].id, *expected_id);
        assert_eq!(provs[idx].tool_id(), *expected_id);
        assert!(provs[idx].is_read_only());

        let data = provs[idx].query(&TableQuery::default()).unwrap();
        assert!(
            data.total_rows > 0,
            "offline provider {} should yield synthetic rows",
            expected_id
        );
        assert!(!data.schema.columns.is_empty());
        for row in &data.rows {
            assert_eq!(
                row.cells.len(),
                data.schema.columns.len(),
                "row cell count mismatch for {}",
                expected_id
            );
        }
    }

    // Verify apply_row_limit and TableQuery pagination/sorting
    let limited_ctx = offline_ctx().with_max_rows(Some(1));
    for prov in providers(&limited_ctx) {
        let data = prov
            .query(&TableQuery {
                sort: vec![(0, SortDirection::Desc)],
                limit: Some(1),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(data.rows.len(), 1);
        assert_eq!(data.total_rows, 1);
    }
}

#[test]
fn test_mcp_registry_policy_gates_and_jsonrpc_dispatch() {
    let ctx = offline_ctx();

    // 1. ReadOnlyOnly blocks both mutating actions with -32003
    let mut ro_reg = McpServerRegistry::new(PolicyMode::ReadOnlyOnly);
    for p in providers(&ctx) {
        ro_reg.register_table(p);
    }
    for a in actions(&ctx) {
        ro_reg.register_action(a);
    }

    let tools = ro_reg.list_tools();
    assert_eq!(tools.as_array().unwrap().len(), 13);

    // Every read-only table works under ReadOnlyOnly
    let ping_res = ro_reg.dispatch("lan.ping", &json!({ "limit": 2 })).unwrap();
    assert_eq!(ping_res["tool_id"], "lan.ping");
    assert_eq!(ping_res["returned_rows"], 2);

    // Mutating actions blocked under ReadOnlyOnly with -32003
    let wol_ro_err = ro_reg
        .dispatch(
            "lan.wol.send",
            &json!({ "mac": "aa:bb:cc:dd:ee:ff", "dry_run": true, "confirm_destructive": true }),
        )
        .unwrap_err();
    assert_eq!(wol_ro_err.code, JsonRpcError::POLICY_DENIED);

    let close_ro_err = ro_reg
        .dispatch(
            "lan.openfiles.close",
            &json!({ "file_id": 101, "dry_run": true, "confirm_destructive": true }),
        )
        .unwrap_err();
    assert_eq!(close_ro_err.code, JsonRpcError::POLICY_DENIED);

    // 2. AllowMutating requires confirm_destructive == true
    let mut mut_reg = McpServerRegistry::new(PolicyMode::AllowMutating);
    for p in providers(&ctx) {
        mut_reg.register_table(p);
    }
    for a in actions(&ctx) {
        mut_reg.register_action(a);
    }

    let unconfirmed_wol = mut_reg
        .dispatch("lan.wol.send", &json!({ "mac": "aa:bb:cc:dd:ee:ff" }))
        .unwrap_err();
    assert_eq!(unconfirmed_wol.code, JsonRpcError::POLICY_DENIED);

    let unconfirmed_close = mut_reg
        .dispatch("lan.openfiles.close", &json!({ "file_id": 101 }))
        .unwrap_err();
    assert_eq!(unconfirmed_close.code, JsonRpcError::POLICY_DENIED);

    // 3. AllowMutating + confirm_destructive + dry_run succeeds cleanly
    let wol_dry = mut_reg
        .dispatch(
            "lan.wol.send",
            &json!({
                "mac": "00:11:32:30:40:20",
                "broadcast_ip": "192.168.1.255",
                "port": 9,
                "dry_run": true,
                "confirm_destructive": true
            }),
        )
        .unwrap();
    assert_eq!(wol_dry["dry_run"], true);
    assert_eq!(wol_dry["would_send"], true);
    assert_eq!(wol_dry["packet_bytes"], 102);

    let close_dry = mut_reg
        .dispatch(
            "lan.openfiles.close",
            &json!({
                "file_id": 101,
                "dry_run": true,
                "confirm_destructive": true
            }),
        )
        .unwrap();
    assert_eq!(close_dry["dry_run"], true);
    assert_eq!(close_dry["would_close"], true);

    // 4. AllowMutating + confirm_destructive + dry_run:false in Offline simulates cleanly
    let wol_sim = mut_reg
        .dispatch(
            "lan.wol.send",
            &json!({
                "mac": "00:11:32:30:40:20",
                "dry_run": false,
                "confirm_destructive": true
            }),
        )
        .unwrap();
    assert_eq!(wol_sim["offline_simulated"], true);
    assert_eq!(wol_sim["sent"], true);

    let close_sim = mut_reg
        .dispatch(
            "lan.openfiles.close",
            &json!({
                "file_id": 101,
                "dry_run": false,
                "confirm_destructive": true
            }),
        )
        .unwrap();
    assert_eq!(close_sim["offline_simulated"], true);
    assert_eq!(close_sim["closed"], true);

    // Missing file_id in offline fixture maps to NotFound (-32601), NOT -32003
    let close_missing = mut_reg
        .dispatch(
            "lan.openfiles.close",
            &json!({
                "file_id": 9999,
                "dry_run": false,
                "confirm_destructive": true
            }),
        )
        .unwrap_err();
    assert_eq!(close_missing.code, JsonRpcError::METHOD_NOT_FOUND);

    // 5. Full JSON-RPC request/response roundtrip
    let rpc_req = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "lan.shares",
            "arguments": {
                "filter": "share_type == 'Disk'"
            }
        }
    });
    let rpc_resp = mut_reg.handle_jsonrpc_request(&rpc_req).unwrap();
    assert_eq!(rpc_resp["id"], 7);
    assert_eq!(rpc_resp["result"]["isError"], false);
}

#[test]
fn test_offline_config_custom_db_and_fixture_overrides() {
    let dir = std::env::temp_dir().join(format!("net2rust_lan_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let oui_path = dir.join("custom_oui.csv");
    std::fs::write(&oui_path, "prefix,vendor\n00:11:32,Custom Synology Lab\n").unwrap();

    let geoip_path = dir.join("custom_geoip.csv");
    std::fs::write(
        &geoip_path,
        "cidr,country_code,country_name,asn,org\n203.0.113.0/24,JP,Japan,AS64555,Lab Net\n",
    )
    .unwrap();

    let ctx = NetContext::offline(OfflineConfig {
        fixture_dir: Some(dir.clone()),
        oui_db_path: Some(oui_path),
        geoip_db_path: Some(geoip_path),
        ..Default::default()
    });

    let oui = net2rust_lan::oui::OuiDatabase::for_context(&ctx).unwrap();
    assert_eq!(
        oui.lookup(MacAddr::new([0x00, 0x11, 0x32, 0x01, 0x02, 0x03])),
        Some("Custom Synology Lab")
    );

    let geo = net2rust_lan::geoip::GeoIpDatabase::for_context(&ctx).unwrap();
    let info = geo.lookup(std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)));
    assert_eq!(info.country_code, "JP");
    assert_eq!(info.asn, "AS64555");

    // Verify custom OUI propagates into offline lan.wol fixture
    let wol_provider = providers(&ctx).into_iter().find(|p| p.tool_id() == "lan.wol").unwrap();
    let wol_data = wol_provider.query(&TableQuery::default()).unwrap();
    assert_eq!(
        wol_data.rows[0].cells[3],
        guap_table::CellValue::Text("Custom Synology Lab".into())
    );

    // Verify fixture_dir JSON override for lan.ping
    let ping_json = serde_json::json!([
        {
            "host": "custom-fixture.lan",
            "ip": "192.0.2.55",
            "protocol": "ICMP",
            "port": null,
            "status": "Succeeded",
            "rtt_ms": 1.25,
            "min_rtt_ms": 1.25,
            "avg_rtt_ms": 1.25,
            "max_rtt_ms": 1.25,
            "sent": 1,
            "succeeded": 1,
            "failed": 0,
            "loss_pct": 0.0,
            "ttl": 64,
            "last_checked": "2026-11-23T12:00:00Z"
        }
    ]);
    std::fs::write(
        dir.join("lan.ping.json"),
        serde_json::to_string_pretty(&ping_json).unwrap(),
    )
    .unwrap();
    let ping_provider = providers(&ctx).into_iter().find(|p| p.tool_id() == "lan.ping").unwrap();
    let ping_data = ping_provider.query(&TableQuery::default()).unwrap();
    assert_eq!(ping_data.total_rows, 1);
    assert_eq!(
        ping_data.rows[0].cells[0],
        guap_table::CellValue::Text("custom-fixture.lan".into())
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_action_parameter_validation_errors() {
    let ctx = offline_ctx();
    let mut reg = McpServerRegistry::new(PolicyMode::AllowMutating);
    for a in actions(&ctx) {
        reg.register_action(a);
    }

    for bad_wol in [
        json!({ "confirm_destructive": true }),
        json!({ "mac": "not-a-mac", "confirm_destructive": true }),
        json!({ "mac": "00:11:22:33:44:55", "broadcast_ip": "invalid-ip", "confirm_destructive": true }),
        json!({ "mac": "00:11:22:33:44:55", "port": 0, "confirm_destructive": true }),
        json!({ "mac": "00:11:22:33:44:55", "port": 70000, "confirm_destructive": true }),
        json!({ "mac": "00:11:22:33:44:55", "repeat_count": 11, "confirm_destructive": true }),
    ] {
        let err = reg.dispatch("lan.wol.send", &bad_wol).unwrap_err();
        assert_eq!(err.code, JsonRpcError::INVALID_PARAMS);
    }

    for bad_close in [
        json!({ "confirm_destructive": true }),
        json!({ "file_id": 0, "confirm_destructive": true }),
        json!({ "file_id": 101, "server": "   ", "confirm_destructive": true }),
    ] {
        let err = reg.dispatch("lan.openfiles.close", &bad_close).unwrap_err();
        assert_eq!(err.code, JsonRpcError::INVALID_PARAMS);
    }
}

#[test]
fn test_loopback_speedtest_and_nbstat_integration() {
    // 1) DownTesterProvider -> real ureq vs 127.0.0.1:0 TcpListener
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let payload_len = 256 * 1024usize;
    let t = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).unwrap();
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {payload_len}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(header.as_bytes()).unwrap();
        stream.write_all(&vec![0xAAu8; payload_len]).unwrap();
        stream.flush().unwrap();
    });

    let url = format!("http://127.0.0.1:{port}/bench.bin");
    let speed = DownTesterProvider::new(NetContext::live()).with_urls(vec![url]);
    let data = speed.query(&TableQuery::default()).unwrap();
    t.join().unwrap();
    assert_eq!(data.total_rows, 1);
    assert_eq!(data.rows[0].cells[2], guap_table::CellValue::Bytes(payload_len as u64));

    // 2) Loopback NBSTAT UDP roundtrip
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let nb_thread = std::thread::spawn(move || {
        let mut req = [0u8; 128];
        let (n, peer) = udp.recv_from(&mut req).unwrap();
        assert_eq!(n, 50);
        let txid = u16::from_be_bytes([req[0], req[1]]);
        assert_eq!(&req[..n], &build_nbstat_query(txid));

        let mut resp = Vec::new();
        resp.extend_from_slice(&txid.to_be_bytes());
        resp.extend_from_slice(&0x8400u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes());
        let mut wildcard = [0u8; 16];
        wildcard[0] = b'*';
        resp.extend_from_slice(&encode_netbios_name(&wildcard));
        resp.extend_from_slice(&0x0021u16.to_be_bytes());
        resp.extend_from_slice(&0x0001u16.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes());
        resp.extend_from_slice(&(1u16 + 18 + 6).to_be_bytes());
        resp.push(1);
        let mut name = [b' '; 15];
        name[..7].copy_from_slice(b"TESTBOX");
        resp.extend_from_slice(&name);
        resp.push(0x00);
        resp.extend_from_slice(&0x0400u16.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x50, 0x56, 0x01, 0x02, 0x03]);
        udp.send_to(&resp, peer).unwrap();
    });

    let (nb, _) = query_nbstat_udp_socket(udp_addr, Duration::from_secs(2), 0x7788)
        .unwrap()
        .expect("loopback NBSTAT reply");
    nb_thread.join().unwrap();
    assert_eq!(nb.computer_name.as_deref(), Some("TESTBOX"));
    assert_eq!(nb.mac, Some(MacAddr::new([0x00, 0x50, 0x56, 0x01, 0x02, 0x03])));

    // 3) PermissionDenied never maps to -32003 and magic packet is 102 bytes
    let rpc_perm: JsonRpcError = guap_mcp::McpToolError::from(NetError::PermissionDenied("denied".into())).into();
    assert_ne!(rpc_perm.code, JsonRpcError::POLICY_DENIED);
    assert_eq!(build_magic_packet(MacAddr::new([1, 2, 3, 4, 5, 6])).len(), 102);
}

#[test]
fn test_regression_additional_properties_false_enforced_via_mcp() {
    let ctx = offline_ctx();
    let mut reg = McpServerRegistry::new(PolicyMode::AllowMutating);
    for a in actions(&ctx) {
        reg.register_action(a);
    }

    // Verify OpenFilesCloseAction inputSchema includes maximum: 4294967295 on file_id
    let tools = reg.list_tools();
    let close_tool = tools
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "lan.openfiles.close")
        .unwrap();
    assert_eq!(
        close_tool["inputSchema"]["properties"]["file_id"]["maximum"],
        4_294_967_295u64
    );

    // Unknown fields must return -32602 INVALID_PARAMS for both dry_run: true and dry_run: false
    for dry_run in [true, false] {
        let wol_err = reg
            .dispatch(
                "lan.wol.send",
                &json!({
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "confirm_destructive": true,
                    "dry_run": dry_run,
                    "unexpected_attacker_field": "payload"
                }),
            )
            .unwrap_err();
        assert_eq!(wol_err.code, JsonRpcError::INVALID_PARAMS);

        let close_err = reg
            .dispatch(
                "lan.openfiles.close",
                &json!({
                    "file_id": 101,
                    "confirm_destructive": true,
                    "dry_run": dry_run,
                    "unexpected_attacker_field": "payload"
                }),
            )
            .unwrap_err();
        assert_eq!(close_err.code, JsonRpcError::INVALID_PARAMS);
    }
}

#[test]
fn test_regression_geoip_and_oui_csv_comments_and_rfc4180_quotes() {
    let geo_csv = "\
# Generated 2026-11-23

cidr,country_code,country_name,asn,org
1.1.1.0/24,KR,\"Korea, Republic of\",AS13335,\"Cloudflare, Inc.\"
198.51.100.0/24,US,\"United States\",AS64512,\"Acme \"\"Lab\"\", Inc.\"
";
    let geo = net2rust_lan::geoip::GeoIpDatabase::from_csv_str(geo_csv).unwrap();
    let info = geo.lookup(std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    assert_eq!(info.country_code, "KR");
    assert_eq!(info.country_name, "Korea, Republic of");
    assert_eq!(info.asn, "AS13335");
    assert_eq!(info.as_org, "Cloudflare, Inc.");

    let escaped = geo.lookup(std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)));
    assert_eq!(escaped.as_org, r#"Acme "Lab", Inc."#);

    assert!(matches!(
        net2rust_lan::geoip::GeoIpDatabase::from_csv_str(
            "cidr,country_code,country_name,asn,org\n1.1.1.0/24,AU,Australia,AS13335,\"Unclosed\n"
        ),
        Err(NetError::ParseError(_))
    ));

    let oui_csv = "\
# OUI DB

prefix,vendor
00:50:56,\"Acme, Inc.\"
AA:BB:CC,\"Cloudflare \"\"Edge\"\", Inc.\"
";
    let oui = net2rust_lan::oui::OuiDatabase::from_csv_str(oui_csv).unwrap();
    assert_eq!(
        oui.lookup(MacAddr::new([0x00, 0x50, 0x56, 0x11, 0x22, 0x33])),
        Some("Acme, Inc.")
    );
    assert_eq!(
        oui.lookup(MacAddr::new([0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33])),
        Some(r#"Cloudflare "Edge", Inc."#)
    );
    assert!(matches!(
        net2rust_lan::oui::OuiDatabase::from_csv_str("prefix,vendor\n00:50:56,\"Unclosed\n"),
        Err(NetError::ParseError(_))
    ));
}
