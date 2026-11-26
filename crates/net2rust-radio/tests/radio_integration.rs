use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use guap_mcp::{McpServerRegistry, McpToolError, PolicyMode};
use guap_table::{CellValue, TableProvider, TableQuery};
use net2rust_core::{DomainCrateExport, FORBIDDEN_WLAN_PROFILE_FLAG, MacAddr, NetContext, OfflineConfig};
use net2rust_radio::backend::{BluetoothClassicDevice, OfflineMockRadioBackend};
use net2rust_radio::ble_ad::{encode_ad_sections, parse_ble_ad};
use net2rust_radio::bt_cod::decode_cod;
use net2rust_radio::bt_lookup::{lookup_company_id, lookup_oui, mac_from_bt_u64};
use net2rust_radio::bt_tools::{BtLogEventType, diff_snapshots, snapshot_from_devices};
use net2rust_radio::ie_parser::parse_ie_stream;
use net2rust_radio::wlan_xml::{parse_wlan_profile_xml, set_connection_mode_xml};
use net2rust_radio::{
    RadioDomain, actions, actions_with_backend, providers, providers_with_backends, tool_descriptors,
};
use serde_json::json;

fn find_provider<'a>(list: &'a [Arc<dyn TableProvider>], tool_id: &str) -> &'a Arc<dyn TableProvider> {
    list.iter()
        .find(|p| p.tool_id() == tool_id)
        .unwrap_or_else(|| panic!("missing provider {tool_id}"))
}

#[test]
fn test_all_10_offline_providers_and_descriptors() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let descs = tool_descriptors();
    assert_eq!(descs.len(), 10);
    assert_eq!(RadioDomain::tool_descriptors(), descs);

    let expected_ids: BTreeSet<&str> = [
        "radio.wifi-info",
        "radio.wifi-scan",
        "radio.wifi-console",
        "radio.wifi-conn",
        "radio.wifi-profiles",
        "radio.wifi-hosted",
        "radio.bt-view",
        "radio.bt-log",
        "radio.bt-cl",
        "radio.ble",
    ]
    .into_iter()
    .collect();

    let actual_desc_ids: BTreeSet<&str> = descs.iter().map(|d| d.id).collect();
    assert_eq!(actual_desc_ids, expected_ids);

    let provs = providers(&ctx);
    assert_eq!(provs.len(), 10);
    let actual_prov_ids: BTreeSet<&str> = provs.iter().map(|p| p.tool_id()).collect();
    assert_eq!(actual_prov_ids, expected_ids);

    for p in &provs {
        assert!(p.is_read_only());
        let data = p.query(&TableQuery::default()).unwrap_or_else(|e| {
            panic!("offline provider {} failed: {e}", p.tool_id());
        });
        assert!(!data.rows.is_empty(), "provider {} returned 0 rows", p.tool_id());
        assert_eq!(data.rows[0].cells.len(), data.schema.columns.len());
        assert!(data.rows[0].detail_json.is_some());
    }

    // Verify raw_bytes on wifi-info (IEs), wifi-profiles (sanitized XML), and ble (AD bytes).
    let wifi_info = find_provider(&provs, "radio.wifi-info")
        .query(&TableQuery::default())
        .unwrap();
    assert!(
        wifi_info
            .rows
            .iter()
            .all(|r| r.raw_bytes.as_ref().is_some_and(|b| !b.is_empty()))
    );

    let profiles = find_provider(&provs, "radio.wifi-profiles")
        .query(&TableQuery::default())
        .unwrap();
    for row in &profiles.rows {
        let xml_bytes = row.raw_bytes.as_ref().expect("profiles must populate raw_bytes");
        let xml_str = std::str::from_utf8(xml_bytes).unwrap();
        assert!(!xml_str.contains("SYNTHETIC-PROTECTED-BLOB"));
        if xml_str.contains("keyMaterial") {
            assert!(xml_str.contains("<keyMaterial>[REDACTED]</keyMaterial>"));
        }
    }

    let ble = find_provider(&provs, "radio.ble")
        .query(&TableQuery::default())
        .unwrap();
    assert!(
        ble.rows
            .iter()
            .all(|r| r.raw_bytes.as_ref().is_some_and(|b| !b.is_empty()))
    );
}

#[test]
fn test_row_limit_and_wifi_scan_detection_counter() {
    let ctx = NetContext::offline(OfflineConfig::default()).with_max_rows(Some(2));
    let provs = providers(&ctx);

    let wifi_info = find_provider(&provs, "radio.wifi-info")
        .query(&TableQuery::default())
        .unwrap();
    assert_eq!(wifi_info.rows.len(), 2);

    let scan_prov = find_provider(&provs, "radio.wifi-scan");
    let first = scan_prov.query(&TableQuery::default()).unwrap();
    let second = scan_prov.query(&TableQuery::default()).unwrap();
    let det_idx = first.schema.column_index("detection_count").unwrap();
    assert_eq!(first.rows[0].cells[det_idx], CellValue::Uint(1));
    assert_eq!(second.rows[0].cells[det_idx], CellValue::Uint(2));
}

#[test]
fn test_mutating_actions_dry_run_and_apply_with_shared_backend() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let shared_backend = Arc::new(OfflineMockRadioBackend::default());
    let provs = providers_with_backends(&ctx, Arc::clone(&shared_backend) as _, Arc::clone(&shared_backend) as _);
    let acts = actions_with_backend(Arc::clone(&shared_backend) as _);
    assert_eq!(acts.len(), 5);

    let act_map: HashMap<&str, _> = acts.iter().map(|a| (a.command_id(), Arc::clone(a))).collect();

    // 1. set-order dry_run vs apply
    let set_order = &act_map["radio.wifi-profiles.set-order"];
    let dry = set_order
        .execute(&json!({ "profile_name": "LabHidden", "position": 0 }), true)
        .unwrap();
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["applied"], false);
    assert!(shared_backend.mutation_log().is_empty());

    let applied = set_order
        .execute(&json!({ "profile_name": "LabHidden", "position": 0 }), false)
        .unwrap();
    assert_eq!(applied["applied"], true);

    let profiles_tbl = find_provider(&provs, "radio.wifi-profiles")
        .query(&TableQuery::default())
        .unwrap();
    assert_eq!(profiles_tbl.rows[0].cells[0], CellValue::Text("LabHidden".to_string()));

    // 2. toggle-auto dry_run vs apply (LabHidden starts as manual -> flips to auto)
    let toggle = &act_map["radio.wifi-profiles.toggle-auto"];
    let toggle_dry = toggle.execute(&json!({ "profile_name": "LabHidden" }), true).unwrap();
    assert_eq!(toggle_dry["preview"]["target_mode"], "auto");

    let toggle_apply = toggle.execute(&json!({ "profile_name": "LabHidden" }), false).unwrap();
    assert_eq!(toggle_apply["result"]["connection_mode"], "auto");

    // 3. delete dry_run vs apply
    let delete = &act_map["radio.wifi-profiles.delete"];
    let del_dry = delete.execute(&json!({ "profile_name": "NextGen-6E" }), true).unwrap();
    assert_eq!(del_dry["applied"], false);
    let del_apply = delete.execute(&json!({ "profile_name": "NextGen-6E" }), false).unwrap();
    assert_eq!(del_apply["result"]["deleted"], true);

    let profiles_after_del = find_provider(&provs, "radio.wifi-profiles")
        .query(&TableQuery::default())
        .unwrap();
    assert_eq!(profiles_after_del.rows.len(), 2);

    // 4. hosted.start & hosted.stop
    let hosted_start = &act_map["radio.wifi-hosted.start"];
    let start_dry = hosted_start
        .execute(&json!({ "ssid": "TestAP", "max_peers": 5 }), true)
        .unwrap();
    assert_eq!(start_dry["dry_run"], true);

    let start_apply = hosted_start
        .execute(&json!({ "ssid": "TestAP", "max_peers": 5 }), false)
        .unwrap();
    assert_eq!(start_apply["result"]["state"], "Active");
    assert_eq!(start_apply["result"]["ssid"], "TestAP");

    let hosted_tbl = find_provider(&provs, "radio.wifi-hosted")
        .query(&TableQuery::default())
        .unwrap();
    assert_eq!(hosted_tbl.rows[0].cells[0], CellValue::Text("TestAP".to_string()));
    assert_eq!(hosted_tbl.rows[0].cells[1], CellValue::Text("Active".to_string()));

    let hosted_stop = &act_map["radio.wifi-hosted.stop"];
    let stop_apply = hosted_stop.execute(&json!({ "force": true }), false).unwrap();
    assert_eq!(stop_apply["result"]["state"], "Idle");

    // 5. Invalid parameters validation
    assert!(matches!(
        set_order.execute(&json!({ "profile_name": "", "position": 0 }), true),
        Err(McpToolError::InvalidParams(_))
    ));
    assert!(matches!(
        hosted_start.execute(&json!({ "max_peers": 101 }), true),
        Err(McpToolError::InvalidParams(_))
    ));
    assert!(matches!(
        hosted_start.execute(&json!({ "ssid": "123456789012345678901234567890123" }), true),
        Err(McpToolError::InvalidParams(_))
    ));
    assert!(matches!(
        delete.execute(&json!({ "profile_name": "DoesNotExist" }), true),
        Err(McpToolError::NotFound(_))
    ));
}

#[test]
fn test_mcp_policy_gate_enforces_readonly_vs_allow_mutating() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let mut ro_registry = McpServerRegistry::new(PolicyMode::ReadOnlyOnly);
    for p in providers(&ctx) {
        ro_registry.register_table(p);
    }
    for a in actions(&ctx) {
        ro_registry.register_action(a);
    }

    let err = ro_registry
        .dispatch(
            "radio.wifi-profiles.set-order",
            &json!({ "profile_name": "CorpNet-5G", "position": 1, "confirm_destructive": true }),
        )
        .unwrap_err();
    assert_eq!(err.code, guap_mcp::JsonRpcError::POLICY_DENIED);

    let mut rw_registry = McpServerRegistry::new(PolicyMode::AllowMutating);
    for a in actions(&ctx) {
        rw_registry.register_action(a);
    }
    // Missing confirm_destructive still denied
    let err2 = rw_registry
        .dispatch(
            "radio.wifi-profiles.delete",
            &json!({ "profile_name": "CorpNet-5G", "dry_run": true }),
        )
        .unwrap_err();
    assert_eq!(err2.code, guap_mcp::JsonRpcError::POLICY_DENIED);

    // With confirm_destructive + dry_run succeeds
    let ok = rw_registry
        .dispatch(
            "radio.wifi-profiles.delete",
            &json!({ "profile_name": "CorpNet-5G", "confirm_destructive": true, "dry_run": true }),
        )
        .unwrap();
    assert_eq!(ok["dry_run"], true);
}

#[test]
fn test_bt_log_offline_and_incremental_diff_snapshots() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let provs = providers(&ctx);
    let bt_log = find_provider(&provs, "radio.bt-log")
        .query(&TableQuery::default())
        .unwrap();
    let ev_idx = bt_log.schema.column_index("event_type").unwrap();
    let types: Vec<&str> = bt_log
        .rows
        .iter()
        .filter_map(|r| match &r.cells[ev_idx] {
            CellValue::Text(s) => Some(s.as_str()),
            _ => None,
        })
        .collect();
    assert!(types.contains(&"Arrived"));
    assert!(types.contains(&"Departed"));

    // Unit snapshot diff check
    let dev_a = BluetoothClassicDevice {
        name: "DevA".to_string(),
        address: MacAddr::new([0x54, 0xB7, 0xE5, 0x01, 0x02, 0x03]),
        class_of_device: 0x240418,
        connected: true,
        remembered: true,
        authenticated: true,
        last_seen: None,
        last_used: None,
    };
    let dev_b = BluetoothClassicDevice {
        name: "DevB".to_string(),
        address: MacAddr::new([0x70, 0x88, 0x6B, 0x04, 0x05, 0x06]),
        class_of_device: 0x002540,
        connected: false,
        remembered: true,
        authenticated: true,
        last_seen: None,
        last_used: None,
    };
    let s1 = snapshot_from_devices(&[dev_a]);
    let s2 = snapshot_from_devices(&[dev_b]);
    let delta = diff_snapshots(&s1, &s2, Utc::now());
    assert_eq!(delta.len(), 2);
    assert!(
        delta
            .iter()
            .any(|e| e.event_type == BtLogEventType::Arrived && e.device_name == "DevB")
    );
    assert!(
        delta
            .iter()
            .any(|e| e.event_type == BtLogEventType::Departed && e.device_name == "DevA")
    );
}

#[test]
fn test_r4_compliance_and_xml_and_parsers_integration() {
    assert_eq!(FORBIDDEN_WLAN_PROFILE_FLAG, 0x0000_0004);
    #[cfg(windows)]
    {
        assert_eq!(net2rust_radio::win32_wlan::WLAN_PROFILE_READ_FLAGS, 0);
        assert_eq!(
            net2rust_radio::win32_wlan::WLAN_PROFILE_READ_FLAGS & FORBIDDEN_WLAN_PROFILE_FLAG,
            0
        );
    }

    let xml = r#"<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"><name>SecNet</name><connectionType>ESS</connectionType><connectionMode>auto</connectionMode><MSM><security><authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption></authEncryption><sharedKey><keyMaterial>DoNotLeakThisSecret</keyMaterial></sharedKey></security></MSM></WLANProfile>"#;
    let meta = parse_wlan_profile_xml(xml).unwrap();
    assert!(!meta.sanitized_xml.contains("DoNotLeakThisSecret"));
    assert!(meta.sanitized_xml.contains("[REDACTED]"));

    let updated = set_connection_mode_xml(xml, false).unwrap();
    assert!(!updated.contains("DoNotLeakThisSecret"));
    assert_eq!(parse_wlan_profile_xml(&updated).unwrap().connection_mode, "manual");

    // Verify CoD, OUI, Company ID, BT MAC, BLE AD, IE parser round-trips
    assert_eq!(decode_cod(0x240418).minor_class, "Headphones");
    assert_eq!(lookup_company_id(0x004C), Some("Apple, Inc."));
    assert_eq!(
        lookup_oui(&MacAddr::new([0x02, 0x00, 0x00, 0x11, 0x22, 0x33])),
        "Locally Administered (Random)"
    );
    assert_eq!(
        mac_from_bt_u64(0x0000_1122_3344_5566),
        MacAddr::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    );

    let ad = encode_ad_sections(&[(0x09, b"Sensor".to_vec()), (0xFF, vec![0x4C, 0x00, 0x01])]);
    let parsed_ad = parse_ble_ad(&ad).unwrap();
    assert_eq!(parsed_ad.local_name.as_deref(), Some("Sensor"));
    assert_eq!(
        parsed_ad.manufacturer_data[0].company_name.as_deref(),
        Some("Apple, Inc.")
    );

    let parsed_ie = parse_ie_stream(&[0, 4, b'T', b'e', b's', b't', 3, 1, 6]);
    assert_eq!(parsed_ie.ssid.as_deref(), Some("Test"));
    assert_eq!(parsed_ie.ds_channel, Some(6));
}

#[test]
fn test_offline_fault_scenarios_return_structured_errors() {
    for scenario in [
        "hardware_absent",
        "permission_denied",
        "driver_unavailable",
        "not_supported",
    ] {
        let ctx = NetContext::offline(OfflineConfig {
            scenario: Some(scenario.to_string()),
            ..Default::default()
        });
        for p in providers(&ctx) {
            let err = p.query(&TableQuery::default()).unwrap_err();
            assert!(!err.to_string().is_empty());
        }
    }
}

#[test]
fn test_live_mode_probe_is_graceful_without_panics() {
    let ctx = NetContext::live().with_timeout(Duration::from_millis(300));
    let provs = providers(&ctx);
    assert_eq!(provs.len(), 10);
    for p in provs {
        // Must either succeed (if hardware/permission available) or return a structured TableError::Provider without panicking.
        let _ = p.query(&TableQuery::default());
    }
}
