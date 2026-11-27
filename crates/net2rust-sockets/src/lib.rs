pub mod actions;
pub mod diff;
pub mod etw_decode;
#[cfg(windows)]
pub mod etw_net;
pub mod model;
pub mod offline;
pub mod oui;
pub mod providers;
pub mod schema;
#[cfg(windows)]
pub mod win32_dns;
#[cfg(windows)]
pub mod win32_iphelper;
#[cfg(windows)]
pub mod win32_proc;

use std::sync::Arc;

use guap_mcp::ActionCommand;
use guap_table::TableProvider;
use net2rust_core::{DomainCrateExport, NetContext, ToolCategory, ToolDescriptor};

pub struct SocketsDomain;

impl DomainCrateExport for SocketsDomain {
    fn category() -> ToolCategory {
        ToolCategory::Sockets
    }

    fn tool_descriptors() -> Vec<ToolDescriptor> {
        tool_descriptors()
    }

    fn providers(ctx: &NetContext) -> Vec<Arc<dyn TableProvider>> {
        providers(ctx)
    }

    fn actions(ctx: &NetContext) -> Vec<Arc<dyn ActionCommand>> {
        actions(ctx)
    }
}

pub fn tool_descriptors() -> Vec<ToolDescriptor> {
    schema::all_tool_descriptors()
}

pub fn providers(ctx: &NetContext) -> Vec<Arc<dyn TableProvider>> {
    providers::build_all_providers(ctx)
}

pub fn actions(ctx: &NetContext) -> Vec<Arc<dyn ActionCommand>> {
    actions::build_all_actions(ctx)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use chrono::{TimeZone, Utc};
    use guap_mcp::{ActionRiskLevel, JsonRpcError, McpServerRegistry, PolicyMode};
    use guap_table::{CellValue, ColumnType, CompareOp, FilterExpr, SortDirection, TableQuery};
    use net2rust_core::{NetContext, OfflineConfig};
    use serde_json::json;

    use super::*;
    use crate::diff::{
        AdapterSnapshot, CounterKind, CounterSample, CounterSnapshot, TcpDiffEngine, diff_adapters, diff_counters,
    };
    use crate::etw_decode::{
        DnsLookupCorrelator, KERNEL_NETWORK_GUID_STR, RawEtwRecord, TCPIP_GUID_STR, TcpErrorsCorrelator,
        decode_dns_client, decode_kernel_network, decode_tcpip,
    };
    use crate::model::{
        RawAdapterRow, decode_sockaddr_inet_bytes, decode_tcp4_owner_module_table, decode_tcp6_owner_module_table,
        decode_udp4_owner_module_table, decode_udp6_owner_module_table, filetime_i64_to_utc, parse_reg_dns_list,
        utc_to_filetime_i64,
    };

    struct TempDirGuard(std::path::PathBuf);
    impl TempDirGuard {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("net2rust_sockets_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_domain_export_contract_and_non_colliding_ids() {
        assert_eq!(SocketsDomain::category(), ToolCategory::Sockets);

        let descriptors = SocketsDomain::tool_descriptors();
        assert_eq!(descriptors.len(), 13);

        let expected_ids = [
            "sockets.ports",
            "sockets.tcplog",
            "sockets.live",
            "sockets.app-net",
            "sockets.proc-tcp",
            "sockets.tcp-errors",
            "sockets.dns-log",
            "sockets.counters",
            "sockets.adapter-watch",
            "sockets.interfaces",
            "sockets.routes",
            "sockets.neighbors",
            "sockets.paths",
        ];
        let actual_ids: Vec<&str> = descriptors.iter().map(|d| d.id).collect();
        assert_eq!(actual_ids, expected_ids);

        let ctx = NetContext::offline(OfflineConfig::default());
        let provs = SocketsDomain::providers(&ctx);
        assert_eq!(provs.len(), 13);
        for (p, exp) in provs.iter().zip(expected_ids.iter()) {
            assert_eq!(p.tool_id(), *exp);
            assert!(p.is_read_only());
        }

        let acts = SocketsDomain::actions(&ctx);
        assert_eq!(acts.len(), 3);
        let provider_set: BTreeSet<&str> = expected_ids.into_iter().collect();
        for a in &acts {
            assert_eq!(a.risk_level(), ActionRiskLevel::PrivilegedMutating);
            assert!(
                !provider_set.contains(a.command_id()),
                "action ID {} collides with table provider ID",
                a.command_id()
            );
        }
    }

    #[test]
    fn test_all_13_providers_offline_and_apply_query() {
        let ctx = NetContext::offline(OfflineConfig::default());
        let provs = providers(&ctx);
        assert_eq!(provs.len(), 13);

        for provider in &provs {
            let schema = provider.schema();
            let full = provider.query(&TableQuery::default()).unwrap_or_else(|e| {
                panic!("provider {} failed in offline mode: {e}", provider.tool_id());
            });
            assert!(!full.rows.is_empty(), "provider {} returned 0 rows", provider.tool_id());
            assert_eq!(full.total_rows, full.rows.len());

            for row in &full.rows {
                assert_eq!(
                    row.cells.len(),
                    schema.columns.len(),
                    "row cell count mismatch on {}",
                    provider.tool_id()
                );
            }

            // Test limit + offset + total_rows semantics + column projection
            let first_col_id = schema.columns[0].id.clone();
            let paged = provider
                .query(&TableQuery {
                    columns: Some(vec![first_col_id]),
                    offset: 0,
                    limit: Some(1),
                    ..TableQuery::default()
                })
                .unwrap();
            assert_eq!(paged.rows.len(), 1);
            assert_eq!(paged.total_rows, full.total_rows);
            assert_eq!(paged.schema.columns.len(), 1);
            assert_eq!(paged.rows[0].cells.len(), 1);
        }

        // Verify Duration millisecond scaling on routes & dns-log
        let routes_p = provs.iter().find(|p| p.tool_id() == "sockets.routes").unwrap();
        let routes_data = routes_p.query(&TableQuery::default()).unwrap();
        assert_eq!(routes_data.schema.columns[7].col_type, ColumnType::Duration);
        assert!(matches!(routes_data.rows[0].cells[7], CellValue::Uint(ms) if ms >= 1_000_000));

        // Verify filter + sort on sockets.ports
        let ports_p = provs.iter().find(|p| p.tool_id() == "sockets.ports").unwrap();
        let filtered = ports_p
            .query(&TableQuery {
                filter: Some(FilterExpr::Compare {
                    column: "protocol".to_string(),
                    op: CompareOp::Eq,
                    value: CellValue::Text("TCP".to_string()),
                }),
                sort: vec![(4, SortDirection::Desc)],
                ..TableQuery::default()
            })
            .unwrap();
        assert!(filtered.total_rows >= 2);
        assert!(
            filtered
                .rows
                .iter()
                .all(|r| r.cells[2] == CellValue::Text("TCP".to_string()))
        );

        // Verify sockets.counters wrap-safe DeltaPerSec is populated
        let counters_p = provs.iter().find(|p| p.tool_id() == "sockets.counters").unwrap();
        let counters_data = counters_p.query(&TableQuery::default()).unwrap();
        let ip_rx = counters_data
            .rows
            .iter()
            .find(|r| r.cells[1] == CellValue::Text("IPv4.InReceives".to_string()))
            .unwrap();
        assert_eq!(ip_rx.cells[3], CellValue::Float(50.0));
    }

    #[test]
    fn test_offline_scenarios_empty_access_denied_and_fixture_dir() {
        // 1) access_denied scenario propagates NetError::PermissionDenied
        let denied_ctx = NetContext::offline(OfflineConfig {
            scenario: Some("access_denied".to_string()),
            ..OfflineConfig::default()
        });
        for p in providers(&denied_ctx) {
            let err = p.query(&TableQuery::default()).unwrap_err();
            assert!(
                err.to_string().contains("permission denied"),
                "unexpected error for {}: {err}",
                p.tool_id()
            );
        }

        // 2) empty scenario yields 0 rows without error
        let empty_ctx = NetContext::offline(OfflineConfig {
            scenario: Some("empty".to_string()),
            ..OfflineConfig::default()
        });
        for p in providers(&empty_ctx) {
            let data = p.query(&TableQuery::default()).unwrap();
            assert_eq!(data.total_rows, 0, "expected 0 rows for {}", p.tool_id());
            assert!(data.rows.is_empty());
        }

        // 3) custom fixture_dir + etl_path JSONL injection
        let tmp = TempDirGuard::new("fixture_dir");
        let sockets_dir = tmp.path().join("sockets");
        std::fs::create_dir_all(&sockets_dir).unwrap();
        std::fs::write(
            sockets_dir.join("neighbors.json"),
            r#"[{"interface_index":7,"ip_address":"10.1.2.3","mac_address":"52:54:00:11:22:33","state":"Reachable","is_router":false,"is_unreachable":false}]"#,
        )
        .unwrap();

        let etl_jsonl = tmp.path().join("custom_events.jsonl");
        let rec = RawEtwRecord {
            provider_guid: KERNEL_NETWORK_GUID_STR.to_string(),
            event_id: 42,
            version: 0,
            timestamp_utc: Utc.with_ymd_and_hms(2026, 11, 22, 10, 0, 0).unwrap(),
            header_process_id: 9999,
            activity_id: [0; 16],
            is_64bit: true,
            user_data: {
                let mut d = Vec::new();
                d.extend_from_slice(&4242u32.to_le_bytes());
                d.extend_from_slice(&512u32.to_le_bytes());
                d.extend_from_slice(&[8, 8, 8, 8]);
                d.extend_from_slice(&[10, 0, 0, 5]);
                d.extend_from_slice(&53u16.to_be_bytes());
                d.extend_from_slice(&51000u16.to_be_bytes());
                d.extend_from_slice(&1u32.to_le_bytes());
                d.extend_from_slice(&77u32.to_le_bytes());
                d
            },
        };
        std::fs::write(&etl_jsonl, serde_json::to_string(&rec).unwrap()).unwrap();

        let custom_ctx = NetContext::offline(OfflineConfig {
            fixture_dir: Some(tmp.path().to_path_buf()),
            etl_path: Some(etl_jsonl),
            ..OfflineConfig::default()
        });
        let custom_provs = providers(&custom_ctx);
        let nb = custom_provs
            .iter()
            .find(|p| p.tool_id() == "sockets.neighbors")
            .unwrap()
            .query(&TableQuery::default())
            .unwrap();
        assert_eq!(nb.total_rows, 1);
        assert_eq!(nb.rows[0].cells[1], CellValue::Text("10.1.2.3".to_string()));
        assert!(matches!(&nb.rows[0].cells[5], CellValue::Text(v) if v.contains("QEMU")));

        let live = custom_provs
            .iter()
            .find(|p| p.tool_id() == "sockets.live")
            .unwrap()
            .query(&TableQuery::default())
            .unwrap();
        assert_eq!(live.total_rows, 1);
        assert_eq!(live.rows[0].cells[6], CellValue::Uint(4242));
        assert_eq!(live.rows[0].cells[8], CellValue::Bytes(512));
    }

    #[test]
    fn test_pure_rust_mib_sockaddr_filetime_and_diff_decoders() {
        // SOCKADDR_INET IPv4
        let mut sa4 = [0u8; 28];
        sa4[0..2].copy_from_slice(&2u16.to_le_bytes());
        sa4[2..4].copy_from_slice(&443u16.to_be_bytes());
        sa4[4..8].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(
            decode_sockaddr_inet_bytes(&sa4).unwrap(),
            (IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443)
        );

        // SOCKADDR_INET IPv6
        let mut sa6 = [0u8; 28];
        sa6[0..2].copy_from_slice(&23u16.to_le_bytes());
        sa6[2..4].copy_from_slice(&8443u16.to_be_bytes());
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        sa6[8..24].copy_from_slice(&v6.octets());
        assert_eq!(decode_sockaddr_inet_bytes(&sa6).unwrap(), (IpAddr::V6(v6), 8443));

        // Invalid family
        let mut bad = [0u8; 28];
        bad[0..2].copy_from_slice(&99u16.to_le_bytes());
        assert!(decode_sockaddr_inet_bytes(&bad).is_err());

        // Truncated MIB tables rejected cleanly
        assert!(decode_tcp4_owner_module_table(&[1, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(decode_tcp6_owner_module_table(&[1, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(decode_udp4_owner_module_table(&[1, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(decode_udp6_owner_module_table(&[1, 0, 0, 0, 0, 0, 0, 0]).is_err());

        // FILETIME edge cases
        assert_eq!(filetime_i64_to_utc(0), None);
        assert_eq!(filetime_i64_to_utc(-100), None);
        assert_eq!(filetime_i64_to_utc(10_000_000), None);
        let ts = Utc.with_ymd_and_hms(2026, 11, 20, 12, 34, 56).unwrap();
        assert_eq!(filetime_i64_to_utc(utc_to_filetime_i64(ts)), Some(ts));

        // Registry DNS parser
        assert_eq!(
            parse_reg_dns_list("1.1.1.1, 8.8.8.8  1.1.1.1\t9.9.9.9"),
            vec!["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        );

        // Counter wraparound & gauge
        let mut m0 = std::collections::BTreeMap::new();
        m0.insert(
            ("IPv4".into(), "InReceives".into()),
            CounterSample {
                value: u64::from(u32::MAX - 9),
                kind: CounterKind::Counter32,
            },
        );
        m0.insert(
            ("TCP".into(), "CurrEstab".into()),
            CounterSample {
                value: 20,
                kind: CounterKind::Gauge,
            },
        );
        let mut m1 = std::collections::BTreeMap::new();
        m1.insert(
            ("IPv4".into(), "InReceives".into()),
            CounterSample {
                value: 90,
                kind: CounterKind::Counter32,
            },
        );
        m1.insert(
            ("TCP".into(), "CurrEstab".into()),
            CounterSample {
                value: 15,
                kind: CounterKind::Gauge,
            },
        );
        let c0 = CounterSnapshot {
            captured_at_ns: 1_000_000_000,
            values: m0,
        };
        let c1 = CounterSnapshot {
            captured_at_ns: 3_000_000_000,
            values: m1,
        };
        assert!(diff_counters(None, &c1).iter().all(|r| r.delta_per_sec.is_none()));
        let diffed = diff_counters(Some(&c0), &c1);
        let rx = diffed.iter().find(|r| r.metric_name == "InReceives").unwrap();
        assert_eq!(rx.delta_per_sec, Some(50.0));
        let gauge = diffed.iter().find(|r| r.metric_name == "CurrEstab").unwrap();
        assert_eq!(gauge.delta_per_sec, None);

        // Adapter rates
        let mut a0 = std::collections::BTreeMap::new();
        a0.insert(
            1,
            RawAdapterRow {
                luid: 1,
                interface_index: 1,
                adapter_name: "eth0".into(),
                description: "NIC".into(),
                media_state: "Connected (Up)".into(),
                link_speed: Some(1_000_000_000),
                bytes_sent: 1000,
                bytes_recvd: 2000,
                errors: 0,
                discards: 0,
            },
        );
        let mut a1 = a0.clone();
        a1.get_mut(&1).unwrap().bytes_sent = 3000;
        a1.get_mut(&1).unwrap().bytes_recvd = 6000;
        let ad = diff_adapters(
            Some(&AdapterSnapshot {
                captured_at_ns: 0,
                rows: a0,
            }),
            &AdapterSnapshot {
                captured_at_ns: 2_000_000_000,
                rows: a1,
            },
        );
        assert_eq!(ad[0].rx_rate_bps, Some(2000.0));
        assert_eq!(ad[0].tx_rate_bps, Some(1000.0));

        // Kernel-Network keyword mask matches Microsoft-Windows-Kernel-Network (IPv4=0x10 | IPv6=0x20)
        assert_eq!(crate::providers::KERNEL_NETWORK_KEYWORDS_ALL, 0x30);

        // TcpDiffEngine transitions (including single Close for CLOSED -> absent lifecycle)
        let snaps = offline::load_tcp_snapshots(&OfflineConfig::default()).unwrap();
        let events = TcpDiffEngine::diff_sequence(&snaps);
        assert!(events.iter().any(|e| e.event_type == "Listen"));
        assert!(events.iter().any(|e| e.event_type == "Open"));
        assert!(events.iter().any(|e| e.event_type == "Close"));

        let mut close_engine = TcpDiffEngine::new();
        let key = crate::diff::TcpEndpointKey {
            ip_version: 4,
            local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            local_port: 55000,
            remote_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            remote_port: 8080,
            pid: 1234,
        };
        let mut s1 = std::collections::BTreeMap::new();
        s1.insert(
            key.clone(),
            crate::diff::TcpEndpointState {
                state_code: 5,
                process_name: Some("probe.exe".into()),
            },
        );
        let mut s2 = std::collections::BTreeMap::new();
        s2.insert(
            key.clone(),
            crate::diff::TcpEndpointState {
                state_code: 1, // CLOSED
                process_name: Some("probe.exe".into()),
            },
        );
        let s3 = std::collections::BTreeMap::new();
        assert!(
            close_engine
                .step(&crate::diff::TcpSnapshot {
                    captured_at: Utc::now(),
                    entries: s1,
                })
                .is_empty()
        );
        let ev_close = close_engine.step(&crate::diff::TcpSnapshot {
            captured_at: Utc::now(),
            entries: s2,
        });
        assert_eq!(ev_close.len(), 1);
        assert_eq!(ev_close[0].event_type, "Close");
        let ev_absent = close_engine.step(&crate::diff::TcpSnapshot {
            captured_at: Utc::now(),
            entries: s3,
        });
        assert!(
            ev_absent.is_empty(),
            "must not emit duplicate Close when CLOSED socket disappears in next snapshot"
        );
    }

    #[test]
    fn test_pure_rust_etw_decoders_and_correlators() {
        let cfg = OfflineConfig::default();

        // Kernel-Network
        let kn_recs = offline::load_kernel_network_records(&cfg).unwrap();
        for rec in &kn_recs {
            let ev = decode_kernel_network(rec).unwrap();
            assert_ne!(ev.pid, u32::MAX, "must use UserData[0..4] PID");
            assert!(ev.local_port > 0 && ev.remote_port > 0);
        }

        // Kernel-Network Retransmit (event 14) uses outbound (saddr, sport, daddr, dport) orientation
        let mut retx_data = Vec::new();
        retx_data.extend_from_slice(&777u32.to_le_bytes());
        retx_data.extend_from_slice(&128u32.to_le_bytes());
        retx_data.extend_from_slice(&[93, 184, 216, 34]); // daddr
        retx_data.extend_from_slice(&[10, 0, 0, 2]); // saddr
        retx_data.extend_from_slice(&443u16.to_be_bytes()); // dport
        retx_data.extend_from_slice(&51234u16.to_be_bytes()); // sport
        retx_data.extend_from_slice(&1u32.to_le_bytes());
        retx_data.extend_from_slice(&99u32.to_le_bytes());
        let retx_ev = decode_kernel_network(&RawEtwRecord {
            provider_guid: KERNEL_NETWORK_GUID_STR.to_string(),
            event_id: 14,
            version: 0,
            timestamp_utc: Utc::now(),
            header_process_id: 777,
            activity_id: [0; 16],
            is_64bit: true,
            user_data: retx_data,
        })
        .unwrap();
        assert_eq!(retx_ev.local_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(retx_ev.local_port, 51234);
        assert_eq!(retx_ev.remote_addr, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(retx_ev.remote_port, 443);

        // TCPIP 64-bit TCB correlation + failure decoding
        let tcpip_recs = offline::load_tcpip_records(&cfg).unwrap();
        let mut corr = TcpErrorsCorrelator::default();
        for rec in &tcpip_recs {
            let ev = decode_tcpip(rec).unwrap();
            corr.ingest(&ev);
        }
        let err_entries = corr.into_entries();
        assert_eq!(err_entries.len(), 3);
        assert!(err_entries.iter().any(|e| e.error_status == "Refused"));
        assert!(
            err_entries
                .iter()
                .any(|e| e.error_status == "Timeout" && e.attempt_count >= 2)
        );

        // TCPIP 32-bit pointer layout check
        let mut data32 = Vec::new();
        data32.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // 4-byte TCB
        data32.extend_from_slice(&16u32.to_le_bytes());
        data32.extend_from_slice(&2u16.to_le_bytes());
        data32.extend_from_slice(&50000u16.to_be_bytes());
        data32.extend_from_slice(&[10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        data32.extend_from_slice(&16u32.to_le_bytes());
        data32.extend_from_slice(&2u16.to_le_bytes());
        data32.extend_from_slice(&443u16.to_be_bytes());
        data32.extend_from_slice(&[1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        data32.extend_from_slice(&5u32.to_le_bytes());
        data32.extend_from_slice(&4242u32.to_le_bytes());
        let ev32 = decode_tcpip(&RawEtwRecord {
            provider_guid: TCPIP_GUID_STR.to_string(),
            event_id: 1300,
            version: 0,
            timestamp_utc: Utc::now(),
            header_process_id: 0,
            activity_id: [0; 16],
            is_64bit: false,
            user_data: data32,
        })
        .unwrap();
        assert!(matches!(
            ev32,
            crate::etw_decode::TcpIpEvent::EndpointContext {
                tcb: 0x1234_5678,
                pid: Some(4242),
                ..
            }
        ));

        // DNS-Client UTF-16LE + ActivityId latency
        let (dns_recs, dns_cache) = offline::load_dns_client_records(&cfg).unwrap();
        let mut dns_corr = DnsLookupCorrelator::default();
        for rec in &dns_recs {
            let ev = decode_dns_client(rec).unwrap();
            dns_corr.ingest(&ev);
        }
        dns_corr.merge_cache_entries(&dns_cache, Utc::now());
        let dns_rows = dns_corr.into_entries();
        assert_eq!(dns_rows.len(), 3);
        assert_eq!(dns_rows[0].latency_ms, Some(18));
        assert_eq!(dns_rows[1].status, "NXDOMAIN");
        assert_eq!(dns_rows[1].latency_ms, Some(42));
        assert_eq!(dns_rows[2].status, "CACHED");
    }

    #[test]
    fn test_mutating_actions_validation_dry_run_offline_and_mcp_policy_gate() {
        let isolated_cfg = OfflineConfig {
            scenario: Some("action_mutation_isolation".to_string()),
            ..OfflineConfig::default()
        };
        let ctx = NetContext::offline(isolated_cfg);

        // Register in McpServerRegistry under ReadOnlyOnly first
        let mut ro_registry = McpServerRegistry::new(PolicyMode::ReadOnlyOnly);
        for p in providers(&ctx) {
            ro_registry.register_table(p);
        }
        for a in actions(&ctx) {
            ro_registry.register_action(a);
        }
        let tools_val = ro_registry.list_tools();
        assert_eq!(tools_val.as_array().unwrap().len(), 16);

        let denied = ro_registry
            .dispatch(
                "sockets.ports.close",
                &json!({
                    "local_addr": "192.168.1.50",
                    "local_port": 54321,
                    "remote_addr": "93.184.216.34",
                    "remote_port": 443,
                    "confirm_destructive": true
                }),
            )
            .unwrap_err();
        assert_eq!(denied.code, JsonRpcError::POLICY_DENIED);

        // Now AllowMutating
        let mut rw_registry = McpServerRegistry::new(PolicyMode::AllowMutating);
        for p in providers(&ctx) {
            rw_registry.register_table(p);
        }
        for a in actions(&ctx) {
            rw_registry.register_action(a);
        }

        // Missing confirm_destructive -> -32003
        let unconfirmed = rw_registry
            .dispatch(
                "sockets.ports.close",
                &json!({
                    "local_addr": "192.168.1.50",
                    "local_port": 54321,
                    "remote_addr": "93.184.216.34",
                    "remote_port": 443
                }),
            )
            .unwrap_err();
        assert_eq!(unconfirmed.code, JsonRpcError::POLICY_DENIED);

        // Validation MUST run BEFORE dry_run=true!
        let bad_ipv6_close = rw_registry
            .dispatch(
                "sockets.ports.close",
                &json!({
                    "local_addr": "::1",
                    "local_port": 55100,
                    "remote_addr": "::1",
                    "remote_port": 443,
                    "dry_run": true,
                    "confirm_destructive": true
                }),
            )
            .unwrap_err();
        assert_ne!(bad_ipv6_close.code, JsonRpcError::POLICY_DENIED);
        assert!(bad_ipv6_close.message.contains("IPv4"));

        let bad_family_route = rw_registry
            .dispatch(
                "sockets.routes.add",
                &json!({
                    "destination": "10.20.0.0/16",
                    "next_hop": "fe80::1",
                    "interface_index": 12,
                    "dry_run": true,
                    "confirm_destructive": true
                }),
            )
            .unwrap_err();
        assert_eq!(bad_family_route.code, JsonRpcError::INVALID_PARAMS);

        let missing_iface_route = rw_registry
            .dispatch(
                "sockets.routes.add",
                &json!({
                    "destination": "10.20.0.0/16",
                    "next_hop": "192.168.1.1",
                    "dry_run": true,
                    "confirm_destructive": true
                }),
            )
            .unwrap_err();
        assert_eq!(missing_iface_route.code, JsonRpcError::INVALID_PARAMS);

        // Valid dry_run = true preview (also verifying explicit JSON null for optional fields)
        let dry_route_nulls = rw_registry
            .dispatch(
                "sockets.routes.add",
                &json!({
                    "destination": "10.21.0.0/16",
                    "prefix_length": null,
                    "next_hop": "192.168.1.1",
                    "interface_index": 12,
                    "interface_alias": null,
                    "metric": null,
                    "dry_run": true,
                    "confirm_destructive": true
                }),
            )
            .unwrap();
        assert_eq!(dry_route_nulls["dry_run"], json!(true));
        assert_eq!(dry_route_nulls["route"]["metric"], json!(0));

        // Valid dry_run = true preview
        let dry_close = rw_registry
            .dispatch(
                "sockets.ports.close",
                &json!({
                    "local_addr": "192.168.1.50",
                    "local_port": 54321,
                    "remote_addr": "93.184.216.34",
                    "remote_port": 443,
                    "dry_run": true,
                    "confirm_destructive": true
                }),
            )
            .unwrap();
        assert_eq!(dry_close["dry_run"], json!(true));

        // Actual offline mutations (dry_run = false)
        let close_res = rw_registry
            .dispatch(
                "sockets.ports.close",
                &json!({
                    "local_addr": "192.168.1.50",
                    "local_port": 54321,
                    "remote_addr": "93.184.216.34",
                    "remote_port": 443,
                    "dry_run": false,
                    "confirm_destructive": true
                }),
            )
            .unwrap();
        assert_eq!(close_res["closed"], json!(true));

        let add_res = rw_registry
            .dispatch(
                "sockets.routes.add",
                &json!({
                    "destination": "10.20.0.0/16",
                    "next_hop": "192.168.1.1",
                    "interface_index": 12,
                    "metric": 50,
                    "dry_run": false,
                    "confirm_destructive": true
                }),
            )
            .unwrap();
        assert_eq!(add_res["added"], json!(true));

        let routes_after_add = rw_registry.dispatch("sockets.routes", &json!({})).unwrap();
        assert_eq!(routes_after_add["total_rows"], json!(4));

        let del_res = rw_registry
            .dispatch(
                "sockets.routes.delete",
                &json!({
                    "destination": "10.20.0.0/16",
                    "next_hop": "192.168.1.1",
                    "interface_index": 12,
                    "dry_run": false,
                    "confirm_destructive": true
                }),
            )
            .unwrap();
        assert_eq!(del_res["deleted"], json!(true));

        let routes_after_del = rw_registry.dispatch("sockets.routes", &json!({})).unwrap();
        assert_eq!(routes_after_del["total_rows"], json!(3));
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_mib_struct_layouts_and_live_non_admin_graceful() {
        use std::mem::{offset_of, size_of};
        use std::time::Duration;
        use windows::Win32::NetworkManagement::IpHelper::{
            MIB_TCP6ROW_OWNER_MODULE, MIB_TCP6TABLE_OWNER_MODULE, MIB_TCPROW_OWNER_MODULE, MIB_TCPTABLE_OWNER_MODULE,
            MIB_UDP6ROW_OWNER_MODULE, MIB_UDP6TABLE_OWNER_MODULE, MIB_UDPROW_OWNER_MODULE, MIB_UDPTABLE_OWNER_MODULE,
        };

        assert_eq!(size_of::<MIB_TCPROW_OWNER_MODULE>(), 160);
        assert_eq!(offset_of!(MIB_TCPTABLE_OWNER_MODULE, table), 8);
        assert_eq!(size_of::<MIB_TCP6ROW_OWNER_MODULE>(), 192);
        assert_eq!(offset_of!(MIB_TCP6TABLE_OWNER_MODULE, table), 8);
        assert_eq!(size_of::<MIB_UDPROW_OWNER_MODULE>(), 160);
        assert_eq!(offset_of!(MIB_UDPTABLE_OWNER_MODULE, table), 8);
        assert_eq!(size_of::<MIB_UDP6ROW_OWNER_MODULE>(), 176);
        assert_eq!(offset_of!(MIB_UDP6TABLE_OWNER_MODULE, table), 8);

        // Live queries with short bounded timeout (must never hang or panic)
        let ctx = NetContext::live()
            .with_timeout(Duration::from_millis(120))
            .with_max_rows(Some(25));
        let provs = providers(&ctx);

        for id in [
            "sockets.ports",
            "sockets.proc-tcp",
            "sockets.counters",
            "sockets.adapter-watch",
            "sockets.interfaces",
            "sockets.routes",
            "sockets.neighbors",
            "sockets.paths",
            "sockets.tcplog",
        ] {
            let p = provs.iter().find(|p| p.tool_id() == id).unwrap();
            let res = p.query(&TableQuery::default());
            assert!(res.is_ok(), "live query {id} failed unexpectedly: {:?}", res.err());
        }

        // Second sample on live counters & adapter-watch computes non-null rate/delta columns
        std::thread::sleep(Duration::from_millis(20));
        let counters_p = provs.iter().find(|p| p.tool_id() == "sockets.counters").unwrap();
        let c2 = counters_p.query(&TableQuery::default()).unwrap();
        assert!(c2.rows.iter().any(|r| matches!(r.cells[3], CellValue::Float(_))));

        let adapter_p = provs.iter().find(|p| p.tool_id() == "sockets.adapter-watch").unwrap();
        let a2 = adapter_p.query(&TableQuery::default()).unwrap();
        assert!(a2.rows.iter().any(|r| matches!(r.cells[6], CellValue::Float(_))));

        // Live dry_run=true and IPv6 rejection on mutating actions
        let acts = actions(&ctx);
        let close_act = acts.iter().find(|a| a.command_id() == "sockets.ports.close").unwrap();
        let dry_close = close_act
            .execute(
                &json!({
                    "local_addr": "127.0.0.1",
                    "local_port": 54321,
                    "remote_addr": "127.0.0.1",
                    "remote_port": 443
                }),
                true,
            )
            .unwrap();
        assert_eq!(dry_close["dry_run"], json!(true));
        assert!(
            close_act
                .execute(
                    &json!({
                        "local_addr": "::1",
                        "local_port": 54321,
                        "remote_addr": "::1",
                        "remote_port": 443
                    }),
                    false,
                )
                .is_err()
        );

        // Kernel-Network / TCPIP / DNS-Client ETW tools gracefully either succeed or return PermissionDenied
        for id in [
            "sockets.live",
            "sockets.app-net",
            "sockets.tcp-errors",
            "sockets.dns-log",
        ] {
            let p = provs.iter().find(|p| p.tool_id() == id).unwrap();
            match p.query(&TableQuery::default()) {
                Ok(_) => {}
                Err(e) => {
                    let msg = e.to_string().to_ascii_lowercase();
                    assert!(
                        msg.contains("permission denied") || msg.contains("elevation"),
                        "unexpected non-permission error for {id}: {e}"
                    );
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_live_etw_flush_before_stop_delivers_events() {
        use std::net::{TcpListener, TcpStream, ToSocketAddrs};
        use std::time::{Duration, Instant};

        // Obtain an unused ephemeral loopback port.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let unused_addr = listener.local_addr().unwrap();
        drop(listener);

        let timeout = Duration::from_millis(400);
        let ctx = NetContext::live().with_timeout(timeout);
        let provs = providers(&ctx);

        // 1) Verify capture_provider_window(TCPIP) + sockets.tcp-errors deliver > 0 events in < 2s.
        let stim_tcp_raw = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            let _ = TcpStream::connect_timeout(&unused_addr, Duration::from_millis(180));
        });
        let t0 = Instant::now();
        let tcp_raw_res = crate::etw_net::capture_provider_window(
            "test_tcperr_raw",
            crate::etw_net::tcpip_guid(),
            u64::MAX,
            timeout,
            None,
        );
        let tcp_raw_elapsed = t0.elapsed();
        let _ = stim_tcp_raw.join();
        assert!(
            tcp_raw_elapsed < Duration::from_secs(2),
            "TCPIP capture_provider_window exceeded 2s: {tcp_raw_elapsed:?}"
        );
        match tcp_raw_res {
            Ok(recs) => assert!(
                !recs.is_empty(),
                "capture_provider_window(TCPIP) delivered 0 raw events in 400ms window"
            ),
            Err(net2rust_core::NetError::PermissionDenied(_)) => {}
            Err(e) => panic!("unexpected TCPIP ETW error: {e}"),
        }

        let tcp_err_p = provs.iter().find(|p| p.tool_id() == "sockets.tcp-errors").unwrap();
        let stim_tcp_prov = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            let _ = TcpStream::connect_timeout(&unused_addr, Duration::from_millis(180));
        });
        let t1 = Instant::now();
        let tcp_err_res = tcp_err_p.query(&TableQuery::default());
        let tcp_err_elapsed = t1.elapsed();
        let _ = stim_tcp_prov.join();
        assert!(
            tcp_err_elapsed < Duration::from_secs(2),
            "sockets.tcp-errors exceeded 2s: {tcp_err_elapsed:?}"
        );
        if let Err(e) = tcp_err_res {
            let msg = e.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("permission denied") || msg.contains("elevation"),
                "unexpected sockets.tcp-errors error: {e}"
            );
        }

        // 2) Verify capture_provider_window(DNS-Client) + sockets.dns-log deliver > 0 events in < 2s.
        let stim_dns_raw = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(80));
            let _ = ("etw-live-probe.invalid", 80).to_socket_addrs();
        });
        let t2 = Instant::now();
        let dns_raw_res = crate::etw_net::capture_provider_window(
            "test_dnslog_raw",
            crate::etw_net::dns_client_guid(),
            u64::MAX,
            timeout,
            None,
        );
        let dns_raw_elapsed = t2.elapsed();
        let _ = stim_dns_raw.join();
        assert!(
            dns_raw_elapsed < Duration::from_secs(2),
            "DNS-Client capture_provider_window exceeded 2s: {dns_raw_elapsed:?}"
        );
        match dns_raw_res {
            Ok(recs) => assert!(
                !recs.is_empty(),
                "capture_provider_window(DNS-Client) delivered 0 raw events in 400ms window"
            ),
            Err(net2rust_core::NetError::PermissionDenied(_)) => {}
            Err(e) => panic!("unexpected DNS-Client ETW error: {e}"),
        }

        let dns_log_p = provs.iter().find(|p| p.tool_id() == "sockets.dns-log").unwrap();
        let stim_dns_prov = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(80));
            let _ = ("etw-live-probe-2.invalid", 80).to_socket_addrs();
        });
        let t3 = Instant::now();
        let dns_log_res = dns_log_p.query(&TableQuery::default());
        let dns_log_elapsed = t3.elapsed();
        let _ = stim_dns_prov.join();
        assert!(
            dns_log_elapsed < Duration::from_secs(2),
            "sockets.dns-log exceeded 2s: {dns_log_elapsed:?}"
        );
        match dns_log_res {
            Ok(data) => assert!(
                data.total_rows > 0,
                "sockets.dns-log returned 0 decoded rows under live DNS stimulus in 400ms window"
            ),
            Err(e) => {
                let msg = e.to_string().to_ascii_lowercase();
                assert!(
                    msg.contains("permission denied") || msg.contains("elevation"),
                    "unexpected sockets.dns-log error: {e}"
                );
            }
        }
    }
}
