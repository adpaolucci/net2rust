use std::collections::BTreeSet;

use guap_table::{CellValue, CompareOp, FilterExpr, GetNirQuery, TableQuery};
use net2rust_core::{DomainCrateExport, NetContext, OfflineConfig, ToolCategory};
use net2rust_osint::{OsintDomain, actions, providers, tool_descriptors};

#[test]
fn test_osint_domain_exports_and_schema_parity() {
    let ctx = NetContext::offline(OfflineConfig::default());
    assert_eq!(OsintDomain::category(), ToolCategory::Osint);

    let descriptors = tool_descriptors();
    let provs = providers(&ctx);
    let acts = actions(&ctx);

    assert_eq!(descriptors.len(), 10);
    assert_eq!(provs.len(), 10);
    assert_eq!(acts.len(), 3);

    let expected_ids = [
        "osint.ipnet",
        "osint.whosip",
        "osint.ipoffline",
        "osint.whois-domain",
        "osint.whoiscl",
        "osint.dns",
        "osint.hosting",
        "osint.oui",
        "osint.set-dns",
        "osint.net-profiles",
    ];

    let desc_ids: Vec<&str> = descriptors.iter().map(|d| d.id).collect();
    let prov_ids: Vec<&str> = provs.iter().map(|p| p.tool_id()).collect();
    assert_eq!(desc_ids, expected_ids);
    assert_eq!(prov_ids, expected_ids);

    for (d, p) in descriptors.iter().zip(provs.iter()) {
        assert_eq!(d.category, ToolCategory::Osint);
        assert!(d.read_only);
        assert!(p.is_read_only());
        let schema = p.schema();
        assert_eq!(schema.tool_id, d.id);
        assert!(!schema.columns.is_empty());

        let data = p.query(&TableQuery::default()).expect("offline default query");
        assert!(!data.rows.is_empty(), "provider {} returned 0 default rows", d.id);
        for row in &data.rows {
            assert_eq!(
                row.cells.len(),
                schema.columns.len(),
                "column arity mismatch in {}",
                d.id
            );
        }
    }

    assert!(descriptors[8].has_mutating_action);
    assert!(descriptors[9].has_mutating_action);

    let action_ids: BTreeSet<&str> = acts.iter().map(|a| a.command_id()).collect();
    assert_eq!(
        action_ids,
        BTreeSet::from([
            "osint.set-dns.apply",
            "osint.net-profiles.connect",
            "osint.net-profiles.disconnect"
        ])
    );
}

#[test]
fn test_all_10_providers_filter_sort_projection_and_pagination() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let provs = providers(&ctx);
    let by_id = |id: &str| {
        provs
            .iter()
            .find(|p| p.tool_id() == id)
            .expect("provider exists")
            .as_ref()
    };

    // 1. osint.ipnet targeted lookup + projection
    let ipnet_q = TableQuery {
        filter: Some(FilterExpr::Compare {
            column: "IPAddress".into(),
            op: CompareOp::Eq,
            value: CellValue::Text("8.8.8.8".into()),
        }),
        columns: Some(vec!["IPAddress".into(), "OrgName".into(), "Country".into()]),
        ..Default::default()
    };
    let ipnet_data = by_id("osint.ipnet").query(&ipnet_q).unwrap();
    assert_eq!(ipnet_data.rows.len(), 1);
    assert_eq!(ipnet_data.rows[0].cells[1], CellValue::Text("Google LLC".into()));

    // 2. osint.whosip
    let whosip_q = GetNirQuery {
        filter_expr: Some("IP = 1.1.1.1".into()),
        ..Default::default()
    };
    let whosip_data = whosip_q.execute_provider(by_id("osint.whosip")).unwrap();
    assert_eq!(whosip_data.rows.len(), 1);
    assert_eq!(whosip_data.rows[0].cells[5], CellValue::Text("APNIC".into()));

    // 3. osint.ipoffline
    let ipoff_q = GetNirQuery {
        filter_expr: Some("IPAddress = \"8.8.8.8,193.0.0.1\"".into()),
        ..Default::default()
    };
    let ipoff_data = ipoff_q.execute_provider(by_id("osint.ipoffline")).unwrap();
    assert_eq!(ipoff_data.rows.len(), 2);
    assert_eq!(ipoff_data.rows[0].cells[4], CellValue::Uint(15169));
    assert_eq!(ipoff_data.rows[1].cells[1], CellValue::Text("NL".into()));

    // 4. osint.whois-domain
    let wdom_q = GetNirQuery {
        filter_expr: Some("Domain = example.co.uk".into()),
        ..Default::default()
    };
    let wdom_data = wdom_q.execute_provider(by_id("osint.whois-domain")).unwrap();
    assert_eq!(wdom_data.rows.len(), 1);
    assert!(wdom_data.rows[0].cells[1].to_string().contains("Nominet"));

    // 5. osint.whoiscl
    let wcl_q = GetNirQuery {
        filter_expr: Some("Query = \"8.8.8.8,example.com\"".into()),
        ..Default::default()
    };
    let wcl_data = wcl_q.execute_provider(by_id("osint.whoiscl")).unwrap();
    assert_eq!(wcl_data.rows.len(), 2);

    // 6. osint.dns (directive Domain + preserved RecordType filter!)
    let dns_q = GetNirQuery {
        filter_expr: Some("Domain = example.com AND RecordType = MX".into()),
        ..Default::default()
    };
    let dns_data = dns_q.execute_provider(by_id("osint.dns")).unwrap();
    assert_eq!(dns_data.rows.len(), 1);
    assert_eq!(dns_data.rows[0].cells[1], CellValue::Text("MX".into()));
    assert_eq!(dns_data.rows[0].cells[4], CellValue::Uint(10));

    // 7. osint.hosting
    let host_q = GetNirQuery {
        filter_expr: Some("Domain = example.com".into()),
        ..Default::default()
    };
    let host_data = host_q.execute_provider(by_id("osint.hosting")).unwrap();
    assert_eq!(host_data.rows.len(), 1);
    assert_eq!(host_data.rows[0].cells[1], CellValue::Text("93.184.216.34".into()));

    // 8. osint.oui (directive MACPrefix normalized from full MAC -> 24-bit prefix!)
    let oui_q = GetNirQuery {
        filter_expr: Some("MACPrefix = \"00:50:56:aa:bb:cc\"".into()),
        ..Default::default()
    };
    let oui_data = oui_q.execute_provider(by_id("osint.oui")).unwrap();
    assert_eq!(oui_data.rows.len(), 1);
    assert_eq!(oui_data.rows[0].cells[0], CellValue::Text("00:50:56".into()));
    assert_eq!(oui_data.rows[0].cells[1], CellValue::Text("VMware, Inc.".into()));

    // Pagination + sort on osint.oui default full table
    let paged = by_id("osint.oui")
        .query(&TableQuery {
            offset: 2,
            limit: Some(5),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(paged.rows.len(), 5);
    assert!(paged.total_rows > 10);

    // 9. osint.set-dns
    let sdns_q = GetNirQuery {
        filter_expr: Some("AdapterName = Ethernet".into()),
        ..Default::default()
    };
    let sdns_data = sdns_q.execute_provider(by_id("osint.set-dns")).unwrap();
    assert_eq!(sdns_data.rows.len(), 1);

    // 10. osint.net-profiles
    let nprof_q = GetNirQuery {
        filter_expr: Some("Connected = true".into()),
        ..Default::default()
    };
    let nprof_data = nprof_q.execute_provider(by_id("osint.net-profiles")).unwrap();
    assert_eq!(nprof_data.rows.len(), 1);
    assert_eq!(nprof_data.rows[0].cells[0], CellValue::Text("CorpNet.internal".into()));
}

#[test]
fn test_offline_config_fixture_dir_and_db_path_overrides() {
    let unique = format!(
        "osint_fixture_dir_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let dir = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&dir).unwrap();

    let geo_path = dir.join("geo.csv");
    std::fs::write(&geo_path, "198.51.100.64/26,JP,Japan,AS,64500,FIXTURE-JP-NET\n").unwrap();
    let oui_path = dir.join("oui.csv");
    std::fs::write(&oui_path, "MA-L,DEADBEEF,Fixture Vendor Corp,Tokyo JP\n")
        .or_else(|_| std::fs::write(&oui_path, "MA-L,DEADBE,Fixture Vendor Corp,Tokyo JP\n"))
        .unwrap();
    std::fs::write(&oui_path, "MA-L,DEADBE,Fixture Vendor Corp,Tokyo JP\n").unwrap();
    std::fs::write(dir.join("whoiscl_targets.txt"), "# comment\n8.8.8.8\nexample.org\n").unwrap();

    let ctx = NetContext::offline(OfflineConfig {
        fixture_dir: Some(dir.clone()),
        geoip_db_path: Some(geo_path),
        oui_db_path: Some(oui_path),
        ..Default::default()
    });

    let provs = providers(&ctx);
    let by_id = |id: &str| provs.iter().find(|p| p.tool_id() == id).unwrap().as_ref();

    let geo_res = GetNirQuery {
        filter_expr: Some("IPAddress = 198.51.100.70".into()),
        ..Default::default()
    }
    .execute_provider(by_id("osint.ipoffline"))
    .unwrap();
    assert_eq!(geo_res.rows[0].cells[1], CellValue::Text("JP".into()));
    assert_eq!(geo_res.rows[0].cells[4], CellValue::Uint(64500));

    let oui_res = GetNirQuery {
        filter_expr: Some("MACPrefix = \"de:ad:be:01:02:03\"".into()),
        ..Default::default()
    }
    .execute_provider(by_id("osint.oui"))
    .unwrap();
    assert_eq!(oui_res.rows[0].cells[1], CellValue::Text("Fixture Vendor Corp".into()));

    let wcl_res = by_id("osint.whoiscl").query(&TableQuery::default()).unwrap();
    assert_eq!(wcl_res.rows.len(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_regression_filter_or_and_partial_contains_across_all_8_directive_providers() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let provs = providers(&ctx);
    let by_id = |id: &str| provs.iter().find(|p| p.tool_id() == id).unwrap().as_ref();

    let eq = |col: &str, val: &str| FilterExpr::Compare {
        column: col.into(),
        op: CompareOp::Eq,
        value: CellValue::Text(val.into()),
    };

    // 1. Mixed FilterExpr::Or(directive, non_directive) across ALL 8 directive providers
    let or_cases = [
        (
            "osint.ipnet",
            eq("IPAddress", "8.8.8.8"),
            eq("Country", "AU"),
            "8.8.8.8",
        ),
        ("osint.whosip", eq("IP", "8.8.8.8"), eq("RIR", "APNIC"), "8.8.8.8"),
        (
            "osint.ipoffline",
            eq("IPAddress", "8.8.8.8"),
            eq("CountryCode", "NL"),
            "8.8.8.8",
        ),
        (
            "osint.whois-domain",
            eq("Domain", "example.com"),
            eq("Registrar", "NoSuchRegistrar"),
            "example.com",
        ),
        (
            "osint.whoiscl",
            eq("Query", "8.8.8.8"),
            eq("WhoisServer", "NoSuchServer"),
            "8.8.8.8",
        ),
        (
            "osint.dns",
            eq("Domain", "example.com"),
            eq("Value", "192.0.2.99"),
            "example.com",
        ),
        (
            "osint.hosting",
            eq("Domain", "example.com"),
            eq("Country", "ZZ"),
            "example.com",
        ),
        (
            "osint.oui",
            eq("MACPrefix", "00:50:56"),
            eq("Country", "ZZ"),
            "00:50:56",
        ),
    ];

    for (tool_id, left, right, expected_cell0) in or_cases {
        let res = by_id(tool_id)
            .query(&TableQuery {
                filter: Some(FilterExpr::Or(vec![left, right])),
                ..Default::default()
            })
            .unwrap_or_else(|e| panic!("{tool_id} mixed Or failed: {e}"));
        assert!(
            res.rows
                .iter()
                .any(|r| r.cells[0] == CellValue::Text(expected_cell0.into())),
            "{tool_id} mixed Or dropped left directive target '{expected_cell0}' (got {} rows)",
            res.rows.len()
        );
    }

    // Verify right-hand default rows are ALSO preserved in mixed Or (not dropped!)
    let ipnet_both = by_id("osint.ipnet")
        .query(&TableQuery {
            filter: Some(FilterExpr::Or(vec![eq("IPAddress", "8.8.8.8"), eq("Country", "AU")])),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(ipnet_both.rows.len(), 2);
    assert!(
        ipnet_both
            .rows
            .iter()
            .any(|r| r.cells[0] == CellValue::Text("8.8.8.8".into()))
    );
    assert!(
        ipnet_both
            .rows
            .iter()
            .any(|r| r.cells[0] == CellValue::Text("1.1.1.1".into()))
    );

    // Verify non-default target + default right-hand branch on osint.ipoffline
    let ipoff_non_seed = by_id("osint.ipoffline")
        .query(&TableQuery {
            filter: Some(FilterExpr::Or(vec![
                eq("IPAddress", "4.4.4.4"),
                eq("CountryCode", "NL"),
            ])),
            ..Default::default()
        })
        .unwrap();
    assert!(
        ipoff_non_seed
            .rows
            .iter()
            .any(|r| r.cells[0] == CellValue::Text("4.4.4.4".into()))
    );
    assert!(
        ipoff_non_seed
            .rows
            .iter()
            .any(|r| r.cells[0] == CellValue::Text("193.0.0.1".into()))
    );

    // 2. osint.oui mixed Or with full MAC normalized to 24-bit MACPrefix
    let oui_norm_or = by_id("osint.oui")
        .query(&TableQuery {
            filter: Some(FilterExpr::Or(vec![
                eq("MACPrefix", "00:50:56:aa:bb:cc"),
                eq("Country", "ZZ"),
            ])),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        oui_norm_or
            .rows
            .iter()
            .filter(|r| r.cells[0] == CellValue::Text("00:50:56".into()))
            .count(),
        1
    );

    // 3. Homogeneous Or, And, Not, and osint.dns PTR + Or(RecordType, Value)
    let homo_or = by_id("osint.ipoffline")
        .query(&TableQuery {
            filter: Some(FilterExpr::Or(vec![
                eq("IPAddress", "8.8.8.8"),
                eq("IPAddress", "1.1.1.1"),
            ])),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(homo_or.rows.len(), 2);

    let and_empty = by_id("osint.ipnet")
        .query(&TableQuery {
            filter: Some(FilterExpr::And(vec![eq("IPAddress", "8.8.8.8"), eq("Country", "AU")])),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(and_empty.rows.len(), 0);

    let not_res = by_id("osint.ipnet")
        .query(&TableQuery {
            filter: Some(FilterExpr::Not(Box::new(eq("IPAddress", "8.8.8.8")))),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(not_res.rows.len(), 2);
    assert!(
        !not_res
            .rows
            .iter()
            .any(|r| r.cells[0] == CellValue::Text("8.8.8.8".into()))
    );

    let dns_ptr = by_id("osint.dns")
        .query(&TableQuery {
            filter: Some(eq("Domain", "93.184.216.34")),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(dns_ptr.rows.len(), 1);
    assert_eq!(dns_ptr.rows[0].cells[1], CellValue::Text("PTR".into()));

    let dns_or_rr = by_id("osint.dns")
        .query(&TableQuery {
            filter: Some(FilterExpr::Or(vec![
                eq("RecordType", "MX"),
                eq("Value", "93.184.216.34"),
            ])),
            ..Default::default()
        })
        .unwrap();
    assert!(
        dns_or_rr
            .rows
            .iter()
            .any(|r| r.cells[1] == CellValue::Text("MX".into()))
    );
    assert!(dns_or_rr.rows.iter().any(|r| r.cells[1] == CellValue::Text("A".into())));

    // 4. Partial Contains must evaluate as substring filter over default rows (never fail IP/MAC parse)
    for (tool_id, col, pat, expected_substr) in [
        ("osint.ipoffline", "IPAddress", "8.8", "8.8.8.8"),
        ("osint.ipnet", "IPAddress", "8.8", "8.8.8.8"),
        ("osint.whosip", "IP", "8.8", "8.8.8.8"),
        ("osint.oui", "MACPrefix", "00:50", "00:50:56"),
        ("osint.whois-domain", "Domain", "example", "example.com"),
    ] {
        let partial = by_id(tool_id)
            .query(&TableQuery {
                filter: Some(FilterExpr::Contains {
                    column: Some(col.into()),
                    pattern: pat.into(),
                    case_sensitive: false,
                }),
                ..Default::default()
            })
            .unwrap_or_else(|e| panic!("{tool_id} partial Contains('{pat}') failed: {e}"));
        assert!(
            partial
                .rows
                .iter()
                .any(|r| r.cells[0].to_string().contains(expected_substr)),
            "{tool_id} partial Contains('{pat}') did not match '{expected_substr}'"
        );
    }
}

#[test]
fn test_regression_dns_record_type_dns_server_oui_space_mac_and_contradictory_and() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let provs = providers(&ctx);
    let by_id = |id: &str| provs.iter().find(|p| p.tool_id() == id).unwrap().as_ref();

    let eq = |col: &str, val: &str| FilterExpr::Compare {
        column: col.into(),
        op: CompareOp::Eq,
        value: CellValue::Text(val.into()),
    };

    // 1. osint.dns comma-separated RecordType = "MX, A" returns both MX and A rows
    let dns_multi_rr = by_id("osint.dns")
        .query(&TableQuery {
            filter: Some(FilterExpr::And(vec![
                eq("Domain", "example.com"),
                eq("RecordType", "MX, A"),
            ])),
            ..Default::default()
        })
        .expect("osint.dns RecordType='MX, A' succeeds");
    assert_eq!(dns_multi_rr.rows.len(), 2);
    assert!(
        dns_multi_rr
            .rows
            .iter()
            .any(|r| r.cells[1] == CellValue::Text("MX".into()))
    );
    assert!(
        dns_multi_rr
            .rows
            .iter()
            .any(|r| r.cells[1] == CellValue::Text("A".into()))
    );

    // 2. osint.dns lowercase RecordType = "mx" normalizes to "MX"
    let dns_lower_rr = by_id("osint.dns")
        .query(&TableQuery {
            filter: Some(FilterExpr::And(vec![
                eq("Domain", "example.com"),
                eq("RecordType", "mx"),
            ])),
            ..Default::default()
        })
        .expect("osint.dns RecordType='mx' succeeds");
    assert_eq!(dns_lower_rr.rows.len(), 1);
    assert_eq!(dns_lower_rr.rows[0].cells[1], CellValue::Text("MX".into()));

    // 3. osint.dns Or/And over distinct DnsServer values must evaluate accurately (0 rows on mismatch)
    let dns_or_srv = by_id("osint.dns")
        .query(&TableQuery {
            filter: Some(FilterExpr::Or(vec![
                eq("DnsServer", "8.8.8.8"),
                eq("DnsServer", "9.9.9.9"),
            ])),
            ..Default::default()
        })
        .expect("osint.dns Or(DnsServer) succeeds");
    assert_eq!(dns_or_srv.rows.len(), 0);

    let dns_and_srv = by_id("osint.dns")
        .query(&TableQuery {
            filter: Some(FilterExpr::And(vec![
                eq("DnsServer", "8.8.8.8"),
                eq("DnsServer", "9.9.9.9"),
            ])),
            ..Default::default()
        })
        .expect("osint.dns And(DnsServer) succeeds");
    assert_eq!(dns_and_srv.rows.len(), 0);

    let dns_single_srv = by_id("osint.dns")
        .query(&TableQuery {
            filter: Some(eq("DnsServer", "8.8.8.8")),
            ..Default::default()
        })
        .expect("osint.dns single DnsServer succeeds");
    assert!(!dns_single_srv.rows.is_empty());
    assert!(
        dns_single_srv
            .rows
            .iter()
            .all(|r| r.cells[5] == CellValue::Text("8.8.8.8:53".into()))
    );

    // 4. osint.oui space-separated 12-nibble MAC lookups preserve MA-M / MA-S LPM
    let oui_mam = by_id("osint.oui")
        .query(&TableQuery {
            filter: Some(eq("MACPrefix", "00 55 DA 5A BC DE")),
            ..Default::default()
        })
        .expect("osint.oui space-separated MA-M lookup");
    assert_eq!(oui_mam.rows.len(), 1);
    assert_eq!(oui_mam.rows[0].cells[0], CellValue::Text("00:55:DA:5".into()));
    assert_eq!(oui_mam.rows[0].cells[4], CellValue::Text("MA-M".into()));

    let oui_mas = by_id("osint.oui")
        .query(&TableQuery {
            filter: Some(eq("MACPrefix", "70 B3 D5 1A 20 01")),
            ..Default::default()
        })
        .expect("osint.oui space-separated MA-S lookup");
    assert_eq!(oui_mas.rows.len(), 1);
    assert_eq!(oui_mas.rows[0].cells[0], CellValue::Text("70:B3:D5:1A:2".into()));
    assert_eq!(oui_mas.rows[0].cells[4], CellValue::Text("MA-S".into()));

    // 5. Contradictory same-column FilterExpr::And must return 0 rows instead of union
    for (tool_id, col, val_a, val_b) in [
        ("osint.ipnet", "IPAddress", "8.8.8.8", "1.1.1.1"),
        ("osint.whosip", "IP", "8.8.8.8", "1.1.1.1"),
        ("osint.ipoffline", "IPAddress", "8.8.8.8", "1.1.1.1"),
        ("osint.whois-domain", "Domain", "example.com", "example.org"),
        ("osint.whoiscl", "Query", "8.8.8.8", "example.com"),
        ("osint.hosting", "Domain", "example.com", "example.org"),
        ("osint.oui", "MACPrefix", "00:50:56", "00:00:0C"),
    ] {
        let contra = by_id(tool_id)
            .query(&TableQuery {
                filter: Some(FilterExpr::And(vec![eq(col, val_a), eq(col, val_b)])),
                ..Default::default()
            })
            .unwrap_or_else(|e| panic!("{tool_id} contradictory And failed: {e}"));
        assert_eq!(
            contra.rows.len(),
            0,
            "{tool_id} contradictory And({col}={val_a}, {col}={val_b}) must return 0 rows"
        );
    }

    // Duplicate/alias same-value And still succeeds and returns the 1 matching row
    let same_val_and = by_id("osint.ipnet")
        .query(&TableQuery {
            filter: Some(FilterExpr::And(vec![eq("IPAddress", "8.8.8.8"), eq("IP", "8.8.8.8")])),
            ..Default::default()
        })
        .expect("non-conflicting alias And succeeds");
    assert_eq!(same_val_and.rows.len(), 1);
    assert_eq!(same_val_and.rows[0].cells[0], CellValue::Text("8.8.8.8".into()));
}
