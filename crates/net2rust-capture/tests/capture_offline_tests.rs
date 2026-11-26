use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use guap_table::{CellValue, ColumnType, FilterExpr, SortDirection, TableQuery};
use net2rust_capture::capture::etw_ndis::{
    NDIS_EVENT_ID_PACKET_FRAGMENT, NDIS_PACKET_CAPTURE_GUID_BYTES, SyntheticEtwRecord, decode_ndis_packet_fragment,
    encode_synthetic_etl, parse_synthetic_etl,
};
use net2rust_capture::capture::fixtures::{
    base_timestamp, build_default_ethernet_pcap_bytes, build_default_pcapng_bytes, build_default_synthetic_etl_bytes,
    build_eth_frame, build_ipv4_packet, build_malformed_dns_packets, build_tcp_segment,
};
use net2rust_capture::capture::pcap::{Endianness, encode_pcap_be_ns, encode_pcap_le_us, parse_pcap};
use net2rust_capture::capture::pcapng::{
    BLOCK_EPB, BLOCK_IDB, BLOCK_PB, BLOCK_SHB, BLOCK_SPB, encode_pcapng, parse_pcapng,
};
use net2rust_capture::capture::{CaptureRequest, CapturedPacket, LinkType, MAX_CAPTURE_PACKET_BYTES, capture_packets};
use net2rust_capture::decode::dns_wire::parse_dns_message;
use net2rust_capture::sha256::sha256_hex;
use net2rust_capture::{CaptureDomain, actions, providers, tool_descriptors};
use net2rust_core::{DomainCrateExport, NetContext, NetError, OfflineConfig, ToolCategory};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempPathGuard {
    path: PathBuf,
    is_dir: bool,
}

impl TempPathGuard {
    fn new_file(ext: &str) -> Self {
        let id = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("net2rust_capture_test_{pid}_{id}.{ext}"));
        Self { path, is_dir: false }
    }

    fn new_dir() -> Self {
        let id = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("net2rust_capture_dir_{pid}_{id}"));
        fs::create_dir_all(&path).unwrap();
        Self { path, is_dir: true }
    }
}

impl Drop for TempPathGuard {
    fn drop(&mut self) {
        if self.is_dir {
            let _ = fs::remove_dir_all(&self.path);
        } else {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[test]
fn test_all_11_providers_default_offline_and_query_features() {
    let ctx = NetContext::offline(OfflineConfig::default());
    assert_eq!(CaptureDomain::category(), ToolCategory::Capture);
    assert_eq!(tool_descriptors().len(), 11);
    assert_eq!(providers(&ctx).len(), 11);
    assert!(actions(&ctx).is_empty());

    for prov in providers(&ctx) {
        assert!(prov.is_read_only());
        let full = prov.query(&TableQuery::default()).unwrap();
        assert!(!full.rows.is_empty(), "{} had no rows", prov.tool_id());

        // Check IP/MAC columns strictly use CellValue::Text or CellValue::Null
        for (cidx, col) in full.schema.columns.iter().enumerate() {
            if matches!(col.col_type, ColumnType::IpAddr | ColumnType::MacAddr) {
                for row in &full.rows {
                    assert!(
                        matches!(row.cells[cidx], CellValue::Text(_) | CellValue::Null),
                        "column {} in {} used non-Text cell {:?}",
                        col.id,
                        prov.tool_id(),
                        row.cells[cidx]
                    );
                }
            }
        }

        // Test offset, limit, and column projection
        let first_col = full.schema.columns[0].id.clone();
        let proj = prov
            .query(&TableQuery {
                filter: None,
                sort: vec![(0, SortDirection::Desc)],
                columns: Some(vec![first_col.clone()]),
                offset: 0,
                limit: Some(1),
            })
            .unwrap();
        assert_eq!(proj.schema.columns.len(), 1);
        assert_eq!(proj.schema.columns[0].id, first_col);
        assert!(proj.rows.len() <= 1);
    }

    // Test FilterExpr::Contains on capture.dns
    let dns_prov = providers(&ctx)
        .into_iter()
        .find(|p| p.tool_id() == "capture.dns")
        .unwrap();
    let filtered = dns_prov
        .query(&TableQuery {
            filter: Some(FilterExpr::Contains {
                column: Some("query_name".to_string()),
                pattern: "example.com".to_string(),
                case_sensitive: false,
            }),
            sort: Vec::new(),
            columns: None,
            offset: 0,
            limit: None,
        })
        .unwrap();
    assert!(filtered.rows.len() >= 2);
}

#[test]
fn test_offline_pcap_pcapng_etl_and_fixture_dir_loading() {
    // 1. OfflineConfig.pcap_path (.pcap)
    let pcap_file = TempPathGuard::new_file("pcap");
    fs::write(&pcap_file.path, build_default_ethernet_pcap_bytes()).unwrap();
    let ctx_pcap = NetContext::offline(OfflineConfig {
        pcap_path: Some(pcap_file.path.clone()),
        ..Default::default()
    });
    let sniff_pcap = providers(&ctx_pcap)
        .into_iter()
        .find(|p| p.tool_id() == "capture.sniff")
        .unwrap();
    assert!(!sniff_pcap.query(&TableQuery::default()).unwrap().rows.is_empty());

    // 2. OfflineConfig.pcap_path (.pcapng including RadioTap)
    let pcapng_file = TempPathGuard::new_file("pcapng");
    fs::write(&pcapng_file.path, build_default_pcapng_bytes()).unwrap();
    let ctx_ng = NetContext::offline(OfflineConfig {
        pcap_path: Some(pcapng_file.path.clone()),
        ..Default::default()
    });
    let wifi_ng = providers(&ctx_ng)
        .into_iter()
        .find(|p| p.tool_id() == "capture.wifi-mon")
        .unwrap();
    let wifi_tbl = wifi_ng.query(&TableQuery::default()).unwrap();
    assert_eq!(wifi_tbl.rows.len(), 3);

    // 3. OfflineConfig.etl_path (synthetic N2RETL1\0)
    let etl_file = TempPathGuard::new_file("etl");
    fs::write(&etl_file.path, build_default_synthetic_etl_bytes()).unwrap();
    let ctx_etl = NetContext::offline(OfflineConfig {
        etl_path: Some(etl_file.path.clone()),
        ..Default::default()
    });
    let dns_etl = providers(&ctx_etl)
        .into_iter()
        .find(|p| p.tool_id() == "capture.dns")
        .unwrap();
    assert!(!dns_etl.query(&TableQuery::default()).unwrap().rows.is_empty());

    // 4. OfflineConfig.fixture_dir
    let dir = TempPathGuard::new_dir();
    fs::write(dir.path.join("capture.pcapng"), build_default_pcapng_bytes()).unwrap();
    let ctx_dir = NetContext::offline(OfflineConfig {
        fixture_dir: Some(dir.path.clone()),
        ..Default::default()
    });
    let pkts = capture_packets(&ctx_dir, &CaptureRequest::default()).unwrap();
    assert!(pkts.len() >= 15);
}

#[test]
fn test_pcap_all_linktypes_endianness_and_bounds_errors() {
    let all_links = [
        LinkType::Null,
        LinkType::Ethernet,
        LinkType::RawIp,
        LinkType::Ieee80211,
        LinkType::Ieee80211Radiotap,
        LinkType::Ipv4,
        LinkType::Ipv6,
    ];
    for link in all_links {
        let pkt = CapturedPacket {
            packet_no: 1,
            timestamp: Some(base_timestamp()),
            link_type: link,
            original_len: 4,
            interface_id: None,
            interface_name: None,
            data: vec![0x45, 0x00, 0x00, 0x14],
        };
        let le = encode_pcap_le_us(link, std::slice::from_ref(&pkt));
        let (hdr, pkts) = parse_pcap(&le).unwrap();
        assert_eq!(hdr.link_type, link);
        assert_eq!(pkts.len(), 1);

        let be = encode_pcap_be_ns(link, std::slice::from_ref(&pkt));
        let (hdr_be, pkts_be) = parse_pcap(&be).unwrap();
        assert_eq!(hdr_be.link_type, link);
        assert_eq!(pkts_be.len(), 1);
    }

    // Bounds: incl_len > MAX_CAPTURE_PACKET_BYTES
    let mut oom_pcap = encode_pcap_le_us(
        LinkType::Ethernet,
        &[CapturedPacket {
            packet_no: 1,
            timestamp: None,
            link_type: LinkType::Ethernet,
            original_len: 4,
            interface_id: None,
            interface_name: None,
            data: vec![1, 2, 3, 4],
        }],
    );
    let huge = (MAX_CAPTURE_PACKET_BYTES as u32) + 1;
    oom_pcap[32..36].copy_from_slice(&huge.to_le_bytes());
    assert!(matches!(parse_pcap(&oom_pcap), Err(NetError::ParseError(_))));

    // Bounds: incl_len > snaplen (snaplen = 2, incl_len = 4)
    let mut snap_err = oom_pcap;
    snap_err[16..20].copy_from_slice(&2u32.to_le_bytes());
    snap_err[32..36].copy_from_slice(&4u32.to_le_bytes());
    assert!(matches!(parse_pcap(&snap_err), Err(NetError::ParseError(_))));
}

#[test]
fn test_pcapng_spb_pb_unknown_block_and_if_tsresol() {
    // Build custom LE PCAPNG containing SHB + IDB (with if_tsoffset & binary if_tsresol) + Unknown block + SPB + PB + EPB
    let mut stream = Vec::new();
    let push_block = |out: &mut Vec<u8>, btype: u32, body: &[u8]| {
        let len = (12 + body.len()) as u32;
        out.extend_from_slice(&btype.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(&len.to_le_bytes());
    };

    // SHB
    let mut shb = Vec::new();
    shb.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
    push_block(&mut stream, BLOCK_SHB, &shb);

    // IDB with if_tsresol=9 (ns) and if_tsoffset=+100s
    let mut idb = Vec::new();
    idb.extend_from_slice(&1u16.to_le_bytes()); // Ethernet
    idb.extend_from_slice(&0u16.to_le_bytes());
    idb.extend_from_slice(&65535u32.to_le_bytes());
    idb.extend_from_slice(&9u16.to_le_bytes());
    idb.extend_from_slice(&1u16.to_le_bytes());
    idb.extend_from_slice(&[9, 0, 0, 0]);
    idb.extend_from_slice(&14u16.to_le_bytes());
    idb.extend_from_slice(&8u16.to_le_bytes());
    idb.extend_from_slice(&100i64.to_le_bytes());
    idb.extend_from_slice(&0u32.to_le_bytes());
    push_block(&mut stream, BLOCK_IDB, &idb);

    // Unknown custom block (0x0BAD_0001)
    push_block(&mut stream, 0x0BAD_0001, &[1, 2, 3, 4, 5, 6, 7, 8]);

    // SPB (4-byte orig_len + 4-byte padded data)
    let mut spb = Vec::new();
    spb.extend_from_slice(&4u32.to_le_bytes());
    spb.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    push_block(&mut stream, BLOCK_SPB, &spb);

    // Obsolete PB
    let mut pb = Vec::new();
    pb.extend_from_slice(&0u16.to_le_bytes());
    pb.extend_from_slice(&0u16.to_le_bytes());
    pb.extend_from_slice(&0u32.to_le_bytes());
    pb.extend_from_slice(&1_000_000u32.to_le_bytes());
    pb.extend_from_slice(&4u32.to_le_bytes());
    pb.extend_from_slice(&4u32.to_le_bytes());
    pb.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    push_block(&mut stream, BLOCK_PB, &pb);

    // EPB
    let mut epb = Vec::new();
    epb.extend_from_slice(&0u32.to_le_bytes());
    epb.extend_from_slice(&0u32.to_le_bytes());
    epb.extend_from_slice(&2_000_000_000u32.to_le_bytes());
    epb.extend_from_slice(&4u32.to_le_bytes());
    epb.extend_from_slice(&4u32.to_le_bytes());
    epb.extend_from_slice(&[0x55, 0x66, 0x77, 0x88]);
    push_block(&mut stream, BLOCK_EPB, &epb);

    let pkts = parse_pcapng(&stream).unwrap();
    assert_eq!(pkts.len(), 3);
    assert_eq!(pkts[0].data, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(pkts[1].data, vec![0x11, 0x22, 0x33, 0x44]);
    assert_eq!(pkts[2].data, vec![0x55, 0x66, 0x77, 0x88]);
    // EPB timestamp = 2s + 100s offset = 102s
    assert_eq!(pkts[2].timestamp.unwrap().timestamp(), 102);

    // Also test Big Endian PCAPNG roundtrip
    let be = encode_pcapng(&[(LinkType::Ethernet, "eth0", 6)], &pkts, Endianness::Big);
    assert_eq!(parse_pcapng(&be).unwrap().len(), 3);
}

#[test]
fn test_dns_compression_pointer_loop_and_malformed_table_rows() {
    let malformed = build_malformed_dns_packets();
    // Direct wire checks must fail immediately without hang
    for pkt in &malformed {
        let udp_payload = &pkt.data[14 + 20 + 8..];
        assert!(matches!(
            parse_dns_message(udp_payload, false),
            Err(NetError::ParseError(_))
        ));
    }

    // End-to-end via capture.dns scenario="malformed-dns"
    let ctx = NetContext::offline(OfflineConfig {
        scenario: Some("malformed-dns".to_string()),
        ..Default::default()
    });
    let dns_prov = providers(&ctx)
        .into_iter()
        .find(|p| p.tool_id() == "capture.dns")
        .unwrap();
    let tbl = dns_prov.query(&TableQuery::default()).unwrap();
    assert_eq!(tbl.rows.len(), 2);
    for row in &tbl.rows {
        assert_eq!(row.cells[4], CellValue::Text("MALFORMED".to_string()));
    }
}

#[test]
fn test_latency_karns_retransmission_exclusion() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let lat_prov = providers(&ctx)
        .into_iter()
        .find(|p| p.tool_id() == "capture.latency")
        .unwrap();
    let tbl = lat_prov.query(&TableQuery::default()).unwrap();
    // 2 valid handshakes (port 80: 12.5ms, port 443: 20.0ms); retransmitted SYN on 198.51.100.77:8443 excluded!
    assert_eq!(tbl.rows.len(), 2);
    for row in &tbl.rows {
        assert_ne!(row.cells[1], CellValue::Text("198.51.100.77".to_string()));
        assert_ne!(row.cells[2], CellValue::Uint(8443));
    }
    let port80 = tbl.rows.iter().find(|r| r.cells[2] == CellValue::Uint(80)).unwrap();
    assert_eq!(port80.cells[4], CellValue::Float(12.5));
    let port443 = tbl.rows.iter().find(|r| r.cells[2] == CellValue::Uint(443)).unwrap();
    assert_eq!(port443.cells[4], CellValue::Float(20.0));
}

#[test]
fn test_website_virtual_saved_path_and_sha256_digest() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let web_prov = providers(&ctx)
        .into_iter()
        .find(|p| p.tool_id() == "capture.website")
        .unwrap();
    let tbl = web_prov.query(&TableQuery::default()).unwrap();
    assert_eq!(tbl.rows.len(), 2);

    let js_row = &tbl.rows[0];
    assert_eq!(js_row.cells[4], CellValue::Bytes(19)); // "console.log(\"ok\");\n"
    assert!(matches!(&js_row.cells[6], CellValue::Text(s) if s == "virtual://cdn.example.com/assets/app.js"));
    let expected_hash = sha256_hex(b"console.log(\"ok\");\n");
    assert_eq!(js_row.detail_json.as_ref().unwrap()["sha256"], expected_hash);

    let html_row = &tbl.rows[1];
    assert!(matches!(&html_row.cells[6], CellValue::Text(s) if s == "virtual://cdn.example.com/index.html"));
    assert!(html_row.raw_bytes.is_some());
}

#[test]
fn test_wifi_mon_and_whois_lan_and_mdns_and_dhcp() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let provs = providers(&ctx);

    let wifi = provs.iter().find(|p| p.tool_id() == "capture.wifi-mon").unwrap();
    let wifi_tbl = wifi.query(&TableQuery::default()).unwrap();
    assert_eq!(wifi_tbl.rows.len(), 3);
    assert!(
        wifi_tbl
            .rows
            .iter()
            .any(|r| r.cells[0] == CellValue::Text("CorpGuest".to_string()))
    );
    assert!(
        wifi_tbl
            .rows
            .iter()
            .any(|r| r.cells[5] == CellValue::Text("802.11ax (HE)".to_string()))
    );

    let whois = provs.iter().find(|p| p.tool_id() == "capture.whois-lan").unwrap();
    let whois_tbl = whois.query(&TableQuery::default()).unwrap();
    assert!(whois_tbl.rows.len() >= 3);
    assert!(
        whois_tbl
            .rows
            .iter()
            .any(|r| r.cells[3] == CellValue::Text("Oracle VirtualBox".to_string()))
    );

    let mdns = provs.iter().find(|p| p.tool_id() == "capture.mdns").unwrap();
    let mdns_tbl = mdns.query(&TableQuery::default()).unwrap();
    assert!(!mdns_tbl.rows.is_empty());
    assert!(mdns_tbl.rows.iter().any(
        |r| r.cells[1] == CellValue::Text("Office Printer._ipp._tcp.local".to_string())
            && r.cells[5] == CellValue::Uint(631)
    ));

    let dhcp = provs.iter().find(|p| p.tool_id() == "capture.dhcp").unwrap();
    let dhcp_tbl = dhcp.query(&TableQuery::default()).unwrap();
    assert_eq!(dhcp_tbl.rows.len(), 2);
}

#[test]
fn test_etw_and_npcap_graceful_live_fallbacks() {
    // 1. Live wifi-mon with allow_npcap=false must gracefully return DriverUnavailable (via TableError::Provider)
    let no_npcap_live = NetContext::live()
        .with_allow_npcap(false)
        .with_timeout(Duration::from_millis(80));
    let wifi = providers(&no_npcap_live)
        .into_iter()
        .find(|p| p.tool_id() == "capture.wifi-mon")
        .unwrap();
    let err = wifi.query(&TableQuery::default()).unwrap_err();
    assert!(err.to_string().contains("Npcap") || err.to_string().contains("disabled"));

    // 2. probe_npcap() never panics (either loads wpcap.dll or returns DriverUnavailable)
    match net2rust_capture::capture::wpcap::probe_npcap() {
        Ok(_) => {}
        Err(NetError::DriverUnavailable(_)) => {}
        Err(other) => panic!("unexpected probe_npcap error: {other}"),
    }

    // 3. Live capture_packets with allow_npcap=false either captures (if elevated) or returns structured NetError
    let res = capture_packets(&no_npcap_live, &CaptureRequest::default());
    match res {
        Ok(_) => {}
        Err(NetError::PermissionDenied(_)) | Err(NetError::DriverUnavailable(_)) | Err(NetError::NotSupported(_)) => {}
        Err(other) => panic!("unexpected live capture error: {other}"),
    }

    // 4. Synthetic ETL truncation test
    let rec = SyntheticEtwRecord {
        provider_guid: NDIS_PACKET_CAPTURE_GUID_BYTES,
        event_id: NDIS_EVENT_ID_PACKET_FRAGMENT,
        timestamp_filetime: 134_000_000_000_000_000,
        user_data: vec![1, 0, 0, 0, 1, 0, 0, 0, 50, 0, 0, 0, 1, 2, 3],
    };
    let bad_etl = encode_synthetic_etl(&[rec]);
    assert!(matches!(parse_synthetic_etl(&bad_etl), Err(NetError::ParseError(_))));
    assert!(matches!(
        decode_ndis_packet_fragment(NDIS_EVENT_ID_PACKET_FRAGMENT, 0, &[0u8; 4], 1),
        Err(NetError::ParseError(_))
    ));
}

#[test]
fn test_pipelined_head_and_chunked_overflow_via_http_and_website() {
    let t0 = base_timestamp();
    let cmac = [0x08, 0x00, 0x27, 0x11, 0x22, 0x33];
    let smac = [0x00, 0x50, 0x56, 0xaa, 0xbb, 0xcc];
    let cip = Ipv4Addr::new(192, 168, 1, 25);
    let sip = Ipv4Addr::new(93, 184, 216, 34);

    let req_pipe = b"HEAD /big.bin HTTP/1.1\r\nHost: pipe.example.com\r\n\r\nGET /after-head.txt HTTP/1.1\r\nHost: pipe.example.com\r\n\r\n";
    let resp_pipe = b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\nContent-Type: application/octet-stream\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello";

    // Also include a separate connection with a crafted chunked overflow payload
    let req_bad = b"GET /bad HTTP/1.1\r\nHost: bad.example.com\r\n\r\n";
    let resp_bad = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffed\r\nAAAA";

    let mut pkts = Vec::new();
    let mut push = |offset_ms: i64, src: Ipv4Addr, dst: Ipv4Addr, sp: u16, dp: u16, seq: u32, payload: &[u8]| {
        let (dmac, sm) = if src == cip { (smac, cmac) } else { (cmac, smac) };
        let frame = build_eth_frame(
            dmac,
            sm,
            0x0800,
            None,
            &build_ipv4_packet(src, dst, 6, &build_tcp_segment(sp, dp, seq, 1, 0x18, payload)),
        );
        pkts.push(CapturedPacket {
            packet_no: (pkts.len() + 1) as u64,
            timestamp: Some(t0 + ChronoDuration::milliseconds(offset_ms)),
            link_type: LinkType::Ethernet,
            original_len: frame.len() as u32,
            interface_id: Some(0),
            interface_name: Some("eth0".to_string()),
            data: frame,
        });
    };

    push(0, cip, sip, 55001, 80, 100, req_pipe);
    push(5, sip, cip, 80, 55001, 200, resp_pipe);
    push(10, cip, sip, 55002, 80, 100, req_bad);
    push(15, sip, cip, 80, 55002, 200, resp_bad);

    let pcap_file = TempPathGuard::new_file("pcap");
    fs::write(&pcap_file.path, encode_pcap_le_us(LinkType::Ethernet, &pkts)).unwrap();
    let ctx = NetContext::offline(OfflineConfig {
        pcap_path: Some(pcap_file.path.clone()),
        ..Default::default()
    });
    let provs = providers(&ctx);

    let http_tbl = provs
        .iter()
        .find(|p| p.tool_id() == "capture.http")
        .unwrap()
        .query(&TableQuery::default())
        .unwrap();
    let after_head = http_tbl
        .rows
        .iter()
        .find(|r| r.cells[3] == CellValue::Text("/after-head.txt".to_string()))
        .expect("missing pipelined GET /after-head.txt row");
    assert_eq!(after_head.cells[4], CellValue::Uint(200));
    assert_eq!(after_head.cells[6], CellValue::Bytes(5));

    let web_tbl = provs
        .iter()
        .find(|p| p.tool_id() == "capture.website")
        .unwrap()
        .query(&TableQuery::default())
        .unwrap();
    let web_after = web_tbl
        .rows
        .iter()
        .find(|r| r.cells[6] == CellValue::Text("virtual://pipe.example.com/after-head.txt".to_string()))
        .expect("missing website /after-head.txt row");
    assert_eq!(web_after.cells[4], CellValue::Bytes(5));
    assert_eq!(web_after.cells[5], CellValue::Uint(200));
    assert_eq!(web_after.detail_json.as_ref().unwrap()["sha256"], sha256_hex(b"hello"));
}

#[test]
fn test_pcapng_high_ts_resol_and_dns_tcp_per_frame_timestamps() {
    let t0 = base_timestamp();
    let pkt = CapturedPacket {
        packet_no: 1,
        timestamp: Some(t0),
        link_type: LinkType::Ethernet,
        original_len: 4,
        interface_id: Some(0),
        interface_name: Some("eth0".to_string()),
        data: vec![1, 2, 3, 4],
    };
    for resol in [12u8, 50u8] {
        let encoded = encode_pcapng(
            &[(LinkType::Ethernet, "eth0", resol)],
            std::slice::from_ref(&pkt),
            Endianness::Little,
        );
        assert_eq!(parse_pcapng(&encoded).unwrap().len(), 1);
    }

    // DNS-over-TCP with SYN at t0, query 1 at t0 + 20ms, query 2 at t0 + 80ms
    let cmac = [0x08, 0x00, 0x27, 0x11, 0x22, 0x33];
    let dmac = [0x00, 0x50, 0x56, 0xaa, 0xbb, 0xcc];
    let cip = Ipv4Addr::new(192, 168, 1, 25);
    let dip = Ipv4Addr::new(8, 8, 8, 8);

    let build_tcp_dns_query = |tx_id: u16, label: &[u8]| -> Vec<u8> {
        let mut dns = Vec::new();
        dns.extend_from_slice(&tx_id.to_be_bytes());
        dns.extend_from_slice(&0x0100u16.to_be_bytes());
        dns.extend_from_slice(&1u16.to_be_bytes());
        dns.extend_from_slice(&[0u8; 6]);
        dns.push(label.len() as u8);
        dns.extend_from_slice(label);
        dns.extend_from_slice(&[3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        let mut framed = (dns.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&dns);
        framed
    };

    let q1 = build_tcp_dns_query(0x1111, b"first");
    let q2 = build_tcp_dns_query(0x2222, b"second");

    let mut pkts = Vec::new();
    let mut push_c = |offset_ms: i64, seq: u32, flags: u16, payload: &[u8]| {
        let frame = build_eth_frame(
            dmac,
            cmac,
            0x0800,
            None,
            &build_ipv4_packet(cip, dip, 6, &build_tcp_segment(56000, 53, seq, 1, flags, payload)),
        );
        pkts.push(CapturedPacket {
            packet_no: (pkts.len() + 1) as u64,
            timestamp: Some(t0 + ChronoDuration::milliseconds(offset_ms)),
            link_type: LinkType::Ethernet,
            original_len: frame.len() as u32,
            interface_id: Some(0),
            interface_name: Some("eth0".to_string()),
            data: frame,
        });
    };

    push_c(0, 999, 0x0002, b""); // SYN at t0 + 0ms
    push_c(20, 1000, 0x0018, &q1); // Frame 1 at t0 + 20ms
    push_c(80, 1000 + q1.len() as u32, 0x0018, &q2); // Frame 2 at t0 + 80ms

    let pcap_file = TempPathGuard::new_file("pcap");
    fs::write(&pcap_file.path, encode_pcap_le_us(LinkType::Ethernet, &pkts)).unwrap();
    let ctx = NetContext::offline(OfflineConfig {
        pcap_path: Some(pcap_file.path.clone()),
        ..Default::default()
    });
    let dns_tbl = providers(&ctx)
        .into_iter()
        .find(|p| p.tool_id() == "capture.dns")
        .unwrap()
        .query(&TableQuery::default())
        .unwrap();
    assert_eq!(dns_tbl.rows.len(), 2);
    assert_eq!(
        dns_tbl.rows[0].cells[0],
        CellValue::Timestamp(t0 + ChronoDuration::milliseconds(20))
    );
    assert_eq!(
        dns_tbl.rows[1].cells[0],
        CellValue::Timestamp(t0 + ChronoDuration::milliseconds(80))
    );
}

#[test]
fn test_pipelined_head_followed_by_get_with_100_continue_and_multi_1xx() {
    let t0 = base_timestamp();
    let cmac = [0x08, 0x00, 0x27, 0x11, 0x22, 0x33];
    let smac = [0x00, 0x50, 0x56, 0xaa, 0xbb, 0xcc];
    let cip = Ipv4Addr::new(192, 168, 1, 25);
    let sip = Ipv4Addr::new(93, 184, 216, 34);

    // 1. Exact Challenger 2 Defect A scenario: HEAD /big.bin (CL 5000) + GET /after-head.txt (100 Continue + 200 OK "hello")
    let req_pipe = b"HEAD /big.bin HTTP/1.1\r\nHost: pipe1xx.example.com\r\n\r\nGET /after-head.txt HTTP/1.1\r\nHost: pipe1xx.example.com\r\n\r\n";
    let resp_pipe = b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\nContent-Type: application/octet-stream\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello";

    // 2. Multi-1xx (103 Early Hints + 100 Continue + 200 OK "world")
    let req_multi = b"GET /multi-1xx.txt HTTP/1.1\r\nHost: multi1xx.example.com\r\n\r\n";
    let resp_multi = b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nworld";

    let mut pkts = Vec::new();
    let mut push = |offset_ms: i64, src: Ipv4Addr, dst: Ipv4Addr, sp: u16, dp: u16, seq: u32, payload: &[u8]| {
        let (dmac, sm) = if src == cip { (smac, cmac) } else { (cmac, smac) };
        let frame = build_eth_frame(
            dmac,
            sm,
            0x0800,
            None,
            &build_ipv4_packet(src, dst, 6, &build_tcp_segment(sp, dp, seq, 1, 0x18, payload)),
        );
        pkts.push(CapturedPacket {
            packet_no: (pkts.len() + 1) as u64,
            timestamp: Some(t0 + ChronoDuration::milliseconds(offset_ms)),
            link_type: LinkType::Ethernet,
            original_len: frame.len() as u32,
            interface_id: Some(0),
            interface_name: Some("eth0".to_string()),
            data: frame,
        });
    };

    push(0, cip, sip, 55101, 80, 100, req_pipe);
    push(5, sip, cip, 80, 55101, 200, resp_pipe);
    push(10, cip, sip, 55102, 80, 100, req_multi);
    push(15, sip, cip, 80, 55102, 200, resp_multi);

    let pcap_file = TempPathGuard::new_file("pcap");
    fs::write(&pcap_file.path, encode_pcap_le_us(LinkType::Ethernet, &pkts)).unwrap();
    let ctx = NetContext::offline(OfflineConfig {
        pcap_path: Some(pcap_file.path.clone()),
        ..Default::default()
    });
    let provs = providers(&ctx);

    let http_tbl = provs
        .iter()
        .find(|p| p.tool_id() == "capture.http")
        .unwrap()
        .query(&TableQuery::default())
        .unwrap();
    assert_eq!(http_tbl.rows.len(), 3);

    let after_head = http_tbl
        .rows
        .iter()
        .find(|r| r.cells[3] == CellValue::Text("/after-head.txt".to_string()))
        .expect("missing pipelined GET /after-head.txt row");
    assert_eq!(after_head.cells[4], CellValue::Uint(200));
    assert_eq!(after_head.cells[6], CellValue::Bytes(5));

    let multi = http_tbl
        .rows
        .iter()
        .find(|r| r.cells[3] == CellValue::Text("/multi-1xx.txt".to_string()))
        .expect("missing GET /multi-1xx.txt row");
    assert_eq!(multi.cells[4], CellValue::Uint(200));
    assert_eq!(multi.cells[6], CellValue::Bytes(5));

    let web_tbl = provs
        .iter()
        .find(|p| p.tool_id() == "capture.website")
        .unwrap()
        .query(&TableQuery::default())
        .unwrap();
    let web_after = web_tbl
        .rows
        .iter()
        .find(|r| r.cells[6] == CellValue::Text("virtual://pipe1xx.example.com/after-head.txt".to_string()))
        .expect("missing website /after-head.txt row");
    assert_eq!(web_after.cells[4], CellValue::Bytes(5));
    assert_eq!(web_after.cells[5], CellValue::Uint(200));
    assert_eq!(web_after.detail_json.as_ref().unwrap()["sha256"], sha256_hex(b"hello"));

    let web_multi = web_tbl
        .rows
        .iter()
        .find(|r| r.cells[6] == CellValue::Text("virtual://multi1xx.example.com/multi-1xx.txt".to_string()))
        .expect("missing website /multi-1xx.txt row");
    assert_eq!(web_multi.cells[4], CellValue::Bytes(5));
    assert_eq!(web_multi.cells[5], CellValue::Uint(200));
    assert_eq!(web_multi.detail_json.as_ref().unwrap()["sha256"], sha256_hex(b"world"));
}
