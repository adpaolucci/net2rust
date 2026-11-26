use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Duration as ChronoDuration;
use guap_table::{CellValue, Row, TableQuery};
use net2rust_capture::capture::fixtures::{base_timestamp, build_eth_frame, build_ipv4_packet, build_tcp_segment};
use net2rust_capture::capture::pcap::Endianness;
use net2rust_capture::capture::pcap::encode_pcap_le_us;
use net2rust_capture::capture::pcapng::encode_pcapng;
use net2rust_capture::capture::{CapturedPacket, LinkType};
use net2rust_capture::providers;
use net2rust_core::{NetContext, OfflineConfig};

static R4_TMP_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempCaptureFile {
    path: PathBuf,
}

impl TempCaptureFile {
    fn new(ext: &str, bytes: &[u8]) -> Self {
        let id = R4_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("net2rust_r4_test_{}_{id}.{ext}", std::process::id()));
        fs::write(&path, bytes).unwrap();
        Self { path }
    }
}

impl Drop for TempCaptureFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

const FORBIDDEN_SECRETS: &[&str] = &[
    "dXNlcjpzZWNyZXQ=",
    "tok123",
    "secret_api_val",
    "leak123",
    "hunter2",
    "AGFsaWNlAGh1bnRlcjI=",
];

fn assert_row_contains_no_secrets(tool_id: &str, row: &Row) {
    for (idx, cell) in row.cells.iter().enumerate() {
        let text = cell.to_string();
        for secret in FORBIDDEN_SECRETS {
            assert!(
                !text.contains(secret),
                "R4 VIOLATION in {tool_id} row {} cell[{idx}]: leaked '{secret}' in '{text}'",
                row.id
            );
        }
        // Specific cookie values s1, t1, s2
        if tool_id == "capture.cookies" && idx == 3 {
            assert_ne!(text, "s1");
            assert_ne!(text, "t1");
            assert_ne!(text, "s2");
        }
    }

    if let Some(ref detail) = row.detail_json {
        let d_str = detail.to_string();
        for secret in FORBIDDEN_SECRETS {
            assert!(
                !d_str.contains(secret),
                "R4 VIOLATION in {tool_id} row {} detail_json: leaked '{secret}'",
                row.id
            );
        }
        assert!(!d_str.contains("\"s1\""));
        assert!(!d_str.contains("\"t1\""));
        assert!(!d_str.contains("\"s2\""));
    }

    if let Some(ref raw) = row.raw_bytes {
        let raw_lossy = String::from_utf8_lossy(raw);
        for secret in FORBIDDEN_SECRETS {
            assert!(
                !raw_lossy.contains(secret),
                "R4 VIOLATION in {tool_id} row {} raw_bytes: leaked '{secret}'",
                row.id
            );
        }
        assert!(!raw_lossy.contains("JSESSIONID=s1"));
        assert!(!raw_lossy.contains("auth_token=t1"));
        assert!(!raw_lossy.contains("sid=s2"));
    }
}

#[test]
fn test_r4_redaction_across_all_11_tools_and_raw_bytes() {
    let ctx = NetContext::offline(OfflineConfig::default());
    for prov in providers(&ctx) {
        let tbl = prov.query(&TableQuery::default()).unwrap();
        for row in &tbl.rows {
            assert_row_contains_no_secrets(prov.tool_id(), row);
        }
    }

    // Verify capture.http has [REDACTED] in query param and headers
    let http = providers(&ctx)
        .into_iter()
        .find(|p| p.tool_id() == "capture.http")
        .unwrap();
    let http_tbl = http.query(&TableQuery::default()).unwrap();
    let app_js = &http_tbl.rows[0];
    assert_eq!(
        app_js.cells[3],
        CellValue::Text("/assets/app.js?token=[REDACTED]&v=2".to_string())
    );
    assert!(app_js.raw_bytes.is_none(), "sensitive HTTP request must omit raw_bytes");
    let req_hdrs = &app_js.detail_json.as_ref().unwrap()["request_headers"];
    assert_eq!(req_hdrs["Authorization"], "[REDACTED]");
    assert_eq!(req_hdrs["Proxy-Authorization"], "[REDACTED]");
    assert_eq!(req_hdrs["X-Api-Key"], "[REDACTED]");

    // Verify capture.cookies redacts auth cookies while keeping non-auth cookies
    let cookies = providers(&ctx)
        .into_iter()
        .find(|p| p.tool_id() == "capture.cookies")
        .unwrap();
    let ck_tbl = cookies.query(&TableQuery::default()).unwrap();
    assert!(
        ck_tbl
            .rows
            .iter()
            .any(|r| r.cells[2] == CellValue::Text("JSESSIONID".to_string())
                && r.cells[3] == CellValue::Text("[REDACTED]".to_string()))
    );
    assert!(
        ck_tbl
            .rows
            .iter()
            .any(|r| r.cells[2] == CellValue::Text("auth_token".to_string())
                && r.cells[3] == CellValue::Text("[REDACTED]".to_string()))
    );
    assert!(
        ck_tbl
            .rows
            .iter()
            .any(|r| r.cells[2] == CellValue::Text("sid".to_string())
                && r.cells[3] == CellValue::Text("[REDACTED]".to_string()))
    );
    assert!(ck_tbl.rows.iter().any(
        |r| r.cells[2] == CellValue::Text("theme".to_string()) && r.cells[3] == CellValue::Text("dark".to_string())
    ));
    assert!(
        ck_tbl
            .rows
            .iter()
            .any(|r| r.cells[2] == CellValue::Text("prefs".to_string())
                && r.cells[3] == CellValue::Text("compact".to_string()))
    );
}

#[test]
fn test_r4_redaction_holds_even_when_redact_sensitive_headers_is_false() {
    let ctx = NetContext::offline(OfflineConfig::default()).with_redact_sensitive_headers(false);
    for prov in providers(&ctx) {
        let tbl = prov.query(&TableQuery::default()).unwrap();
        for row in &tbl.rows {
            assert_row_contains_no_secrets(prov.tool_id(), row);
        }
    }
}

#[test]
fn test_r4_source_audit_no_forbidden_symbols() {
    fn visit_rs(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit_rs(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    visit_rs(&src_root, &mut files);
    assert!(!files.is_empty());

    let forbidden = [
        "SniffPass",
        "SocketSniff",
        "CreateRemoteThread",
        "WriteProcessMemory",
        "SetWindowsHookEx",
    ];
    for file in files {
        let content = std::fs::read_to_string(&file).unwrap();
        for term in forbidden {
            assert!(
                !content.contains(term),
                "forbidden R4 term '{term}' found in {}",
                file.display()
            );
        }
    }
}

fn build_adversarial_r4_packets() -> Vec<CapturedPacket> {
    let t0 = base_timestamp();
    let cmac = [0x08, 0x00, 0x27, 0x11, 0x22, 0x33];
    let smac = [0x00, 0x50, 0x56, 0xaa, 0xbb, 0xcc];
    let cip = Ipv4Addr::new(192, 168, 1, 25);
    let sip = Ipv4Addr::new(93, 184, 216, 34);
    let mut pkts = Vec::new();

    let mut push_tcp =
        |offset_ms: i64, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, sp: u16, dp: u16, seq: u32, payload: &[u8]| {
            let (dmac, sm) = if src_ip == cip { (smac, cmac) } else { (cmac, smac) };
            let frame = build_eth_frame(
                dmac,
                sm,
                0x0800,
                None,
                &build_ipv4_packet(src_ip, dst_ip, 6, &build_tcp_segment(sp, dp, seq, 1, 0x18, payload)),
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

    // 1. Extended sensitive headers + pwd cookie
    let req1 = b"GET /api/v1/data?safe=1 HTTP/1.1\r\nHost: api.example.com\r\nX-Session-Id: ADV_X_SESS_ID_401\r\nX-Bearer-Token: ADV_X_BEARER_402\r\nApi-Key: ADV_API_KEY_NO_X_403\r\nAuth-Token: ADV_AUTH_TOK_NO_X_404\r\nAccess-Token: ADV_ACCESS_TOK_405\r\nCookie: theme=light; my_pwd=ADV_COOKIE_PWD_S5_301\r\n\r\n";
    let resp1 = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok";
    push_tcp(0, cip, sip, 53001, 80, 1000, req1);
    push_tcp(5, sip, cip, 80, 53001, 1000, resp1);

    // 2. URL userinfo credentials + Referer/Location URL credentials + pwd query
    let req2 = b"GET http://alice:ADV_USERINFO_PASS_501@example.com/admin?pwd=ADV_URL_PWD_502 HTTP/1.1\r\nHost: example.com\r\nReferer: https://bob:ADV_REFERER_PASS_503@example.org/cb?token=ADV_REF_TOK_504\r\n\r\n";
    let resp2 = b"HTTP/1.1 302 Found\r\nLocation: https://carol:ADV_LOC_PASS_505@example.net/next?access_token=ADV_LOC_TOK_506\r\nContent-Length: 9\r\nContent-Type: text/html\r\n\r\nsecretdoc";
    push_tcp(10, cip, sip, 53002, 80, 2000, req2);
    push_tcp(15, sip, cip, 80, 53002, 2000, resp2);

    // 3. Multi-packet cleartext auth initiation + bare continuation on non-standard port 5870
    push_tcp(20, cip, sip, 53004, 5870, 3000, b"AUTH PLAIN\r\n");
    push_tcp(25, sip, cip, 5870, 53004, 3000, b"334 \r\n");
    push_tcp(30, cip, sip, 53004, 5870, 3012, b"ADV_SMTP_CONT_B64_207\r\n");

    pkts
}

#[test]
fn test_r4_adversarial_extended_headers_pwd_cookie_url_userinfo_and_multipacket_auth() {
    let adv_secrets = [
        "ADV_X_SESS_ID_401",
        "ADV_X_BEARER_402",
        "ADV_API_KEY_NO_X_403",
        "ADV_AUTH_TOK_NO_X_404",
        "ADV_ACCESS_TOK_405",
        "ADV_COOKIE_PWD_S5_301",
        "ADV_USERINFO_PASS_501",
        "ADV_URL_PWD_502",
        "ADV_REFERER_PASS_503",
        "ADV_REF_TOK_504",
        "ADV_LOC_PASS_505",
        "ADV_LOC_TOK_506",
        "ADV_SMTP_CONT_B64_207",
    ];

    let pkts = build_adversarial_r4_packets();
    let pcap_file = TempCaptureFile::new("pcap", &encode_pcap_le_us(LinkType::Ethernet, &pkts));
    let pcapng_file = TempCaptureFile::new(
        "pcapng",
        &encode_pcapng(&[(LinkType::Ethernet, "eth0", 6)], &pkts, Endianness::Little),
    );

    for path in [&pcap_file.path, &pcapng_file.path] {
        for redact in [true, false] {
            let ctx = NetContext::offline(OfflineConfig {
                pcap_path: Some(path.clone()),
                ..Default::default()
            })
            .with_redact_sensitive_headers(redact);

            for prov in providers(&ctx) {
                let tbl = prov.query(&TableQuery::default()).unwrap();
                for row in &tbl.rows {
                    for (cidx, cell) in row.cells.iter().enumerate() {
                        let s = cell.to_string();
                        for sec in adv_secrets {
                            assert!(
                                !s.contains(sec),
                                "R4 leak in {} (redact={redact}) row {} cell[{cidx}]: {s}",
                                prov.tool_id(),
                                row.id
                            );
                        }
                    }
                    if let Some(ref dj) = row.detail_json {
                        let ds = dj.to_string();
                        for sec in adv_secrets {
                            assert!(
                                !ds.contains(sec),
                                "R4 leak in {} (redact={redact}) row {} detail_json: {ds}",
                                prov.tool_id(),
                                row.id
                            );
                        }
                    }
                    if let Some(ref rb) = row.raw_bytes {
                        let rs = String::from_utf8_lossy(rb);
                        for sec in adv_secrets {
                            assert!(
                                !rs.contains(sec),
                                "R4 leak in {} (redact={redact}) row {} raw_bytes: {rs}",
                                prov.tool_id(),
                                row.id
                            );
                        }
                    }
                }
            }

            // Specific behavior checks for sniff, http, cookies, website
            let provs = providers(&ctx);
            let sniff_tbl = provs
                .iter()
                .find(|p| p.tool_id() == "capture.sniff")
                .unwrap()
                .query(&TableQuery::default())
                .unwrap();
            let cont_row = sniff_tbl
                .rows
                .iter()
                .find(|r| r.cells[4] == CellValue::Uint(53004) && r.id == 7)
                .expect("continuation packet row missing");
            assert!(
                cont_row.cells[9]
                    .to_string()
                    .contains("[R4: authentication stream omitted]"),
                "expected continuation suppression marker, got {:?}",
                cont_row.cells[9]
            );
            assert!(cont_row.raw_bytes.is_none(), "continuation row must omit raw_bytes");

            let http_tbl = provs
                .iter()
                .find(|p| p.tool_id() == "capture.http")
                .unwrap()
                .query(&TableQuery::default())
                .unwrap();
            assert_eq!(http_tbl.rows.len(), 2);
            let r1_detail = http_tbl.rows[0].detail_json.as_ref().unwrap();
            assert_eq!(r1_detail["r4_redacted"], true);
            assert_eq!(r1_detail["request_headers"]["Cookie"], "theme=light; my_pwd=[REDACTED]");
            assert!(http_tbl.rows[0].raw_bytes.is_none());

            let r2 = &http_tbl.rows[1];
            assert_eq!(
                r2.cells[3],
                CellValue::Text("http://[REDACTED]@example.com/admin?pwd=[REDACTED]".to_string())
            );
            assert!(r2.raw_bytes.is_none());

            let ck_tbl = provs
                .iter()
                .find(|p| p.tool_id() == "capture.cookies")
                .unwrap()
                .query(&TableQuery::default())
                .unwrap();
            assert!(
                ck_tbl
                    .rows
                    .iter()
                    .any(|r| r.cells[2] == CellValue::Text("my_pwd".to_string())
                        && r.cells[3] == CellValue::Text("[REDACTED]".to_string()))
            );
        }
    }
}

#[test]
fn test_r4_xoauth2_sasl_continuations_and_host_userinfo_across_all_tools() {
    let t0 = base_timestamp();
    let cmac = [0x08, 0x00, 0x27, 0x11, 0x22, 0x33];
    let smac = [0x00, 0x50, 0x56, 0xaa, 0xbb, 0xcc];
    let cip = Ipv4Addr::new(192, 168, 1, 25);
    let sip = Ipv4Addr::new(93, 184, 216, 34);
    let mut pkts = Vec::new();

    let mut push_tcp =
        |offset_ms: i64, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, sp: u16, dp: u16, seq: u32, payload: &[u8]| {
            let (dmac, sm) = if src_ip == cip { (smac, cmac) } else { (cmac, smac) };
            let frame = build_eth_frame(
                dmac,
                sm,
                0x0800,
                None,
                &build_ipv4_packet(src_ip, dst_ip, 6, &build_tcp_segment(sp, dp, seq, 1, 0x18, payload)),
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

    // 1. Multi-packet AUTH XOAUTH2, OAUTHBEARER, SCRAM-SHA-256 on non-standard port 5870
    push_tcp(0, cip, sip, 54001, 5870, 100, b"AUTH XOAUTH2\r\n");
    push_tcp(5, sip, cip, 5870, 54001, 100, b"334 \r\n");
    push_tcp(10, cip, sip, 54001, 5870, 114, b"ADV_XOAUTH2_CONT_209\r\n");

    push_tcp(15, cip, sip, 54002, 5870, 100, b"AUTH OAUTHBEARER\r\n");
    push_tcp(20, cip, sip, 54002, 5870, 118, b"ADV_OAUTHBEARER_CONT_210\r\n");

    push_tcp(25, cip, sip, 54003, 5870, 100, b"AUTH SCRAM-SHA-256\r\n");
    push_tcp(30, cip, sip, 54003, 5870, 120, b"ADV_SCRAM_CONT_211\r\n");

    // 2. Host: user:pass@host userinfo
    let req_host_ui = b"GET /host-ui HTTP/1.1\r\nHost: dave:ADV_HOST_UI_PASS_601@example.com\r\n\r\n";
    let resp_host_ui = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Type: text/plain\r\n\r\ndone";
    push_tcp(35, cip, sip, 54004, 80, 100, req_host_ui);
    push_tcp(40, sip, cip, 80, 54004, 100, resp_host_ui);

    // 3. Benign non-authority '@' in path & email query param must be preserved
    let req_benign = b"GET /users/@alice?email=alice@example.com HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let resp_benign = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nhi";
    push_tcp(45, cip, sip, 54005, 80, 100, req_benign);
    push_tcp(50, sip, cip, 80, 54005, 100, resp_benign);

    let secrets = [
        "ADV_XOAUTH2_CONT_209",
        "ADV_OAUTHBEARER_CONT_210",
        "ADV_SCRAM_CONT_211",
        "ADV_HOST_UI_PASS_601",
    ];

    let pcap_file = TempCaptureFile::new("pcap", &encode_pcap_le_us(LinkType::Ethernet, &pkts));
    let pcapng_file = TempCaptureFile::new(
        "pcapng",
        &encode_pcapng(&[(LinkType::Ethernet, "eth0", 6)], &pkts, Endianness::Little),
    );

    for path in [&pcap_file.path, &pcapng_file.path] {
        for redact in [true, false] {
            let ctx = NetContext::offline(OfflineConfig {
                pcap_path: Some(path.clone()),
                ..Default::default()
            })
            .with_redact_sensitive_headers(redact);
            let provs = providers(&ctx);

            for prov in &provs {
                let tbl = prov.query(&TableQuery::default()).unwrap();
                for row in &tbl.rows {
                    for (cidx, cell) in row.cells.iter().enumerate() {
                        let s = cell.to_string();
                        for sec in secrets {
                            assert!(
                                !s.contains(sec),
                                "R4 leak in {} (redact={redact}) row {} cell[{cidx}]: {s}",
                                prov.tool_id(),
                                row.id
                            );
                        }
                    }
                    if let Some(ref dj) = row.detail_json {
                        let ds = dj.to_string();
                        for sec in secrets {
                            assert!(
                                !ds.contains(sec),
                                "R4 leak in {} (redact={redact}) row {} detail_json: {ds}",
                                prov.tool_id(),
                                row.id
                            );
                        }
                    }
                    if let Some(ref rb) = row.raw_bytes {
                        let rs = String::from_utf8_lossy(rb);
                        for sec in secrets {
                            assert!(
                                !rs.contains(sec),
                                "R4 leak in {} (redact={redact}) row {} raw_bytes: {rs}",
                                prov.tool_id(),
                                row.id
                            );
                        }
                    }
                }
            }

            // capture.sniff assertions for continuations & Host userinfo
            let sniff_tbl = provs
                .iter()
                .find(|p| p.tool_id() == "capture.sniff")
                .unwrap()
                .query(&TableQuery::default())
                .unwrap();
            for pkt_no in [3u64, 5, 7] {
                let row = sniff_tbl.rows.iter().find(|r| r.id == pkt_no).unwrap();
                assert!(
                    row.cells[9].to_string().contains("[R4: authentication stream omitted]"),
                    "expected SASL continuation omission at pkt {pkt_no}, got {:?}",
                    row.cells[9]
                );
                assert!(row.raw_bytes.is_none());
            }
            let host_ui_sniff = sniff_tbl.rows.iter().find(|r| r.id == 8).unwrap();
            assert!(host_ui_sniff.raw_bytes.is_none());
            assert!(host_ui_sniff.cells[9].to_string().contains("redacted"));

            // capture.http assertions for Host userinfo & benign '@' preservation
            let http_tbl = provs
                .iter()
                .find(|p| p.tool_id() == "capture.http")
                .unwrap()
                .query(&TableQuery::default())
                .unwrap();
            let host_ui_row = http_tbl
                .rows
                .iter()
                .find(|r| r.cells[3] == CellValue::Text("/host-ui".to_string()))
                .unwrap();
            assert_eq!(
                host_ui_row.cells[2],
                CellValue::Text("[REDACTED]@example.com".to_string())
            );
            let detail = host_ui_row.detail_json.as_ref().unwrap();
            assert_eq!(detail["request_headers"]["Host"], "[REDACTED]@example.com");
            assert_eq!(detail["r4_redacted"], true);
            assert!(host_ui_row.raw_bytes.is_none());

            let benign_row = http_tbl
                .rows
                .iter()
                .find(|r| r.cells[3] == CellValue::Text("/users/@alice?email=alice@example.com".to_string()))
                .unwrap();
            assert_eq!(benign_row.cells[2], CellValue::Text("example.com".to_string()));
            assert_eq!(benign_row.detail_json.as_ref().unwrap()["r4_redacted"], false);
            assert!(benign_row.raw_bytes.is_some());

            // capture.website assertions
            let web_tbl = provs
                .iter()
                .find(|p| p.tool_id() == "capture.website")
                .unwrap()
                .query(&TableQuery::default())
                .unwrap();
            let web_host_ui = web_tbl
                .rows
                .iter()
                .find(|r| r.cells[6] == CellValue::Text("virtual://[REDACTED]@example.com/host-ui".to_string()))
                .unwrap();
            assert_eq!(
                web_host_ui.cells[1],
                CellValue::Text("[REDACTED]@example.com".to_string())
            );
            assert_eq!(web_host_ui.detail_json.as_ref().unwrap()["r4_redacted"], true);
            assert!(web_host_ui.raw_bytes.is_none());
        }
    }
}

#[test]
fn test_r4_mixed_case_auth_verbs_multiword_pass_and_untainted_prose() {
    let t0 = base_timestamp();
    let cmac = [0x08, 0x00, 0x27, 0x11, 0x22, 0x33];
    let smac = [0x00, 0x50, 0x56, 0xaa, 0xbb, 0xcc];
    let cip = Ipv4Addr::new(192, 168, 1, 25);
    let sip = Ipv4Addr::new(93, 184, 216, 34);
    let mut pkts = Vec::new();

    let mut push_tcp =
        |offset_ms: i64, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, sp: u16, dp: u16, seq: u32, payload: &[u8]| {
            let (dmac, sm) = if src_ip == cip { (smac, cmac) } else { (cmac, smac) };
            let frame = build_eth_frame(
                dmac,
                sm,
                0x0800,
                None,
                &build_ipv4_packet(src_ip, dst_ip, 6, &build_tcp_segment(sp, dp, seq, 1, 0x18, payload)),
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

    // 1. Mixed-case SMTP Auth XOAUTH2 on non-standard port 5870 -> continuation secret
    push_tcp(0, cip, sip, 55001, 5870, 100, b"Auth XOAUTH2\r\n");
    push_tcp(5, sip, cip, 5870, 55001, 100, b"334 \r\n");
    push_tcp(10, cip, sip, 55001, 5870, 114, b"ADV_MIXED_AUTH_901\r\n");

    // 2. Mixed-case IMAP A001 Authenticate XOAUTH2 on non-standard port 1430 -> continuation secret
    push_tcp(15, cip, sip, 55002, 1430, 100, b"A001 Authenticate XOAUTH2\r\n");
    push_tcp(20, sip, cip, 1430, 55002, 100, b"+ \r\n");
    push_tcp(25, cip, sip, 55002, 1430, 127, b"ADV_MIXED_IMAP_902\r\n");

    // 3. Mixed-case POP3/FTP Pass <pw> on non-standard port 1100
    push_tcp(30, cip, sip, 55003, 1100, 100, b"Pass ADV_MIXED_PASS_903\r\n");

    // 4. Lowercase multi-word pass <words> on non-standard port 1100
    push_tcp(35, cip, sip, 55004, 1100, 100, b"pass my ADV_MULTIWORD_PASS_904\r\n");

    // 5. Benign TitleCase prose on port 9999 must stay untainted
    push_tcp(40, cip, sip, 55005, 9999, 100, b"Auth Required\r\n");
    push_tcp(45, cip, sip, 55005, 9999, 115, b"User Guide\r\n");
    push_tcp(50, cip, sip, 55005, 9999, 127, b"Login Page\r\n");
    push_tcp(55, cip, sip, 55005, 9999, 139, b"BENIGN_PROSE_NEXT_LINE\r\n");

    let secrets = [
        "ADV_MIXED_AUTH_901",
        "ADV_MIXED_IMAP_902",
        "ADV_MIXED_PASS_903",
        "ADV_MULTIWORD_PASS_904",
    ];

    let pcap_file = TempCaptureFile::new("pcap", &encode_pcap_le_us(LinkType::Ethernet, &pkts));
    let pcapng_file = TempCaptureFile::new(
        "pcapng",
        &encode_pcapng(&[(LinkType::Ethernet, "eth0", 6)], &pkts, Endianness::Little),
    );

    for path in [&pcap_file.path, &pcapng_file.path] {
        for redact in [true, false] {
            let ctx = NetContext::offline(OfflineConfig {
                pcap_path: Some(path.clone()),
                ..Default::default()
            })
            .with_redact_sensitive_headers(redact);
            let provs = providers(&ctx);

            for prov in &provs {
                let tbl = prov.query(&TableQuery::default()).unwrap();
                for row in &tbl.rows {
                    for (cidx, cell) in row.cells.iter().enumerate() {
                        let s = cell.to_string();
                        for sec in secrets {
                            assert!(
                                !s.contains(sec),
                                "R4 leak in {} (redact={redact}) row {} cell[{cidx}]: {s}",
                                prov.tool_id(),
                                row.id
                            );
                        }
                    }
                    if let Some(ref dj) = row.detail_json {
                        let ds = dj.to_string();
                        for sec in secrets {
                            assert!(
                                !ds.contains(sec),
                                "R4 leak in {} (redact={redact}) row {} detail_json: {ds}",
                                prov.tool_id(),
                                row.id
                            );
                        }
                    }
                    if let Some(ref rb) = row.raw_bytes {
                        let rs = String::from_utf8_lossy(rb);
                        for sec in secrets {
                            assert!(
                                !rs.contains(sec),
                                "R4 leak in {} (redact={redact}) row {} raw_bytes: {rs}",
                                prov.tool_id(),
                                row.id
                            );
                        }
                    }
                }
            }

            let sniff_tbl = provs
                .iter()
                .find(|p| p.tool_id() == "capture.sniff")
                .unwrap()
                .query(&TableQuery::default())
                .unwrap();

            // Continuation packets (3 and 6) must omit stream and raw_bytes
            for cont_pkt_no in [3u64, 6] {
                let row = sniff_tbl.rows.iter().find(|r| r.id == cont_pkt_no).unwrap();
                assert!(
                    row.cells[9].to_string().contains("[R4: authentication stream omitted]"),
                    "expected stream omission at pkt {cont_pkt_no}, got {:?}",
                    row.cells[9]
                );
                assert!(row.raw_bytes.is_none());
            }

            // Pass & pass multi-word packets (7 and 8) must suppress summary and omit raw_bytes
            for pass_pkt_no in [7u64, 8] {
                let row = sniff_tbl.rows.iter().find(|r| r.id == pass_pkt_no).unwrap();
                assert!(
                    row.cells[9].to_string().contains("redacted"),
                    "expected redaction summary at pkt {pass_pkt_no}, got {:?}",
                    row.cells[9]
                );
                assert!(row.raw_bytes.is_none());
            }

            // Benign prose packets (9..=12) must remain untainted
            for (pkt_no, expected) in [
                (9u64, "TCP Auth Required"),
                (10, "TCP User Guide"),
                (11, "TCP Login Page"),
                (12, "TCP BENIGN_PROSE_NEXT_LINE"),
            ] {
                let row = sniff_tbl.rows.iter().find(|r| r.id == pkt_no).unwrap();
                assert_eq!(row.cells[9], CellValue::Text(expected.to_string()));
                assert!(row.raw_bytes.is_some(), "benign prose pkt {pkt_no} must keep raw_bytes");
            }
        }
    }
}

#[test]
fn test_r4_imap_login_mixed_case_non_digit_tags_and_untainted_prose() {
    let t0 = base_timestamp();
    let cmac = [0x08, 0x00, 0x27, 0x11, 0x22, 0x33];
    let smac = [0x00, 0x50, 0x56, 0xaa, 0xbb, 0xcc];
    let cip = Ipv4Addr::new(192, 168, 1, 25);
    let sip = Ipv4Addr::new(93, 184, 216, 34);
    let mut pkts = Vec::new();

    let mut push_tcp =
        |offset_ms: i64, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, sp: u16, dp: u16, seq: u32, payload: &[u8]| {
            let (dmac, sm) = if src_ip == cip { (smac, cmac) } else { (cmac, smac) };
            let frame = build_eth_frame(
                dmac,
                sm,
                0x0800,
                None,
                &build_ipv4_packet(src_ip, dst_ip, 6, &build_tcp_segment(sp, dp, seq, 1, 0x18, payload)),
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

    let login_cases: &[(u16, &[u8], &[u8])] = &[
        (56001, b"Login Alice Secret\r\n", b"CONT_LOGIN_SECRET_1\r\n"),
        (56002, b"lOgIn Alice Secret\r\n", b"CONT_LOGIN_SECRET_2\r\n"),
        (56003, b"TAG Login Alice Secret\r\n", b"CONT_LOGIN_SECRET_3\r\n"),
        (56004, b"imap Login Alice Secret\r\n", b"CONT_LOGIN_SECRET_4\r\n"),
        (56005, b"a Login Alice Secret\r\n", b"CONT_LOGIN_SECRET_5\r\n"),
        (56006, b"Please lOgIn Alice Secret\r\n", b"CONT_LOGIN_SECRET_6\r\n"),
    ];

    let mut offset_ms = 0i64;
    for &(sp, cmd, cont) in login_cases {
        push_tcp(offset_ms, cip, sip, sp, 1430, 100, cmd);
        offset_ms += 5;
        push_tcp(
            offset_ms,
            cip,
            sip,
            sp,
            1430,
            100 + u32::try_from(cmd.len()).unwrap(),
            cont,
        );
        offset_ms += 5;
    }

    // Benign prose that must stay untainted
    push_tcp(offset_ms, cip, sip, 56010, 9999, 100, b"Login Page\r\n");
    offset_ms += 5;
    push_tcp(offset_ms, cip, sip, 56010, 9999, 112, b"Please Login Right Now\r\n");
    offset_ms += 5;
    push_tcp(offset_ms, cip, sip, 56010, 9999, 136, b"BENIGN_PROSE_AFTER_LOGIN\r\n");

    let forbidden = [
        "Secret",
        "Alice",
        "CONT_LOGIN_SECRET_1",
        "CONT_LOGIN_SECRET_2",
        "CONT_LOGIN_SECRET_3",
        "CONT_LOGIN_SECRET_4",
        "CONT_LOGIN_SECRET_5",
        "CONT_LOGIN_SECRET_6",
    ];

    let pcap_file = TempCaptureFile::new("pcap", &encode_pcap_le_us(LinkType::Ethernet, &pkts));
    let pcapng_file = TempCaptureFile::new(
        "pcapng",
        &encode_pcapng(&[(LinkType::Ethernet, "eth0", 6)], &pkts, Endianness::Little),
    );

    for path in [&pcap_file.path, &pcapng_file.path] {
        for redact in [true, false] {
            let ctx = NetContext::offline(OfflineConfig {
                pcap_path: Some(path.clone()),
                ..Default::default()
            })
            .with_redact_sensitive_headers(redact);
            let provs = providers(&ctx);

            for prov in &provs {
                let tbl = prov.query(&TableQuery::default()).unwrap();
                for row in &tbl.rows {
                    for (cidx, cell) in row.cells.iter().enumerate() {
                        let s = cell.to_string();
                        for sec in forbidden {
                            assert!(
                                !s.contains(sec),
                                "R4 leak in {} (redact={redact}) row {} cell[{cidx}]: {s}",
                                prov.tool_id(),
                                row.id
                            );
                        }
                    }
                    if let Some(ref dj) = row.detail_json {
                        let ds = dj.to_string();
                        for sec in forbidden {
                            assert!(
                                !ds.contains(sec),
                                "R4 leak in {} (redact={redact}) row {} detail_json: {ds}",
                                prov.tool_id(),
                                row.id
                            );
                        }
                    }
                    if let Some(ref rb) = row.raw_bytes {
                        let rs = String::from_utf8_lossy(rb);
                        for sec in forbidden {
                            assert!(
                                !rs.contains(sec),
                                "R4 leak in {} (redact={redact}) row {} raw_bytes: {rs}",
                                prov.tool_id(),
                                row.id
                            );
                        }
                    }
                }
            }

            let sniff_tbl = provs
                .iter()
                .find(|p| p.tool_id() == "capture.sniff")
                .unwrap()
                .query(&TableQuery::default())
                .unwrap();

            // Each of the 6 LOGIN cases: packet 2*i+1 is redacted LOGIN, packet 2*i+2 is tainted flow continuation
            for idx in 0..login_cases.len() {
                let login_pkt_no = (idx * 2 + 1) as u64;
                let cont_pkt_no = (idx * 2 + 2) as u64;

                let login_row = sniff_tbl.rows.iter().find(|r| r.id == login_pkt_no).unwrap();
                assert!(
                    login_row.cells[9].to_string().contains("redacted"),
                    "expected redacted summary at LOGIN pkt {login_pkt_no}, got {:?}",
                    login_row.cells[9]
                );
                assert!(
                    login_row.raw_bytes.is_none(),
                    "LOGIN pkt {login_pkt_no} must omit raw_bytes"
                );

                let cont_row = sniff_tbl.rows.iter().find(|r| r.id == cont_pkt_no).unwrap();
                assert!(
                    cont_row.cells[9]
                        .to_string()
                        .contains("[R4: authentication stream omitted]"),
                    "expected tainted flow omission at cont pkt {cont_pkt_no}, got {:?}",
                    cont_row.cells[9]
                );
                assert!(
                    cont_row.raw_bytes.is_none(),
                    "cont pkt {cont_pkt_no} must omit raw_bytes"
                );
            }

            // Benign prose packets (13..=15) must remain untainted
            for (pkt_no, expected) in [
                (13u64, "TCP Login Page"),
                (14, "TCP Please Login Right Now"),
                (15, "TCP BENIGN_PROSE_AFTER_LOGIN"),
            ] {
                let row = sniff_tbl.rows.iter().find(|r| r.id == pkt_no).unwrap();
                assert_eq!(row.cells[9], CellValue::Text(expected.to_string()));
                assert!(row.raw_bytes.is_some(), "benign prose pkt {pkt_no} must keep raw_bytes");
            }
        }
    }
}
