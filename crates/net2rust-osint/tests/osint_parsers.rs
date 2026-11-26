use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use chrono::{Datelike, Timelike};
use net2rust_core::{MacAddr, NetError};
use net2rust_osint::dns_wire::{
    DnsRecordType, decode_dns_response, decode_name, encode_dns_name, encode_dns_query, ip_to_arpa_name,
    query_dns_with_fallback,
};
use net2rust_osint::geoip_db::OfflineIpDb;
use net2rust_osint::model::{decode_registry_systemtime, filetime_to_utc, parse_guid_flexible};
use net2rust_osint::oui_db::{OfflineOuiDb, RegistryBlock};
use net2rust_osint::tools::dns::{build_synthetic_dns_reply, query_dns_records};
use net2rust_osint::tools::hosting::{HostingDeps, analyze_domain_hosting};
use net2rust_osint::tools::ipnet::lookup_ipnet_whois_only;
use net2rust_osint::tools::whois_domain::lookup_whois_domain;
use net2rust_osint::tools::whoiscl::run_whoiscl_batch;
use net2rust_osint::tools::whosip::lookup_whosip;
use net2rust_osint::transport::{
    MockDnsTransport, MockRdapTransport, MockWhoisTransport, RdapHttpResponse, StdDnsTransport, StdWhoisTransport,
    UreqRdapTransport,
};
use net2rust_osint::whois::{ip_range_to_cidrs, parse_rdap_ip, parse_whois_domain, parse_whois_ip};

struct TempDirGuard {
    path: std::path::PathBuf,
}

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let unique = format!(
            "{prefix}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn spawn_whois_server(routes: HashMap<String, String>, max_conns: usize) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp whois");
    let addr = listener.local_addr().expect("local addr");
    let handle = thread::spawn(move || {
        for _ in 0..max_conns {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            let key = line.trim().to_ascii_lowercase();
            let body = routes
                .get(&key)
                .or_else(|| routes.get("*"))
                .cloned()
                .unwrap_or_else(|| "% No match found\n".to_string());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });
    (addr, handle)
}

#[test]
fn test_ip_range_to_cidrs_and_whois_parsers() {
    let cidrs_pow2 = ip_range_to_cidrs("193.0.0.0".parse().unwrap(), "193.0.7.255".parse().unwrap());
    assert_eq!(cidrs_pow2, vec!["193.0.0.0/21"]);

    let cidrs_multi = ip_range_to_cidrs("10.0.0.0".parse().unwrap(), "10.0.2.255".parse().unwrap());
    assert_eq!(cidrs_multi, vec!["10.0.0.0/23", "10.0.2.0/24"]);

    let cidrs_v6 = ip_range_to_cidrs("2001:db8::".parse().unwrap(), "2001:db8::ffff".parse().unwrap());
    assert_eq!(cidrs_v6, vec!["2001:db8::/112"]);

    let ripe_raw = "\
inetnum:        193.0.0.0 - 193.0.7.255
netname:        RIPE-NCC
country:        NL
org:            ORG-RIPE1-RIPE
last-modified:  2024-02-15T10:00:00Z
source:         RIPE

% Abuse contact for '193.0.0.0 - 193.0.7.255' is 'abuse@ripe.net'

organisation:   ORG-RIPE1-RIPE
org-name:       RIPE Network Coordination Centre
";
    let parsed = parse_whois_ip("193.0.0.1".parse().unwrap(), "RIPE", ripe_raw);
    assert_eq!(parsed.cidr, "193.0.0.0/21");
    assert_eq!(parsed.org_name, "RIPE Network Coordination Centre");
    assert_eq!(parsed.abuse_email, "abuse@ripe.net");
    assert_eq!(parsed.country, "NL");
    assert_eq!(parsed.rir, "RIPE");
}

#[test]
fn test_localhost_tcp_whois_ipnet_and_referral_chasing() {
    let mut arin_routes = HashMap::new();
    arin_routes.insert(
        "n + 8.8.8.8".to_string(),
        "NetRange: 8.8.8.0 - 8.8.8.255\nCIDR: 8.8.8.0/24\nOrgName: Google LLC\nCountry: US\nOrgAbuseEmail: network-abuse@google.com\nOriginAS: AS15169\nUpdated: 2023-12-28\n".to_string(),
    );
    arin_routes.insert(
        "n + 193.0.0.1".to_string(),
        "ReferralServer: whois://whois.ripe.net\n".to_string(),
    );

    let mut ripe_routes = HashMap::new();
    ripe_routes.insert(
        "-b 193.0.0.1".to_string(),
        "inetnum: 193.0.0.0 - 193.0.7.255\nnetname: RIPE-NCC\ncountry: NL\norg: ORG-RIPE1\nsource: RIPE\n\norganisation: ORG-RIPE1\norg-name: RIPE NCC\nabuse-mailbox: abuse@ripe.net\n".to_string(),
    );

    let (arin_addr, arin_handle) = spawn_whois_server(arin_routes, 2);
    let (ripe_addr, ripe_handle) = spawn_whois_server(ripe_routes, 1);

    let transport = StdWhoisTransport::new()
        .with_override("whois.arin.net", arin_addr)
        .with_override("whois.ripe.net", ripe_addr);

    let ip_rec = lookup_ipnet_whois_only("8.8.8.8".parse().unwrap(), &transport, Duration::from_secs(2))
        .expect("localhost ARIN whois");
    assert_eq!(ip_rec.org_name, "Google LLC");
    assert_eq!(ip_rec.abuse_email, "network-abuse@google.com");
    assert_eq!(ip_rec.cidr, "8.8.8.0/24");

    // Referral chase: ARIN -> RIPE
    let rdap = MockRdapTransport::new();
    let geoip = OfflineIpDb::embedded();
    let whosip = lookup_whosip(
        "193.0.0.1".parse().unwrap(),
        Some("whois.arin.net"),
        &transport,
        &rdap,
        &geoip,
        Duration::from_secs(2),
    )
    .expect("whosip referral chase");
    assert_eq!(whosip.owner, "RIPE NCC");
    assert_eq!(whosip.rir, "RIPE");
    assert_eq!(whosip.referral_chain.len(), 2);

    arin_handle.join().expect("arin thread");
    ripe_handle.join().expect("ripe thread");
}

#[test]
fn test_whosip_cycle_detection_and_hop_cap() {
    let mut mock_whois = MockWhoisTransport::new();
    // Cycle A <-> B
    mock_whois.insert_server_default("whois.a.test", "ReferralServer: whois://whois.b.test\n");
    mock_whois.insert_server_default("whois.b.test", "ReferralServer: whois://whois.a.test\n");

    let rdap = MockRdapTransport::new();
    let geoip = OfflineIpDb::embedded();
    let rec = lookup_whosip(
        "8.8.8.8".parse().unwrap(),
        Some("whois.a.test"),
        &mock_whois,
        &rdap,
        &geoip,
        Duration::from_secs(1),
    )
    .expect("cycle terminates cleanly");
    assert_eq!(rec.referral_chain.len(), 2);

    // Long chain > MAX_REFERRAL_HOPS (6)
    let mut chain_whois = MockWhoisTransport::new();
    for i in 0..10 {
        chain_whois.insert_server_default(
            format!("whois.hop{i}.test"),
            format!("ReferralServer: whois://whois.hop{}.test\n", i + 1),
        );
    }
    let rec2 = lookup_whosip(
        "8.8.8.8".parse().unwrap(),
        Some("whois.hop0.test"),
        &chain_whois,
        &rdap,
        &geoip,
        Duration::from_secs(1),
    )
    .expect("hop cap terminates cleanly");
    assert_eq!(rec2.referral_chain.len(), 6);
}

#[test]
fn test_localhost_http_rdap_redirect_and_referral() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind http rdap");
    let addr = listener.local_addr().expect("http addr");
    let base = format!("http://{addr}");
    let base_clone = base.clone();

    let handle = thread::spawn(move || {
        // Expect 2 requests: 1) /ip/8.8.8.8 -> 302 redirect to /final/8.8.8.8, 2) /final/8.8.8.8 -> 200 JSON
        for _ in 0..2 {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let first_line = req.lines().next().unwrap_or("");
            if first_line.contains("/ip/8.8.8.8") {
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {base_clone}/final/8.8.8.8\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(resp.as_bytes());
            } else {
                let body = serde_json::json!({
                    "handle": "NET-8-8-8-0-2",
                    "startAddress": "8.8.8.0",
                    "endAddress": "8.8.8.255",
                    "name": "GOGL",
                    "country": "US",
                    "port43": "whois.arin.net",
                    "cidr0_cidrs": [{ "v4prefix": "8.8.8.0", "length": 24 }],
                    "arin_originas0_originautnums": [15169],
                    "events": [{ "eventAction": "last changed", "eventDate": "2024-01-01T00:00:00Z" }],
                    "entities": [{
                        "roles": ["registrant"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]],
                        "entities": [{
                            "roles": ["abuse"],
                            "vcardArray": ["vcard", [["email", {}, "text", "network-abuse@google.com"]]]
                        }]
                    }]
                })
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/rdap+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
            let _ = stream.flush();
        }
    });

    let rdap = UreqRdapTransport::new().with_base_override("https://rdap.arin.net/registry", base);
    let whois = MockWhoisTransport::new();
    let geoip = OfflineIpDb::embedded();

    let rec = lookup_whosip(
        "8.8.8.8".parse().unwrap(),
        None,
        &whois,
        &rdap,
        &geoip,
        Duration::from_secs(3),
    )
    .expect("RDAP redirect + JSON");
    assert_eq!(rec.owner, "Google LLC");
    assert_eq!(rec.asn, "AS15169");
    assert_eq!(rec.net_block, "8.8.8.0/24");

    handle.join().expect("http thread");
}

#[test]
fn test_domain_whois_multi_tld_chasing_and_whoiscl_isolation() {
    let mut whois = MockWhoisTransport::new();
    whois.insert(
        "whois.verisign-grs.com",
        "=example.com",
        "Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: whois.registrar.test\nRegistry Expiry Date: 2028-01-01T00:00:00Z\nName Server: NS1.EXAMPLE.COM\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n",
    );
    whois.insert(
        "whois.registrar.test",
        "example.com",
        "Domain Name: example.com\nRegistrar: Example Registrar Inc.\nCreation Date: 2000-01-01T00:00:00Z\nUpdated Date: 2025-01-01T00:00:00Z\n",
    );
    whois.insert("whois.iana.org", "xyz", "refer: whois.nic.xyz\n");
    whois.insert(
        "whois.nic.xyz",
        "example.xyz",
        "Domain Name: example.xyz\nRegistrar: XYZ Registrar\nRegistry Expiry Date: 2027-05-05T00:00:00Z\n",
    );

    let rdap = MockRdapTransport::new();
    let com = lookup_whois_domain("https://EXAMPLE.COM/path", &whois, &rdap, Duration::from_secs(1)).unwrap();
    assert_eq!(com.domain, "example.com");
    assert_eq!(com.registrar, "Example Registrar Inc.");
    assert_eq!(com.expiry_date, "2028-01-01T00:00:00Z");
    assert_eq!(com.name_servers, "ns1.example.com");
    assert_eq!(com.status, "clientTransferProhibited");

    let xyz = lookup_whois_domain("example.xyz", &whois, &rdap, Duration::from_secs(1)).unwrap();
    assert_eq!(xyz.registrar, "XYZ Registrar");

    // Multi-TLD parser coverage: .uk, .de, .jp
    let uk = parse_whois_domain(
        "example.co.uk",
        "whois.nic.uk",
        "Registrar:\n    Nominet Tag\n\nRelevant dates:\n    Registered on: 2001-01-01\n    Expiry date: 2026-01-01\n\nName servers:\n    ns1.uk.test\n",
    );
    assert_eq!(uk.registrar, "Nominet Tag");
    assert_eq!(uk.expiry_date, "2026-01-01");

    let de = parse_whois_domain(
        "example.de",
        "whois.denic.de",
        "Domain: example.de\nNserver: ns1.denic.de\nStatus: connect\nChanged: 2024-03-01T12:00:00+01:00\n",
    );
    assert_eq!(de.status, "connect");
    assert_eq!(de.name_servers, "ns1.denic.de");

    let jp = parse_whois_domain(
        "example.jp",
        "whois.jprs.jp",
        "[Domain Name]                   EXAMPLE.JP\n[Name Server]                   ns1.example.jp\n[Created on]                    2005/04/01\n[Expires on]                    2026/04/30\n",
    );
    assert_eq!(jp.created_date, "2005/04/01");
    assert_eq!(jp.expiry_date, "2026/04/30");

    // Batch WhoisCL error isolation
    let geoip = OfflineIpDb::embedded();
    let batch = run_whoiscl_batch(
        &[
            "example.com".to_string(),
            "nonexistent.invalid_tld_without_fixture".to_string(),
            "example.xyz".to_string(),
        ],
        &whois,
        &rdap,
        &geoip,
        Duration::from_secs(1),
    );
    assert_eq!(batch.len(), 3);
    assert!(batch[0].error.is_none());
    assert_eq!(batch[1].whois_server, "error");
    assert!(batch[1].raw_text.starts_with("ERROR:"));
    assert!(batch[2].error.is_none());
}

#[test]
fn test_dns_wire_all_10_rr_types_arpa_tcp_fallback_and_loop_guard() {
    // Reverse ARPA builder
    assert_eq!(
        ip_to_arpa_name("192.0.2.10".parse::<IpAddr>().unwrap()),
        "10.2.0.192.in-addr.arpa"
    );
    assert_eq!(
        ip_to_arpa_name("2001:db8::1".parse::<IpAddr>().unwrap()),
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    );

    // All 10 RR types via build_synthetic_dns_reply + decode_dns_response
    for (idx, &rr) in DnsRecordType::all().iter().enumerate() {
        let tx = 0x1000 + idx as u16;
        let qname = if rr == DnsRecordType::PTR {
            "34.216.184.93.in-addr.arpa"
        } else {
            "example.com"
        };
        let pkt = build_synthetic_dns_reply(tx, qname, rr.to_qtype());
        let decoded = decode_dns_response(&pkt, tx).expect("decode synthetic rr");
        assert_eq!(decoded.answers.len(), 1);
        assert_eq!(decoded.answers[0].record_type, rr.as_str());
        if matches!(rr, DnsRecordType::MX | DnsRecordType::SRV) {
            assert_eq!(decoded.answers[0].priority, Some(10));
        } else {
            assert_eq!(decoded.answers[0].priority, None);
        }
    }

    // Compression pointer loop guard (self-pointer 0xC00C at offset 12, and 2-node cycle)
    let mut loop_pkt = vec![0u8; 16];
    loop_pkt[12] = 0xC0;
    loop_pkt[13] = 0x0C; // points to offset 12
    let err = decode_name(&loop_pkt, 12).unwrap_err();
    assert!(matches!(err, NetError::ParseError(_)));

    let mut two_node = vec![0u8; 20];
    two_node[12] = 0xC0;
    two_node[13] = 0x0E; // 12 -> 14
    two_node[14] = 0xC0;
    two_node[15] = 0x0C; // 14 -> 12
    assert!(matches!(
        decode_name(&two_node, 12).unwrap_err(),
        NetError::ParseError(_)
    ));

    // Truncated packet + invalid tag
    assert!(matches!(
        decode_dns_response(&[0u8; 5], 1).unwrap_err(),
        NetError::ParseError(_)
    ));
    let mut bad_tag = vec![0u8; 16];
    bad_tag[12] = 0x80; // reserved tag
    assert!(matches!(
        decode_name(&bad_tag, 12).unwrap_err(),
        NetError::ParseError(_)
    ));

    // Real localhost UDP -> TCP TC=1 fallback
    let udp_sock = UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    let udp_addr = udp_sock.local_addr().expect("udp addr");
    let tcp_listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let tcp_addr = tcp_listener.local_addr().expect("tcp addr");

    let udp_thread = thread::spawn(move || {
        let mut buf = [0u8; 512];
        let (n, peer) = udp_sock.recv_from(&mut buf).expect("recv udp");
        assert!(n >= 12);
        let tx = u16::from_be_bytes([buf[0], buf[1]]);
        let mut reply = encode_dns_query(tx, "example.com", DnsRecordType::TXT).unwrap();
        // Set QR=1, TC=1, RD=1, RA=1 -> 0x8380
        reply[2] = 0x83;
        reply[3] = 0x80;
        let _ = udp_sock.send_to(&reply, peer);
    });

    let tcp_thread = thread::spawn(move || {
        let (mut stream, _) = tcp_listener.accept().expect("accept tcp dns");
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).expect("read tcp len");
        let qlen = u16::from_be_bytes(len_buf) as usize;
        let mut qbuf = vec![0u8; qlen];
        stream.read_exact(&mut qbuf).expect("read tcp query");
        let tx = u16::from_be_bytes([qbuf[0], qbuf[1]]);
        let resp = build_synthetic_dns_reply(tx, "example.com", DnsRecordType::TXT.to_qtype());
        let _ = stream.write_all(&(resp.len() as u16).to_be_bytes());
        let _ = stream.write_all(&resp);
        let _ = stream.flush();
    });

    // Use a custom wrapper that routes UDP to udp_addr and TCP to tcp_addr via StdDnsTransport
    let std_dns = StdDnsTransport::new();
    let tcp_fallback_transport = UdpTcpSplitTransport {
        udp: udp_addr,
        tcp: tcp_addr,
        inner: std_dns,
    };
    let msg = query_dns_with_fallback(
        &tcp_fallback_transport,
        udp_addr,
        "example.com",
        DnsRecordType::TXT,
        0x55AA,
        Duration::from_secs(2),
    )
    .expect("UDP->TCP TC=1 fallback succeeds");
    assert!(msg.used_tcp);
    assert_eq!(msg.answers.len(), 1);
    assert_eq!(msg.answers[0].value, "v=spf1 -all");

    udp_thread.join().unwrap();
    tcp_thread.join().unwrap();
    let _ = encode_dns_name("example.com");
}

struct UdpTcpSplitTransport {
    udp: SocketAddr,
    tcp: SocketAddr,
    inner: StdDnsTransport,
}

impl net2rust_osint::transport::DnsTransport for UdpTcpSplitTransport {
    fn exchange(
        &self,
        _server: SocketAddr,
        query_packet: &[u8],
        use_tcp: bool,
        timeout: Duration,
    ) -> net2rust_core::NetResult<Vec<u8>> {
        let target = if use_tcp { self.tcp } else { self.udp };
        self.inner.exchange(target, query_packet, use_tcp, timeout)
    }
}

#[test]
fn test_embedded_geoip_and_oui_lpm_and_csv_overrides() {
    let dir = TempDirGuard::new("osint_db_override");

    // GeoIP LPM: 8.8.8.0/24 (Google AS15169) vs 8.0.0.0/8 (Level3 AS3356)
    let mut geo = OfflineIpDb::embedded();
    let google = geo.lookup("8.8.8.8".parse().unwrap());
    assert_eq!(google.asn, Some(15169));
    assert_eq!(google.country_code, "US");
    let level3 = geo.lookup("8.1.2.3".parse().unwrap());
    assert_eq!(level3.asn, Some(3356));

    // IPv6 LPM + v4-mapped IPv6
    let g_v6 = geo.lookup("2001:4860:4860::8888".parse().unwrap());
    assert_eq!(g_v6.asn, Some(15169));
    let mapped = geo.lookup("::ffff:8.8.8.8".parse().unwrap());
    assert_eq!(mapped.asn, Some(15169));

    // Reserved
    let rfc1918 = geo.lookup("192.168.10.20".parse().unwrap());
    assert_eq!(rfc1918.country_code, "ZZ");
    assert_eq!(rfc1918.asn, None);

    // Custom CSV override
    let geo_csv = dir.path.join("custom_geo.csv");
    std::fs::write(
        &geo_csv,
        "cidr,country_code,country_name,continent,asn,as_name\n203.0.113.128/25,CA,Canada,NA,64512,TEST-LAB-CA\n",
    )
    .unwrap();
    geo.merge_csv_file(&geo_csv).unwrap();
    let custom_hit = geo.lookup("203.0.113.200".parse().unwrap());
    assert_eq!(custom_hit.country_code, "CA");
    assert_eq!(custom_hit.asn, Some(64512));

    // OUI LPM: MA-S > MA-M > MA-L
    let mut oui = OfflineOuiDb::embedded();
    let mas = oui.lookup_mac(MacAddr::parse("70:B3:D5:1A:20:01").unwrap()).unwrap();
    assert_eq!(mas.registry_block, RegistryBlock::MaS);
    assert_eq!(mas.vendor_name, "Acme Embedded Systems GmbH");

    let mal_fallback = oui.lookup_mac(MacAddr::parse("70:B3:D5:FF:EE:01").unwrap()).unwrap();
    assert_eq!(mal_fallback.registry_block, RegistryBlock::MaL);

    let mam = oui.lookup_mac(MacAddr::parse("00:55:DA:5A:BC:DE").unwrap()).unwrap();
    assert_eq!(mam.registry_block, RegistryBlock::MaM);
    assert_eq!(mam.vendor_name, "Ubiquiti Inc");

    // All MacAddr formats + partial prefixes
    assert_eq!(oui.lookup_str("0050.56aa.bbcc").unwrap().vendor_name, "VMware, Inc.");
    assert_eq!(oui.lookup_str("00-50-56-aa-bb-cc").unwrap().vendor_name, "VMware, Inc.");
    assert_eq!(oui.lookup_str("005056aabbcc").unwrap().vendor_name, "VMware, Inc.");
    assert_eq!(oui.lookup_str("00:50:56").unwrap().vendor_name, "VMware, Inc.");
    assert_eq!(oui.lookup_str("00:55:DA:5").unwrap().registry_block, RegistryBlock::MaM);
    assert_eq!(
        oui.lookup_str("70:B3:D5:1A:2").unwrap().registry_block,
        RegistryBlock::MaS
    );

    // Custom IEEE CSV override
    let oui_csv = dir.path.join("custom_oui.csv");
    std::fs::write(
        &oui_csv,
        "Registry,Assignment,Organization Name,Organization Address\nMA-L,AABBCC,Custom Corp,Toronto ON CA\n",
    )
    .unwrap();
    oui.merge_csv_file(&oui_csv).unwrap();
    let custom_oui = oui.lookup_str("aa:bb:cc:11:22:33").unwrap();
    assert_eq!(custom_oui.vendor_name, "Custom Corp");
    assert_eq!(custom_oui.country, "CA");
}

#[test]
fn test_hosting_aggregation_and_partial_failure_resilience() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_c = Arc::clone(&calls);
    let dns = MockDnsTransport::new(move |_srv, query, _tcp| {
        calls_c.fetch_add(1, Ordering::Relaxed);
        let tx = u16::from_be_bytes([query[0], query[1]]);
        let (qname, next) = decode_name(query, 12)?;
        let qtype = u16::from_be_bytes([query[next], query[next + 1]]);
        Ok(build_synthetic_dns_reply(tx, &qname, qtype))
    });
    // Empty WHOIS/RDAP mocks -> domain WHOIS fails, DNS + GeoIP still succeed
    let failing_whois = MockWhoisTransport::new();
    let failing_rdap = MockRdapTransport::new();
    let geoip = OfflineIpDb::embedded();

    let profile = analyze_domain_hosting(
        "example.com",
        &HostingDeps {
            dns_server: "1.1.1.1:53".parse().unwrap(),
            dns: &dns,
            whois: &failing_whois,
            rdap: &failing_rdap,
            geoip: &geoip,
            timeout: Duration::from_secs(1),
            use_live_ip_whois: false,
        },
    );
    assert_eq!(profile.domain, "example.com");
    assert_eq!(profile.web_host_ip, "93.184.216.34");
    assert_eq!(profile.country, "US");
    assert!(profile.dns_provider.contains("IANA"));
    assert!(!profile.warnings.is_empty());
    assert!(calls.load(Ordering::Relaxed) >= 4);
    let _ = query_dns_records(
        "example.com",
        &[DnsRecordType::A],
        "1.1.1.1:53".parse().unwrap(),
        &dns,
        Duration::from_secs(1),
    );
}

#[test]
fn test_systemtime_filetime_and_guid_helpers() {
    // 2026-11-23 12:34:56.789 (Monday=1)
    let mut bytes = [0u8; 16];
    bytes[0..2].copy_from_slice(&2026u16.to_le_bytes());
    bytes[2..4].copy_from_slice(&11u16.to_le_bytes());
    bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&23u16.to_le_bytes());
    bytes[8..10].copy_from_slice(&12u16.to_le_bytes());
    bytes[10..12].copy_from_slice(&34u16.to_le_bytes());
    bytes[12..14].copy_from_slice(&56u16.to_le_bytes());
    bytes[14..16].copy_from_slice(&789u16.to_le_bytes());

    let dt = decode_registry_systemtime(&bytes).expect("valid SYSTEMTIME");
    assert_eq!(dt.year(), 2026);
    assert_eq!(dt.month(), 11);
    assert_eq!(dt.day(), 23);
    assert_eq!(dt.hour(), 12);
    assert_eq!(dt.minute(), 34);
    assert_eq!(dt.second(), 56);

    assert!(decode_registry_systemtime(&[0u8; 16]).is_none());
    assert!(decode_registry_systemtime(&[0u8; 10]).is_none());
    let mut bad_month = bytes;
    bad_month[2..4].copy_from_slice(&13u16.to_le_bytes());
    assert!(decode_registry_systemtime(&bad_month).is_none());

    // FILETIME for 1970-01-01T00:00:01Z
    let ft_unix_plus_1s = 116_444_736_000_000_000u64 + 10_000_000;
    assert_eq!(filetime_to_utc(ft_unix_plus_1s).unwrap().timestamp(), 1);
    assert!(filetime_to_utc(0).is_none());

    // GUID normalization
    assert_eq!(
        parse_guid_flexible("11111111-2222-3333-4444-555555555555").unwrap(),
        "{11111111-2222-3333-4444-555555555555}"
    );
    assert_eq!(
        parse_guid_flexible("{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}").unwrap(),
        "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
    );
    assert!(parse_guid_flexible("not-a-guid").is_err());
}

#[test]
fn test_regression_oui_invalid_inputs_mam_fallback_and_csv_comments() {
    // 1. oui_db::parse_prefix_key must reject non-hex / malformed inputs instead of stripping garbage
    let oui = OfflineOuiDb::embedded();
    for bad in [
        "00:50:56:ZZ:ZZ:ZZ",
        "bad-005056",
        "hi-005056",
        "ab:cd:ef:gh:ij:kl",
        "00:50:56:",
        "00:50-56",
        "00-5056",
        "",
    ] {
        assert!(
            matches!(oui.lookup_str(bad), Err(NetError::ParseError(_))),
            "expected ParseError for invalid OUI input '{bad}'"
        );
    }

    // 2. 9-nibble partial prefix under MA-M must fall back to MA-M before MA-L
    let mut custom_oui = OfflineOuiDb::empty();
    let oui_count = custom_oui
        .merge_csv_str(
            "\n# leading comment\n\n\
             Registry,Assignment,Organization Name,Organization Address\n\
             MA-L,00:55:DA,Parent-L,Addr US\n\
             MA-M,00:55:DA:0,Parent-M,Addr US\n\
             MA-S,00:55:DA:01:2,Child-S,Addr US\n",
        )
        .expect("OUI CSV with leading comments and header parses");
    assert_eq!(oui_count, 3);

    let mam_hit = custom_oui.lookup_str("00:55:DA:09:9").expect("9-nibble lookup");
    assert_eq!(mam_hit.registry_block, RegistryBlock::MaM);
    assert_eq!(mam_hit.vendor_name, "Parent-M");
    let mas_hit = custom_oui.lookup_str("00:55:DA:01:2").expect("exact MA-S lookup");
    assert_eq!(mas_hit.registry_block, RegistryBlock::MaS);
    assert_eq!(mas_hit.vendor_name, "Child-S");

    // 3. GeoIP CSV with leading # comment and blank line before header
    let mut geo = OfflineIpDb::empty();
    let geo_count = geo
        .merge_csv_str(
            "# GeoIP override comment\n\n\
             cidr,country_code,country_name,continent,asn,as_name\n\
             1.2.3.0/24,US,United States,NA,64510,TEST-NET\n",
        )
        .expect("GeoIP CSV with leading comment before header parses");
    assert_eq!(geo_count, 1);
    let hit = geo.lookup("1.2.3.4".parse().unwrap());
    assert_eq!(hit.asn, Some(64510));
    assert_eq!(hit.country_code, "US");
}

#[test]
fn test_regression_rdap_is_referral_stub_non_stub_with_related_link() {
    let ripe_resp = RdapHttpResponse {
        final_url: "https://rdap.db.ripe.net/ip/193.0.0.1".to_string(),
        status: 200,
        body: serde_json::json!({
            "startAddress": "193.0.0.0",
            "endAddress": "193.0.7.255",
            "name": "RIPE-NCC",
            "country": "NL",
            "port43": "whois.ripe.net",
            "links": [
                {
                    "rel": "related",
                    "type": "application/rdap+json",
                    "href": "https://rdap.db.ripe.net/autnum/3333"
                }
            ],
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "RIPE Network Coordination Centre"]]]
                }
            ]
        }),
    };
    let parsed_ripe = parse_rdap_ip("193.0.0.1".parse().unwrap(), "RIPE", &ripe_resp).unwrap();
    assert!(
        !parsed_ripe.is_referral_stub,
        "authoritative RIPE RDAP record with rel=related link must not be flagged as referral stub"
    );

    let arin_stub_resp = RdapHttpResponse {
        final_url: "https://rdap.arin.net/registry/ip/193.0.0.1".to_string(),
        status: 200,
        body: serde_json::json!({
            "startAddress": "193.0.0.0",
            "endAddress": "193.0.255.255",
            "port43": "whois.ripe.net",
            "links": [
                {
                    "rel": "related",
                    "type": "application/rdap+json",
                    "href": "https://rdap.db.ripe.net/ip/193.0.0.1"
                }
            ],
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "RIPE"]]]
                }
            ]
        }),
    };
    let parsed_stub = parse_rdap_ip("193.0.0.1".parse().unwrap(), "ARIN", &arin_stub_resp).unwrap();
    assert!(
        parsed_stub.is_referral_stub,
        "cross-RIR RDAP stub with mismatched port43 authority should be flagged as referral stub"
    );
}

#[test]
fn test_regression_oui_space_separated_macs_and_csv_bom_space_comments() {
    // 1. Space-separated 12-nibble full MAC addresses must preserve MA-S > MA-M > MA-L LPM
    let oui = OfflineOuiDb::embedded();
    let mam = oui
        .lookup_str("00 55 DA 5A BC DE")
        .expect("space-separated MA-M MAC lookup");
    assert_eq!(mam.registry_block, RegistryBlock::MaM);
    assert_eq!(mam.vendor_name, "Ubiquiti Inc");
    assert_eq!(mam.mac_prefix, "00:55:DA:5");

    let mas = oui
        .lookup_str("70 B3 D5 1A 20 01")
        .expect("space-separated MA-S MAC lookup");
    assert_eq!(mas.registry_block, RegistryBlock::MaS);
    assert_eq!(mas.vendor_name, "Acme Embedded Systems GmbH");
    assert_eq!(mas.mac_prefix, "70:B3:D5:1A:2");

    let unknown = oui
        .lookup_str("aa bb cc dd ee ff")
        .expect("unknown space-separated MAC returns Unknown Vendor");
    assert_eq!(unknown.registry_block, RegistryBlock::MaL);
    assert_eq!(unknown.mac_prefix, "AA:BB:CC");
    assert_eq!(unknown.vendor_name, "Unknown Vendor");

    // 2. Leading UTF-8 BOM followed by space and '#' must be skipped cleanly in GeoIP and OUI CSVs
    let mut custom_oui = OfflineOuiDb::empty();
    let oui_count = custom_oui
        .merge_csv_str(
            "\u{FEFF} # BOM then space then comment\n\
             \u{FEFF}Registry,Assignment,Organization Name,Organization Address\n\
             MA-L,00:55:DA,Parent-L,Addr US\n",
        )
        .expect("OUI CSV with BOM + space + # comment parses");
    assert_eq!(oui_count, 1);

    let mut geo = OfflineIpDb::empty();
    let geo_count = geo
        .merge_csv_str(
            "\u{FEFF} # BOM then space then comment\n\
             \u{FEFF}cidr,country_code,country_name,continent,asn,as_name\n\
             198.51.100.0/24,US,United States,NA,64511,BOM-TEST-NET\n",
        )
        .expect("GeoIP CSV with BOM + space + # comment parses");
    assert_eq!(geo_count, 1);
    let hit = geo.lookup("198.51.100.42".parse().unwrap());
    assert_eq!(hit.asn, Some(64511));
    assert_eq!(hit.country_code, "US");
}
