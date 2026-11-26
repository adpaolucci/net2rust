#![forbid(unsafe_code)]

pub mod context;
pub mod error;
pub mod net_primitives;
pub mod packet;
pub mod r4;
pub mod types;

pub use context::{ExecutionMode, NetContext, OfflineConfig};
pub use error::{NetError, NetResult};
pub use net_primitives::{CidrV4, CidrV6, MacAddr};
pub use packet::{
    ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_QINQ, ETHERTYPE_VLAN_8021Q, EthernetHeader, IP_PROTO_ICMP,
    IP_PROTO_ICMPV6, IP_PROTO_TCP, IP_PROTO_UDP, Ipv4Header, Ipv6Header, PacketSummary, TcpHeader, UdpHeader,
    parse_ethernet, parse_ipv4, parse_ipv6, parse_tcp, parse_udp, summarize_frame,
};
pub use r4::{FORBIDDEN_WLAN_PROFILE_FLAG, sanitize_cookie_header, sanitize_http_header, sanitize_wlan_profile_xml};
pub use types::{DomainCrateExport, ToolCategory, ToolDescriptor};

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use std::time::Duration;

    use guap_mcp::McpToolError;
    use guap_table::TableError;

    use super::*;

    #[test]
    fn test_net_error_to_table_and_mcp_mappings() {
        let table_err: TableError = NetError::DriverUnavailable("ndis etw missing".into()).into();
        assert!(matches!(table_err, TableError::Provider(ref m) if m.contains("ndis etw missing")));

        let mcp_invalid: McpToolError = NetError::InvalidInput("bad cidr".into()).into();
        assert!(matches!(mcp_invalid, McpToolError::InvalidParams(ref m) if m == "bad cidr"));

        let mcp_not_found: McpToolError = NetError::HardwareNotFound("wlan0".into()).into();
        assert!(matches!(mcp_not_found, McpToolError::NotFound(ref m) if m == "wlan0"));

        // OS-level PermissionDenied MUST map to ExecutionFailed so -32003 remains PolicyMode-only.
        let mcp_perm: McpToolError = NetError::PermissionDenied("admin required".into()).into();
        assert!(matches!(mcp_perm, McpToolError::ExecutionFailed(ref m) if m.contains("admin required")));

        let mcp_io: McpToolError = NetError::Io(io::Error::new(io::ErrorKind::TimedOut, "timed out")).into();
        assert!(matches!(mcp_io, McpToolError::ExecutionFailed(ref m) if m.contains("timed out")));
    }

    #[test]
    fn test_net_context_live_and_offline() {
        let live = NetContext::live();
        assert!(!live.is_offline());
        assert!(live.offline_config().is_none());
        assert!(live.redact_sensitive_headers);
        assert!(live.allow_npcap);
        assert_eq!(live.timeout, Duration::from_secs(5));

        let cfg = OfflineConfig {
            scenario: Some("synthetic".into()),
            ..OfflineConfig::default()
        };
        let offline = NetContext::offline(cfg.clone())
            .with_max_rows(Some(2))
            .with_allow_npcap(false);
        assert!(offline.is_offline());
        assert_eq!(offline.offline_config(), Some(&cfg));
        assert!(!offline.allow_npcap);
        assert!(offline.redact_sensitive_headers);

        let mut rows = vec![1, 2, 3, 4];
        offline.apply_row_limit(&mut rows);
        assert_eq!(rows, vec![1, 2]);
    }

    #[test]
    fn test_tool_category_roundtrip() {
        for &cat in ToolCategory::all() {
            let parsed = ToolCategory::from_str(cat.as_str()).unwrap();
            assert_eq!(parsed, cat);
            assert_eq!(cat.to_string(), cat.as_str());
        }
        assert!(ToolCategory::from_str("cred").is_err());
    }

    #[test]
    fn test_mac_addr_parsing_formatting_and_flags() {
        let expected = MacAddr::new([0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
        assert_eq!(MacAddr::from_str("02:1A:2B:3C:4D:5E").unwrap(), expected);
        assert_eq!(MacAddr::from_str("02-1a-2b-3c-4d-5e").unwrap(), expected);
        assert_eq!(MacAddr::from_str("021a2b3c4d5e").unwrap(), expected);
        assert_eq!(MacAddr::from_str("021a.2b3c.4d5e").unwrap(), expected);

        assert_eq!(expected.to_colon_string(), "02:1a:2b:3c:4d:5e");
        assert_eq!(expected.to_dash_string(), "02-1a-2b-3c-4d-5e");
        assert_eq!(expected.oui_prefix(), [0x02, 0x1a, 0x2b]);
        assert_eq!(expected.oui_hex(), "021A2B");
        assert!(!expected.is_multicast());
        assert!(expected.is_locally_administered());
        assert!(!expected.is_broadcast());
        assert!(!expected.is_zero());

        let mcast = MacAddr::from_str("01:00:5e:00:00:01").unwrap();
        assert!(mcast.is_multicast());
        assert!(!mcast.is_locally_administered());

        let bcast = MacAddr::from_str("ff:ff:ff:ff:ff:ff").unwrap();
        assert!(bcast.is_broadcast());
        assert!(bcast.is_multicast());

        let json = serde_json::to_string(&expected).unwrap();
        assert_eq!(json, "\"02:1a:2b:3c:4d:5e\"");
        let back: MacAddr = serde_json::from_str(&json).unwrap();
        assert_eq!(back, expected);

        assert!(MacAddr::from_str("").is_err());
        assert!(MacAddr::from_str("02:1a:2b:3c:4d").is_err());
        assert!(MacAddr::from_str("zz:1a:2b:3c:4d:5e").is_err());
        assert!(MacAddr::from_str("02:1a-2b:3c:4d:5e").is_err());
    }

    #[test]
    fn test_cidr_v4_and_v6() {
        let v4 = CidrV4::from_str("192.168.10.42/24").unwrap();
        assert_eq!(v4.network(), Ipv4Addr::new(192, 168, 10, 0));
        assert_eq!(v4.prefix_len(), 24);
        assert_eq!(v4.netmask(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(v4.broadcast(), Ipv4Addr::new(192, 168, 10, 255));
        assert_eq!(v4.host_count(), 256);
        assert!(v4.contains(Ipv4Addr::new(192, 168, 10, 1)));
        assert!(!v4.contains(Ipv4Addr::new(192, 168, 11, 1)));
        assert_eq!(v4.to_string(), "192.168.10.0/24");

        let default_v4 = CidrV4::from_str("0.0.0.0/0").unwrap();
        assert_eq!(default_v4.broadcast(), Ipv4Addr::new(255, 255, 255, 255));
        assert!(default_v4.contains(Ipv4Addr::new(8, 8, 8, 8)));

        assert!(CidrV4::from_str("10.0.0.1/33").is_err());
        assert!(CidrV4::from_str("10.0.0.1").is_err());

        let v6 = CidrV6::from_str("2001:db8:abcd:0012::1/64").unwrap();
        assert_eq!(v6.network(), Ipv6Addr::from_str("2001:db8:abcd:12::").unwrap());
        assert_eq!(v6.prefix_len(), 64);
        assert!(v6.contains(Ipv6Addr::from_str("2001:db8:abcd:12::ffff").unwrap()));
        assert!(!v6.contains(Ipv6Addr::from_str("2001:db8:abcd:13::1").unwrap()));

        let default_v6 = CidrV6::from_str("::/0").unwrap();
        assert!(default_v6.contains(Ipv6Addr::LOCALHOST));
        assert!(CidrV6::from_str("::/129").is_err());
    }

    #[test]
    fn test_packet_parsers_ipv4_tcp_and_vlan() {
        // Ethernet (14) + 802.1Q VLAN 100 (4) + IPv4 (20) + TCP (20) + payload (4) = 62 bytes
        let mut frame = Vec::new();
        // dst mac
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        // src mac
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // 802.1Q ethertype + VLAN ID 100 + inner IPv4 ethertype
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&100u16.to_be_bytes());
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        // IPv4 header (20 bytes, total_length = 44, proto = 6 TCP)
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x2c, // ver/ihl, tos, total_len=44
            0x12, 0x34, 0x40, 0x00, // id, DF flag, frag=0
            64, 6, 0x00, 0x00, // ttl, proto=TCP, checksum
            192, 168, 1, 10, // src ip
            93, 184, 216, 34, // dst ip
        ]);
        // TCP header (20 bytes, data_offset=5, SYN|ACK = 0x0012)
        frame.extend_from_slice(&[
            0xd4, 0x31, 0x01, 0xbb, // src 54321, dst 443
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x02, // ack
            0x50, 0x12, 0xfa, 0xf0, // offset=5, flags=SYN|ACK, win
            0x00, 0x00, 0x00, 0x00, // checksum, urg
        ]);
        frame.extend_from_slice(b"PING");

        let summary = summarize_frame(&frame).unwrap();
        assert_eq!(summary.ethernet.vlan_id, Some(100));
        assert_eq!(summary.ethernet.ethertype, ETHERTYPE_IPV4);
        assert_eq!(summary.src_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
        assert_eq!(summary.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert_eq!(summary.ip_protocol, Some(IP_PROTO_TCP));
        assert_eq!(summary.src_port, Some(54321));
        assert_eq!(summary.dst_port, Some(443));
        assert_eq!(summary.tcp_flags, Some(0x0012));
        assert_eq!(summary.tcp.unwrap().flag_names(), "ACK|SYN");
        assert_eq!(summary.payload_offset, 58);
        assert_eq!(summary.payload_len, 4);
    }

    #[test]
    fn test_packet_parsers_ipv6_udp_and_malformed_bounds() {
        // Ethernet (14) + IPv6 (40) + UDP (8) + payload (3)
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame.extend_from_slice(&0x86DDu16.to_be_bytes());
        frame.extend_from_slice(&[
            0x60, 0x00, 0x00, 0x00, // v6
            0x00, 0x0b, 17, 64, // payload_len = 11 (8 UDP + 3 data), next=UDP, hop=64
        ]);
        frame.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        frame.extend_from_slice(&Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888).octets());
        frame.extend_from_slice(&[
            0x14, 0xe9, 0x14, 0xe9, // 5353 -> 5353
            0x00, 0x0b, 0x00, 0x00, // len=11, checksum
        ]);
        frame.extend_from_slice(b"DNS");

        let summary = summarize_frame(&frame).unwrap();
        assert_eq!(summary.src_ip, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(summary.src_port, Some(5353));
        assert_eq!(summary.dst_port, Some(5353));
        assert_eq!(summary.payload_len, 3);

        // Truncated/invalid bounds checks must return Err, never panic.
        assert!(parse_ethernet(&[0u8; 13]).is_err());
        assert!(parse_ipv4(&[0x45, 0, 0, 20]).is_err());
        assert!(parse_ipv4(&[0x65; 20]).is_err()); // wrong version
        assert!(parse_ipv4(&[0x44; 20]).is_err()); // IHL < 5
        assert!(parse_ipv6(&[0x60; 39]).is_err());
        assert!(parse_tcp(&[0u8; 19]).is_err());
        assert!(parse_tcp(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(parse_udp(&[0u8; 7]).is_err());
        assert!(parse_udp(&[0, 80, 0, 80, 0, 4, 0, 0]).is_err());

        // Declared lengths exceeding available slice must return Err (no silent clamping).
        let mut ipv4_over = [0u8; 20];
        ipv4_over[0] = 0x45;
        ipv4_over[2..4].copy_from_slice(&100u16.to_be_bytes());
        assert!(parse_ipv4(&ipv4_over).is_err());

        let mut ipv6_over = [0u8; 40];
        ipv6_over[0] = 0x60;
        ipv6_over[4..6].copy_from_slice(&100u16.to_be_bytes());
        assert!(parse_ipv6(&ipv6_over).is_err());

        let udp_over = [0, 80, 0, 80, 0, 100, 0, 0];
        assert!(parse_udp(&udp_over).is_err());
    }

    #[test]
    fn test_summarize_frame_non_initial_ipv4_fragment() {
        // Ethernet (14) + IPv4 (20, total_length=24, proto=TCP, fragment_offset=2 -> 16-byte offset) + 4 bytes fragment payload
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&[
            0x45,
            0x00,
            0x00,
            0x18, // total_length = 24
            0x12,
            0x34,
            0x00,
            0x02, // fragment_offset = 2 (non-initial)
            64,
            IP_PROTO_TCP,
            0x00,
            0x00, // proto = TCP
            10,
            0,
            0,
            1, // src
            10,
            0,
            0,
            2, // dst
        ]);
        frame.extend_from_slice(b"FRAG");

        let summary = summarize_frame(&frame).unwrap();
        assert_eq!(summary.ip_protocol, Some(IP_PROTO_TCP));
        assert_eq!(summary.ipv4.unwrap().fragment_offset, 2);
        assert_eq!(summary.src_port, None);
        assert_eq!(summary.dst_port, None);
        assert_eq!(summary.tcp_flags, None);
        assert!(summary.tcp.is_none());
        assert!(summary.udp.is_none());
        assert_eq!(summary.payload_offset, 34);
        assert_eq!(summary.payload_len, 4);
    }

    #[test]
    fn test_r4_sanitizers() {
        assert_eq!(FORBIDDEN_WLAN_PROFILE_FLAG, 0x0000_0004);

        assert_eq!(
            sanitize_http_header("Authorization", "Bearer super-secret-jwt"),
            "[REDACTED]"
        );
        assert_eq!(
            sanitize_http_header("proxy-authorization", "Basic dXNlcjpwYXNz"),
            "[REDACTED]"
        );
        assert_eq!(sanitize_http_header("X-Api-Key", "live_key_12345"), "[REDACTED]");
        assert_eq!(sanitize_http_header("X-Auth-Token", "tok_abc"), "[REDACTED]");
        assert_eq!(
            sanitize_http_header("Content-Type", "application/json"),
            "application/json"
        );

        let cookie = "theme=dark; JSESSIONID=secret123; auth_token=xyz; lang=en-US";
        assert_eq!(
            sanitize_http_header("Cookie", cookie),
            "theme=dark; JSESSIONID=[REDACTED]; auth_token=[REDACTED]; lang=en-US"
        );

        let set_cookie =
            "my_session_id=abc999; Path=/; Domain=.example.com; HttpOnly; Secure; SameSite=Lax; Max-Age=3600";
        assert_eq!(
            sanitize_http_header("Set-Cookie", set_cookie),
            "my_session_id=[REDACTED]; Path=/; Domain=.example.com; HttpOnly; Secure; SameSite=Lax; Max-Age=3600"
        );

        let wlan_xml = r#"<WLANProfile>
  <MSM>
    <security>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>SuperSecretWiFiPassphrase!</keyMaterial>
      </sharedKey>
    </security>
  </MSM>
</WLANProfile>"#;
        let sanitized_xml = sanitize_wlan_profile_xml(wlan_xml);
        assert!(!sanitized_xml.contains("SuperSecretWiFiPassphrase!"));
        assert!(sanitized_xml.contains("<keyMaterial>[REDACTED]</keyMaterial>"));

        let multiline_case = "<KEYMATERIAL attr=\"1\">\n  secret-line-1\n  secret-line-2\n</KeyMaterial>";
        assert_eq!(
            sanitize_wlan_profile_xml(multiline_case),
            "<keyMaterial>[REDACTED]</keyMaterial>"
        );

        let truncated_xml = "<keyMaterial>partial-secret-without-end";
        assert_eq!(
            sanitize_wlan_profile_xml(truncated_xml),
            "<keyMaterial>[REDACTED]</keyMaterial>"
        );

        // Hardening: non-standard auth headers and Set-Cookie2
        assert_eq!(sanitize_http_header("X-Auth", "secret-auth"), "[REDACTED]");
        assert_eq!(sanitize_http_header("X-Token", "secret-token"), "[REDACTED]");
        assert_eq!(sanitize_http_header("X-Session-Id", "sess-xyz"), "[REDACTED]");
        assert_eq!(sanitize_http_header("X-Jwt-Token", "eyJabc.def.ghi"), "[REDACTED]");
        assert_eq!(sanitize_http_header("X-Bearer-Token", "bearer-123"), "[REDACTED]");
        assert_eq!(
            sanitize_http_header("Set-Cookie2", "session_id=topsecret; Version=1"),
            "session_id=[REDACTED]; Version=1"
        );

        // Hardening: quote-aware opening tag scanning against spoofed `/>` inside attributes
        let quoted_gt_double = r#"<WLANProfile><keyMaterial attr="x/>">LEAKED_WIFI_PASS</keyMaterial></WLANProfile>"#;
        let out_double = sanitize_wlan_profile_xml(quoted_gt_double);
        assert!(!out_double.contains("LEAKED_WIFI_PASS"));
        assert_eq!(
            out_double,
            "<WLANProfile><keyMaterial>[REDACTED]</keyMaterial></WLANProfile>"
        );

        let quoted_gt_single = "<WLANProfile><keyMaterial attr='x/>'>LEAKED_SINGLE</keyMaterial ></WLANProfile>";
        let out_single = sanitize_wlan_profile_xml(quoted_gt_single);
        assert!(!out_single.contains("LEAKED_SINGLE"));
        assert_eq!(
            out_single,
            "<WLANProfile><keyMaterial>[REDACTED]</keyMaterial></WLANProfile>"
        );

        let self_closing_quoted = r#"<WLANProfile><keyMaterial attr="x/>" /></WLANProfile>"#;
        assert_eq!(sanitize_wlan_profile_xml(self_closing_quoted), self_closing_quoted);

        // Hardening: namespace prefix + closing tag trailing whitespace + keyMaterialType preservation
        let namespaced_xml = "<wlan:WLANProfile><wlan:keyMaterialType>passPhrase</wlan:keyMaterialType><wlan:keyMaterial>NS_LEAKED_PASS</wlan:keyMaterial ></wlan:WLANProfile>";
        let out_ns = sanitize_wlan_profile_xml(namespaced_xml);
        assert!(!out_ns.contains("NS_LEAKED_PASS"));
        assert!(out_ns.contains("<wlan:keyMaterialType>passPhrase</wlan:keyMaterialType>"));
        assert_eq!(
            out_ns,
            "<wlan:WLANProfile><wlan:keyMaterialType>passPhrase</wlan:keyMaterialType><wlan:keyMaterial>[REDACTED]</wlan:keyMaterial></wlan:WLANProfile>"
        );

        let non_ns_type = "<keyMaterialType>passPhrase</keyMaterialType>";
        assert_eq!(sanitize_wlan_profile_xml(non_ns_type), non_ns_type);
    }
}
