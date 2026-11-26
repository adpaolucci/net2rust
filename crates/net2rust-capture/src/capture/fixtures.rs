//! Deterministic pure-Rust synthetic packet, PCAP, PCAPNG, and NDIS-ETW fixtures covering all 11 tools,
//! R4 adversarial redaction cases, Karn's TCP retransmission RTT edge case, and malformed DNS loops.

use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};

use super::etw_ndis::encode_packets_as_synthetic_etl;
use super::pcap::{Endianness, encode_pcap_le_us};
use super::pcapng::encode_pcapng;
use super::{CapturedPacket, LinkType};

pub fn base_timestamp() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 20, 12, 0, 0).unwrap()
}

pub fn build_eth_frame(dst: [u8; 6], src: [u8; 6], ethertype: u16, vlan: Option<u16>, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(18 + payload.len());
    out.extend_from_slice(&dst);
    out.extend_from_slice(&src);
    if let Some(vid) = vlan {
        out.extend_from_slice(&0x8100u16.to_be_bytes());
        out.extend_from_slice(&vid.to_be_bytes());
    }
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn build_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = (20 + payload.len()) as u16;
    let mut out = Vec::with_capacity(usize::from(total_len));
    out.push(0x45);
    out.push(0x00);
    out.extend_from_slice(&total_len.to_be_bytes());
    out.extend_from_slice(&0x1234u16.to_be_bytes());
    out.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
    out.push(64);
    out.push(proto);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(payload);
    out
}

pub fn build_ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(40 + payload.len());
    out.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.push(next_header);
    out.push(64);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(payload);
    out
}

pub fn build_tcp_segment(src_port: u16, dst_port: u16, seq: u32, ack: u32, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + payload.len());
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&ack.to_be_bytes());
    let off_and_ns = 0x50u8 | (((flags >> 8) as u8) & 0x01);
    out.push(off_and_ns);
    out.push((flags & 0xFF) as u8);
    out.extend_from_slice(&65535u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(payload);
    out
}

pub fn build_udp_datagram(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let len = (8 + payload.len()) as u16;
    let mut out = Vec::with_capacity(usize::from(len));
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    out
}

fn build_arp(oper: u16, sha: [u8; 6], spa: Ipv4Addr, tha: [u8; 6], tpa: Ipv4Addr) -> Vec<u8> {
    let mut out = Vec::with_capacity(28);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0x0800u16.to_be_bytes());
    out.push(6);
    out.push(4);
    out.extend_from_slice(&oper.to_be_bytes());
    out.extend_from_slice(&sha);
    out.extend_from_slice(&spa.octets());
    out.extend_from_slice(&tha);
    out.extend_from_slice(&tpa.octets());
    out
}

fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let trimmed = name.trim_end_matches('.');
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    out
}

fn build_dns_query(tx_id: u16, qname: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tx_id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query RD=1
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&encode_dns_name(qname));
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&qclass.to_be_bytes());
    out
}

fn build_dns_response(tx_id: u16, qname: &str, qtype: u16, rcode: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let flags = 0x8180u16 | (rcode & 0x000F);
    out.extend_from_slice(&tx_id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&1u16.to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&encode_dns_name(qname));
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    // Answer RR using compression pointer to offset 12 (0xC00C)
    out.extend_from_slice(&[0xC0, 0x0C]);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

#[allow(clippy::too_many_arguments)]
fn build_dhcp_packet(
    op: u8,
    xid: u32,
    mac: [u8; 6],
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    siaddr: Ipv4Addr,
    msg_type: u8,
    extra_opts: &[u8],
) -> Vec<u8> {
    let mut out = vec![0u8; 240];
    out[0] = op;
    out[1] = 1; // htype Ethernet
    out[2] = 6; // hlen
    out[4..8].copy_from_slice(&xid.to_be_bytes());
    out[12..16].copy_from_slice(&ciaddr.octets());
    out[16..20].copy_from_slice(&yiaddr.octets());
    out[20..24].copy_from_slice(&siaddr.octets());
    out[28..34].copy_from_slice(&mac);
    out[236..240].copy_from_slice(&0x6382_5363u32.to_be_bytes());
    // Option 53: DHCP Message Type
    out.extend_from_slice(&[53, 1, msg_type]);
    out.extend_from_slice(extra_opts);
    out.push(255); // End
    out
}

fn build_mdns_announcement() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_be_bytes()); // tx_id 0
    out.extend_from_slice(&0x8400u16.to_be_bytes()); // response, authoritative
    out.extend_from_slice(&0u16.to_be_bytes()); // qd
    out.extend_from_slice(&1u16.to_be_bytes()); // an = 1 (PTR)
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&3u16.to_be_bytes()); // ar = 3 (SRV, TXT, A)

    // PTR: _ipp._tcp.local -> Office Printer._ipp._tcp.local
    let svc_type = encode_dns_name("_ipp._tcp.local");
    let inst_name = encode_dns_name("Office Printer._ipp._tcp.local");
    out.extend_from_slice(&svc_type);
    out.extend_from_slice(&12u16.to_be_bytes()); // PTR
    out.extend_from_slice(&0x0001u16.to_be_bytes()); // IN
    out.extend_from_slice(&4500u32.to_be_bytes());
    out.extend_from_slice(&(inst_name.len() as u16).to_be_bytes());
    out.extend_from_slice(&inst_name);

    // Additional SRV (with cache-flush 0x8001)
    let target = encode_dns_name("printer.local");
    out.extend_from_slice(&inst_name);
    out.extend_from_slice(&33u16.to_be_bytes()); // SRV
    out.extend_from_slice(&0x8001u16.to_be_bytes());
    out.extend_from_slice(&120u32.to_be_bytes());
    out.extend_from_slice(&((6 + target.len()) as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // priority
    out.extend_from_slice(&0u16.to_be_bytes()); // weight
    out.extend_from_slice(&631u16.to_be_bytes()); // port
    out.extend_from_slice(&target);

    // Additional TXT (cache-flush 0x8001)
    let txt1 = b"path=/ipp/print";
    let txt2 = b"ty=LaserJet";
    let txt_len = 1 + txt1.len() + 1 + txt2.len();
    out.extend_from_slice(&inst_name);
    out.extend_from_slice(&16u16.to_be_bytes()); // TXT
    out.extend_from_slice(&0x8001u16.to_be_bytes());
    out.extend_from_slice(&4500u32.to_be_bytes());
    out.extend_from_slice(&(txt_len as u16).to_be_bytes());
    out.push(txt1.len() as u8);
    out.extend_from_slice(txt1);
    out.push(txt2.len() as u8);
    out.extend_from_slice(txt2);

    // Additional A (cache-flush 0x8001)
    out.extend_from_slice(&target);
    out.extend_from_slice(&1u16.to_be_bytes()); // A
    out.extend_from_slice(&0x8001u16.to_be_bytes());
    out.extend_from_slice(&120u32.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&[192, 168, 1, 50]);

    out
}

fn encode_netbios_name(name: &str, suffix: u8) -> Vec<u8> {
    let mut padded = [b' '; 16];
    for (i, b) in name.as_bytes().iter().take(15).enumerate() {
        padded[i] = b.to_ascii_uppercase();
    }
    padded[15] = suffix;
    let mut out = Vec::with_capacity(34);
    out.push(32);
    for byte in padded {
        out.push(b'A' + (byte >> 4));
        out.push(b'A' + (byte & 0x0F));
    }
    out.push(0);
    out
}

fn build_nbns_registration(name: &str, ip: Ipv4Addr) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x1122u16.to_be_bytes());
    out.extend_from_slice(&0x2910u16.to_be_bytes()); // registration request
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // arcount
    out.extend_from_slice(&encode_netbios_name(name, 0x00));
    out.extend_from_slice(&0x0020u16.to_be_bytes()); // NB
    out.extend_from_slice(&0x0001u16.to_be_bytes()); // IN
    out.extend_from_slice(&encode_netbios_name(name, 0x00));
    out.extend_from_slice(&0x0020u16.to_be_bytes());
    out.extend_from_slice(&0x0001u16.to_be_bytes());
    out.extend_from_slice(&300u32.to_be_bytes());
    out.extend_from_slice(&6u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&ip.octets());
    out
}

#[allow(clippy::too_many_arguments)]
fn build_radiotap_beacon(
    ssid: &str,
    bssid: [u8; 6],
    freq_mhz: u16,
    channel: u8,
    rssi_dbm: i8,
    beacon_interval: u16,
    is_he: bool,
    with_wpa3: bool,
) -> Vec<u8> {
    // RadioTap header: version=0, pad=0, it_len=18, it_present = TSFT(0x01)|Flags(0x02)|Rate(0x04)|Channel(0x08)|AntSignal(0x20) = 0x2F?
    // Wait: using Flags(1)+Rate(2)+Channel(3)+AntSignal(5) = bitmask 0x0000_002E:
    // Header = 8B -> Flags(1B @8), Rate(1B @9), Channel(4B @10, already 2-byte aligned!), AntSignal(1B @14) => total 15B (pad to 16B).
    let mut rt = Vec::new();
    rt.push(0); // version
    rt.push(0); // pad
    rt.extend_from_slice(&16u16.to_le_bytes()); // it_len = 16
    rt.extend_from_slice(&0x0000_002Eu32.to_le_bytes()); // Flags + Rate + Channel + AntSignal
    rt.push(0x10); // Flags: bit 0x10 = FCS present at end
    rt.push(12); // Rate: 6 Mbps (12 * 500 kbps)
    rt.extend_from_slice(&freq_mhz.to_le_bytes());
    let ch_flags: u16 = if freq_mhz >= 5000 { 0x0140 } else { 0x00A0 };
    rt.extend_from_slice(&ch_flags.to_le_bytes());
    rt.push(rssi_dbm as u8);
    rt.push(0); // padding to 16 bytes

    // 802.11 Beacon Management Header (24 bytes)
    let mut dot11 = Vec::new();
    dot11.extend_from_slice(&0x0080u16.to_le_bytes()); // Type 0 (Mgmt), Subtype 8 (Beacon)
    dot11.extend_from_slice(&0u16.to_le_bytes()); // duration
    dot11.extend_from_slice(&[0xff; 6]); // addr1 DA
    dot11.extend_from_slice(&bssid); // addr2 SA
    dot11.extend_from_slice(&bssid); // addr3 BSSID
    dot11.extend_from_slice(&0x0010u16.to_le_bytes()); // seq_ctrl

    // Fixed parameters (12 bytes): timestamp (8), beacon_interval (2), capability (2)
    dot11.extend_from_slice(&[0u8; 8]);
    dot11.extend_from_slice(&beacon_interval.to_le_bytes());
    dot11.extend_from_slice(&0x0411u16.to_le_bytes()); // ESS + Privacy

    // IE 0: SSID
    dot11.push(0);
    dot11.push(ssid.len() as u8);
    dot11.extend_from_slice(ssid.as_bytes());

    // IE 3: DS Parameter Set (channel)
    dot11.push(3);
    dot11.push(1);
    dot11.push(channel);

    // IE 45: HT Capabilities (26 bytes)
    dot11.push(45);
    dot11.push(26);
    dot11.extend_from_slice(&[0u8; 26]);

    if is_he {
        // IE 255 + ext 35: HE Capabilities
        dot11.push(255);
        dot11.push(4);
        dot11.push(35);
        dot11.extend_from_slice(&[0u8; 3]);
    } else {
        // IE 191: VHT Capabilities (12 bytes)
        dot11.push(191);
        dot11.push(12);
        dot11.extend_from_slice(&[0u8; 12]);
    }

    // IE 48: RSN
    let mut rsn = Vec::new();
    rsn.extend_from_slice(&1u16.to_le_bytes()); // version 1
    rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // group CCMP
    rsn.extend_from_slice(&1u16.to_le_bytes()); // pairwise count
    rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // CCMP
    if with_wpa3 {
        rsn.extend_from_slice(&2u16.to_le_bytes()); // 2 AKMs: PSK + SAE (WPA2/WPA3)
        rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x02]);
        rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x08]);
    } else {
        rsn.extend_from_slice(&1u16.to_le_bytes()); // 1 AKM: PSK (WPA2-PSK)
        rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x02]);
    }
    rsn.extend_from_slice(&0u16.to_le_bytes()); // RSN caps
    dot11.push(48);
    dot11.push(rsn.len() as u8);
    dot11.extend_from_slice(&rsn);

    // 4-byte trailing FCS (matches Flags & 0x10)
    dot11.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    rt.extend_from_slice(&dot11);
    rt
}

fn build_radiotap_probe_req(ssid: &str, sa: [u8; 6], freq_mhz: u16, rssi_dbm: i8) -> Vec<u8> {
    let mut rt = Vec::new();
    rt.push(0);
    rt.push(0);
    rt.extend_from_slice(&16u16.to_le_bytes());
    rt.extend_from_slice(&0x0000_002Eu32.to_le_bytes());
    rt.push(0x00); // no FCS
    rt.push(2); // 1 Mbps
    rt.extend_from_slice(&freq_mhz.to_le_bytes());
    rt.extend_from_slice(&0x00A0u16.to_le_bytes());
    rt.push(rssi_dbm as u8);
    rt.push(0);

    // 802.11 Probe Request (subtype 4): 24-byte header, NO fixed params!
    rt.extend_from_slice(&0x0040u16.to_le_bytes());
    rt.extend_from_slice(&0u16.to_le_bytes());
    rt.extend_from_slice(&[0xff; 6]); // DA
    rt.extend_from_slice(&sa); // SA
    rt.extend_from_slice(&[0xff; 6]); // BSSID
    rt.extend_from_slice(&0x0020u16.to_le_bytes());

    rt.push(0);
    rt.push(ssid.len() as u8);
    rt.extend_from_slice(ssid.as_bytes());
    rt
}

pub fn build_malformed_dns_packets() -> Vec<CapturedPacket> {
    let t0 = base_timestamp();
    let client_mac = [0x08, 0x00, 0x27, 0x11, 0x22, 0x33];
    let dns_mac = [0x00, 0x50, 0x56, 0xaa, 0xbb, 0xcc];
    let client_ip = Ipv4Addr::new(192, 168, 1, 25);
    let dns_ip = Ipv4Addr::new(8, 8, 8, 8);

    // 1. Self-referential DNS compression pointer loop (0xC0 0x0C at offset 12)
    let mut loop_dns = vec![
        0xBA, 0xAD, 0x01, 0x00, // tx_id=0xBAAD, flags
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    loop_dns.extend_from_slice(&[0xC0, 0x0C]); // points directly to offset 12!
    loop_dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    // 2. Out-of-bounds compression pointer (0xC0 0xFF)
    let mut oob_dns = vec![
        0xDE, 0xAD, 0x01, 0x00, // tx_id=0xDEAD, flags
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    oob_dns.extend_from_slice(&[0xC0, 0xFF]); // OOB pointer
    oob_dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    vec![
        CapturedPacket {
            packet_no: 1,
            timestamp: Some(t0),
            link_type: LinkType::Ethernet,
            original_len: 0,
            interface_id: Some(0),
            interface_name: Some("eth0".to_string()),
            data: build_eth_frame(
                dns_mac,
                client_mac,
                0x0800,
                None,
                &build_ipv4_packet(client_ip, dns_ip, 17, &build_udp_datagram(54001, 53, &loop_dns)),
            ),
        },
        CapturedPacket {
            packet_no: 2,
            timestamp: Some(t0 + ChronoDuration::milliseconds(5)),
            link_type: LinkType::Ethernet,
            original_len: 0,
            interface_id: Some(0),
            interface_name: Some("eth0".to_string()),
            data: build_eth_frame(
                dns_mac,
                client_mac,
                0x0800,
                None,
                &build_ipv4_packet(client_ip, dns_ip, 17, &build_udp_datagram(54002, 53, &oob_dns)),
            ),
        },
    ]
    .into_iter()
    .map(|mut p| {
        p.original_len = p.data.len() as u32;
        p
    })
    .collect()
}

pub fn build_default_fixture_packets(scenario: Option<&str>) -> Vec<CapturedPacket> {
    if scenario == Some("malformed-dns") {
        return build_malformed_dns_packets();
    }

    let t0 = base_timestamp();
    let mut pkts: Vec<CapturedPacket> = Vec::new();
    let mut push_eth = |offset_us: i64, frame: Vec<u8>| {
        let len = frame.len() as u32;
        pkts.push(CapturedPacket {
            packet_no: (pkts.len() + 1) as u64,
            timestamp: Some(t0 + ChronoDuration::microseconds(offset_us)),
            link_type: LinkType::Ethernet,
            original_len: len,
            interface_id: Some(0),
            interface_name: Some("eth0".to_string()),
            data: frame,
        });
    };

    let client_mac = [0x08, 0x00, 0x27, 0x11, 0x22, 0x33]; // VirtualBox
    let router_mac = [0x00, 0x50, 0x56, 0xaa, 0xbb, 0xcc]; // VMware
    let printer_mac = [0xb8, 0x27, 0xeb, 0x44, 0x55, 0x66]; // Raspberry Pi

    let client_ip = Ipv4Addr::new(192, 168, 1, 25);
    let router_ip = Ipv4Addr::new(192, 168, 1, 1);
    let printer_ip = Ipv4Addr::new(192, 168, 1, 50);
    let web_ip = Ipv4Addr::new(93, 184, 216, 34);
    let dns_ip = Ipv4Addr::new(8, 8, 8, 8);

    // 1. ARP Request & Reply
    push_eth(
        0,
        build_eth_frame(
            [0xff; 6],
            client_mac,
            0x0806,
            None,
            &build_arp(1, client_mac, client_ip, [0; 6], router_ip),
        ),
    );
    push_eth(
        1_200,
        build_eth_frame(
            client_mac,
            router_mac,
            0x0806,
            None,
            &build_arp(2, router_mac, router_ip, client_mac, client_ip),
        ),
    );

    // 2. TCP Handshake #1 (valid RTT = 12.5 ms) + HTTP multi-segment + chunked + R4 secrets
    let mut seq_c = 1000u32;
    let seq_s = 5000u32;
    push_eth(
        10_000,
        build_eth_frame(
            router_mac,
            client_mac,
            0x0800,
            Some(100),
            &build_ipv4_packet(
                client_ip,
                web_ip,
                6,
                &build_tcp_segment(54321, 80, seq_c, 0, 0x0002, b""),
            ),
        ),
    );
    seq_c += 1;
    push_eth(
        22_500, // +12.500 ms RTT
        build_eth_frame(
            client_mac,
            router_mac,
            0x0800,
            Some(100),
            &build_ipv4_packet(
                web_ip,
                client_ip,
                6,
                &build_tcp_segment(80, 54321, seq_s, seq_c, 0x0012, b""),
            ),
        ),
    );
    let ack_s = seq_s + 1;
    push_eth(
        23_000,
        build_eth_frame(
            router_mac,
            client_mac,
            0x0800,
            Some(100),
            &build_ipv4_packet(
                client_ip,
                web_ip,
                6,
                &build_tcp_segment(54321, 80, seq_c, ack_s, 0x0010, b""),
            ),
        ),
    );

    // Split HTTP request across 2 TCP segments (with R4 test headers/cookies/query)
    let http_req_1 = b"GET /assets/app.js?token=leak123&v=2 HTTP/1.1\r\nHost: cdn.example.com\r\nAuthorization: Basic dXNlcjpzZWNyZXQ=\r\n";
    let http_req_2 = b"Proxy-Authorization: Bearer tok123\r\nX-Api-Key: secret_api_val\r\nCookie: theme=dark; JSESSIONID=s1; auth_token=t1\r\nUser-Agent: Net2RustTest/1.0\r\n\r\n";
    push_eth(
        24_000,
        build_eth_frame(
            router_mac,
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                client_ip,
                web_ip,
                6,
                &build_tcp_segment(54321, 80, seq_c, ack_s, 0x0018, http_req_1),
            ),
        ),
    );
    seq_c += http_req_1.len() as u32;
    push_eth(
        24_500,
        build_eth_frame(
            router_mac,
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                client_ip,
                web_ip,
                6,
                &build_tcp_segment(54321, 80, seq_c, ack_s, 0x0018, http_req_2),
            ),
        ),
    );
    seq_c += http_req_2.len() as u32;

    let http_resp_1 = b"HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\nContent-Type: application/javascript; charset=utf-8\r\nSet-Cookie: sid=s2; Domain=.example.com; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600\r\nSet-Cookie: prefs=compact; Path=/\r\nTransfer-Encoding: chunked\r\n\r\n13\r\nconsole.log(\"ok\");\n\r\n0\r\n\r\n";
    push_eth(
        35_000,
        build_eth_frame(
            client_mac,
            router_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                web_ip,
                client_ip,
                6,
                &build_tcp_segment(80, 54321, ack_s, seq_c, 0x0018, http_resp_1),
            ),
        ),
    );

    // Second pipelined benign HTML asset on same TCP connection
    let ack_s2 = ack_s + http_resp_1.len() as u32;
    let http_req_3 = b"GET /index.html HTTP/1.1\r\nHost: cdn.example.com\r\nUser-Agent: Net2RustTest/1.0\r\n\r\n";
    push_eth(
        40_000,
        build_eth_frame(
            router_mac,
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                client_ip,
                web_ip,
                6,
                &build_tcp_segment(54321, 80, seq_c, ack_s2, 0x0018, http_req_3),
            ),
        ),
    );
    let seq_c2 = seq_c + http_req_3.len() as u32;
    let html_body = b"<!doctype html><html><body>ok</body></html>";
    let http_resp_2 = format!(
        "HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
        html_body.len(),
        std::str::from_utf8(html_body).unwrap()
    );
    push_eth(
        48_000,
        build_eth_frame(
            client_mac,
            router_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                web_ip,
                client_ip,
                6,
                &build_tcp_segment(80, 54321, ack_s2, seq_c2, 0x0019, http_resp_2.as_bytes()),
            ),
        ),
    );

    // 3. TCP Latency Handshake #2 (same client->web:443, 20.0 ms valid RTT) + Handshake #3 (retransmitted SYN -> MUST be excluded by Karn's algorithm!)
    push_eth(
        50_000,
        build_eth_frame(
            router_mac,
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                client_ip,
                web_ip,
                6,
                &build_tcp_segment(54322, 443, 2000, 0, 0x0002, b""),
            ),
        ),
    );
    push_eth(
        70_000, // +20.0 ms
        build_eth_frame(
            client_mac,
            router_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                web_ip,
                client_ip,
                6,
                &build_tcp_segment(443, 54322, 7000, 2001, 0x0012, b""),
            ),
        ),
    );

    // Retransmitted SYN on port 8443 -> must NOT produce a latency sample!
    let slow_ip = Ipv4Addr::new(198, 51, 100, 77);
    push_eth(
        75_000,
        build_eth_frame(
            router_mac,
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                client_ip,
                slow_ip,
                6,
                &build_tcp_segment(54323, 8443, 3000, 0, 0x0002, b""),
            ),
        ),
    );
    push_eth(
        80_000, // retransmitted SYN (same 4-tuple, same seq=3000)
        build_eth_frame(
            router_mac,
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                client_ip,
                slow_ip,
                6,
                &build_tcp_segment(54323, 8443, 3000, 0, 0x0002, b""),
            ),
        ),
    );
    push_eth(
        95_000,
        build_eth_frame(
            client_mac,
            router_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                slow_ip,
                client_ip,
                6,
                &build_tcp_segment(8443, 54323, 9000, 3001, 0x0012, b""),
            ),
        ),
    );

    // 4. IPv6 with Hop-by-Hop extension header (next=0 -> 58 ICMPv6) + ICMPv4 Echo
    push_eth(
        100_000,
        build_eth_frame(
            router_mac,
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(client_ip, dns_ip, 1, &[8, 0, 0, 0, 0x12, 0x34, 0, 1]),
        ),
    );
    let mut hop_by_hop_icmpv6 = vec![58, 0, 0, 0, 0, 0, 0, 0]; // 8-byte Hop-by-Hop -> ICMPv6 (58)
    hop_by_hop_icmpv6.extend_from_slice(&[135, 0, 0, 0, 0, 0, 0, 0]); // NS
    push_eth(
        102_000,
        build_eth_frame(
            router_mac,
            client_mac,
            0x86DD,
            None,
            &build_ipv6_packet(
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
                0,
                &hop_by_hop_icmpv6,
            ),
        ),
    );

    // 5. DNS UDP + TCP (2-byte length prefix) + unanswered query
    push_eth(
        110_000,
        build_eth_frame(
            router_mac,
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                client_ip,
                dns_ip,
                17,
                &build_udp_datagram(51001, 53, &build_dns_query(0x1A2B, "example.com", 1, 1)),
            ),
        ),
    );
    push_eth(
        118_200, // +8.2 ms
        build_eth_frame(
            client_mac,
            router_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                dns_ip,
                client_ip,
                17,
                &build_udp_datagram(
                    53,
                    51001,
                    &build_dns_response(0x1A2B, "example.com", 1, 0, 300, &[93, 184, 216, 34]),
                ),
            ),
        ),
    );
    // Unanswered DNS query
    push_eth(
        120_000,
        build_eth_frame(
            router_mac,
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                client_ip,
                dns_ip,
                17,
                &build_udp_datagram(51002, 53, &build_dns_query(0x3C4D, "unanswered.example.org", 28, 1)),
            ),
        ),
    );
    // DNS over TCP (2-byte length prefix)
    let tcp_dns_q = build_dns_query(0x5E6F, "tcp-dns.example.com", 16, 1);
    let mut tcp_dns_q_framed = (tcp_dns_q.len() as u16).to_be_bytes().to_vec();
    tcp_dns_q_framed.extend_from_slice(&tcp_dns_q);
    push_eth(
        125_000,
        build_eth_frame(
            router_mac,
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                client_ip,
                dns_ip,
                6,
                &build_tcp_segment(52000, 53, 10, 0, 0x0018, &tcp_dns_q_framed),
            ),
        ),
    );
    let txt_rdata = b"\x0bv=spf1 -all";
    let tcp_dns_r = build_dns_response(0x5E6F, "tcp-dns.example.com", 16, 0, 600, txt_rdata);
    let mut tcp_dns_r_framed = (tcp_dns_r.len() as u16).to_be_bytes().to_vec();
    tcp_dns_r_framed.extend_from_slice(&tcp_dns_r);
    push_eth(
        130_000,
        build_eth_frame(
            client_mac,
            router_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                dns_ip,
                client_ip,
                6,
                &build_tcp_segment(
                    53,
                    52000,
                    20,
                    10 + tcp_dns_q_framed.len() as u32,
                    0x0018,
                    &tcp_dns_r_framed,
                ),
            ),
        ),
    );

    // 6. DHCPv4 Discover -> Offer -> Request -> Ack
    let dhcp_discover = build_dhcp_packet(
        1,
        0xCAFE_BABE,
        client_mac,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        1,
        &[
            12, 9, b'l', b'a', b'p', b't', b'o', b'p', b'-', b'0', b'1', 60, 8, b'M', b'S', b'F', b'T', b' ', b'5',
            b'.', b'0',
        ],
    );
    push_eth(
        140_000,
        build_eth_frame(
            [0xff; 6],
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::BROADCAST,
                17,
                &build_udp_datagram(68, 67, &dhcp_discover),
            ),
        ),
    );
    let dhcp_ack = build_dhcp_packet(
        2,
        0xCAFE_BABE,
        client_mac,
        Ipv4Addr::UNSPECIFIED,
        client_ip,
        router_ip,
        5,
        &[
            1, 4, 255, 255, 255, 0, // subnet
            3, 4, 192, 168, 1, 1, // gateway
            6, 4, 8, 8, 8, 8, // DNS
            51, 4, 0, 1, 0x51, 0x80, // 86400s
            54, 4, 192, 168, 1, 1, // server id
        ],
    );
    push_eth(
        145_000,
        build_eth_frame(
            client_mac,
            router_mac,
            0x0800,
            None,
            &build_ipv4_packet(router_ip, client_ip, 17, &build_udp_datagram(67, 68, &dhcp_ack)),
        ),
    );

    // 7. mDNS / DNS-SD announcement (UDP 5353 -> 224.0.0.251)
    push_eth(
        150_000,
        build_eth_frame(
            [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb],
            printer_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                printer_ip,
                Ipv4Addr::new(224, 0, 0, 251),
                17,
                &build_udp_datagram(5353, 5353, &build_mdns_announcement()),
            ),
        ),
    );

    // 8. LAN Discovery: NBNS UDP 137 + SSDP UDP 1900
    push_eth(
        155_000,
        build_eth_frame(
            [0xff; 6],
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                client_ip,
                Ipv4Addr::new(192, 168, 1, 255),
                17,
                &build_udp_datagram(137, 137, &build_nbns_registration("WORKSTATION1", client_ip)),
            ),
        ),
    );
    let ssdp_notify = b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\nSERVER: Windows/10.0 UPnP/1.0 Net2RustHost/1.0\r\nUSN: uuid:12345678-0000-0000-0000-000000000001::upnp:rootdevice\r\nLOCATION: http://192.168.1.25:2869/upnp\r\n\r\n";
    push_eth(
        160_000,
        build_eth_frame(
            [0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa],
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                client_ip,
                Ipv4Addr::new(239, 255, 255, 250),
                17,
                &build_udp_datagram(1900, 1900, ssdp_notify),
            ),
        ),
    );

    // 9. R4 Cleartext Credential Suppression Cases (POP3 110, IMAP 143, FTP 21, SMTP 587)
    let pop3_ip = Ipv4Addr::new(203, 0, 113, 10);
    push_eth(
        170_000,
        build_eth_frame(
            router_mac,
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                client_ip,
                pop3_ip,
                6,
                &build_tcp_segment(55110, 110, 1, 1, 0x0018, b"PASS hunter2\r\n"),
            ),
        ),
    );
    push_eth(
        171_000,
        build_eth_frame(
            router_mac,
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                client_ip,
                pop3_ip,
                6,
                &build_tcp_segment(55143, 143, 1, 1, 0x0018, b"a1 LOGIN alice hunter2\r\n"),
            ),
        ),
    );
    push_eth(
        172_000,
        build_eth_frame(
            router_mac,
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                client_ip,
                pop3_ip,
                6,
                &build_tcp_segment(55021, 21, 1, 1, 0x0018, b"PASS hunter2\r\n"),
            ),
        ),
    );
    push_eth(
        173_000,
        build_eth_frame(
            router_mac,
            client_mac,
            0x0800,
            None,
            &build_ipv4_packet(
                client_ip,
                pop3_ip,
                6,
                &build_tcp_segment(55587, 587, 1, 1, 0x0018, b"AUTH PLAIN AGFsaWNlAGh1bnRlcjI=\r\n"),
            ),
        ),
    );

    // 10. 802.11 RadioTap frames (Beacon + Probe Request) for `capture.wifi-mon`
    let rt1 = build_radiotap_beacon(
        "CorpGuest",
        [0x00, 0x50, 0x56, 0x11, 0x22, 0x33],
        5180,
        36,
        -52,
        100,
        false,
        true,
    );
    pkts.push(CapturedPacket {
        packet_no: (pkts.len() + 1) as u64,
        timestamp: Some(t0 + ChronoDuration::microseconds(180_000)),
        link_type: LinkType::Ieee80211Radiotap,
        original_len: rt1.len() as u32,
        interface_id: Some(1),
        interface_name: Some("wlan0mon".to_string()),
        data: rt1,
    });

    let rt2 = build_radiotap_beacon(
        "LabWiFi6",
        [0xb8, 0x27, 0xeb, 0xaa, 0xbb, 0x01],
        2437,
        6,
        -64,
        100,
        true,
        false,
    );
    pkts.push(CapturedPacket {
        packet_no: (pkts.len() + 1) as u64,
        timestamp: Some(t0 + ChronoDuration::microseconds(185_000)),
        link_type: LinkType::Ieee80211Radiotap,
        original_len: rt2.len() as u32,
        interface_id: Some(1),
        interface_name: Some("wlan0mon".to_string()),
        data: rt2,
    });

    let rt3 = build_radiotap_probe_req("HomeNet", [0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e], 2412, -71);
    pkts.push(CapturedPacket {
        packet_no: (pkts.len() + 1) as u64,
        timestamp: Some(t0 + ChronoDuration::microseconds(190_000)),
        link_type: LinkType::Ieee80211Radiotap,
        original_len: rt3.len() as u32,
        interface_id: Some(1),
        interface_name: Some("wlan0mon".to_string()),
        data: rt3,
    });

    pkts
}

pub fn build_default_pcapng_bytes() -> Vec<u8> {
    let pkts = build_default_fixture_packets(None);
    encode_pcapng(
        &[
            (LinkType::Ethernet, "eth0", 6),
            (LinkType::Ieee80211Radiotap, "wlan0mon", 9),
        ],
        &pkts,
        Endianness::Little,
    )
}

pub fn build_default_ethernet_pcap_bytes() -> Vec<u8> {
    let pkts: Vec<CapturedPacket> = build_default_fixture_packets(None)
        .into_iter()
        .filter(|p| p.link_type == LinkType::Ethernet)
        .collect();
    encode_pcap_le_us(LinkType::Ethernet, &pkts)
}

pub fn build_default_synthetic_etl_bytes() -> Vec<u8> {
    let pkts: Vec<CapturedPacket> = build_default_fixture_packets(None)
        .into_iter()
        .filter(|p| p.link_type == LinkType::Ethernet)
        .collect();
    encode_packets_as_synthetic_etl(&pkts)
}
