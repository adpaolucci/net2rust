//! Unified L2–L4 frame decoder built atop `net2rust_core::packet`, adding LinkType dispatch,
//! ARP (`0x0806`), ICMPv4/ICMPv6, and bounded IPv6 extension-header traversal.

use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, Utc};
use net2rust_core::{
    ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, IP_PROTO_ICMP, IP_PROTO_ICMPV6, IP_PROTO_TCP, IP_PROTO_UDP, MacAddr,
    NetError, NetResult, TcpHeader, UdpHeader, parse_ethernet, parse_ipv4, parse_ipv6, parse_tcp, parse_udp,
};

use crate::capture::{CapturedPacket, LinkType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub oper: u16,
    pub sha: MacAddr,
    pub spa: Ipv4Addr,
    pub tha: MacAddr,
    pub tpa: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest: [u8; 4],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L4Header {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Icmpv4(IcmpHeader),
    Icmpv6(IcmpHeader),
}

#[derive(Debug, Clone)]
pub struct DecodedPacket<'a> {
    pub packet_no: u64,
    pub timestamp: Option<DateTime<Utc>>,
    pub link_type: LinkType,
    pub original_len: u32,
    pub ethernet_type_label: String,
    pub protocol_label: String,
    pub vlan_id: Option<u16>,
    pub src_mac: Option<MacAddr>,
    pub dst_mac: Option<MacAddr>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub ip_proto: Option<u8>,
    pub tcp_flags: Option<u16>,
    pub tcp_flags_text: Option<String>,
    pub is_non_initial_fragment: bool,
    pub arp: Option<ArpPacket>,
    pub l4: Option<L4Header>,
    pub payload_offset: usize,
    pub payload: &'a [u8],
    pub raw_frame: &'a [u8],
}

fn parse_arp(bytes: &[u8]) -> NetResult<ArpPacket> {
    if bytes.len() < 28 {
        return Err(NetError::ParseError(format!(
            "truncated ARP packet: expected 28 bytes, got {}",
            bytes.len()
        )));
    }
    let htype = u16::from_be_bytes([bytes[0], bytes[1]]);
    let ptype = u16::from_be_bytes([bytes[2], bytes[3]]);
    let hlen = bytes[4];
    let plen = bytes[5];
    if htype != 1 || ptype != ETHERTYPE_IPV4 || hlen != 6 || plen != 4 {
        return Err(NetError::ParseError(format!(
            "unsupported ARP hw/proto {htype:#x}/{ptype:#x} len {hlen}/{plen}"
        )));
    }
    let oper = u16::from_be_bytes([bytes[6], bytes[7]]);
    let sha = MacAddr::new([bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13]]);
    let spa = Ipv4Addr::new(bytes[14], bytes[15], bytes[16], bytes[17]);
    let tha = MacAddr::new([bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23]]);
    let tpa = Ipv4Addr::new(bytes[24], bytes[25], bytes[26], bytes[27]);
    Ok(ArpPacket {
        oper,
        sha,
        spa,
        tha,
        tpa,
    })
}

fn parse_icmp(bytes: &[u8]) -> NetResult<(IcmpHeader, &[u8])> {
    if bytes.len() < 8 {
        return Err(NetError::ParseError(format!(
            "truncated ICMP header: expected 8 bytes, got {}",
            bytes.len()
        )));
    }
    Ok((
        IcmpHeader {
            icmp_type: bytes[0],
            code: bytes[1],
            checksum: u16::from_be_bytes([bytes[2], bytes[3]]),
            rest: [bytes[4], bytes[5], bytes[6], bytes[7]],
        },
        &bytes[8..],
    ))
}

fn walk_ipv6_extensions(mut next_header: u8, mut payload: &[u8]) -> NetResult<(u8, &[u8], bool)> {
    const MAX_IPV6_EXT_HEADERS: usize = 8;
    let mut non_initial_fragment = false;

    for _ in 0..MAX_IPV6_EXT_HEADERS {
        match next_header {
            0 | 43 | 60 => {
                // Hop-by-Hop (0), Routing (43), Destination Options (60)
                if payload.len() < 2 {
                    return Err(NetError::ParseError("truncated IPv6 extension header".to_string()));
                }
                let next = payload[0];
                let ext_len = (usize::from(payload[1]) + 1) * 8;
                if ext_len > payload.len() {
                    return Err(NetError::ParseError(format!(
                        "truncated IPv6 extension header {next_header}: needed {ext_len}, available {}",
                        payload.len()
                    )));
                }
                next_header = next;
                payload = &payload[ext_len..];
            }
            44 => {
                // Fragment Header (fixed 8 bytes)
                if payload.len() < 8 {
                    return Err(NetError::ParseError(
                        "truncated IPv6 Fragment extension header".to_string(),
                    ));
                }
                let next = payload[0];
                let frag_off_flags = u16::from_be_bytes([payload[2], payload[3]]);
                if (frag_off_flags & 0xFFF8) != 0 {
                    non_initial_fragment = true;
                }
                next_header = next;
                payload = &payload[8..];
            }
            51 => {
                // Authentication Header
                if payload.len() < 2 {
                    return Err(NetError::ParseError("truncated IPv6 AH header".to_string()));
                }
                let next = payload[0];
                let ext_len = (usize::from(payload[1]) + 2) * 4;
                if ext_len > payload.len() {
                    return Err(NetError::ParseError("truncated IPv6 AH body".to_string()));
                }
                next_header = next;
                payload = &payload[ext_len..];
            }
            _ => break,
        }
    }

    Ok((next_header, payload, non_initial_fragment))
}

pub fn decode_packet(pkt: &CapturedPacket) -> NetResult<DecodedPacket<'_>> {
    let raw = pkt.data.as_slice();
    let mut src_mac = None;
    let mut dst_mac = None;
    let mut vlan_id = None;

    let (ethertype_opt, l3_bytes, l3_offset): (Option<u16>, &[u8], usize) = match pkt.link_type {
        LinkType::Ethernet => {
            let (eth, rest) = parse_ethernet(raw)?;
            src_mac = Some(eth.src_mac);
            dst_mac = Some(eth.dst_mac);
            vlan_id = eth.vlan_id;
            (Some(eth.ethertype), rest, eth.header_len)
        }
        LinkType::Null => {
            if raw.len() < 4 {
                return Err(NetError::ParseError("truncated DLT_NULL header".to_string()));
            }
            let fam_le = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let fam_be = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let et = if fam_le == 2 || fam_be == 2 {
                ETHERTYPE_IPV4
            } else {
                ETHERTYPE_IPV6
            };
            (Some(et), &raw[4..], 4)
        }
        LinkType::RawIp => {
            if raw.is_empty() {
                return Err(NetError::ParseError("empty DLT_RAW frame".to_string()));
            }
            let et = match raw[0] >> 4 {
                4 => ETHERTYPE_IPV4,
                6 => ETHERTYPE_IPV6,
                v => return Err(NetError::ParseError(format!("unknown IP version {v} in DLT_RAW"))),
            };
            (Some(et), raw, 0)
        }
        LinkType::Ipv4 => (Some(ETHERTYPE_IPV4), raw, 0),
        LinkType::Ipv6 => (Some(ETHERTYPE_IPV6), raw, 0),
        LinkType::LinuxSll => {
            if raw.len() < 16 {
                return Err(NetError::ParseError("truncated DLT_LINUX_SLL header".to_string()));
            }
            let et = u16::from_be_bytes([raw[14], raw[15]]);
            (Some(et), &raw[16..], 16)
        }
        LinkType::Ieee80211 | LinkType::Ieee80211Radiotap => {
            return Ok(DecodedPacket {
                packet_no: pkt.packet_no,
                timestamp: pkt.timestamp,
                link_type: pkt.link_type,
                original_len: pkt.original_len,
                ethernet_type_label: "802.11".to_string(),
                protocol_label: "802.11".to_string(),
                vlan_id: None,
                src_mac: None,
                dst_mac: None,
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                ip_proto: None,
                tcp_flags: None,
                tcp_flags_text: None,
                is_non_initial_fragment: false,
                arp: None,
                l4: None,
                payload_offset: 0,
                payload: raw,
                raw_frame: raw,
            });
        }
        LinkType::Other(dlt) => {
            return Ok(DecodedPacket {
                packet_no: pkt.packet_no,
                timestamp: pkt.timestamp,
                link_type: pkt.link_type,
                original_len: pkt.original_len,
                ethernet_type_label: format!("DLT({dlt})"),
                protocol_label: format!("DLT({dlt})"),
                vlan_id: None,
                src_mac: None,
                dst_mac: None,
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                ip_proto: None,
                tcp_flags: None,
                tcp_flags_text: None,
                is_non_initial_fragment: false,
                arp: None,
                l4: None,
                payload_offset: 0,
                payload: raw,
                raw_frame: raw,
            });
        }
    };

    let ethertype = ethertype_opt.unwrap_or(0);
    let prefix = if vlan_id.is_some() { "VLAN/" } else { "" };

    match ethertype {
        ETHERTYPE_ARP => {
            let arp = parse_arp(l3_bytes)?;
            Ok(DecodedPacket {
                packet_no: pkt.packet_no,
                timestamp: pkt.timestamp,
                link_type: pkt.link_type,
                original_len: pkt.original_len,
                ethernet_type_label: format!("{prefix}ARP"),
                protocol_label: "ARP".to_string(),
                vlan_id,
                src_mac: Some(arp.sha),
                dst_mac: dst_mac.or(Some(arp.tha)),
                src_ip: Some(IpAddr::V4(arp.spa)),
                dst_ip: Some(IpAddr::V4(arp.tpa)),
                src_port: None,
                dst_port: None,
                ip_proto: None,
                tcp_flags: None,
                tcp_flags_text: None,
                is_non_initial_fragment: false,
                arp: Some(arp),
                l4: None,
                payload_offset: l3_offset,
                payload: l3_bytes,
                raw_frame: raw,
            })
        }
        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => {
            let is_v4 = ethertype == ETHERTYPE_IPV4;
            let (src_ip, dst_ip, ip_proto, l4_bytes, l4_offset, is_non_initial_fragment) = if is_v4 {
                let (v4, rest) = parse_ipv4(l3_bytes)?;
                (
                    IpAddr::V4(v4.src_ip),
                    IpAddr::V4(v4.dst_ip),
                    v4.protocol,
                    rest,
                    l3_offset + v4.header_len,
                    v4.fragment_offset > 0,
                )
            } else {
                let (v6, rest) = parse_ipv6(l3_bytes)?;
                let (final_proto, final_rest, non_init) = walk_ipv6_extensions(v6.next_header, rest)?;
                let consumed_ext = rest.len().saturating_sub(final_rest.len());
                (
                    IpAddr::V6(v6.src_ip),
                    IpAddr::V6(v6.dst_ip),
                    final_proto,
                    final_rest,
                    l3_offset + v6.header_len + consumed_ext,
                    non_init,
                )
            };

            let ethernet_type_label = format!("{prefix}{}", if is_v4 { "IPv4" } else { "IPv6" });

            if is_non_initial_fragment {
                return Ok(DecodedPacket {
                    packet_no: pkt.packet_no,
                    timestamp: pkt.timestamp,
                    link_type: pkt.link_type,
                    original_len: pkt.original_len,
                    ethernet_type_label,
                    protocol_label: if is_v4 {
                        format!("IPv4({ip_proto})")
                    } else {
                        format!("IPv6({ip_proto})")
                    },
                    vlan_id,
                    src_mac,
                    dst_mac,
                    src_ip: Some(src_ip),
                    dst_ip: Some(dst_ip),
                    src_port: None,
                    dst_port: None,
                    ip_proto: Some(ip_proto),
                    tcp_flags: None,
                    tcp_flags_text: None,
                    is_non_initial_fragment: true,
                    arp: None,
                    l4: None,
                    payload_offset: l4_offset,
                    payload: l4_bytes,
                    raw_frame: raw,
                });
            }

            let mut src_port = None;
            let mut dst_port = None;
            let mut tcp_flags = None;
            let mut tcp_flags_text = None;
            let mut l4 = None;
            let mut payload_offset = l4_offset;
            let mut payload = l4_bytes;

            let protocol_label = match ip_proto {
                IP_PROTO_TCP => {
                    let (tcp, app) = parse_tcp(l4_bytes)?;
                    src_port = Some(tcp.src_port);
                    dst_port = Some(tcp.dst_port);
                    tcp_flags = Some(tcp.flags);
                    tcp_flags_text = Some(tcp.flag_names());
                    payload_offset += tcp.header_len;
                    payload = app;
                    l4 = Some(L4Header::Tcp(tcp));
                    "TCP".to_string()
                }
                IP_PROTO_UDP => {
                    let (udp, app) = parse_udp(l4_bytes)?;
                    src_port = Some(udp.src_port);
                    dst_port = Some(udp.dst_port);
                    payload_offset += udp.header_len;
                    payload = app;
                    l4 = Some(L4Header::Udp(udp));
                    "UDP".to_string()
                }
                IP_PROTO_ICMP => {
                    let (icmp, app) = parse_icmp(l4_bytes)?;
                    payload_offset += 8;
                    payload = app;
                    l4 = Some(L4Header::Icmpv4(icmp));
                    "ICMP".to_string()
                }
                IP_PROTO_ICMPV6 => {
                    let (icmp, app) = parse_icmp(l4_bytes)?;
                    payload_offset += 8;
                    payload = app;
                    l4 = Some(L4Header::Icmpv6(icmp));
                    "ICMPv6".to_string()
                }
                other => {
                    if is_v4 {
                        format!("IPv4({other})")
                    } else {
                        format!("IPv6({other})")
                    }
                }
            };

            Ok(DecodedPacket {
                packet_no: pkt.packet_no,
                timestamp: pkt.timestamp,
                link_type: pkt.link_type,
                original_len: pkt.original_len,
                ethernet_type_label,
                protocol_label,
                vlan_id,
                src_mac,
                dst_mac,
                src_ip: Some(src_ip),
                dst_ip: Some(dst_ip),
                src_port,
                dst_port,
                ip_proto: Some(ip_proto),
                tcp_flags,
                tcp_flags_text,
                is_non_initial_fragment: false,
                arp: None,
                l4,
                payload_offset,
                payload,
                raw_frame: raw,
            })
        }
        other => Ok(DecodedPacket {
            packet_no: pkt.packet_no,
            timestamp: pkt.timestamp,
            link_type: pkt.link_type,
            original_len: pkt.original_len,
            ethernet_type_label: format!("{prefix}0x{other:04X}"),
            protocol_label: format!("ETH(0x{other:04X})"),
            vlan_id,
            src_mac,
            dst_mac,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            ip_proto: None,
            tcp_flags: None,
            tcp_flags_text: None,
            is_non_initial_fragment: false,
            arp: None,
            l4: None,
            payload_offset: l3_offset,
            payload: l3_bytes,
            raw_frame: raw,
        }),
    }
}
