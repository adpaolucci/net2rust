use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::{MacAddr, NetError};

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_VLAN_8021Q: u16 = 0x8100;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_QINQ: u16 = 0x88A8;

pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;
pub const IP_PROTO_ICMPV6: u8 = 58;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthernetHeader {
    pub dst_mac: MacAddr,
    pub src_mac: MacAddr,
    pub ethertype: u16,
    pub vlan_id: Option<u16>,
    pub header_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub header_len: usize,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub header_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub header_len: usize,
    pub flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    pub fn flag_names(&self) -> String {
        let mut names = Vec::new();
        if (self.flags & 0x0100) != 0 {
            names.push("NS");
        }
        if (self.flags & 0x0080) != 0 {
            names.push("CWR");
        }
        if (self.flags & 0x0040) != 0 {
            names.push("ECE");
        }
        if (self.flags & 0x0020) != 0 {
            names.push("URG");
        }
        if (self.flags & 0x0010) != 0 {
            names.push("ACK");
        }
        if (self.flags & 0x0008) != 0 {
            names.push("PSH");
        }
        if (self.flags & 0x0004) != 0 {
            names.push("RST");
        }
        if (self.flags & 0x0002) != 0 {
            names.push("SYN");
        }
        if (self.flags & 0x0001) != 0 {
            names.push("FIN");
        }
        if names.is_empty() {
            "NONE".to_string()
        } else {
            names.join("|")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub header_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketSummary {
    pub ethernet: EthernetHeader,
    pub ipv4: Option<Ipv4Header>,
    pub ipv6: Option<Ipv6Header>,
    pub tcp: Option<TcpHeader>,
    pub udp: Option<UdpHeader>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub ip_protocol: Option<u8>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<u16>,
    pub payload_offset: usize,
    pub payload_len: usize,
    pub frame_len: usize,
}

pub fn parse_ethernet(frame: &[u8]) -> Result<(EthernetHeader, &[u8]), NetError> {
    if frame.len() < 14 {
        return Err(NetError::ParseError(format!(
            "truncated Ethernet frame: expected at least 14 bytes, got {}",
            frame.len()
        )));
    }

    let dst_mac = MacAddr::new([frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]]);
    let src_mac = MacAddr::new([frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]]);
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14usize;
    let mut vlan_id = None;

    // Handle up to two stacked 802.1Q / QinQ tags safely without unbounded loops.
    for _ in 0..2 {
        if ethertype != ETHERTYPE_VLAN_8021Q && ethertype != ETHERTYPE_QINQ {
            break;
        }
        if frame.len() < offset + 4 {
            return Err(NetError::ParseError(format!(
                "truncated 802.1Q VLAN tag at offset {offset}: frame len {}",
                frame.len()
            )));
        }
        let tci = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
        vlan_id = Some(tci & 0x0FFF);
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }

    Ok((
        EthernetHeader {
            dst_mac,
            src_mac,
            ethertype,
            vlan_id,
            header_len: offset,
        },
        &frame[offset..],
    ))
}

pub fn parse_ipv4(packet: &[u8]) -> Result<(Ipv4Header, &[u8]), NetError> {
    if packet.len() < 20 {
        return Err(NetError::ParseError(format!(
            "truncated IPv4 header: expected at least 20 bytes, got {}",
            packet.len()
        )));
    }

    let version = packet[0] >> 4;
    if version != 4 {
        return Err(NetError::ParseError(format!(
            "invalid IPv4 version {version}, expected 4"
        )));
    }

    let ihl = packet[0] & 0x0F;
    if ihl < 5 {
        return Err(NetError::ParseError(format!("invalid IPv4 IHL {ihl} (minimum is 5)")));
    }

    let header_len = usize::from(ihl) * 4;
    if packet.len() < header_len {
        return Err(NetError::ParseError(format!(
            "truncated IPv4 options: header_len {header_len}, available {}",
            packet.len()
        )));
    }

    let total_length = u16::from_be_bytes([packet[2], packet[3]]);
    let total_len = usize::from(total_length);
    if total_len < header_len {
        return Err(NetError::ParseError(format!(
            "invalid IPv4 total_length {total_length} < header_len {header_len}"
        )));
    }
    if total_len > packet.len() {
        return Err(NetError::ParseError(format!(
            "truncated IPv4 packet: total_length {total_len}, available {}",
            packet.len()
        )));
    }

    let flags_and_frag = u16::from_be_bytes([packet[6], packet[7]]);
    let header = Ipv4Header {
        version,
        ihl,
        header_len,
        dscp: packet[1] >> 2,
        ecn: packet[1] & 0x03,
        total_length,
        identification: u16::from_be_bytes([packet[4], packet[5]]),
        flags: ((flags_and_frag >> 13) & 0x07) as u8,
        fragment_offset: flags_and_frag & 0x1FFF,
        ttl: packet[8],
        protocol: packet[9],
        checksum: u16::from_be_bytes([packet[10], packet[11]]),
        src_ip: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        dst_ip: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
    };

    Ok((header, &packet[header_len..total_len]))
}

pub fn parse_ipv6(packet: &[u8]) -> Result<(Ipv6Header, &[u8]), NetError> {
    if packet.len() < 40 {
        return Err(NetError::ParseError(format!(
            "truncated IPv6 header: expected 40 bytes, got {}",
            packet.len()
        )));
    }

    let version = packet[0] >> 4;
    if version != 6 {
        return Err(NetError::ParseError(format!(
            "invalid IPv6 version {version}, expected 6"
        )));
    }

    let traffic_class = ((packet[0] & 0x0F) << 4) | (packet[1] >> 4);
    let flow_label = (u32::from(packet[1] & 0x0F) << 16) | (u32::from(packet[2]) << 8) | u32::from(packet[3]);
    let payload_length = u16::from_be_bytes([packet[4], packet[5]]);
    let next_header = packet[6];
    let hop_limit = packet[7];

    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&packet[8..24]);
    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&packet[24..40]);

    let header = Ipv6Header {
        version,
        traffic_class,
        flow_label,
        payload_length,
        next_header,
        hop_limit,
        src_ip: Ipv6Addr::from(src_bytes),
        dst_ip: Ipv6Addr::from(dst_bytes),
        header_len: 40,
    };

    let total_len = 40usize.saturating_add(usize::from(payload_length));
    if total_len > packet.len() {
        return Err(NetError::ParseError(format!(
            "truncated IPv6 packet: expected {total_len} bytes, available {}",
            packet.len()
        )));
    }

    Ok((header, &packet[40..total_len]))
}

pub fn parse_tcp(segment: &[u8]) -> Result<(TcpHeader, &[u8]), NetError> {
    if segment.len() < 20 {
        return Err(NetError::ParseError(format!(
            "truncated TCP header: expected at least 20 bytes, got {}",
            segment.len()
        )));
    }

    let data_offset = segment[12] >> 4;
    if data_offset < 5 {
        return Err(NetError::ParseError(format!(
            "invalid TCP data offset {data_offset} (minimum is 5)"
        )));
    }

    let header_len = usize::from(data_offset) * 4;
    if segment.len() < header_len {
        return Err(NetError::ParseError(format!(
            "truncated TCP options: header_len {header_len}, available {}",
            segment.len()
        )));
    }

    let flags = u16::from_be_bytes([segment[12] & 0x01, segment[13]]);
    let header = TcpHeader {
        src_port: u16::from_be_bytes([segment[0], segment[1]]),
        dst_port: u16::from_be_bytes([segment[2], segment[3]]),
        seq: u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]),
        ack: u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]),
        data_offset,
        header_len,
        flags,
        window: u16::from_be_bytes([segment[14], segment[15]]),
        checksum: u16::from_be_bytes([segment[16], segment[17]]),
        urgent_ptr: u16::from_be_bytes([segment[18], segment[19]]),
    };

    Ok((header, &segment[header_len..]))
}

pub fn parse_udp(datagram: &[u8]) -> Result<(UdpHeader, &[u8]), NetError> {
    if datagram.len() < 8 {
        return Err(NetError::ParseError(format!(
            "truncated UDP header: expected 8 bytes, got {}",
            datagram.len()
        )));
    }

    let length = u16::from_be_bytes([datagram[4], datagram[5]]);
    if length < 8 {
        return Err(NetError::ParseError(format!(
            "invalid UDP length {length} (minimum is 8)"
        )));
    }

    let header = UdpHeader {
        src_port: u16::from_be_bytes([datagram[0], datagram[1]]),
        dst_port: u16::from_be_bytes([datagram[2], datagram[3]]),
        length,
        checksum: u16::from_be_bytes([datagram[6], datagram[7]]),
        header_len: 8,
    };

    let udp_len = usize::from(length);
    if udp_len > datagram.len() {
        return Err(NetError::ParseError(format!(
            "truncated UDP datagram: length {udp_len}, available {}",
            datagram.len()
        )));
    }

    Ok((header, &datagram[8..udp_len]))
}

pub fn summarize_frame(frame: &[u8]) -> Result<PacketSummary, NetError> {
    let (ethernet, l3_bytes) = parse_ethernet(frame)?;
    let mut ipv4 = None;
    let mut ipv6 = None;
    let mut tcp = None;
    let mut udp = None;
    let mut src_ip = None;
    let mut dst_ip = None;
    let mut ip_protocol = None;
    let mut src_port = None;
    let mut dst_port = None;
    let mut tcp_flags = None;
    let mut payload_offset = ethernet.header_len;
    let mut payload_len = l3_bytes.len();

    let mut is_non_initial_fragment = false;
    let (proto, l4_bytes) = match ethernet.ethertype {
        ETHERTYPE_IPV4 => {
            let (v4, rest) = parse_ipv4(l3_bytes)?;
            src_ip = Some(IpAddr::V4(v4.src_ip));
            dst_ip = Some(IpAddr::V4(v4.dst_ip));
            ip_protocol = Some(v4.protocol);
            payload_offset += v4.header_len;
            payload_len = rest.len();
            is_non_initial_fragment = v4.fragment_offset > 0;
            ipv4 = Some(v4);
            (Some(v4.protocol), rest)
        }
        ETHERTYPE_IPV6 => {
            let (v6, rest) = parse_ipv6(l3_bytes)?;
            src_ip = Some(IpAddr::V6(v6.src_ip));
            dst_ip = Some(IpAddr::V6(v6.dst_ip));
            ip_protocol = Some(v6.next_header);
            payload_offset += v6.header_len;
            payload_len = rest.len();
            ipv6 = Some(v6);
            (Some(v6.next_header), rest)
        }
        _ => (None, &[][..]),
    };

    if !is_non_initial_fragment && let Some(proto_num) = proto {
        match proto_num {
            IP_PROTO_TCP => {
                let (hdr, payload) = parse_tcp(l4_bytes)?;
                src_port = Some(hdr.src_port);
                dst_port = Some(hdr.dst_port);
                tcp_flags = Some(hdr.flags);
                payload_offset += hdr.header_len;
                payload_len = payload.len();
                tcp = Some(hdr);
            }
            IP_PROTO_UDP => {
                let (hdr, payload) = parse_udp(l4_bytes)?;
                src_port = Some(hdr.src_port);
                dst_port = Some(hdr.dst_port);
                payload_offset += hdr.header_len;
                payload_len = payload.len();
                udp = Some(hdr);
            }
            _ => {}
        }
    }

    Ok(PacketSummary {
        ethernet,
        ipv4,
        ipv6,
        tcp,
        udp,
        src_ip,
        dst_ip,
        ip_protocol,
        src_port,
        dst_port,
        tcp_flags,
        payload_offset,
        payload_len,
        frame_len: frame.len(),
    })
}
