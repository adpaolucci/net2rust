use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use net2rust_core::{NetError, NetResult};
use serde::{Deserialize, Serialize};

use crate::transport::DnsTransport;

pub const MAX_COMPRESSION_JUMPS: usize = 16;
pub const MAX_DNS_NAME_LEN: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnsRecordType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    MX,
    TXT,
    AAAA,
    SRV,
    CAA,
}

impl DnsRecordType {
    pub const fn all() -> &'static [Self] {
        &[
            Self::A,
            Self::AAAA,
            Self::MX,
            Self::NS,
            Self::TXT,
            Self::SOA,
            Self::CNAME,
            Self::PTR,
            Self::SRV,
            Self::CAA,
        ]
    }

    pub const fn to_qtype(self) -> u16 {
        match self {
            Self::A => 1,
            Self::NS => 2,
            Self::CNAME => 5,
            Self::SOA => 6,
            Self::PTR => 12,
            Self::MX => 15,
            Self::TXT => 16,
            Self::AAAA => 28,
            Self::SRV => 33,
            Self::CAA => 257,
        }
    }

    pub const fn from_qtype(qtype: u16) -> Option<Self> {
        match qtype {
            1 => Some(Self::A),
            2 => Some(Self::NS),
            5 => Some(Self::CNAME),
            6 => Some(Self::SOA),
            12 => Some(Self::PTR),
            15 => Some(Self::MX),
            16 => Some(Self::TXT),
            28 => Some(Self::AAAA),
            33 => Some(Self::SRV),
            257 => Some(Self::CAA),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::NS => "NS",
            Self::CNAME => "CNAME",
            Self::SOA => "SOA",
            Self::PTR => "PTR",
            Self::MX => "MX",
            Self::TXT => "TXT",
            Self::AAAA => "AAAA",
            Self::SRV => "SRV",
            Self::CAA => "CAA",
        }
    }
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DnsRecordType {
    type Err = NetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_uppercase().as_str() {
            "A" => Ok(Self::A),
            "NS" => Ok(Self::NS),
            "CNAME" => Ok(Self::CNAME),
            "SOA" => Ok(Self::SOA),
            "PTR" => Ok(Self::PTR),
            "MX" => Ok(Self::MX),
            "TXT" => Ok(Self::TXT),
            "AAAA" => Ok(Self::AAAA),
            "SRV" => Ok(Self::SRV),
            "CAA" => Ok(Self::CAA),
            other => Err(NetError::InvalidInput(format!("unsupported DNS record type '{other}'"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResourceRecord {
    pub name: String,
    pub record_type: String,
    pub qtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub value: String,
    pub priority: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsMessage {
    pub id: u16,
    pub rcode: u8,
    pub truncated: bool,
    pub recursion_available: bool,
    pub questions: Vec<(String, u16, u16)>,
    pub answers: Vec<DnsResourceRecord>,
    pub authorities: Vec<DnsResourceRecord>,
    pub additionals: Vec<DnsResourceRecord>,
    pub used_tcp: bool,
}

/// Converts an IPv4 or IPv6 address into its RFC 1035 / RFC 3596 reverse DNS ARPA name.
pub fn ip_to_arpa_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mut parts = Vec::with_capacity(32);
            for byte in octets.iter().rev() {
                parts.push(format!("{:x}", byte & 0x0f));
                parts.push(format!("{:x}", (byte >> 4) & 0x0f));
            }
            format!("{}.ip6.arpa", parts.join("."))
        }
    }
}

/// Encodes a domain name as RFC 1035 length-prefixed labels ending in root `0x00`.
pub fn encode_dns_name(name: &str) -> NetResult<Vec<u8>> {
    let trimmed = name.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Ok(vec![0u8]);
    }
    let mut out = Vec::with_capacity(trimmed.len() + 2);
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(NetError::InvalidInput(format!(
                "invalid DNS label '{label}' in '{name}'"
            )));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0u8);
    if out.len() > MAX_DNS_NAME_LEN {
        return Err(NetError::InvalidInput(format!(
            "DNS name '{name}' exceeds {MAX_DNS_NAME_LEN} wire bytes"
        )));
    }
    Ok(out)
}

/// Encodes a standard RFC 1035 DNS query packet (`RD=1`, `QDCOUNT=1`, `IN`).
pub fn encode_dns_query(id: u16, qname: &str, qtype: DnsRecordType) -> NetResult<Vec<u8>> {
    let encoded_name = encode_dns_name(qname)?;
    let mut pkt = Vec::with_capacity(12 + encoded_name.len() + 4);
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0
    pkt.extend_from_slice(&encoded_name);
    pkt.extend_from_slice(&qtype.to_qtype().to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    Ok(pkt)
}

/// Decodes a DNS wire name with strict bounds checking and compression pointer loop detection.
pub fn decode_name(packet: &[u8], start_offset: usize) -> NetResult<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = start_offset;
    let mut next_offset_after_name: Option<usize> = None;
    let mut jumps = 0usize;
    let mut visited_offsets = HashSet::new();
    let mut total_wire_len = 0usize;

    loop {
        if pos >= packet.len() {
            return Err(NetError::ParseError(format!("truncated DNS name at offset {pos}")));
        }
        let len_byte = packet[pos];
        let tag = len_byte & 0xC0;

        if tag == 0xC0 {
            if pos + 1 >= packet.len() {
                return Err(NetError::ParseError("truncated DNS compression pointer".into()));
            }
            if !visited_offsets.insert(pos) {
                return Err(NetError::ParseError("DNS compression pointer loop detected".into()));
            }
            jumps += 1;
            if jumps > MAX_COMPRESSION_JUMPS {
                return Err(NetError::ParseError(format!(
                    "DNS compression pointer jump limit ({MAX_COMPRESSION_JUMPS}) exceeded"
                )));
            }
            let target = (((len_byte & 0x3F) as usize) << 8) | (packet[pos + 1] as usize);
            if target >= packet.len() {
                return Err(NetError::ParseError(format!(
                    "DNS compression pointer target {target} out of bounds ({})",
                    packet.len()
                )));
            }
            if next_offset_after_name.is_none() {
                next_offset_after_name = Some(pos + 2);
            }
            pos = target;
            continue;
        }

        if tag != 0x00 {
            return Err(NetError::ParseError(format!(
                "invalid DNS label tag 0x{len_byte:02x} at offset {pos}"
            )));
        }

        let label_len = len_byte as usize;
        pos += 1;
        if label_len == 0 {
            total_wire_len += 1;
            if total_wire_len > MAX_DNS_NAME_LEN {
                return Err(NetError::ParseError("DNS name exceeded 255 bytes".into()));
            }
            break;
        }

        total_wire_len += 1 + label_len;
        if total_wire_len > MAX_DNS_NAME_LEN {
            return Err(NetError::ParseError("DNS name exceeded 255 bytes".into()));
        }
        if pos + label_len > packet.len() {
            return Err(NetError::ParseError(format!(
                "truncated DNS label at offset {pos} (need {label_len} bytes)"
            )));
        }
        let label = String::from_utf8_lossy(&packet[pos..pos + label_len]).into_owned();
        labels.push(label);
        pos += label_len;
    }

    let next_pos = next_offset_after_name.unwrap_or(pos);
    Ok((labels.join("."), next_pos))
}

/// Decodes a complete RFC 1035 DNS response packet, validating ID, QR flag, and section bounds.
pub fn decode_dns_response(packet: &[u8], expected_id: u16) -> NetResult<DnsMessage> {
    if packet.len() < 12 {
        return Err(NetError::ParseError(format!(
            "DNS packet too short ({} bytes < 12)",
            packet.len()
        )));
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    if id != expected_id {
        return Err(NetError::ParseError(format!(
            "DNS transaction ID mismatch: expected {expected_id}, got {id}"
        )));
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if (flags & 0x8000) == 0 {
        return Err(NetError::ParseError(
            "DNS packet QR bit is 0 (expected response)".into(),
        ));
    }
    let truncated = (flags & 0x0200) != 0;
    let recursion_available = (flags & 0x0080) != 0;
    let rcode = (flags & 0x000F) as u8;

    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let nscount = u16::from_be_bytes([packet[8], packet[9]]) as usize;
    let arcount = u16::from_be_bytes([packet[10], packet[11]]) as usize;

    let mut offset = 12usize;
    let mut questions = Vec::with_capacity(qdcount);
    for _ in 0..qdcount {
        let (qname, next) = decode_name(packet, offset)?;
        if next + 4 > packet.len() {
            return Err(NetError::ParseError("truncated DNS question section".into()));
        }
        let qtype = u16::from_be_bytes([packet[next], packet[next + 1]]);
        let qclass = u16::from_be_bytes([packet[next + 2], packet[next + 3]]);
        questions.push((qname, qtype, qclass));
        offset = next + 4;
    }

    let answers = decode_rr_section(packet, &mut offset, ancount)?;
    let authorities = decode_rr_section(packet, &mut offset, nscount)?;
    let additionals = decode_rr_section(packet, &mut offset, arcount)?;

    Ok(DnsMessage {
        id,
        rcode,
        truncated,
        recursion_available,
        questions,
        answers,
        authorities,
        additionals,
        used_tcp: false,
    })
}

fn decode_rr_section(packet: &[u8], offset: &mut usize, count: usize) -> NetResult<Vec<DnsResourceRecord>> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let (name, next) = decode_name(packet, *offset)?;
        if next + 10 > packet.len() {
            return Err(NetError::ParseError("truncated DNS resource record header".into()));
        }
        let qtype = u16::from_be_bytes([packet[next], packet[next + 1]]);
        let class = u16::from_be_bytes([packet[next + 2], packet[next + 3]]);
        let ttl = u32::from_be_bytes([packet[next + 4], packet[next + 5], packet[next + 6], packet[next + 7]]);
        let rdlength = u16::from_be_bytes([packet[next + 8], packet[next + 9]]) as usize;
        let rdata_start = next + 10;
        let rdata_end = rdata_start
            .checked_add(rdlength)
            .ok_or_else(|| NetError::ParseError("DNS RDLENGTH overflow".into()))?;
        if rdata_end > packet.len() {
            return Err(NetError::ParseError(format!(
                "truncated DNS RDATA (need {rdlength} bytes at {rdata_start}, packet len {})",
                packet.len()
            )));
        }

        let (value, priority) = decode_rdata(packet, qtype, rdata_start, rdlength)?;
        let record_type = DnsRecordType::from_qtype(qtype)
            .map(|t| t.as_str().to_string())
            .unwrap_or_else(|| format!("TYPE{qtype}"));

        records.push(DnsResourceRecord {
            name,
            record_type,
            qtype,
            class,
            ttl,
            value,
            priority,
        });
        *offset = rdata_end;
    }
    Ok(records)
}

fn decode_rdata(packet: &[u8], qtype: u16, start: usize, len: usize) -> NetResult<(String, Option<u16>)> {
    let rdata = &packet[start..start + len];
    match qtype {
        // A
        1 => {
            if rdata.len() != 4 {
                return Err(NetError::ParseError(format!("invalid A RDATA length {}", rdata.len())));
            }
            let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
            Ok((ip.to_string(), None))
        }
        // AAAA
        28 => {
            if rdata.len() != 16 {
                return Err(NetError::ParseError(format!(
                    "invalid AAAA RDATA length {}",
                    rdata.len()
                )));
            }
            let octets: [u8; 16] = rdata.try_into().expect("checked len 16");
            Ok((Ipv6Addr::from(octets).to_string(), None))
        }
        // NS | CNAME | PTR
        2 | 5 | 12 => {
            let (target, end) = decode_name(packet, start)?;
            if end > start + len {
                return Err(NetError::ParseError("DNS name RDATA exceeds RDLENGTH".into()));
            }
            Ok((target, None))
        }
        // MX
        15 => {
            if rdata.len() < 3 {
                return Err(NetError::ParseError("truncated MX RDATA".into()));
            }
            let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
            let (exchange, end) = decode_name(packet, start + 2)?;
            if end > start + len {
                return Err(NetError::ParseError("MX exchange exceeds RDLENGTH".into()));
            }
            Ok((exchange, Some(pref)))
        }
        // TXT
        16 => {
            let mut pos = 0usize;
            let mut chunks = Vec::new();
            while pos < rdata.len() {
                let seg_len = rdata[pos] as usize;
                pos += 1;
                if pos + seg_len > rdata.len() {
                    return Err(NetError::ParseError("truncated TXT character-string".into()));
                }
                chunks.push(String::from_utf8_lossy(&rdata[pos..pos + seg_len]).into_owned());
                pos += seg_len;
            }
            Ok((chunks.join(""), None))
        }
        // SOA
        6 => {
            let (mname, p1) = decode_name(packet, start)?;
            let (rname, p2) = decode_name(packet, p1)?;
            if p2 + 20 > start + len {
                return Err(NetError::ParseError("truncated SOA RDATA timers".into()));
            }
            let serial = u32::from_be_bytes([packet[p2], packet[p2 + 1], packet[p2 + 2], packet[p2 + 3]]);
            let refresh = u32::from_be_bytes([packet[p2 + 4], packet[p2 + 5], packet[p2 + 6], packet[p2 + 7]]);
            let retry = u32::from_be_bytes([packet[p2 + 8], packet[p2 + 9], packet[p2 + 10], packet[p2 + 11]]);
            let expire = u32::from_be_bytes([packet[p2 + 12], packet[p2 + 13], packet[p2 + 14], packet[p2 + 15]]);
            let minimum = u32::from_be_bytes([packet[p2 + 16], packet[p2 + 17], packet[p2 + 18], packet[p2 + 19]]);
            Ok((
                format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"),
                None,
            ))
        }
        // SRV
        33 => {
            if rdata.len() < 7 {
                return Err(NetError::ParseError("truncated SRV RDATA".into()));
            }
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let (target, end) = decode_name(packet, start + 6)?;
            if end > start + len {
                return Err(NetError::ParseError("SRV target exceeds RDLENGTH".into()));
            }
            Ok((format!("{weight} {port} {target}"), Some(priority)))
        }
        // CAA
        257 => {
            if rdata.len() < 2 {
                return Err(NetError::ParseError("truncated CAA RDATA".into()));
            }
            let flags = rdata[0];
            let tag_len = rdata[1] as usize;
            if 2 + tag_len > rdata.len() {
                return Err(NetError::ParseError("truncated CAA tag".into()));
            }
            let tag = String::from_utf8_lossy(&rdata[2..2 + tag_len]);
            let val = String::from_utf8_lossy(&rdata[2 + tag_len..]);
            Ok((format!("{flags} {tag} \"{val}\""), None))
        }
        _ => {
            let mut hex = String::with_capacity(rdata.len() * 2);
            for b in rdata {
                use std::fmt::Write as _;
                let _ = write!(hex, "{b:02x}");
            }
            Ok((hex, None))
        }
    }
}

/// Executes a DNS query over UDP and automatically falls back to TCP when `TC=1` (truncated).
pub fn query_dns_with_fallback(
    transport: &dyn DnsTransport,
    server: SocketAddr,
    qname: &str,
    qtype: DnsRecordType,
    tx_id: u16,
    timeout: Duration,
) -> NetResult<DnsMessage> {
    let query_pkt = encode_dns_query(tx_id, qname, qtype)?;
    let udp_raw = transport.exchange(server, &query_pkt, false, timeout)?;
    let msg = decode_dns_response(&udp_raw, tx_id)?;
    if msg.truncated {
        let tcp_raw = transport.exchange(server, &query_pkt, true, timeout)?;
        let mut tcp_msg = decode_dns_response(&tcp_raw, tx_id)?;
        tcp_msg.used_tcp = true;
        return Ok(tcp_msg);
    }
    Ok(msg)
}

pub fn rcode_description(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}
