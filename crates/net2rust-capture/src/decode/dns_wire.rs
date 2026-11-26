//! RFC 1035 wire DNS/mDNS parser with compression pointer loop/OOB protection,
//! TCP 2-byte length-prefixed framing, and RFC 6762 mDNS cache-flush class masking.

use std::net::{Ipv4Addr, Ipv6Addr};

use net2rust_core::{NetError, NetResult};

const MAX_POINTER_HOPS: usize = 16;
const MAX_LABELS: usize = 128;
const MAX_NAME_LEN: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRdata {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Name(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    Txt(Vec<String>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Soa {
        mname: String,
        rname: String,
        serial: u32,
    },
    Other(Vec<u8>),
}

impl DnsRdata {
    pub fn display_value(&self) -> String {
        match self {
            Self::A(ip) => ip.to_string(),
            Self::Aaaa(ip) => ip.to_string(),
            Self::Name(n) => n.clone(),
            Self::Mx { preference, exchange } => format!("{preference} {exchange}"),
            Self::Txt(parts) => parts.join(" "),
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => format!("{priority} {weight} {port} {target}"),
            Self::Soa { mname, rname, serial } => format!("{mname} {rname} {serial}"),
            Self::Other(bytes) => format!("{}B", bytes.len()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub cache_flush: bool,
    pub ttl: u32,
    pub rdata: DnsRdata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub tx_id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
    pub authorities: Vec<DnsResourceRecord>,
    pub additionals: Vec<DnsResourceRecord>,
}

pub fn qtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        41 => "OPT".to_string(),
        65 => "HTTPS".to_string(),
        255 => "ANY".to_string(),
        other => format!("TYPE({other})"),
    }
}

pub fn rcode_name(rcode: u8) -> String {
    match rcode {
        0 => "NOERROR".to_string(),
        1 => "FORMERR".to_string(),
        2 => "SERVFAIL".to_string(),
        3 => "NXDOMAIN".to_string(),
        4 => "NOTIMP".to_string(),
        5 => "REFUSED".to_string(),
        other => format!("RCODE({other})"),
    }
}

pub fn read_dns_name(msg: &[u8], start_offset: usize) -> NetResult<(String, usize)> {
    if start_offset >= msg.len() {
        return Err(NetError::ParseError(format!(
            "DNS name offset {start_offset} out of bounds (len {})",
            msg.len()
        )));
    }

    let mut visited = vec![false; msg.len()];
    let mut cursor = start_offset;
    let mut jumped = false;
    let mut next_offset = start_offset;
    let mut pointer_hops = 0usize;
    let mut labels: Vec<String> = Vec::new();
    let mut total_decoded_len = 0usize;

    loop {
        if cursor >= msg.len() {
            return Err(NetError::ParseError(format!("truncated DNS name at offset {cursor}")));
        }
        if visited[cursor] {
            return Err(NetError::ParseError(format!(
                "DNS compression pointer cycle detected at offset {cursor}"
            )));
        }
        visited[cursor] = true;

        let tag = msg[cursor];
        if tag == 0 {
            if !jumped {
                next_offset = cursor + 1;
            }
            break;
        }

        if (tag & 0xC0) == 0xC0 {
            if cursor + 1 >= msg.len() {
                return Err(NetError::ParseError("truncated DNS compression pointer".to_string()));
            }
            let ptr = (usize::from(tag & 0x3F) << 8) | usize::from(msg[cursor + 1]);
            if ptr >= msg.len() {
                return Err(NetError::ParseError(format!(
                    "out-of-bounds DNS compression pointer {ptr} >= {}",
                    msg.len()
                )));
            }
            if ptr >= cursor {
                return Err(NetError::ParseError(format!(
                    "invalid forward/self DNS compression pointer {ptr} >= {cursor}"
                )));
            }
            if visited[ptr] {
                return Err(NetError::ParseError(format!(
                    "DNS compression pointer cycle to offset {ptr}"
                )));
            }
            pointer_hops += 1;
            if pointer_hops > MAX_POINTER_HOPS {
                return Err(NetError::ParseError(
                    "DNS compression pointer hop limit exceeded".to_string(),
                ));
            }
            if !jumped {
                next_offset = cursor + 2;
                jumped = true;
            }
            cursor = ptr;
            continue;
        }

        if (tag & 0xC0) != 0 {
            return Err(NetError::ParseError(format!("unsupported DNS label tag 0x{tag:02x}")));
        }

        let label_len = usize::from(tag);
        let label_start = cursor + 1;
        let label_end = label_start + label_len;
        if label_end > msg.len() {
            return Err(NetError::ParseError(format!(
                "truncated DNS label at offset {cursor}: len {label_len}, msg len {}",
                msg.len()
            )));
        }

        total_decoded_len = total_decoded_len + label_len + usize::from(!labels.is_empty());
        if total_decoded_len > MAX_NAME_LEN || labels.len() >= MAX_LABELS {
            return Err(NetError::ParseError(
                "DNS domain name exceeds RFC 1035 limits".to_string(),
            ));
        }

        labels.push(String::from_utf8_lossy(&msg[label_start..label_end]).into_owned());
        cursor = label_end;
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };
    Ok((name, next_offset))
}

fn parse_rdata(msg: &[u8], rtype: u16, rdata_start: usize, rdlength: usize) -> NetResult<DnsRdata> {
    let rdata_end = rdata_start + rdlength;
    let rdata = &msg[rdata_start..rdata_end];
    match rtype {
        1 => {
            if rdlength != 4 {
                return Err(NetError::ParseError(format!("invalid DNS A rdlength {rdlength}")));
            }
            Ok(DnsRdata::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])))
        }
        28 => {
            if rdlength != 16 {
                return Err(NetError::ParseError(format!("invalid DNS AAAA rdlength {rdlength}")));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            Ok(DnsRdata::Aaaa(Ipv6Addr::from(octets)))
        }
        2 | 5 | 12 => {
            let (name, next_off) = read_dns_name(msg, rdata_start)?;
            if next_off > rdata_end {
                return Err(NetError::ParseError(format!(
                    "DNS name RDATA (type {rtype}) exceeds rdlength {rdlength}"
                )));
            }
            Ok(DnsRdata::Name(name))
        }
        6 => {
            let (mname, after_m) = read_dns_name(msg, rdata_start)?;
            if after_m > rdata_end {
                return Err(NetError::ParseError("DNS SOA mname exceeds rdlength".to_string()));
            }
            let (rname, after_r) = read_dns_name(msg, after_m)?;
            if after_r + 20 > rdata_end {
                return Err(NetError::ParseError("truncated DNS SOA RDATA".to_string()));
            }
            let serial = u32::from_be_bytes([msg[after_r], msg[after_r + 1], msg[after_r + 2], msg[after_r + 3]]);
            Ok(DnsRdata::Soa { mname, rname, serial })
        }
        15 => {
            if rdlength < 3 {
                return Err(NetError::ParseError("truncated DNS MX RDATA".to_string()));
            }
            let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
            let (exchange, next_off) = read_dns_name(msg, rdata_start + 2)?;
            if next_off > rdata_end {
                return Err(NetError::ParseError(format!(
                    "DNS MX exchange exceeds rdlength {rdlength}"
                )));
            }
            Ok(DnsRdata::Mx { preference, exchange })
        }
        16 => {
            let mut pos = 0usize;
            let mut strings = Vec::new();
            while pos < rdata.len() {
                let slen = usize::from(rdata[pos]);
                pos += 1;
                if pos + slen > rdata.len() {
                    return Err(NetError::ParseError("truncated DNS TXT chunk".to_string()));
                }
                strings.push(String::from_utf8_lossy(&rdata[pos..pos + slen]).into_owned());
                pos += slen;
            }
            Ok(DnsRdata::Txt(strings))
        }
        33 => {
            if rdlength < 7 {
                return Err(NetError::ParseError("truncated DNS SRV RDATA".to_string()));
            }
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let (target, next_off) = read_dns_name(msg, rdata_start + 6)?;
            if next_off > rdata_end {
                return Err(NetError::ParseError(format!(
                    "DNS SRV target exceeds rdlength {rdlength}"
                )));
            }
            Ok(DnsRdata::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        _ => Ok(DnsRdata::Other(rdata.to_vec())),
    }
}

fn parse_rr_section(
    msg: &[u8],
    mut offset: usize,
    count: u16,
    is_mdns: bool,
) -> NetResult<(Vec<DnsResourceRecord>, usize)> {
    let mut rrs = Vec::new();
    for _ in 0..count {
        let (name, next_off) = read_dns_name(msg, offset)?;
        offset = next_off;
        if offset + 10 > msg.len() {
            return Err(NetError::ParseError("truncated DNS RR header".to_string()));
        }
        let rtype = u16::from_be_bytes([msg[offset], msg[offset + 1]]);
        let raw_class = u16::from_be_bytes([msg[offset + 2], msg[offset + 3]]);
        let ttl = u32::from_be_bytes([msg[offset + 4], msg[offset + 5], msg[offset + 6], msg[offset + 7]]);
        let rdlength = usize::from(u16::from_be_bytes([msg[offset + 8], msg[offset + 9]]));
        offset += 10;

        if offset + rdlength > msg.len() {
            return Err(NetError::ParseError("truncated DNS RR RDATA".to_string()));
        }

        if rtype == 41 {
            // EDNS(0) OPT record: skip cleanly
            offset += rdlength;
            continue;
        }

        let rdata = parse_rdata(msg, rtype, offset, rdlength)?;
        offset += rdlength;

        let (cache_flush, rclass) = if is_mdns {
            ((raw_class & 0x8000) != 0, raw_class & 0x7FFF)
        } else {
            (false, raw_class)
        };

        rrs.push(DnsResourceRecord {
            name,
            rtype,
            rclass,
            cache_flush,
            ttl,
            rdata,
        });
    }
    Ok((rrs, offset))
}

pub fn parse_dns_message(msg: &[u8], is_mdns: bool) -> NetResult<DnsMessage> {
    if msg.len() < 12 {
        return Err(NetError::ParseError(format!(
            "truncated DNS header: expected 12 bytes, got {}",
            msg.len()
        )));
    }

    let tx_id = u16::from_be_bytes([msg[0], msg[1]]);
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let is_response = (flags & 0x8000) != 0;
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let rcode = (flags & 0x0F) as u8;

    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);
    let nscount = u16::from_be_bytes([msg[8], msg[9]]);
    let arcount = u16::from_be_bytes([msg[10], msg[11]]);

    let mut offset = 12usize;
    let mut questions = Vec::new();
    for _ in 0..qdcount {
        let (name, next_off) = read_dns_name(msg, offset)?;
        offset = next_off;
        if offset + 4 > msg.len() {
            return Err(NetError::ParseError("truncated DNS question".to_string()));
        }
        let qtype = u16::from_be_bytes([msg[offset], msg[offset + 1]]);
        let raw_qclass = u16::from_be_bytes([msg[offset + 2], msg[offset + 3]]);
        let qclass = if is_mdns { raw_qclass & 0x7FFF } else { raw_qclass };
        offset += 4;
        questions.push(DnsQuestion { name, qtype, qclass });
    }

    let (answers, offset) = parse_rr_section(msg, offset, ancount, is_mdns)?;
    let (authorities, offset) = parse_rr_section(msg, offset, nscount, is_mdns)?;
    let (additionals, _) = parse_rr_section(msg, offset, arcount, is_mdns)?;

    Ok(DnsMessage {
        tx_id,
        is_response,
        opcode,
        rcode,
        questions,
        answers,
        authorities,
        additionals,
    })
}

pub fn parse_dns_tcp_frames_with_offsets(buf: &[u8], is_mdns: bool) -> Vec<(usize, NetResult<DnsMessage>)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 2 <= buf.len() {
        let frame_offset = pos;
        let msg_len = usize::from(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
        pos += 2;
        if msg_len == 0 || pos + msg_len > buf.len() {
            out.push((
                frame_offset,
                Err(NetError::ParseError("truncated DNS-over-TCP frame".to_string())),
            ));
            break;
        }
        out.push((frame_offset, parse_dns_message(&buf[pos..pos + msg_len], is_mdns)));
        pos += msg_len;
    }
    out
}

pub fn parse_dns_tcp_frames(buf: &[u8], is_mdns: bool) -> Vec<NetResult<DnsMessage>> {
    parse_dns_tcp_frames_with_offsets(buf, is_mdns)
        .into_iter()
        .map(|(_, res)| res)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_compression_pointer_loop_and_oob() {
        // Self-loop at offset 12: 0xC0 0x0C
        let mut loop_pkt = vec![0u8; 16];
        loop_pkt[5] = 1; // qdcount=1
        loop_pkt[12] = 0xC0;
        loop_pkt[13] = 0x0C;
        let err = parse_dns_message(&loop_pkt, false).unwrap_err();
        assert!(matches!(err, NetError::ParseError(_)));

        // OOB pointer: 0xC0 0xFF
        let mut oob_pkt = vec![0u8; 16];
        oob_pkt[5] = 1;
        oob_pkt[12] = 0xC0;
        oob_pkt[13] = 0xFF;
        let err2 = parse_dns_message(&oob_pkt, false).unwrap_err();
        assert!(matches!(err2, NetError::ParseError(_)));
    }

    #[test]
    fn test_dns_rdata_rdlength_upper_bound_rejects_cross_rr_name() {
        // Response with 2 answers: RR1 = a. CNAME rdlength=0, RR2 = b. A 1.2.3.4
        let mut msg = vec![
            0x12, 0x34, 0x81, 0x80, // tx_id, flags
            0x00, 0x00, 0x00, 0x02, // qd=0, an=2
            0x00, 0x00, 0x00, 0x00, // ns=0, ar=0
        ];
        // RR1: "a." CNAME (5) IN ttl=60 rdlength=0
        msg.extend_from_slice(&[1, b'a', 0, 0, 5, 0, 1, 0, 0, 0, 60, 0, 0]);
        // RR2: "b." A (1) IN ttl=60 rdlength=4 1.2.3.4
        msg.extend_from_slice(&[1, b'b', 0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);

        let err = parse_dns_message(&msg, false).unwrap_err();
        assert!(matches!(err, NetError::ParseError(_)));
    }
}
