//! RFC 2131 / RFC 2132 BOOTP/DHCPv4 parser (UDP ports 67/68).

use std::net::Ipv4Addr;

use net2rust_core::{MacAddr, NetError, NetResult};

const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

#[derive(Debug, Clone)]
pub struct DhcpPacket {
    pub op: u8,
    pub xid: u32,
    pub message_type: String,
    pub client_mac: Option<MacAddr>,
    pub requested_ip: Option<Ipv4Addr>,
    pub assigned_ip: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub gateways: Vec<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub dhcp_server: Option<Ipv4Addr>,
    pub hostname: Option<String>,
    pub vendor_class: Option<String>,
    pub lease_sec: Option<u32>,
    pub param_request_list: Vec<u8>,
    pub client_id_hex: Option<String>,
}

fn dhcp_message_type_name(code: u8) -> &'static str {
    match code {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "Ack",
        6 => "Nak",
        7 => "Release",
        8 => "Inform",
        _ => "Bootp",
    }
}

fn non_zero_ip(bytes: &[u8]) -> Option<Ipv4Addr> {
    if bytes.len() < 4 {
        return None;
    }
    let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    if ip.is_unspecified() { None } else { Some(ip) }
}

pub fn parse_dhcp(data: &[u8], udp_src_ip: Option<Ipv4Addr>) -> NetResult<DhcpPacket> {
    if data.len() < 240 {
        return Err(NetError::ParseError(format!(
            "truncated DHCPv4 packet: expected >= 240 bytes, got {}",
            data.len()
        )));
    }
    if data[236..240] != DHCP_MAGIC_COOKIE {
        return Err(NetError::ParseError(
            "invalid DHCPv4 magic cookie (expected 0x63825363)".to_string(),
        ));
    }

    let op = data[0];
    let htype = data[1];
    let hlen = data[2];
    let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    let ciaddr = non_zero_ip(&data[12..16]);
    let yiaddr = non_zero_ip(&data[16..20]);
    let siaddr = non_zero_ip(&data[20..24]);

    let client_mac = if htype == 1 && hlen == 6 {
        Some(MacAddr::new([
            data[28], data[29], data[30], data[31], data[32], data[33],
        ]))
    } else {
        None
    };

    let mut message_type = "Bootp".to_string();
    let mut requested_ip = None;
    let mut subnet_mask = None;
    let mut gateways = Vec::new();
    let mut dns_servers = Vec::new();
    let mut dhcp_server = None;
    let mut hostname = None;
    let mut vendor_class = None;
    let mut lease_sec = None;
    let mut param_request_list = Vec::new();
    let mut client_id_hex = None;

    let mut pos = 240usize;
    while pos < data.len() {
        let code = data[pos];
        if code == 0 {
            pos += 1;
            continue;
        }
        if code == 255 {
            break;
        }
        if pos + 1 >= data.len() {
            break;
        }
        let opt_len = usize::from(data[pos + 1]);
        pos += 2;
        if pos + opt_len > data.len() {
            return Err(NetError::ParseError(format!(
                "truncated DHCP option {code}: len {opt_len}, remaining {}",
                data.len() - pos
            )));
        }
        let val = &data[pos..pos + opt_len];
        pos += opt_len;

        match code {
            1 if val.len() == 4 => {
                subnet_mask = Some(Ipv4Addr::new(val[0], val[1], val[2], val[3]));
            }
            3 => {
                for chunk in val.as_chunks::<4>().0 {
                    gateways.push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
                }
            }
            6 => {
                for chunk in val.as_chunks::<4>().0 {
                    dns_servers.push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
                }
            }
            12 if !val.is_empty() => {
                let s = String::from_utf8_lossy(val).trim_end_matches('\0').to_string();
                if !s.is_empty() {
                    hostname = Some(s);
                }
            }
            50 if val.len() == 4 => {
                requested_ip = Some(Ipv4Addr::new(val[0], val[1], val[2], val[3]));
            }
            51 if val.len() == 4 => {
                lease_sec = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]));
            }
            53 if !val.is_empty() => {
                message_type = dhcp_message_type_name(val[0]).to_string();
            }
            54 if val.len() == 4 => {
                dhcp_server = Some(Ipv4Addr::new(val[0], val[1], val[2], val[3]));
            }
            55 => {
                param_request_list = val.to_vec();
            }
            60 if !val.is_empty() => {
                vendor_class = Some(String::from_utf8_lossy(val).trim_end_matches('\0').to_string());
            }
            61 if !val.is_empty() => {
                use std::fmt::Write as _;
                let mut hex = String::with_capacity(val.len() * 2);
                for b in val {
                    let _ = write!(hex, "{b:02x}");
                }
                client_id_hex = Some(hex);
            }
            _ => {}
        }
    }

    if requested_ip.is_none() {
        requested_ip = ciaddr;
    }
    if dhcp_server.is_none() && op == 2 {
        dhcp_server = siaddr.or(udp_src_ip);
    }

    Ok(DhcpPacket {
        op,
        xid,
        message_type,
        client_mac,
        requested_ip,
        assigned_ip: yiaddr,
        subnet_mask,
        gateways,
        dns_servers,
        dhcp_server,
        hostname,
        vendor_class,
        lease_sec,
        param_request_list,
        client_id_hex,
    })
}
