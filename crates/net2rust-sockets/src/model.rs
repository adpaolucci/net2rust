use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use net2rust_core::{MacAddr, NetError, NetResult};
use serde::{Deserialize, Serialize};

/// 100-nanosecond intervals between 1601-01-01 and 1970-01-01.
pub const FILETIME_UNIX_EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;

/// Convert a Windows `FILETIME` (100ns ticks since 1601-01-01 UTC) to `DateTime<Utc>`.
pub fn filetime_i64_to_utc(ft: i64) -> Option<DateTime<Utc>> {
    if ft <= 0 || ft < FILETIME_UNIX_EPOCH_DIFF_100NS {
        return None;
    }
    let rel_100ns = ft - FILETIME_UNIX_EPOCH_DIFF_100NS;
    let secs = rel_100ns / 10_000_000;
    let rem_100ns = rel_100ns % 10_000_000;
    let nanos = (rem_100ns * 100) as u32;
    DateTime::from_timestamp(secs, nanos)
}

/// Convert `DateTime<Utc>` to Windows `FILETIME` `i64` ticks (useful in tests & fixtures).
pub fn utc_to_filetime_i64(dt: DateTime<Utc>) -> i64 {
    let secs = dt.timestamp();
    let subsec_100ns = i64::from(dt.timestamp_subsec_nanos() / 100);
    secs.saturating_mul(10_000_000)
        .saturating_add(subsec_100ns)
        .saturating_add(FILETIME_UNIX_EPOCH_DIFF_100NS)
}

pub fn tcp_state_name(state: u32) -> &'static str {
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

pub fn route_protocol_name(proto: i32) -> &'static str {
    match proto {
        1 => "Other",
        2 => "Local",
        3 => "NetMgmt",
        4 => "ICMP",
        5 => "EGP",
        6 => "GGP",
        7 => "Hello",
        8 => "RIP",
        9 => "IS-IS",
        10 => "ES-IS",
        11 => "CiscoIGRP",
        12 => "BBN",
        13 => "OSPF",
        14 => "BGP",
        15 => "IDPR",
        16 => "EIGRP",
        17 => "DVMRP",
        18 => "RPL",
        19 => "DHCP",
        10002 => "NT_AutoStatic",
        10006 => "Static",
        10007 => "StaticNonDOD",
        _ => "Unknown",
    }
}

pub fn neighbor_state_name(state: i32) -> &'static str {
    match state {
        0 => "Unreachable",
        1 => "Incomplete",
        2 => "Probe",
        3 => "Delay",
        4 => "Stale",
        5 => "Reachable",
        6 => "Permanent",
        _ => "Unknown",
    }
}

pub fn if_type_name(if_type: u32) -> &'static str {
    match if_type {
        1 => "Other",
        6 => "Ethernet",
        9 => "TokenRing",
        23 => "PPP",
        24 => "Loopback",
        37 => "ATM",
        71 => "Wi-Fi (802.11)",
        131 => "Tunnel",
        144 => "IEEE 1394",
        237 => "WWAN",
        243 => "WWANPP",
        244 => "WWANPP2",
        _ => "Other",
    }
}

pub fn oper_status_name(status: i32) -> &'static str {
    match status {
        1 => "Up",
        2 => "Down",
        3 => "Testing",
        4 => "Unknown",
        5 => "Dormant",
        6 => "NotPresent",
        7 => "LowerLayerDown",
        _ => "Unknown",
    }
}

pub fn media_state_name(media_state: i32, oper_status: i32) -> String {
    let media = match media_state {
        1 => "Connected",
        2 => "Disconnected",
        _ => "Unknown",
    };
    let oper = oper_status_name(oper_status);
    format!("{media} ({oper})")
}

/// Decode a Windows `u32` MIB port field (network byte order in low 16 bits).
#[inline]
pub fn decode_mib_port(raw_port: u32) -> u16 {
    u16::from_be((raw_port & 0xFFFF) as u16)
}

/// Encode a host-order TCP/UDP port into Windows MIB `dwPort` representation.
#[inline]
pub fn encode_mib_port(port: u16) -> u32 {
    u32::from(port.to_be())
}

/// Decode a fixed 28-byte `SOCKADDR_INET` union buffer (little-endian `si_family`).
pub fn decode_sockaddr_inet_bytes(buf: &[u8; 28]) -> NetResult<(IpAddr, u16)> {
    let family = u16::from_le_bytes([buf[0], buf[1]]);
    match family {
        2 => {
            // AF_INET: sin_port at [2..4] BE, sin_addr at [4..8]
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            Ok((IpAddr::V4(ip), port))
        }
        23 => {
            // AF_INET6: sin6_port at [2..4] BE, sin6_addr at [8..24]
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[8..24]);
            Ok((IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        0 => Ok((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
        other => Err(NetError::ParseError(format!(
            "unsupported SOCKADDR_INET family: {other}"
        ))),
    }
}

/// Decode a variable-length `SOCKADDR` buffer (16B IPv4 or 28B IPv6, used in ETW `TDH_OUTTYPE_SOCKETADDRESS`).
pub fn decode_sockaddr_var_bytes(buf: &[u8]) -> NetResult<(IpAddr, u16)> {
    if buf.len() < 2 {
        return Err(NetError::ParseError("truncated SOCKADDR buffer (<2 bytes)".into()));
    }
    let family = u16::from_le_bytes([buf[0], buf[1]]);
    match family {
        2 => {
            if buf.len() < 16 {
                return Err(NetError::ParseError(format!(
                    "truncated SOCKADDR_IN buffer: {} bytes",
                    buf.len()
                )));
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            Ok((IpAddr::V4(ip), port))
        }
        23 => {
            if buf.len() < 28 {
                return Err(NetError::ParseError(format!(
                    "truncated SOCKADDR_IN6 buffer: {} bytes",
                    buf.len()
                )));
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[8..24]);
            Ok((IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        0 => Ok((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
        other => Err(NetError::ParseError(format!("unsupported SOCKADDR family: {other}"))),
    }
}

/// Parse Windows Registry `NameServer` / `DhcpNameServer` comma/whitespace-separated DNS strings.
pub fn parse_reg_dns_list(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in raw.split(|c: char| c == ',' || c.is_ascii_whitespace()) {
        let trimmed = token.trim();
        if !trimmed.is_empty() && !out.iter().any(|existing: &String| existing == trimmed) {
            out.push(trimmed.to_string());
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawProcessMeta {
    pub pid: u32,
    pub name: Option<String>,
    pub path: Option<String>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawTcpEntry {
    pub protocol: String,
    pub state_code: u32,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub pid: u32,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub user_name: Option<String>,
    pub created_time: Option<DateTime<Utc>>,
    pub estats_bytes_sent: Option<u64>,
    pub estats_bytes_recvd: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawUdpEntry {
    pub protocol: String,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub pid: u32,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub user_name: Option<String>,
    pub created_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawPortsBundle {
    pub tcp: Vec<RawTcpEntry>,
    pub udp: Vec<RawUdpEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawAdapterRow {
    pub luid: u64,
    pub interface_index: u32,
    pub adapter_name: String,
    pub description: String,
    pub media_state: String,
    pub link_speed: Option<u64>,
    pub bytes_sent: u64,
    pub bytes_recvd: u64,
    pub errors: u64,
    pub discards: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RawTcpipRegConfig {
    pub enable_dhcp: Option<bool>,
    pub dhcp_server: Option<String>,
    pub name_servers: Vec<String>,
    pub dhcp_name_servers: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub subnet_masks: Vec<String>,
    pub default_gateways: Vec<String>,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawInterfaceConfig {
    pub interface_name: String,
    pub description: String,
    pub guid: String,
    pub mac_address: Option<MacAddr>,
    pub operational_status: String,
    pub if_type: String,
    pub speed_mbps: Option<u64>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub gateway: Vec<String>,
    pub dns_servers: Vec<String>,
    pub dhcp_enabled: bool,
    pub reg_config: Option<RawTcpipRegConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawRouteRow {
    pub destination: IpAddr,
    pub prefix_length: u8,
    pub next_hop: IpAddr,
    pub interface_index: u32,
    pub interface_alias: Option<String>,
    pub metric: u32,
    pub protocol: String,
    pub age_secs: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawNeighborRow {
    pub interface_index: u32,
    pub ip_address: IpAddr,
    pub mac_address: Option<MacAddr>,
    pub state: String,
    pub is_router: bool,
    pub is_unreachable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawPathRow {
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub next_hop: IpAddr,
    pub link_speed_tx: Option<u64>,
    pub link_speed_rx: Option<u64>,
    pub rtt_mean_ms: Option<u32>,
    pub rtt_deviation_ms: Option<u32>,
    pub mtu: u32,
    pub is_reachable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawDnsCacheEntry {
    pub name: String,
    pub record_type: u16,
    pub data_length: u16,
    pub flags: u32,
}

fn read_u32_le(buf: &[u8], off: usize) -> NetResult<u32> {
    let bytes: [u8; 4] = buf
        .get(off..off + 4)
        .ok_or_else(|| NetError::ParseError(format!("unexpected EOF reading u32 at {off}")))?
        .try_into()
        .map_err(|_| NetError::ParseError("slice conversion failed".into()))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_i64_le(buf: &[u8], off: usize) -> NetResult<i64> {
    let bytes: [u8; 8] = buf
        .get(off..off + 8)
        .ok_or_else(|| NetError::ParseError(format!("unexpected EOF reading i64 at {off}")))?
        .try_into()
        .map_err(|_| NetError::ParseError("slice conversion failed".into()))?;
    Ok(i64::from_le_bytes(bytes))
}

/// Pure-Rust decoder for `MIB_TCPTABLE_OWNER_MODULE` raw bytes (64-bit Windows C layout: 8-byte header + 160-byte rows).
pub fn decode_tcp4_owner_module_table(buf: &[u8]) -> NetResult<Vec<RawTcpEntry>> {
    const TABLE_OFFSET: usize = 8;
    const ROW_SIZE: usize = 160;
    if buf.len() < 4 {
        return Err(NetError::ParseError("TCP4 owner-module table buffer < 4 bytes".into()));
    }
    let count = read_u32_le(buf, 0)? as usize;
    if count == 0 {
        return Ok(Vec::new());
    }
    let needed = TABLE_OFFSET
        .checked_add(
            count
                .checked_mul(ROW_SIZE)
                .ok_or_else(|| NetError::ParseError("TCP4 table entry count overflow".into()))?,
        )
        .ok_or_else(|| NetError::ParseError("TCP4 table byte size overflow".into()))?;
    if buf.len() < needed {
        return Err(NetError::ParseError(format!(
            "TCP4 table truncated: need {needed} bytes for {count} rows, got {}",
            buf.len()
        )));
    }

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let base = TABLE_OFFSET + i * ROW_SIZE;
        let state_code = read_u32_le(buf, base)?;
        let local_addr = Ipv4Addr::from(buf[base + 4..base + 8].try_into().unwrap_or([0; 4]));
        let local_port = decode_mib_port(read_u32_le(buf, base + 8)?);
        let remote_addr = Ipv4Addr::from(buf[base + 12..base + 16].try_into().unwrap_or([0; 4]));
        let remote_port = decode_mib_port(read_u32_le(buf, base + 16)?);
        let pid = read_u32_le(buf, base + 20)?;
        let create_ft = read_i64_le(buf, base + 24)?;
        out.push(RawTcpEntry {
            protocol: "TCP".to_string(),
            state_code,
            local_addr: IpAddr::V4(local_addr),
            local_port,
            remote_addr: IpAddr::V4(remote_addr),
            remote_port,
            pid,
            process_name: None,
            process_path: None,
            user_name: None,
            created_time: filetime_i64_to_utc(create_ft),
            estats_bytes_sent: None,
            estats_bytes_recvd: None,
        });
    }
    Ok(out)
}

/// Pure-Rust decoder for `MIB_TCP6TABLE_OWNER_MODULE` raw bytes (64-bit Windows C layout: 8-byte header + 192-byte rows).
pub fn decode_tcp6_owner_module_table(buf: &[u8]) -> NetResult<Vec<RawTcpEntry>> {
    const TABLE_OFFSET: usize = 8;
    const ROW_SIZE: usize = 192;
    if buf.len() < 4 {
        return Err(NetError::ParseError("TCP6 owner-module table buffer < 4 bytes".into()));
    }
    let count = read_u32_le(buf, 0)? as usize;
    if count == 0 {
        return Ok(Vec::new());
    }
    let needed = TABLE_OFFSET
        .checked_add(
            count
                .checked_mul(ROW_SIZE)
                .ok_or_else(|| NetError::ParseError("TCP6 table entry count overflow".into()))?,
        )
        .ok_or_else(|| NetError::ParseError("TCP6 table byte size overflow".into()))?;
    if buf.len() < needed {
        return Err(NetError::ParseError(format!(
            "TCP6 table truncated: need {needed} bytes for {count} rows, got {}",
            buf.len()
        )));
    }

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let base = TABLE_OFFSET + i * ROW_SIZE;
        let mut local_octets = [0u8; 16];
        local_octets.copy_from_slice(&buf[base..base + 16]);
        let local_port = decode_mib_port(read_u32_le(buf, base + 20)?);
        let mut remote_octets = [0u8; 16];
        remote_octets.copy_from_slice(&buf[base + 24..base + 40]);
        let remote_port = decode_mib_port(read_u32_le(buf, base + 44)?);
        let state_code = read_u32_le(buf, base + 48)?;
        let pid = read_u32_le(buf, base + 52)?;
        let create_ft = read_i64_le(buf, base + 56)?;
        out.push(RawTcpEntry {
            protocol: "TCPv6".to_string(),
            state_code,
            local_addr: IpAddr::V6(Ipv6Addr::from(local_octets)),
            local_port,
            remote_addr: IpAddr::V6(Ipv6Addr::from(remote_octets)),
            remote_port,
            pid,
            process_name: None,
            process_path: None,
            user_name: None,
            created_time: filetime_i64_to_utc(create_ft),
            estats_bytes_sent: None,
            estats_bytes_recvd: None,
        });
    }
    Ok(out)
}

/// Pure-Rust decoder for `MIB_UDPTABLE_OWNER_MODULE` raw bytes (64-bit Windows C layout: 8-byte header + 160-byte rows).
pub fn decode_udp4_owner_module_table(buf: &[u8]) -> NetResult<Vec<RawUdpEntry>> {
    const TABLE_OFFSET: usize = 8;
    const ROW_SIZE: usize = 160;
    if buf.len() < 4 {
        return Err(NetError::ParseError("UDP4 owner-module table buffer < 4 bytes".into()));
    }
    let count = read_u32_le(buf, 0)? as usize;
    if count == 0 {
        return Ok(Vec::new());
    }
    let needed = TABLE_OFFSET
        .checked_add(
            count
                .checked_mul(ROW_SIZE)
                .ok_or_else(|| NetError::ParseError("UDP4 table entry count overflow".into()))?,
        )
        .ok_or_else(|| NetError::ParseError("UDP4 table byte size overflow".into()))?;
    if buf.len() < needed {
        return Err(NetError::ParseError(format!(
            "UDP4 table truncated: need {needed} bytes for {count} rows, got {}",
            buf.len()
        )));
    }

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let base = TABLE_OFFSET + i * ROW_SIZE;
        let local_addr = Ipv4Addr::from(buf[base..base + 4].try_into().unwrap_or([0; 4]));
        let local_port = decode_mib_port(read_u32_le(buf, base + 4)?);
        let pid = read_u32_le(buf, base + 8)?;
        let create_ft = read_i64_le(buf, base + 16)?;
        out.push(RawUdpEntry {
            protocol: "UDP".to_string(),
            local_addr: IpAddr::V4(local_addr),
            local_port,
            pid,
            process_name: None,
            process_path: None,
            user_name: None,
            created_time: filetime_i64_to_utc(create_ft),
        });
    }
    Ok(out)
}

/// Pure-Rust decoder for `MIB_UDP6TABLE_OWNER_MODULE` raw bytes (64-bit Windows C layout: 8-byte header + 176-byte rows).
pub fn decode_udp6_owner_module_table(buf: &[u8]) -> NetResult<Vec<RawUdpEntry>> {
    const TABLE_OFFSET: usize = 8;
    const ROW_SIZE: usize = 176;
    if buf.len() < 4 {
        return Err(NetError::ParseError("UDP6 owner-module table buffer < 4 bytes".into()));
    }
    let count = read_u32_le(buf, 0)? as usize;
    if count == 0 {
        return Ok(Vec::new());
    }
    let needed = TABLE_OFFSET
        .checked_add(
            count
                .checked_mul(ROW_SIZE)
                .ok_or_else(|| NetError::ParseError("UDP6 table entry count overflow".into()))?,
        )
        .ok_or_else(|| NetError::ParseError("UDP6 table byte size overflow".into()))?;
    if buf.len() < needed {
        return Err(NetError::ParseError(format!(
            "UDP6 table truncated: need {needed} bytes for {count} rows, got {}",
            buf.len()
        )));
    }

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let base = TABLE_OFFSET + i * ROW_SIZE;
        let mut local_octets = [0u8; 16];
        local_octets.copy_from_slice(&buf[base..base + 16]);
        let local_port = decode_mib_port(read_u32_le(buf, base + 20)?);
        let pid = read_u32_le(buf, base + 24)?;
        let create_ft = read_i64_le(buf, base + 32)?;
        out.push(RawUdpEntry {
            protocol: "UDPv6".to_string(),
            local_addr: IpAddr::V6(Ipv6Addr::from(local_octets)),
            local_port,
            pid,
            process_name: None,
            process_path: None,
            user_name: None,
            created_time: filetime_i64_to_utc(create_ft),
        });
    }
    Ok(out)
}
