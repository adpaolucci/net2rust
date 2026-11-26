use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use net2rust_core::{NetError, NetResult};
use serde::{Deserialize, Serialize};

use crate::model::{RawDnsCacheEntry, decode_sockaddr_var_bytes};

/// `{7DD42A49-5329-4832-8DFD-43D979153A88}` in RFC-4122 big-endian / Windows mixed-endian GUID bytes.
pub const KERNEL_NETWORK_GUID_STR: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
/// `{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}`
pub const TCPIP_GUID_STR: &str = "2F07E2EE-15DB-40F1-90EF-9D7BA282188A";
/// `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`
pub const DNS_CLIENT_GUID_STR: &str = "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEtwRecord {
    pub provider_guid: String,
    pub event_id: u16,
    pub version: u8,
    pub timestamp_utc: DateTime<Utc>,
    pub header_process_id: u32,
    pub activity_id: [u8; 16],
    pub is_64bit: bool,
    pub user_data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KernelNetDirection {
    Send,
    Recv,
    Connect,
    Accept,
    Disconnect,
    Retransmit,
    Reconnect,
    TcpCopy,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelNetEvent {
    pub timestamp_utc: DateTime<Utc>,
    pub event_id: u16,
    pub protocol: &'static str,
    pub direction: KernelNetDirection,
    pub pid: u32,
    pub size: u32,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub conn_id: u32,
    pub failure_code: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpIpEvent {
    EndpointContext {
        timestamp_utc: DateTime<Utc>,
        event_id: u16,
        tcb: u64,
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: IpAddr,
        remote_port: u16,
        state: u32,
        pid: Option<u32>,
    },
    ConnectFailure {
        timestamp_utc: DateTime<Utc>,
        event_id: u16,
        tcb: u64,
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: IpAddr,
        remote_port: u16,
        status: u32,
        pid: u32,
    },
    RetransmitOrTimeout {
        timestamp_utc: DateTime<Utc>,
        event_id: u16,
        tcb: u64,
        status: Option<u32>,
        rexmit_count: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsEventKind {
    QueryCalled,
    QueryCompleted,
    ServerSent,
    ServerResponse,
    CacheLookup,
    CacheResult,
    WireQuery,
    WireResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsClientEvent {
    pub timestamp_utc: DateTime<Utc>,
    pub event_id: u16,
    pub kind: DnsEventKind,
    pub activity_id: [u8; 16],
    pub pid: Option<u32>,
    pub query_name: String,
    pub query_type: u32,
    pub status: Option<u32>,
    pub results: Option<String>,
    pub dns_server: Option<String>,
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_bytes(&mut self, len: usize) -> NetResult<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| NetError::ParseError("cursor offset overflow".into()))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| NetError::ParseError(format!("unexpected EOF at {} (need {len})", self.pos)))?;
        self.pos = end;
        Ok(slice)
    }

    fn read_u16_le(&mut self) -> NetResult<u16> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_u16_be(&mut self) -> NetResult<u16> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn read_u32_le(&mut self) -> NetResult<u32> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64_le(&mut self) -> NetResult<u64> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    fn read_ptr(&mut self, is_64bit: bool) -> NetResult<u64> {
        if is_64bit {
            self.read_u64_le()
        } else {
            self.read_u32_le().map(u64::from)
        }
    }

    fn read_ipv4(&mut self) -> NetResult<IpAddr> {
        let b = self.read_bytes(4)?;
        Ok(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
    }

    fn read_ipv6(&mut self) -> NetResult<IpAddr> {
        let b = self.read_bytes(16)?;
        let mut octets = [0u8; 16];
        octets.copy_from_slice(b);
        Ok(IpAddr::V6(Ipv6Addr::from(octets)))
    }

    fn read_sockaddr_prefixed(&mut self) -> NetResult<(IpAddr, u16)> {
        let len = self.read_u32_le()? as usize;
        let bytes = self.read_bytes(len)?;
        decode_sockaddr_var_bytes(bytes)
    }

    fn read_utf16z(&mut self) -> NetResult<String> {
        let mut units = Vec::new();
        loop {
            let u = self.read_u16_le()?;
            if u == 0 {
                break;
            }
            units.push(u);
        }
        Ok(String::from_utf16_lossy(&units))
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
}

/// Pure-Rust decoder for `Microsoft-Windows-Kernel-Network` binary `UserData`.
pub fn decode_kernel_network(rec: &RawEtwRecord) -> NetResult<KernelNetEvent> {
    let mut c = Cursor::new(&rec.user_data);
    match rec.event_id {
        17 | 49 => {
            let proto_num = c.read_u16_le()?;
            let failure_code = c.read_u16_le()?;
            let protocol = if rec.event_id == 49 || proto_num == 17 {
                "UDP"
            } else {
                "TCP"
            };
            return Ok(KernelNetEvent {
                timestamp_utc: rec.timestamp_utc,
                event_id: rec.event_id,
                protocol,
                direction: KernelNetDirection::Fail,
                pid: rec.header_process_id,
                size: 0,
                local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                local_port: 0,
                remote_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                remote_port: 0,
                conn_id: 0,
                failure_code: Some(failure_code),
            });
        }
        _ => {}
    }

    let is_v6 = matches!(rec.event_id, 26..=34 | 58 | 59);
    let is_udp = matches!(rec.event_id, 42 | 43 | 58 | 59);
    let protocol = match (is_udp, is_v6) {
        (false, false) => "TCP",
        (false, true) => "TCPv6",
        (true, false) => "UDP",
        (true, true) => "UDPv6",
    };
    let direction = match rec.event_id {
        10 | 26 | 42 | 58 => KernelNetDirection::Send,
        11 | 27 | 43 | 59 => KernelNetDirection::Recv,
        12 | 28 => KernelNetDirection::Connect,
        13 | 29 => KernelNetDirection::Disconnect,
        14 | 30 => KernelNetDirection::Retransmit,
        15 | 31 => KernelNetDirection::Accept,
        16 | 32 => KernelNetDirection::Reconnect,
        18 | 34 => KernelNetDirection::TcpCopy,
        other => {
            return Err(NetError::ParseError(format!(
                "unsupported Kernel-Network event_id {other}"
            )));
        }
    };

    // PID is always at UserData[0..4]; EVENT_HEADER.ProcessId can be 0xFFFFFFFF/4 on DPC receive.
    let pid = c.read_u32_le()?;
    let size = c.read_u32_le()?;
    let (daddr, saddr) = if is_v6 {
        (c.read_ipv6()?, c.read_ipv6()?)
    } else {
        (c.read_ipv4()?, c.read_ipv4()?)
    };
    let dport = c.read_u16_be()?;
    let sport = c.read_u16_be()?;

    match rec.event_id {
        10 | 26 => {
            // startime + endtime (8 bytes) before seqnum + connid
            let _ = c.read_bytes(8)?;
        }
        12 | 15 | 28 | 31 => {
            // mss..sndwinscale (16 bytes) before seqnum + connid
            let _ = c.read_bytes(16)?;
        }
        _ => {}
    }
    let _seqnum = c.read_u32_le()?;
    let conn_id = c.read_u32_le()?;

    // Normalize local vs remote endpoint orientation by direction.
    let (local_addr, local_port, remote_addr, remote_port) = match direction {
        KernelNetDirection::Send
        | KernelNetDirection::Connect
        | KernelNetDirection::Reconnect
        | KernelNetDirection::Retransmit => (saddr, sport, daddr, dport),
        _ => (daddr, dport, saddr, sport),
    };

    Ok(KernelNetEvent {
        timestamp_utc: rec.timestamp_utc,
        event_id: rec.event_id,
        protocol,
        direction,
        pid,
        size,
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        conn_id,
        failure_code: None,
    })
}

/// Pure-Rust decoder for `Microsoft-Windows-TCPIP` binary `UserData`.
pub fn decode_tcpip(rec: &RawEtwRecord) -> NetResult<TcpIpEvent> {
    let mut c = Cursor::new(&rec.user_data);
    let ptr_64 = rec.is_64bit;
    match rec.event_id {
        1002 | 1030 | 1182 | 1187 => {
            let tcb = c.read_ptr(ptr_64)?;
            let (local_addr, local_port) = c.read_sockaddr_prefixed()?;
            let (remote_addr, remote_port) = c.read_sockaddr_prefixed()?;
            let state = c.read_u32_le()?;
            let _rexmit = if c.remaining() >= 4 { c.read_u32_le()? } else { 0 };
            Ok(TcpIpEvent::EndpointContext {
                timestamp_utc: rec.timestamp_utc,
                event_id: rec.event_id,
                tcb,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
                pid: if rec.header_process_id != u32::MAX && rec.header_process_id != 0 {
                    Some(rec.header_process_id)
                } else {
                    None
                },
            })
        }
        1300 => {
            let tcb = c.read_ptr(ptr_64)?;
            let (local_addr, local_port) = c.read_sockaddr_prefixed()?;
            let (remote_addr, remote_port) = c.read_sockaddr_prefixed()?;
            let state = c.read_u32_le()?;
            let pid = c.read_u32_le()?;
            Ok(TcpIpEvent::EndpointContext {
                timestamp_utc: rec.timestamp_utc,
                event_id: rec.event_id,
                tcb,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
                pid: Some(pid),
            })
        }
        1018 | 1019 | 1020 | 1021 | 1029 | 1033 | 1034 | 1035 | 1038 | 1043 | 1044 | 1564 => {
            let (local_addr, local_port) = c.read_sockaddr_prefixed()?;
            let (remote_addr, remote_port) = c.read_sockaddr_prefixed()?;
            let status = c.read_u32_le()?;
            let pid = c.read_u32_le()?;
            let _compartment = c.read_u32_le()?;
            let tcb = c.read_ptr(ptr_64)?;
            Ok(TcpIpEvent::ConnectFailure {
                timestamp_utc: rec.timestamp_utc,
                event_id: rec.event_id,
                tcb,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                status,
                pid,
            })
        }
        1351 => {
            let tcb = c.read_ptr(ptr_64)?;
            let _snd_una = c.read_u32_le()?;
            let rexmit_count = c.read_u32_le()?;
            Ok(TcpIpEvent::RetransmitOrTimeout {
                timestamp_utc: rec.timestamp_utc,
                event_id: rec.event_id,
                tcb,
                status: Some(0xC000_00B5), // RTO timeout
                rexmit_count: rexmit_count.max(1),
            })
        }
        1348 | 1418 | 1584 => {
            let tcb = c.read_ptr(ptr_64)?;
            let status = if rec.event_id == 1348 { Some(0xC000_00B5) } else { None };
            Ok(TcpIpEvent::RetransmitOrTimeout {
                timestamp_utc: rec.timestamp_utc,
                event_id: rec.event_id,
                tcb,
                status,
                rexmit_count: 1,
            })
        }
        1590 => {
            let tcb = c.read_ptr(ptr_64)?;
            let _nbl = c.read_ptr(ptr_64)?;
            let status = c.read_u32_le()?;
            Ok(TcpIpEvent::RetransmitOrTimeout {
                timestamp_utc: rec.timestamp_utc,
                event_id: rec.event_id,
                tcb,
                status: Some(status),
                rexmit_count: 1,
            })
        }
        other => Err(NetError::ParseError(format!("unsupported TCPIP event_id {other}"))),
    }
}

pub fn ntstatus_to_label(status: u32) -> String {
    match status {
        0xC000_0236 => "Refused".to_string(),
        0xC000_020C | 0xC000_020D => "Reset".to_string(),
        0xC000_00B5 | 0xC000_0184 => "Timeout".to_string(),
        0xC000_023B => "Aborted".to_string(),
        0xC000_0022 => "AccessDenied".to_string(),
        0xC000_0239 | 0xC000_023A => "Unreachable".to_string(),
        other => format!("0x{other:08X}"),
    }
}

/// Pure-Rust decoder for `Microsoft-Windows-DNS-Client` binary `UserData`.
pub fn decode_dns_client(rec: &RawEtwRecord) -> NetResult<DnsClientEvent> {
    let mut c = Cursor::new(&rec.user_data);
    let header_pid = (rec.header_process_id != 0 && rec.header_process_id != u32::MAX).then_some(rec.header_process_id);
    match rec.event_id {
        3006 => {
            let query_name = c.read_utf16z()?;
            let query_type = c.read_u32_le()?;
            let _options = c.read_u64_le()?;
            let _server_list = c.read_utf16z()?;
            Ok(DnsClientEvent {
                timestamp_utc: rec.timestamp_utc,
                event_id: rec.event_id,
                kind: DnsEventKind::QueryCalled,
                activity_id: rec.activity_id,
                pid: header_pid,
                query_name,
                query_type,
                status: None,
                results: None,
                dns_server: None,
            })
        }
        3008 => {
            let query_name = c.read_utf16z()?;
            let query_type = c.read_u32_le()?;
            let _options = c.read_u64_le()?;
            let status = c.read_u32_le()?;
            let results = c.read_utf16z()?;
            Ok(DnsClientEvent {
                timestamp_utc: rec.timestamp_utc,
                event_id: rec.event_id,
                kind: DnsEventKind::QueryCompleted,
                activity_id: rec.activity_id,
                pid: header_pid,
                query_name,
                query_type,
                status: Some(status),
                results: (!results.is_empty()).then_some(results),
                dns_server: None,
            })
        }
        3010 => {
            let query_name = c.read_utf16z()?;
            let query_type = c.read_u32_le()?;
            let dns_server = c.read_utf16z()?;
            let pid = if rec.version >= 1 && c.remaining() >= 4 {
                Some(c.read_u32_le()?)
            } else {
                header_pid
            };
            Ok(DnsClientEvent {
                timestamp_utc: rec.timestamp_utc,
                event_id: rec.event_id,
                kind: DnsEventKind::ServerSent,
                activity_id: rec.activity_id,
                pid,
                query_name,
                query_type,
                status: None,
                results: None,
                dns_server: (!dns_server.is_empty()).then_some(dns_server),
            })
        }
        3011 => {
            let query_name = c.read_utf16z()?;
            let query_type = c.read_u32_le()?;
            let dns_server = c.read_utf16z()?;
            let status = c.read_u32_le()?;
            let pid = if rec.version >= 1 && c.remaining() >= 4 {
                Some(c.read_u32_le()?)
            } else {
                header_pid
            };
            Ok(DnsClientEvent {
                timestamp_utc: rec.timestamp_utc,
                event_id: rec.event_id,
                kind: DnsEventKind::ServerResponse,
                activity_id: rec.activity_id,
                pid,
                query_name,
                query_type,
                status: Some(status),
                results: None,
                dns_server: (!dns_server.is_empty()).then_some(dns_server),
            })
        }
        3016 => {
            let query_name = c.read_utf16z()?;
            let query_type = c.read_u32_le()?;
            let _options = c.read_u64_le()?;
            let _if_idx = c.read_u32_le()?;
            let pid = if rec.version >= 1 && c.remaining() >= 4 {
                Some(c.read_u32_le()?)
            } else {
                header_pid
            };
            Ok(DnsClientEvent {
                timestamp_utc: rec.timestamp_utc,
                event_id: rec.event_id,
                kind: DnsEventKind::CacheLookup,
                activity_id: rec.activity_id,
                pid,
                query_name,
                query_type,
                status: None,
                results: None,
                dns_server: None,
            })
        }
        3018 => {
            let query_name = c.read_utf16z()?;
            let query_type = c.read_u32_le()?;
            let _options = c.read_u64_le()?;
            let status = c.read_u32_le()?;
            let results = c.read_utf16z()?;
            let pid = if rec.version >= 1 && c.remaining() >= 4 {
                Some(c.read_u32_le()?)
            } else {
                header_pid
            };
            Ok(DnsClientEvent {
                timestamp_utc: rec.timestamp_utc,
                event_id: rec.event_id,
                kind: DnsEventKind::CacheResult,
                activity_id: rec.activity_id,
                pid,
                query_name,
                query_type,
                status: Some(status),
                results: (!results.is_empty()).then_some(results),
                dns_server: None,
            })
        }
        3019 => {
            let query_name = c.read_utf16z()?;
            let query_type = c.read_u32_le()?;
            let _if_idx = c.read_u32_le()?;
            let _net_idx = c.read_u32_le()?;
            let pid = if rec.version >= 1 && c.remaining() >= 4 {
                Some(c.read_u32_le()?)
            } else {
                header_pid
            };
            Ok(DnsClientEvent {
                timestamp_utc: rec.timestamp_utc,
                event_id: rec.event_id,
                kind: DnsEventKind::WireQuery,
                activity_id: rec.activity_id,
                pid,
                query_name,
                query_type,
                status: None,
                results: None,
                dns_server: None,
            })
        }
        3020 => {
            let query_name = c.read_utf16z()?;
            let query_type = c.read_u32_le()?;
            let _net_idx = c.read_u32_le()?;
            let _if_idx = c.read_u32_le()?;
            let status = c.read_u32_le()?;
            let results = c.read_utf16z()?;
            let pid = if rec.version >= 1 && c.remaining() >= 4 {
                Some(c.read_u32_le()?)
            } else {
                header_pid
            };
            Ok(DnsClientEvent {
                timestamp_utc: rec.timestamp_utc,
                event_id: rec.event_id,
                kind: DnsEventKind::WireResponse,
                activity_id: rec.activity_id,
                pid,
                query_name,
                query_type,
                status: Some(status),
                results: (!results.is_empty()).then_some(results),
                dns_server: None,
            })
        }
        other => Err(NetError::ParseError(format!("unsupported DNS-Client event_id {other}"))),
    }
}

pub fn dns_query_type_name(qtype: u32) -> String {
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
        65 => "HTTPS".to_string(),
        255 => "ANY".to_string(),
        other => format!("TYPE{other}"),
    }
}

pub fn dns_status_name(status: u32) -> String {
    match status {
        0 => "NOERROR".to_string(),
        9001 => "FORMERR".to_string(),
        9002 => "SERVFAIL".to_string(),
        9003 => "NXDOMAIN".to_string(),
        9004 => "NOTIMP".to_string(),
        9005 => "REFUSED".to_string(),
        9701 => "NO_RECORDS".to_string(),
        other => format!("WIN32_{other}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveFlowEntry {
    pub timestamp: DateTime<Utc>,
    pub protocol: String,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub pid: u32,
    pub sent_bytes: u64,
    pub recvd_bytes: u64,
    pub send_packets: u64,
    pub recv_packets: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LiveFlowKey {
    protocol: String,
    local_addr: IpAddr,
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
    pid: u32,
}

#[derive(Debug, Default)]
pub struct LiveTcpUdpAccumulator {
    flows: BTreeMap<LiveFlowKey, LiveFlowEntry>,
}

impl LiveTcpUdpAccumulator {
    pub fn ingest(&mut self, ev: &KernelNetEvent) {
        if ev.direction == KernelNetDirection::Fail {
            return;
        }
        let key = LiveFlowKey {
            protocol: ev.protocol.to_string(),
            local_addr: ev.local_addr,
            local_port: ev.local_port,
            remote_addr: ev.remote_addr,
            remote_port: ev.remote_port,
            pid: ev.pid,
        };
        let entry = self.flows.entry(key).or_insert_with(|| LiveFlowEntry {
            timestamp: ev.timestamp_utc,
            protocol: ev.protocol.to_string(),
            local_addr: ev.local_addr,
            local_port: ev.local_port,
            remote_addr: ev.remote_addr,
            remote_port: ev.remote_port,
            pid: ev.pid,
            sent_bytes: 0,
            recvd_bytes: 0,
            send_packets: 0,
            recv_packets: 0,
        });
        if ev.timestamp_utc > entry.timestamp {
            entry.timestamp = ev.timestamp_utc;
        }
        match ev.direction {
            KernelNetDirection::Send => {
                entry.sent_bytes = entry.sent_bytes.saturating_add(u64::from(ev.size));
                entry.send_packets = entry.send_packets.saturating_add(1);
            }
            KernelNetDirection::Recv => {
                entry.recvd_bytes = entry.recvd_bytes.saturating_add(u64::from(ev.size));
                entry.recv_packets = entry.recv_packets.saturating_add(1);
            }
            _ => {}
        }
    }

    pub fn into_entries(self) -> Vec<LiveFlowEntry> {
        self.flows.into_values().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppNetEntry {
    pub pid: u32,
    pub tcp_sent_bytes: u64,
    pub tcp_recvd_bytes: u64,
    pub udp_sent_bytes: u64,
    pub udp_recvd_bytes: u64,
    pub send_speed_bps: u64,
    pub recv_speed_bps: u64,
}

#[derive(Debug, Default)]
pub struct AppNetworkAccumulator {
    per_pid: BTreeMap<u32, (u64, u64, u64, u64)>,
    min_ts: Option<DateTime<Utc>>,
    max_ts: Option<DateTime<Utc>>,
}

impl AppNetworkAccumulator {
    pub fn ingest(&mut self, ev: &KernelNetEvent) {
        if ev.direction == KernelNetDirection::Fail {
            return;
        }
        self.min_ts = Some(match self.min_ts {
            Some(cur) => cur.min(ev.timestamp_utc),
            None => ev.timestamp_utc,
        });
        self.max_ts = Some(match self.max_ts {
            Some(cur) => cur.max(ev.timestamp_utc),
            None => ev.timestamp_utc,
        });

        let entry = self.per_pid.entry(ev.pid).or_insert((0, 0, 0, 0));
        let is_udp = ev.protocol.starts_with("UDP");
        let bytes = u64::from(ev.size);
        match (is_udp, ev.direction) {
            (false, KernelNetDirection::Send) => entry.0 = entry.0.saturating_add(bytes),
            (false, KernelNetDirection::Recv) => entry.1 = entry.1.saturating_add(bytes),
            (true, KernelNetDirection::Send) => entry.2 = entry.2.saturating_add(bytes),
            (true, KernelNetDirection::Recv) => entry.3 = entry.3.saturating_add(bytes),
            _ => {}
        }
    }

    pub fn into_entries(self) -> Vec<AppNetEntry> {
        let elapsed_ms = match (self.min_ts, self.max_ts) {
            (Some(a), Some(b)) => (b - a).num_milliseconds().max(1000) as f64,
            _ => 1000.0,
        };
        let elapsed_secs = elapsed_ms / 1000.0;

        self.per_pid
            .into_iter()
            .map(|(pid, (tcp_tx, tcp_rx, udp_tx, udp_rx))| {
                let total_tx = tcp_tx.saturating_add(udp_tx);
                let total_rx = tcp_rx.saturating_add(udp_rx);
                AppNetEntry {
                    pid,
                    tcp_sent_bytes: tcp_tx,
                    tcp_recvd_bytes: tcp_rx,
                    udp_sent_bytes: udp_tx,
                    udp_recvd_bytes: udp_rx,
                    send_speed_bps: (total_tx as f64 / elapsed_secs).round() as u64,
                    recv_speed_bps: (total_rx as f64 / elapsed_secs).round() as u64,
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpErrorEntry {
    pub timestamp: DateTime<Utc>,
    pub pid: u32,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub attempt_count: u64,
    pub error_status: String,
}

#[derive(Debug, Clone)]
struct EndpointCtx {
    pid: u32,
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TcpErrorKey {
    pid: u32,
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
    error_status: String,
}

#[derive(Debug, Default)]
pub struct TcpErrorsCorrelator {
    tcb_map: HashMap<u64, EndpointCtx>,
    errors: BTreeMap<TcpErrorKey, TcpErrorEntry>,
}

impl TcpErrorsCorrelator {
    pub fn ingest(&mut self, ev: &TcpIpEvent) {
        match ev {
            TcpIpEvent::EndpointContext {
                tcb,
                local_port,
                remote_addr,
                remote_port,
                pid,
                ..
            } => {
                let entry = self.tcb_map.entry(*tcb).or_insert(EndpointCtx {
                    pid: pid.unwrap_or(0),
                    local_port: *local_port,
                    remote_addr: *remote_addr,
                    remote_port: *remote_port,
                });
                if let Some(p) = pid {
                    entry.pid = *p;
                }
                if *local_port != 0 {
                    entry.local_port = *local_port;
                }
                if *remote_port != 0 {
                    entry.remote_addr = *remote_addr;
                    entry.remote_port = *remote_port;
                }
            }
            TcpIpEvent::ConnectFailure {
                timestamp_utc,
                tcb,
                local_port,
                remote_addr,
                remote_port,
                status,
                pid,
                ..
            } => {
                self.tcb_map.insert(
                    *tcb,
                    EndpointCtx {
                        pid: *pid,
                        local_port: *local_port,
                        remote_addr: *remote_addr,
                        remote_port: *remote_port,
                    },
                );
                self.record_error(
                    *timestamp_utc,
                    *pid,
                    *local_port,
                    *remote_addr,
                    *remote_port,
                    1,
                    ntstatus_to_label(*status),
                );
            }
            TcpIpEvent::RetransmitOrTimeout {
                timestamp_utc,
                tcb,
                status,
                rexmit_count,
                ..
            } => {
                if let Some(ctx) = self.tcb_map.get(tcb).cloned() {
                    let label = status
                        .map(ntstatus_to_label)
                        .unwrap_or_else(|| "Retransmit".to_string());
                    self.record_error(
                        *timestamp_utc,
                        ctx.pid,
                        ctx.local_port,
                        ctx.remote_addr,
                        ctx.remote_port,
                        u64::from(*rexmit_count),
                        label,
                    );
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_error(
        &mut self,
        timestamp: DateTime<Utc>,
        pid: u32,
        local_port: u16,
        remote_addr: IpAddr,
        remote_port: u16,
        count: u64,
        error_status: String,
    ) {
        let key = TcpErrorKey {
            pid,
            local_port,
            remote_addr,
            remote_port,
            error_status: error_status.clone(),
        };
        let entry = self.errors.entry(key).or_insert_with(|| TcpErrorEntry {
            timestamp,
            pid,
            local_port,
            remote_addr,
            remote_port,
            attempt_count: 0,
            error_status,
        });
        if timestamp > entry.timestamp {
            entry.timestamp = timestamp;
        }
        entry.attempt_count = entry.attempt_count.saturating_add(count);
    }

    pub fn into_entries(self) -> Vec<TcpErrorEntry> {
        self.errors.into_values().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsLookupEntry {
    pub timestamp: DateTime<Utc>,
    pub pid: Option<u32>,
    pub query_name: String,
    pub query_type: String,
    pub status: String,
    pub result_records: Option<String>,
    pub latency_ms: Option<u64>,
}

type DnsActivityKey = ([u8; 16], String, u32);
type DnsQueryKey = (String, u32);
type DnsStartInfo = (DateTime<Utc>, Option<u32>);

#[derive(Debug, Default)]
pub struct DnsLookupCorrelator {
    start_by_activity: HashMap<DnsActivityKey, DnsStartInfo>,
    start_by_query: HashMap<DnsQueryKey, DnsStartInfo>,
    entries: Vec<DnsLookupEntry>,
}

impl DnsLookupCorrelator {
    pub fn ingest(&mut self, ev: &DnsClientEvent) {
        match ev.kind {
            DnsEventKind::QueryCalled
            | DnsEventKind::ServerSent
            | DnsEventKind::CacheLookup
            | DnsEventKind::WireQuery => {
                let act_key = (ev.activity_id, ev.query_name.clone(), ev.query_type);
                let slot = self
                    .start_by_activity
                    .entry(act_key)
                    .or_insert((ev.timestamp_utc, ev.pid));
                if ev.timestamp_utc < slot.0 {
                    slot.0 = ev.timestamp_utc;
                }
                if slot.1.is_none() {
                    slot.1 = ev.pid;
                }

                let q_key = (ev.query_name.clone(), ev.query_type);
                let q_slot = self.start_by_query.entry(q_key).or_insert((ev.timestamp_utc, ev.pid));
                if q_slot.1.is_none() {
                    q_slot.1 = ev.pid;
                }
            }
            DnsEventKind::QueryCompleted
            | DnsEventKind::ServerResponse
            | DnsEventKind::CacheResult
            | DnsEventKind::WireResponse => {
                let act_key = (ev.activity_id, ev.query_name.clone(), ev.query_type);
                let q_key = (ev.query_name.clone(), ev.query_type);
                let start = self
                    .start_by_activity
                    .get(&act_key)
                    .copied()
                    .or_else(|| self.start_by_query.get(&q_key).copied());

                let pid = ev.pid.or_else(|| start.and_then(|(_, p)| p));
                let latency_ms = start.map(|(t0, _)| (ev.timestamp_utc - t0).num_milliseconds().max(0) as u64);
                let status = ev.status.map(dns_status_name).unwrap_or_else(|| "UNKNOWN".to_string());

                self.entries.push(DnsLookupEntry {
                    timestamp: ev.timestamp_utc,
                    pid,
                    query_name: ev.query_name.clone(),
                    query_type: dns_query_type_name(ev.query_type),
                    status,
                    result_records: ev.results.clone().or_else(|| ev.dns_server.clone()),
                    latency_ms,
                });
            }
        }
    }

    pub fn merge_cache_entries(&mut self, cache: &[RawDnsCacheEntry], snapshot_ts: DateTime<Utc>) {
        for c in cache {
            self.entries.push(DnsLookupEntry {
                timestamp: snapshot_ts,
                pid: None,
                query_name: c.name.clone(),
                query_type: dns_query_type_name(u32::from(c.record_type)),
                status: "CACHED".to_string(),
                result_records: Some(format!("cache_len={} flags=0x{:x}", c.data_length, c.flags)),
                latency_ms: Some(0),
            });
        }
    }

    pub fn into_entries(self) -> Vec<DnsLookupEntry> {
        self.entries
    }
}
