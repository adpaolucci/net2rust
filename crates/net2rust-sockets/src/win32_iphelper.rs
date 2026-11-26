use std::collections::{BTreeMap, HashMap};
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use chrono::Utc;
use net2rust_core::{MacAddr, NetError, NetResult};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BUFFER_OVERFLOW, ERROR_ELEVATION_REQUIRED, ERROR_INSUFFICIENT_BUFFER,
    ERROR_INVALID_PARAMETER, ERROR_NO_DATA, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias, CreateIpForwardEntry2,
    DeleteIpForwardEntry2, FreeMibTable, GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_INCLUDE_GATEWAYS,
    GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses, GetExtendedTcpTable, GetExtendedUdpTable, GetIcmpStatisticsEx,
    GetIfTable2, GetIpForwardTable2, GetIpNetTable2, GetIpPathTable, GetIpStatisticsEx, GetPerTcp6ConnectionEStats,
    GetPerTcpConnectionEStats, GetTcpStatisticsEx, GetUdpStatisticsEx, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_DHCP_ENABLED, InitializeIpForwardEntry, MIB_ICMP_EX_XPSP1, MIB_IF_ROW2, MIB_IF_TABLE2,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPNET_ROW2, MIB_IPNET_TABLE2, MIB_IPPATH_ROW, MIB_IPPATH_TABLE,
    MIB_IPSTATS_LH, MIB_TCP_STATE, MIB_TCP_STATE_DELETE_TCB, MIB_TCP6ROW, MIB_TCP6ROW_OWNER_MODULE,
    MIB_TCP6TABLE_OWNER_MODULE, MIB_TCPROW_LH, MIB_TCPROW_OWNER_MODULE, MIB_TCPSTATS_LH, MIB_TCPTABLE_OWNER_MODULE,
    MIB_UDP6ROW_OWNER_MODULE, MIB_UDP6TABLE_OWNER_MODULE, MIB_UDPROW_OWNER_MODULE, MIB_UDPSTATS,
    MIB_UDPTABLE_OWNER_MODULE, SetPerTcp6ConnectionEStats, SetPerTcpConnectionEStats, SetTcpEntry,
    TCP_ESTATS_DATA_ROD_v0, TCP_ESTATS_DATA_RW_v0, TCP_TABLE_OWNER_MODULE_ALL, TcpConnectionEstatsData,
    UDP_TABLE_OWNER_MODULE,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN6_ADDR, MIB_IPPROTO_NETMGMT, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_INET,
};
use windows::core::PCWSTR;
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

use crate::diff::{CounterKind, CounterSample, CounterSnapshot, TcpEndpointKey, TcpEndpointState, TcpSnapshot};
use crate::model::{
    RawAdapterRow, RawInterfaceConfig, RawNeighborRow, RawPathRow, RawPortsBundle, RawRouteRow, RawTcpEntry,
    RawTcpipRegConfig, RawUdpEntry, decode_mib_port, encode_mib_port, filetime_i64_to_utc, if_type_name,
    media_state_name, neighbor_state_name, oper_status_name, parse_reg_dns_list, route_protocol_name,
};
use crate::win32_proc::ProcessResolver;

struct MibTableGuard<T>(*mut T);

impl<T> Drop for MibTableGuard<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                FreeMibTable(self.0.cast::<c_void>());
            }
        }
    }
}

fn map_win32_err(code: u32, context: &str) -> NetError {
    if code == ERROR_ACCESS_DENIED.0 || code == ERROR_ELEVATION_REQUIRED.0 {
        NetError::PermissionDenied(format!("{context}: Win32 error {code}"))
    } else if code == ERROR_NOT_FOUND.0 || code == 317 {
        NetError::HardwareNotFound(format!("{context}: Win32 error {code}"))
    } else if code == ERROR_INVALID_PARAMETER.0 {
        NetError::InvalidInput(format!("{context}: invalid parameter (Win32 error {code})"))
    } else if code == ERROR_OBJECT_ALREADY_EXISTS.0 {
        NetError::InvalidInput(format!("{context}: entry already exists (Win32 error {code})"))
    } else {
        NetError::NetworkError(format!("{context}: Win32 error {code}"))
    }
}

/// Validate checked byte bounds for a Win32 `GetExtended*Table` flexible-array buffer
/// and return a slice without creating a `&Table` reference (preserving `[Row; 1]` provenance).
unsafe fn extended_table_rows<Row>(buf: &[u64], num_entries: u32, table_offset: usize, rows_ptr: *const Row) -> &[Row] {
    let count = num_entries as usize;
    if count == 0 {
        return &[];
    }
    let Some(bytes_needed) = count
        .checked_mul(std::mem::size_of::<Row>())
        .and_then(|row_bytes| table_offset.checked_add(row_bytes))
    else {
        return &[];
    };
    if bytes_needed > buf.len().saturating_mul(8) {
        return &[];
    }
    unsafe { std::slice::from_raw_parts(rows_ptr, count) }
}

macro_rules! extended_table_slice {
    ($buf:expr, $table_ty:ty, $row_ty:ty) => {{
        let buf: &[u64] = $buf;
        if buf.len().saturating_mul(8) < std::mem::size_of::<$table_ty>() {
            &[][..]
        } else {
            let tbl_ptr = buf.as_ptr().cast::<$table_ty>();
            let count = unsafe { std::ptr::addr_of!((*tbl_ptr).dwNumEntries).read() };
            let rows_ptr = unsafe { std::ptr::addr_of!((*tbl_ptr).table) }.cast::<$row_ty>();
            unsafe { extended_table_rows::<$row_ty>(buf, count, std::mem::offset_of!($table_ty, table), rows_ptr) }
        }
    }};
}

macro_rules! mib_table_slice {
    ($table_ptr:expr, $row_ty:ty) => {{
        let tbl_ptr = $table_ptr;
        if tbl_ptr.is_null() {
            &[][..]
        } else {
            let count = unsafe { std::ptr::addr_of!((*tbl_ptr).NumEntries).read() } as usize;
            if count == 0 {
                &[][..]
            } else {
                let rows_ptr = unsafe { std::ptr::addr_of!((*tbl_ptr).Table) }.cast::<$row_ty>();
                unsafe { std::slice::from_raw_parts(rows_ptr, count) }
            }
        }
    }};
}

fn sockaddr_to_ip(addr: *const SOCKADDR) -> Option<IpAddr> {
    if addr.is_null() {
        return None;
    }
    let family = unsafe { (*addr).sa_family };
    if family == AF_INET {
        let sin = unsafe { &*(addr.cast::<SOCKADDR_IN>()) };
        let raw = unsafe { sin.sin_addr.S_un.S_addr };
        Some(IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes())))
    } else if family == AF_INET6 {
        let sin6 = unsafe { &*(addr.cast::<SOCKADDR_IN6>()) };
        let bytes = unsafe { sin6.sin6_addr.u.Byte };
        Some(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        None
    }
}

pub(crate) fn sockaddr_inet_to_ip(addr: &SOCKADDR_INET) -> IpAddr {
    let family = unsafe { addr.si_family };
    if family == AF_INET {
        let raw = unsafe { addr.Ipv4.sin_addr.S_un.S_addr };
        IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes()))
    } else if family == AF_INET6 {
        let bytes = unsafe { addr.Ipv6.sin6_addr.u.Byte };
        IpAddr::V6(Ipv6Addr::from(bytes))
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }
}

fn ip_to_sockaddr_inet(ip: IpAddr) -> SOCKADDR_INET {
    let mut out = SOCKADDR_INET::default();
    match ip {
        IpAddr::V4(v4) => {
            out.si_family = AF_INET;
            out.Ipv4.sin_family = AF_INET;
            out.Ipv4.sin_addr = IN_ADDR {
                S_un: windows::Win32::Networking::WinSock::IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(v4.octets()),
                },
            };
        }
        IpAddr::V6(v6) => {
            out.si_family = AF_INET6;
            out.Ipv6.sin6_family = AF_INET6;
            out.Ipv6.sin6_addr = IN6_ADDR {
                u: windows::Win32::Networking::WinSock::IN6_ADDR_0 { Byte: v6.octets() },
            };
        }
    }
    out
}

fn luid_to_alias(luid: &NET_LUID_LH) -> Option<String> {
    let mut buf = [0u16; 257];
    let rc = unsafe { ConvertInterfaceLuidToAlias(luid, &mut buf) };
    if rc == NO_ERROR {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let s = String::from_utf16_lossy(&buf[..end]);
        (!s.is_empty()).then_some(s)
    } else {
        None
    }
}

fn query_extended_tcp_bytes(family: u32) -> NetResult<Vec<u64>> {
    let mut aligned = vec![0u64; 1024];
    let mut size = (aligned.len() * 8) as u32;
    for _ in 0..8 {
        let rc = unsafe {
            GetExtendedTcpTable(
                Some(aligned.as_mut_ptr().cast::<c_void>()),
                &mut size,
                true,
                family,
                TCP_TABLE_OWNER_MODULE_ALL,
                0,
            )
        };
        if rc == NO_ERROR.0 {
            return Ok(aligned);
        }
        if rc == ERROR_INSUFFICIENT_BUFFER.0 {
            let needed = (size as usize).div_ceil(8).max(aligned.len() * 2);
            aligned.resize(needed, 0);
            size = (aligned.len() * 8) as u32;
            continue;
        }
        return Err(map_win32_err(rc, "GetExtendedTcpTable"));
    }
    Err(NetError::Internal(
        "GetExtendedTcpTable exceeded buffer resize attempts".to_string(),
    ))
}

fn query_extended_udp_bytes(family: u32) -> NetResult<Vec<u64>> {
    let mut aligned = vec![0u64; 512];
    let mut size = (aligned.len() * 8) as u32;
    for _ in 0..8 {
        let rc = unsafe {
            GetExtendedUdpTable(
                Some(aligned.as_mut_ptr().cast::<c_void>()),
                &mut size,
                true,
                family,
                UDP_TABLE_OWNER_MODULE,
                0,
            )
        };
        if rc == NO_ERROR.0 {
            return Ok(aligned);
        }
        if rc == ERROR_INSUFFICIENT_BUFFER.0 {
            let needed = (size as usize).div_ceil(8).max(aligned.len() * 2);
            aligned.resize(needed, 0);
            size = (aligned.len() * 8) as u32;
            continue;
        }
        return Err(map_win32_err(rc, "GetExtendedUdpTable"));
    }
    Err(NetError::Internal(
        "GetExtendedUdpTable exceeded buffer resize attempts".to_string(),
    ))
}

fn query_tcp4_estats(
    local_addr: u32,
    local_port: u32,
    remote_addr: u32,
    remote_port: u32,
    state: u32,
    allow_enable: &mut bool,
) -> (Option<u64>, Option<u64>) {
    if state == 2 {
        return (None, None);
    }
    let row = MIB_TCPROW_LH {
        Anonymous: windows::Win32::NetworkManagement::IpHelper::MIB_TCPROW_LH_0 { dwState: state },
        dwLocalAddr: local_addr,
        dwLocalPort: local_port,
        dwRemoteAddr: remote_addr,
        dwRemotePort: remote_port,
    };
    let mut rw = TCP_ESTATS_DATA_RW_v0::default();
    let mut rod = TCP_ESTATS_DATA_ROD_v0::default();
    let rw_slice = unsafe {
        std::slice::from_raw_parts_mut((&raw mut rw).cast::<u8>(), std::mem::size_of::<TCP_ESTATS_DATA_RW_v0>())
    };
    let rod_slice = unsafe {
        std::slice::from_raw_parts_mut(
            (&raw mut rod).cast::<u8>(),
            std::mem::size_of::<TCP_ESTATS_DATA_ROD_v0>(),
        )
    };

    let rc = unsafe {
        GetPerTcpConnectionEStats(
            &row,
            TcpConnectionEstatsData,
            Some(rw_slice),
            0,
            None,
            0,
            Some(rod_slice),
            0,
        )
    };
    if rc == NO_ERROR.0 && rw.EnableCollection {
        return (Some(rod.DataBytesOut), Some(rod.DataBytesIn));
    }

    if *allow_enable && !rw.EnableCollection {
        let enable_rw = TCP_ESTATS_DATA_RW_v0 { EnableCollection: true };
        let enable_slice = unsafe {
            std::slice::from_raw_parts(
                (&raw const enable_rw).cast::<u8>(),
                std::mem::size_of::<TCP_ESTATS_DATA_RW_v0>(),
            )
        };
        let set_rc = unsafe { SetPerTcpConnectionEStats(&row, TcpConnectionEstatsData, enable_slice, 0, 0) };
        if set_rc == ERROR_ACCESS_DENIED.0 || set_rc == ERROR_ELEVATION_REQUIRED.0 {
            *allow_enable = false;
        } else if set_rc == NO_ERROR.0 {
            let rc2 = unsafe {
                GetPerTcpConnectionEStats(
                    &row,
                    TcpConnectionEstatsData,
                    Some(rw_slice),
                    0,
                    None,
                    0,
                    Some(rod_slice),
                    0,
                )
            };
            if rc2 == NO_ERROR.0 && rw.EnableCollection {
                return (Some(rod.DataBytesOut), Some(rod.DataBytesIn));
            }
        }
    }
    (None, None)
}

#[allow(clippy::too_many_arguments)]
fn query_tcp6_estats(
    local_addr: [u8; 16],
    local_scope: u32,
    local_port: u32,
    remote_addr: [u8; 16],
    remote_scope: u32,
    remote_port: u32,
    state: u32,
    allow_enable: &mut bool,
) -> (Option<u64>, Option<u64>) {
    if state == 2 {
        return (None, None);
    }
    let row = MIB_TCP6ROW {
        State: MIB_TCP_STATE(state as i32),
        LocalAddr: IN6_ADDR {
            u: windows::Win32::Networking::WinSock::IN6_ADDR_0 { Byte: local_addr },
        },
        dwLocalScopeId: local_scope,
        dwLocalPort: local_port,
        RemoteAddr: IN6_ADDR {
            u: windows::Win32::Networking::WinSock::IN6_ADDR_0 { Byte: remote_addr },
        },
        dwRemoteScopeId: remote_scope,
        dwRemotePort: remote_port,
    };
    let mut rw = TCP_ESTATS_DATA_RW_v0::default();
    let mut rod = TCP_ESTATS_DATA_ROD_v0::default();
    let rw_slice = unsafe {
        std::slice::from_raw_parts_mut((&raw mut rw).cast::<u8>(), std::mem::size_of::<TCP_ESTATS_DATA_RW_v0>())
    };
    let rod_slice = unsafe {
        std::slice::from_raw_parts_mut(
            (&raw mut rod).cast::<u8>(),
            std::mem::size_of::<TCP_ESTATS_DATA_ROD_v0>(),
        )
    };

    let rc = unsafe {
        GetPerTcp6ConnectionEStats(
            &row,
            TcpConnectionEstatsData,
            Some(rw_slice),
            0,
            None,
            0,
            Some(rod_slice),
            0,
        )
    };
    if rc == NO_ERROR.0 && rw.EnableCollection {
        return (Some(rod.DataBytesOut), Some(rod.DataBytesIn));
    }

    if *allow_enable && !rw.EnableCollection {
        let enable_rw = TCP_ESTATS_DATA_RW_v0 { EnableCollection: true };
        let enable_slice = unsafe {
            std::slice::from_raw_parts(
                (&raw const enable_rw).cast::<u8>(),
                std::mem::size_of::<TCP_ESTATS_DATA_RW_v0>(),
            )
        };
        let set_rc = unsafe { SetPerTcp6ConnectionEStats(&row, TcpConnectionEstatsData, enable_slice, 0, 0) };
        if set_rc == ERROR_ACCESS_DENIED.0 || set_rc == ERROR_ELEVATION_REQUIRED.0 {
            *allow_enable = false;
        } else if set_rc == NO_ERROR.0 {
            let rc2 = unsafe {
                GetPerTcp6ConnectionEStats(
                    &row,
                    TcpConnectionEstatsData,
                    Some(rw_slice),
                    0,
                    None,
                    0,
                    Some(rod_slice),
                    0,
                )
            };
            if rc2 == NO_ERROR.0 && rw.EnableCollection {
                return (Some(rod.DataBytesOut), Some(rod.DataBytesIn));
            }
        }
    }
    (None, None)
}

pub fn query_ports_live(include_estats: bool) -> NetResult<RawPortsBundle> {
    let mut resolver = ProcessResolver::new();
    let mut tcp = Vec::new();
    let mut udp = Vec::new();
    let mut allow_enable_estats = include_estats;

    // TCPv4
    let tcp4_buf = query_extended_tcp_bytes(u32::from(AF_INET.0))?;
    for r in extended_table_slice!(&tcp4_buf, MIB_TCPTABLE_OWNER_MODULE, MIB_TCPROW_OWNER_MODULE) {
        let meta = resolver.resolve_with_owner_module(r.dwOwningPid, Some(&r.OwningModuleInfo));
        let (sent, recvd) = if include_estats {
            query_tcp4_estats(
                r.dwLocalAddr,
                r.dwLocalPort,
                r.dwRemoteAddr,
                r.dwRemotePort,
                r.dwState,
                &mut allow_enable_estats,
            )
        } else {
            (None, None)
        };
        tcp.push(RawTcpEntry {
            protocol: "TCP".to_string(),
            state_code: r.dwState,
            local_addr: IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())),
            local_port: decode_mib_port(r.dwLocalPort),
            remote_addr: IpAddr::V4(Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes())),
            remote_port: decode_mib_port(r.dwRemotePort),
            pid: r.dwOwningPid,
            process_name: meta.name,
            process_path: meta.path,
            user_name: meta.user,
            created_time: filetime_i64_to_utc(r.liCreateTimestamp),
            estats_bytes_sent: sent,
            estats_bytes_recvd: recvd,
        });
    }

    // TCPv6
    if let Ok(tcp6_buf) = query_extended_tcp_bytes(u32::from(AF_INET6.0)) {
        for r in extended_table_slice!(&tcp6_buf, MIB_TCP6TABLE_OWNER_MODULE, MIB_TCP6ROW_OWNER_MODULE) {
            let meta = resolver.resolve_with_owner_module(r.dwOwningPid, Some(&r.OwningModuleInfo));
            let (sent, recvd) = if include_estats {
                query_tcp6_estats(
                    r.ucLocalAddr,
                    r.dwLocalScopeId,
                    r.dwLocalPort,
                    r.ucRemoteAddr,
                    r.dwRemoteScopeId,
                    r.dwRemotePort,
                    r.dwState,
                    &mut allow_enable_estats,
                )
            } else {
                (None, None)
            };
            tcp.push(RawTcpEntry {
                protocol: "TCPv6".to_string(),
                state_code: r.dwState,
                local_addr: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                local_port: decode_mib_port(r.dwLocalPort),
                remote_addr: IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)),
                remote_port: decode_mib_port(r.dwRemotePort),
                pid: r.dwOwningPid,
                process_name: meta.name,
                process_path: meta.path,
                user_name: meta.user,
                created_time: filetime_i64_to_utc(r.liCreateTimestamp),
                estats_bytes_sent: sent,
                estats_bytes_recvd: recvd,
            });
        }
    }

    // UDPv4
    let udp4_buf = query_extended_udp_bytes(u32::from(AF_INET.0))?;
    for r in extended_table_slice!(&udp4_buf, MIB_UDPTABLE_OWNER_MODULE, MIB_UDPROW_OWNER_MODULE) {
        let meta = resolver.resolve_with_owner_module(r.dwOwningPid, Some(&r.OwningModuleInfo));
        udp.push(RawUdpEntry {
            protocol: "UDP".to_string(),
            local_addr: IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())),
            local_port: decode_mib_port(r.dwLocalPort),
            pid: r.dwOwningPid,
            process_name: meta.name,
            process_path: meta.path,
            user_name: meta.user,
            created_time: filetime_i64_to_utc(r.liCreateTimestamp),
        });
    }

    // UDPv6
    if let Ok(udp6_buf) = query_extended_udp_bytes(u32::from(AF_INET6.0)) {
        for r in extended_table_slice!(&udp6_buf, MIB_UDP6TABLE_OWNER_MODULE, MIB_UDP6ROW_OWNER_MODULE) {
            let meta = resolver.resolve_with_owner_module(r.dwOwningPid, Some(&r.OwningModuleInfo));
            udp.push(RawUdpEntry {
                protocol: "UDPv6".to_string(),
                local_addr: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                local_port: decode_mib_port(r.dwLocalPort),
                pid: r.dwOwningPid,
                process_name: meta.name,
                process_path: meta.path,
                user_name: meta.user,
                created_time: filetime_i64_to_utc(r.liCreateTimestamp),
            });
        }
    }

    Ok(RawPortsBundle { tcp, udp })
}

pub fn capture_tcp_snapshot_live(resolver: &mut ProcessResolver) -> NetResult<TcpSnapshot> {
    let mut entries = BTreeMap::new();
    let tcp4_buf = query_extended_tcp_bytes(u32::from(AF_INET.0))?;
    for r in extended_table_slice!(&tcp4_buf, MIB_TCPTABLE_OWNER_MODULE, MIB_TCPROW_OWNER_MODULE) {
        let meta = resolver.resolve_with_owner_module(r.dwOwningPid, Some(&r.OwningModuleInfo));
        entries.insert(
            TcpEndpointKey {
                ip_version: 4,
                local_addr: IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())),
                local_port: decode_mib_port(r.dwLocalPort),
                remote_addr: IpAddr::V4(Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes())),
                remote_port: decode_mib_port(r.dwRemotePort),
                pid: r.dwOwningPid,
            },
            TcpEndpointState {
                state_code: r.dwState,
                process_name: meta.name,
            },
        );
    }

    if let Ok(tcp6_buf) = query_extended_tcp_bytes(u32::from(AF_INET6.0)) {
        for r in extended_table_slice!(&tcp6_buf, MIB_TCP6TABLE_OWNER_MODULE, MIB_TCP6ROW_OWNER_MODULE) {
            let meta = resolver.resolve_with_owner_module(r.dwOwningPid, Some(&r.OwningModuleInfo));
            entries.insert(
                TcpEndpointKey {
                    ip_version: 6,
                    local_addr: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                    local_port: decode_mib_port(r.dwLocalPort),
                    remote_addr: IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)),
                    remote_port: decode_mib_port(r.dwRemotePort),
                    pid: r.dwOwningPid,
                },
                TcpEndpointState {
                    state_code: r.dwState,
                    process_name: meta.name,
                },
            );
        }
    }

    Ok(TcpSnapshot {
        captured_at: Utc::now(),
        entries,
    })
}

pub fn query_counters_snapshot_live(captured_at_ns: u64) -> NetResult<CounterSnapshot> {
    let mut values = BTreeMap::new();
    let families = [(u32::from(AF_INET.0), "v4"), (u32::from(AF_INET6.0), "v6")];

    for (af, suffix) in families {
        let mut ip = MIB_IPSTATS_LH::default();
        if unsafe { GetIpStatisticsEx(&mut ip, af) } == NO_ERROR.0 {
            let prefix = if suffix == "v4" { "IPv4" } else { "IPv6" };
            let group = prefix.to_string();
            values.insert(
                (group.clone(), format!("{prefix}.InReceives")),
                CounterSample {
                    value: u64::from(ip.dwInReceives),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.InHdrErrors")),
                CounterSample {
                    value: u64::from(ip.dwInHdrErrors),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.InAddrErrors")),
                CounterSample {
                    value: u64::from(ip.dwInAddrErrors),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.InDelivers")),
                CounterSample {
                    value: u64::from(ip.dwInDelivers),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.OutRequests")),
                CounterSample {
                    value: u64::from(ip.dwOutRequests),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.OutDiscards")),
                CounterSample {
                    value: u64::from(ip.dwOutDiscards),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.OutNoRoutes")),
                CounterSample {
                    value: u64::from(ip.dwOutNoRoutes),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group, format!("{prefix}.NumRoutes")),
                CounterSample {
                    value: u64::from(ip.dwNumRoutes),
                    kind: CounterKind::Gauge,
                },
            );
        }

        let mut tcp = MIB_TCPSTATS_LH::default();
        if unsafe { GetTcpStatisticsEx(&mut tcp, af) } == NO_ERROR.0 {
            let group = "TCP".to_string();
            let prefix = if suffix == "v4" { "TCPv4" } else { "TCPv6" };
            values.insert(
                (group.clone(), format!("{prefix}.ActiveOpens")),
                CounterSample {
                    value: u64::from(tcp.dwActiveOpens),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.PassiveOpens")),
                CounterSample {
                    value: u64::from(tcp.dwPassiveOpens),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.AttemptFails")),
                CounterSample {
                    value: u64::from(tcp.dwAttemptFails),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.EstabResets")),
                CounterSample {
                    value: u64::from(tcp.dwEstabResets),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.CurrEstab")),
                CounterSample {
                    value: u64::from(tcp.dwCurrEstab),
                    kind: CounterKind::Gauge,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.InSegs")),
                CounterSample {
                    value: u64::from(tcp.dwInSegs),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.OutSegs")),
                CounterSample {
                    value: u64::from(tcp.dwOutSegs),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.RetransSegs")),
                CounterSample {
                    value: u64::from(tcp.dwRetransSegs),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.InErrs")),
                CounterSample {
                    value: u64::from(tcp.dwInErrs),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group, format!("{prefix}.OutRsts")),
                CounterSample {
                    value: u64::from(tcp.dwOutRsts),
                    kind: CounterKind::Counter32,
                },
            );
        }

        let mut udp = MIB_UDPSTATS::default();
        if unsafe { GetUdpStatisticsEx(&mut udp, af) } == NO_ERROR.0 {
            let group = "UDP".to_string();
            let prefix = if suffix == "v4" { "UDPv4" } else { "UDPv6" };
            values.insert(
                (group.clone(), format!("{prefix}.InDatagrams")),
                CounterSample {
                    value: u64::from(udp.dwInDatagrams),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.OutDatagrams")),
                CounterSample {
                    value: u64::from(udp.dwOutDatagrams),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.NoPorts")),
                CounterSample {
                    value: u64::from(udp.dwNoPorts),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group, format!("{prefix}.InErrors")),
                CounterSample {
                    value: u64::from(udp.dwInErrors),
                    kind: CounterKind::Counter32,
                },
            );
        }

        let mut icmp = MIB_ICMP_EX_XPSP1::default();
        if unsafe { GetIcmpStatisticsEx(&mut icmp, af) } == NO_ERROR.0 {
            let group = "ICMP".to_string();
            let prefix = if suffix == "v4" { "ICMPv4" } else { "ICMPv6" };
            values.insert(
                (group.clone(), format!("{prefix}.InMsgs")),
                CounterSample {
                    value: u64::from(icmp.icmpInStats.dwMsgs),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.InErrors")),
                CounterSample {
                    value: u64::from(icmp.icmpInStats.dwErrors),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group.clone(), format!("{prefix}.OutMsgs")),
                CounterSample {
                    value: u64::from(icmp.icmpOutStats.dwMsgs),
                    kind: CounterKind::Counter32,
                },
            );
            values.insert(
                (group, format!("{prefix}.OutErrors")),
                CounterSample {
                    value: u64::from(icmp.icmpOutStats.dwErrors),
                    kind: CounterKind::Counter32,
                },
            );
        }
    }

    if values.is_empty() {
        return Err(NetError::NetworkUnavailable(
            "no IP/TCP/UDP/ICMP statistics returned by iphlpapi".to_string(),
        ));
    }

    Ok(CounterSnapshot { captured_at_ns, values })
}

pub fn query_adapters_if_table_live() -> NetResult<Vec<RawAdapterRow>> {
    let mut table_ptr: *mut MIB_IF_TABLE2 = ptr::null_mut();
    let rc = unsafe { GetIfTable2(&mut table_ptr) };
    if rc != NO_ERROR {
        return Err(map_win32_err(rc.0, "GetIfTable2"));
    }
    let _guard = MibTableGuard(table_ptr);
    let rows = mib_table_slice!(table_ptr, MIB_IF_ROW2);
    if rows.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let alias_end = r.Alias.iter().position(|&c| c == 0).unwrap_or(r.Alias.len());
        let desc_end = r
            .Description
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(r.Description.len());
        let adapter_name = String::from_utf16_lossy(&r.Alias[..alias_end]);
        let description = String::from_utf16_lossy(&r.Description[..desc_end]);
        let link_speed = if r.TransmitLinkSpeed == u64::MAX {
            None
        } else {
            Some(r.TransmitLinkSpeed)
        };
        let luid = unsafe { r.InterfaceLuid.Value };
        out.push(RawAdapterRow {
            luid,
            interface_index: r.InterfaceIndex,
            adapter_name,
            description,
            media_state: media_state_name(r.MediaConnectState.0, r.OperStatus.0),
            link_speed,
            bytes_sent: r.OutOctets,
            bytes_recvd: r.InOctets,
            errors: r.InErrors.saturating_add(r.OutErrors),
            discards: r.InDiscards.saturating_add(r.OutDiscards),
        });
    }
    Ok(out)
}

fn read_tcpip_interface_reg(guid: &str) -> Option<RawTcpipRegConfig> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let interfaces = hklm
        .open_subkey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces")
        .ok()?;
    let key = interfaces
        .open_subkey(guid)
        .or_else(|_| interfaces.open_subkey(guid.to_ascii_lowercase()))
        .ok()?;

    let enable_dhcp = key.get_value::<u32, _>("EnableDHCP").ok().map(|v| v != 0);
    let dhcp_server = key.get_value::<String, _>("DhcpServer").ok().filter(|s| !s.is_empty());
    let name_servers = key
        .get_value::<String, _>("NameServer")
        .ok()
        .map(|s| parse_reg_dns_list(&s))
        .unwrap_or_default();
    let dhcp_name_servers = key
        .get_value::<String, _>("DhcpNameServer")
        .ok()
        .map(|s| parse_reg_dns_list(&s))
        .unwrap_or_default();
    let ip_addresses = key.get_value::<Vec<String>, _>("IPAddress").unwrap_or_default();
    let subnet_masks = key.get_value::<Vec<String>, _>("SubnetMask").unwrap_or_default();
    let default_gateways = key.get_value::<Vec<String>, _>("DefaultGateway").unwrap_or_default();
    let domain = key
        .get_value::<String, _>("Domain")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| key.get_value::<String, _>("DhcpDomain").ok().filter(|s| !s.is_empty()));

    Some(RawTcpipRegConfig {
        enable_dhcp,
        dhcp_server,
        name_servers,
        dhcp_name_servers,
        ip_addresses,
        subnet_masks,
        default_gateways,
        domain,
    })
}

pub fn query_interfaces_live() -> NetResult<Vec<RawInterfaceConfig>> {
    let flags = GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX;
    let mut size = 16_384u32;
    let mut aligned = vec![0u64; (size as usize).div_ceil(8)];

    let mut succeeded = false;
    for _ in 0..8 {
        let rc = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                flags,
                None,
                Some(aligned.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                &mut size,
            )
        };
        if rc == NO_ERROR.0 {
            succeeded = true;
            break;
        }
        if rc == ERROR_NO_DATA.0 {
            return Ok(Vec::new());
        }
        if rc == ERROR_BUFFER_OVERFLOW.0 || rc == ERROR_INSUFFICIENT_BUFFER.0 {
            let needed = (size as usize).div_ceil(8).max(aligned.len() * 2);
            aligned.resize(needed, 0);
            size = (aligned.len() * 8) as u32;
            continue;
        }
        return Err(map_win32_err(rc, "GetAdaptersAddresses"));
    }
    if !succeeded {
        return Err(NetError::Internal(
            "GetAdaptersAddresses exceeded buffer resize attempts".to_string(),
        ));
    }

    let mut out = Vec::new();
    let mut cur = aligned.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    let mut steps = 0usize;
    while !cur.is_null() && steps < 4096 {
        steps += 1;
        let adapter = unsafe { &*cur };

        let guid = if adapter.AdapterName.is_null() {
            String::new()
        } else {
            unsafe { adapter.AdapterName.to_string().unwrap_or_default() }
        };
        let interface_name = if adapter.FriendlyName.is_null() {
            guid.clone()
        } else {
            unsafe { adapter.FriendlyName.to_string().unwrap_or_default() }
        };
        let description = if adapter.Description.is_null() {
            String::new()
        } else {
            unsafe { adapter.Description.to_string().unwrap_or_default() }
        };

        let mac_address = if adapter.PhysicalAddressLength == 6 {
            let mut octets = [0u8; 6];
            octets.copy_from_slice(&adapter.PhysicalAddress[..6]);
            Some(MacAddr::new(octets))
        } else {
            None
        };

        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        let mut u_ptr = adapter.FirstUnicastAddress;
        let mut u_steps = 0usize;
        while !u_ptr.is_null() && u_steps < 512 {
            u_steps += 1;
            let u = unsafe { &*u_ptr };
            if let Some(ip) = sockaddr_to_ip(u.Address.lpSockaddr) {
                let formatted = format!("{ip}/{}", u.OnLinkPrefixLength);
                match ip {
                    IpAddr::V4(_) => ipv4.push(formatted),
                    IpAddr::V6(_) => ipv6.push(formatted),
                }
            }
            u_ptr = u.Next;
        }

        let mut gateway = Vec::new();
        let mut gw_ptr = adapter.FirstGatewayAddress;
        let mut gw_steps = 0usize;
        while !gw_ptr.is_null() && gw_steps < 128 {
            gw_steps += 1;
            let gw = unsafe { &*gw_ptr };
            if let Some(ip) = sockaddr_to_ip(gw.Address.lpSockaddr) {
                let s = ip.to_string();
                if !gateway.contains(&s) {
                    gateway.push(s);
                }
            }
            gw_ptr = gw.Next;
        }

        let mut dns_servers = Vec::new();
        let mut dns_ptr = adapter.FirstDnsServerAddress;
        let mut dns_steps = 0usize;
        while !dns_ptr.is_null() && dns_steps < 128 {
            dns_steps += 1;
            let d = unsafe { &*dns_ptr };
            if let Some(ip) = sockaddr_to_ip(d.Address.lpSockaddr) {
                let s = ip.to_string();
                if !dns_servers.contains(&s) {
                    dns_servers.push(s);
                }
            }
            dns_ptr = d.Next;
        }

        let reg_config = (!guid.is_empty()).then(|| read_tcpip_interface_reg(&guid)).flatten();
        if let Some(ref reg) = reg_config {
            for gw in &reg.default_gateways {
                if !gw.is_empty() && !gateway.contains(gw) {
                    gateway.push(gw.clone());
                }
            }
            for dns in reg.name_servers.iter().chain(reg.dhcp_name_servers.iter()) {
                if !dns.is_empty() && !dns_servers.contains(dns) {
                    dns_servers.push(dns.clone());
                }
            }
        }

        let flags_val = unsafe { adapter.Anonymous2.Flags };
        let dhcp_enabled = reg_config
            .as_ref()
            .and_then(|r| r.enable_dhcp)
            .unwrap_or((flags_val & IP_ADAPTER_DHCP_ENABLED) != 0);

        let speed_mbps = if adapter.TransmitLinkSpeed == u64::MAX || adapter.TransmitLinkSpeed == 0 {
            None
        } else {
            Some(adapter.TransmitLinkSpeed / 1_000_000)
        };

        out.push(RawInterfaceConfig {
            interface_name,
            description,
            guid,
            mac_address,
            operational_status: oper_status_name(adapter.OperStatus.0).to_string(),
            if_type: if_type_name(adapter.IfType).to_string(),
            speed_mbps,
            ipv4,
            ipv6,
            gateway,
            dns_servers,
            dhcp_enabled,
            reg_config,
        });

        cur = adapter.Next;
    }

    Ok(out)
}

pub fn query_routes_live() -> NetResult<Vec<RawRouteRow>> {
    let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    let rc = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table_ptr) };
    if rc != NO_ERROR {
        return Err(map_win32_err(rc.0, "GetIpForwardTable2"));
    }
    let _guard = MibTableGuard(table_ptr);
    let rows = mib_table_slice!(table_ptr, MIB_IPFORWARD_ROW2);
    if rows.is_empty() {
        return Ok(Vec::new());
    }

    let mut alias_cache: HashMap<u64, Option<String>> = HashMap::new();
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let luid_val = unsafe { r.InterfaceLuid.Value };
        let interface_alias = alias_cache
            .entry(luid_val)
            .or_insert_with(|| luid_to_alias(&r.InterfaceLuid))
            .clone();

        out.push(RawRouteRow {
            destination: sockaddr_inet_to_ip(&r.DestinationPrefix.Prefix),
            prefix_length: r.DestinationPrefix.PrefixLength,
            next_hop: sockaddr_inet_to_ip(&r.NextHop),
            interface_index: r.InterfaceIndex,
            interface_alias,
            metric: r.Metric,
            protocol: route_protocol_name(r.Protocol.0).to_string(),
            age_secs: r.Age,
        });
    }
    Ok(out)
}

pub fn query_neighbors_live() -> NetResult<Vec<RawNeighborRow>> {
    let mut table_ptr: *mut MIB_IPNET_TABLE2 = ptr::null_mut();
    let rc = unsafe { GetIpNetTable2(AF_UNSPEC, &mut table_ptr) };
    if rc != NO_ERROR {
        return Err(map_win32_err(rc.0, "GetIpNetTable2"));
    }
    let _guard = MibTableGuard(table_ptr);
    let rows = mib_table_slice!(table_ptr, MIB_IPNET_ROW2);
    if rows.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let mac_address = if r.PhysicalAddressLength == 6 {
            let mut octets = [0u8; 6];
            octets.copy_from_slice(&r.PhysicalAddress[..6]);
            Some(MacAddr::new(octets))
        } else {
            None
        };
        let flags = unsafe { r.Anonymous.Flags };
        let is_router = (flags & 0x01) != 0;
        let is_unreachable = (flags & 0x02) != 0;

        out.push(RawNeighborRow {
            interface_index: r.InterfaceIndex,
            ip_address: sockaddr_inet_to_ip(&r.Address),
            mac_address,
            state: neighbor_state_name(r.State.0).to_string(),
            is_router,
            is_unreachable,
        });
    }
    Ok(out)
}

pub fn query_paths_live() -> NetResult<Vec<RawPathRow>> {
    let mut table_ptr: *mut MIB_IPPATH_TABLE = ptr::null_mut();
    let rc = unsafe { GetIpPathTable(AF_UNSPEC, &mut table_ptr) };
    if rc != NO_ERROR {
        return Err(map_win32_err(rc.0, "GetIpPathTable"));
    }
    let _guard = MibTableGuard(table_ptr);
    let rows = mib_table_slice!(table_ptr, MIB_IPPATH_ROW);
    if rows.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(RawPathRow {
            source_ip: sockaddr_inet_to_ip(&r.Source),
            destination_ip: sockaddr_inet_to_ip(&r.Destination),
            next_hop: sockaddr_inet_to_ip(&r.CurrentNextHop),
            link_speed_tx: (r.LinkTransmitSpeed != u64::MAX).then_some(r.LinkTransmitSpeed),
            link_speed_rx: (r.LinkReceiveSpeed != u64::MAX).then_some(r.LinkReceiveSpeed),
            rtt_mean_ms: (r.RttMean != u32::MAX).then_some(r.RttMean),
            rtt_deviation_ms: (r.RttDeviation != u32::MAX).then_some(r.RttDeviation),
            mtu: r.PathMtu,
            is_reachable: r.IsReachable,
        });
    }
    Ok(out)
}

pub fn close_tcp_socket_live(
    local_addr: Ipv4Addr,
    local_port: u16,
    remote_addr: Ipv4Addr,
    remote_port: u16,
) -> NetResult<()> {
    let row = MIB_TCPROW_LH {
        Anonymous: windows::Win32::NetworkManagement::IpHelper::MIB_TCPROW_LH_0 {
            State: MIB_TCP_STATE_DELETE_TCB,
        },
        dwLocalAddr: u32::from_ne_bytes(local_addr.octets()),
        dwLocalPort: encode_mib_port(local_port),
        dwRemoteAddr: u32::from_ne_bytes(remote_addr.octets()),
        dwRemotePort: encode_mib_port(remote_port),
    };
    let rc = unsafe { SetTcpEntry(&row) };
    if rc == NO_ERROR.0 {
        Ok(())
    } else {
        Err(map_win32_err(rc, "SetTcpEntry"))
    }
}

fn resolve_luid_live(interface_index: Option<u32>, interface_alias: Option<&str>) -> NetResult<NET_LUID_LH> {
    let mut luid = NET_LUID_LH::default();
    if let Some(idx) = interface_index {
        let rc = unsafe { ConvertInterfaceIndexToLuid(idx, &mut luid) };
        if rc != NO_ERROR {
            return Err(map_win32_err(rc.0, "ConvertInterfaceIndexToLuid"));
        }
        return Ok(luid);
    }
    if let Some(alias) = interface_alias {
        let mut wide: Vec<u16> = alias.encode_utf16().collect();
        wide.push(0);
        let rc = unsafe { ConvertInterfaceAliasToLuid(PCWSTR(wide.as_ptr()), &mut luid) };
        if rc != NO_ERROR {
            return Err(map_win32_err(rc.0, "ConvertInterfaceAliasToLuid"));
        }
        return Ok(luid);
    }
    Err(NetError::InvalidInput(
        "either interface_index or interface_alias is required".to_string(),
    ))
}

pub fn add_route_live(
    destination: IpAddr,
    prefix_length: u8,
    next_hop: IpAddr,
    interface_index: Option<u32>,
    interface_alias: Option<&str>,
    metric: u32,
) -> NetResult<()> {
    let luid = resolve_luid_live(interface_index, interface_alias)?;
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid;
    if let Some(idx) = interface_index {
        row.InterfaceIndex = idx;
    }
    row.DestinationPrefix.Prefix = ip_to_sockaddr_inet(destination);
    row.DestinationPrefix.PrefixLength = prefix_length;
    row.NextHop = ip_to_sockaddr_inet(next_hop);
    row.Metric = metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;

    let rc = unsafe { CreateIpForwardEntry2(&row) };
    if rc == NO_ERROR {
        Ok(())
    } else {
        Err(map_win32_err(rc.0, "CreateIpForwardEntry2"))
    }
}

pub fn delete_route_live(
    destination: IpAddr,
    prefix_length: u8,
    next_hop: IpAddr,
    interface_index: Option<u32>,
    interface_alias: Option<&str>,
) -> NetResult<()> {
    let luid = resolve_luid_live(interface_index, interface_alias)?;
    let luid_val = unsafe { luid.Value };

    let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    let rc = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table_ptr) };
    if rc != NO_ERROR {
        return Err(map_win32_err(rc.0, "GetIpForwardTable2"));
    }
    let _guard = MibTableGuard(table_ptr);
    let rows = mib_table_slice!(table_ptr, MIB_IPFORWARD_ROW2);
    if rows.is_empty() {
        return Err(NetError::HardwareNotFound("routing table is empty".to_string()));
    }

    let matched = rows
        .iter()
        .find(|r| {
            let r_luid = unsafe { r.InterfaceLuid.Value };
            r_luid == luid_val
                && r.DestinationPrefix.PrefixLength == prefix_length
                && sockaddr_inet_to_ip(&r.DestinationPrefix.Prefix) == destination
                && sockaddr_inet_to_ip(&r.NextHop) == next_hop
        })
        .copied()
        .ok_or_else(|| {
            NetError::HardwareNotFound(format!(
                "matching route {destination}/{prefix_length} via {next_hop} not found"
            ))
        })?;

    let del_rc = unsafe { DeleteIpForwardEntry2(&matched) };
    if del_rc == NO_ERROR {
        Ok(())
    } else {
        Err(map_win32_err(del_rc.0, "DeleteIpForwardEntry2"))
    }
}
