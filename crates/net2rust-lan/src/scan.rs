use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use net2rust_core::{CidrV4, MacAddr, NetContext, NetError, NetResult};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::common::run_bounded;
use crate::fixtures;
use crate::netbios::{LiveUdpNetbiosBackend, NetbiosBackend};
use crate::oui::OuiDatabase;
use crate::ping::{LivePingBackend, PingBackend, PingStatus};
use crate::resolve::{DnsBackend, LiveWinSockDnsBackend};

pub const MAX_SCAN_HOSTS: usize = 4096;
pub const DEFAULT_TCP_PROBE_PORTS: &[u16] = &[22, 80, 135, 139, 443, 445, 3389];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub interface_index: u32,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalInterfaceInfo {
    pub index: u32,
    pub name: String,
    pub ip: Ipv4Addr,
    pub cidr: CidrV4,
    pub mac: Option<MacAddr>,
}

pub trait ArpBackend: Send + Sync {
    fn arp_table(&self) -> NetResult<Vec<ArpEntry>>;
    fn send_arp(&self, target: Ipv4Addr) -> NetResult<Option<MacAddr>>;
    fn local_interfaces(&self) -> NetResult<Vec<LocalInterfaceInfo>>;
}

pub trait TcpProbeBackend: Send + Sync {
    fn probe_ports(&self, ip: IpAddr, ports: &[u16], timeout: Duration) -> Vec<u16>;
}

#[derive(Debug, Default)]
pub struct LiveTcpProbeBackend;

impl TcpProbeBackend for LiveTcpProbeBackend {
    fn probe_ports(&self, ip: IpAddr, ports: &[u16], timeout: Duration) -> Vec<u16> {
        let mut open = Vec::new();
        for &port in ports {
            if TcpStream::connect_timeout(&SocketAddr::new(ip, port), timeout).is_ok() {
                open.push(port);
            }
        }
        open
    }
}

#[derive(Debug, Default)]
pub struct LiveWin32ArpBackend;

impl ArpBackend for LiveWin32ArpBackend {
    fn arp_table(&self) -> NetResult<Vec<ArpEntry>> {
        #[cfg(windows)]
        {
            win32_arp::read_arp_table()
        }
        #[cfg(not(windows))]
        {
            Ok(Vec::new())
        }
    }

    fn send_arp(&self, target: Ipv4Addr) -> NetResult<Option<MacAddr>> {
        #[cfg(windows)]
        {
            win32_arp::send_arp_probe(target)
        }
        #[cfg(not(windows))]
        {
            let _ = target;
            Ok(None)
        }
    }

    fn local_interfaces(&self) -> NetResult<Vec<LocalInterfaceInfo>> {
        #[cfg(windows)]
        {
            win32_arp::read_local_interfaces()
        }
        #[cfg(not(windows))]
        {
            Ok(Vec::new())
        }
    }
}

#[cfg(windows)]
mod win32_arp {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::net::Ipv4Addr;
    use std::ptr;

    use net2rust_core::{CidrV4, MacAddr, NetError, NetResult};
    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses, GetIpNetTable2, IF_TYPE_SOFTWARE_LOOPBACK,
        IP_ADAPTER_ADDRESSES_LH, MIB_IPNET_TABLE2, SendARP,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::{
        AF_INET, NlnsDelay, NlnsIncomplete, NlnsPermanent, NlnsProbe, NlnsReachable, NlnsStale, NlnsUnreachable,
        SOCKADDR_IN,
    };

    use super::{ArpEntry, LocalInterfaceInfo};
    use crate::common::{ipv4_to_win32_u32, pwstr_to_string, win32_u32_to_ipv4};

    struct MibNetTableGuard(*mut MIB_IPNET_TABLE2);
    impl Drop for MibNetTableGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was allocated by `GetIpNetTable2`.
                unsafe { FreeMibTable(self.0.cast::<c_void>()) };
            }
        }
    }

    pub fn read_arp_table() -> NetResult<Vec<ArpEntry>> {
        let mut table_ptr: *mut MIB_IPNET_TABLE2 = ptr::null_mut();
        // SAFETY: `table_ptr` receives a Win32-allocated `MIB_IPNET_TABLE2`.
        let err = unsafe { GetIpNetTable2(AF_INET, &mut table_ptr) };
        if err != NO_ERROR {
            return Err(NetError::NetworkError(format!(
                "GetIpNetTable2 failed with Win32 error {}",
                err.0
            )));
        }
        let _guard = MibNetTableGuard(table_ptr);
        if table_ptr.is_null() {
            return Ok(Vec::new());
        }

        // SAFETY: `table_ptr` is non-null and owns `NumEntries` contiguous `MIB_IPNET_ROW2` elements.
        let (num_entries, rows) = unsafe {
            let count = (*table_ptr).NumEntries as usize;
            let first = ptr::addr_of!((*table_ptr).Table[0]);
            (count, std::slice::from_raw_parts(first, count))
        };
        let _ = num_entries;

        let mut out = Vec::new();
        for row in rows {
            // SAFETY: Inspecting union discriminant `si_family` and matching `Ipv4` arm.
            let family = unsafe { row.Address.si_family };
            if family != AF_INET {
                continue;
            }
            if row.State == NlnsUnreachable || row.PhysicalAddressLength != 6 {
                continue;
            }
            let mut mac_bytes = [0u8; 6];
            mac_bytes.copy_from_slice(&row.PhysicalAddress[..6]);
            let mac = MacAddr::new(mac_bytes);
            if mac.is_zero() || mac.is_broadcast() || mac.is_multicast() {
                continue;
            }
            // SAFETY: `si_family == AF_INET` guarantees the `Ipv4` union arm is active.
            let raw_ip = unsafe { row.Address.Ipv4.sin_addr.S_un.S_addr };
            let ip = win32_u32_to_ipv4(raw_ip);
            let state = match row.State {
                s if s == NlnsReachable => "Reachable",
                s if s == NlnsPermanent => "Permanent",
                s if s == NlnsStale => "Stale",
                s if s == NlnsDelay => "Delay",
                s if s == NlnsProbe => "Probe",
                s if s == NlnsIncomplete => "Incomplete",
                _ => "Other",
            };
            out.push(ArpEntry {
                ip,
                mac,
                interface_index: row.InterfaceIndex,
                state: state.to_string(),
            });
        }
        Ok(out)
    }

    pub fn send_arp_probe(target: Ipv4Addr) -> NetResult<Option<MacAddr>> {
        let mut mac_buf = [0u8; 6];
        let mut phy_len = 6u32;
        // SAFETY: `mac_buf` is 6 bytes and `phy_len` is initialized to 6.
        let rc = unsafe {
            SendARP(
                ipv4_to_win32_u32(target),
                0,
                mac_buf.as_mut_ptr().cast::<c_void>(),
                &mut phy_len,
            )
        };
        if rc == NO_ERROR.0 && phy_len == 6 {
            let mac = MacAddr::new(mac_buf);
            if mac.is_zero() { Ok(None) } else { Ok(Some(mac)) }
        } else {
            Ok(None)
        }
    }

    pub fn read_local_interfaces() -> NetResult<Vec<LocalInterfaceInfo>> {
        let mut buf_size = 16_384u32;
        let mut buf: Vec<u64>;
        let mut attempts = 0;
        loop {
            attempts += 1;
            buf = vec![0u64; (buf_size as usize).div_ceil(8)];
            // SAFETY: `buf` is 8-byte aligned and sized `buf_size` bytes.
            let rc = unsafe {
                GetAdaptersAddresses(
                    AF_INET.0 as u32,
                    GAA_FLAG_INCLUDE_PREFIX,
                    None,
                    Some(buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                    &mut buf_size,
                )
            };
            if rc == ERROR_SUCCESS.0 {
                break;
            }
            if rc == ERROR_BUFFER_OVERFLOW.0 && attempts < 4 {
                continue;
            }
            return Err(NetError::NetworkError(format!(
                "GetAdaptersAddresses failed with Win32 error {rc}"
            )));
        }

        let mut out = Vec::new();
        let mut cur = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !cur.is_null() {
            // SAFETY: `cur` points within `buf` populated by `GetAdaptersAddresses`.
            let adapter = unsafe { &*cur };
            if adapter.IfType != IF_TYPE_SOFTWARE_LOOPBACK && adapter.OperStatus == IfOperStatusUp {
                // SAFETY: `FriendlyName` is a valid NUL-terminated PWSTR inside `buf` or null.
                let name = unsafe { pwstr_to_string(adapter.FriendlyName) };
                // SAFETY: `Anonymous1.Anonymous` is a POD struct with `IfIndex`.
                let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
                let mac = if adapter.PhysicalAddressLength == 6 {
                    let mut m = [0u8; 6];
                    m.copy_from_slice(&adapter.PhysicalAddress[..6]);
                    let parsed = MacAddr::new(m);
                    if parsed.is_zero() { None } else { Some(parsed) }
                } else {
                    None
                };

                let mut uc = adapter.FirstUnicastAddress;
                while !uc.is_null() {
                    // SAFETY: `uc` points to a valid `IP_ADAPTER_UNICAST_ADDRESS_LH` in `buf`.
                    let uaddr = unsafe { &*uc };
                    let sa = uaddr.Address.lpSockaddr;
                    if !sa.is_null() && (uaddr.Address.iSockaddrLength as usize) >= size_of::<SOCKADDR_IN>() {
                        // SAFETY: `sa` points to a `SOCKADDR` header.
                        let family = unsafe { (*sa).sa_family };
                        if family == AF_INET {
                            // SAFETY: `family == AF_INET` and `iSockaddrLength >= size_of::<SOCKADDR_IN>()`.
                            let sin = unsafe { ptr::read_unaligned(sa.cast::<SOCKADDR_IN>()) };
                            // SAFETY: `S_un.S_addr` is a plain `u32`.
                            let ip = win32_u32_to_ipv4(unsafe { sin.sin_addr.S_un.S_addr });
                            let prefix = uaddr.OnLinkPrefixLength.min(32);
                            if let Ok(cidr) = CidrV4::new(ip, prefix) {
                                out.push(LocalInterfaceInfo {
                                    index,
                                    name: name.clone(),
                                    ip,
                                    cidr,
                                    mac,
                                });
                            }
                        }
                    }
                    uc = uaddr.Next;
                }
            }
            cur = adapter.Next;
        }
        Ok(out)
    }
}

/// Expands a `CidrV4` into scannable host IPv4 addresses while enforcing a strict host cap.
pub fn expand_cidr_hosts(cidr: CidrV4, max_hosts: usize) -> NetResult<Vec<Ipv4Addr>> {
    let total = cidr.host_count();
    let scannable = if cidr.prefix_len() >= 31 {
        total
    } else {
        total.saturating_sub(2)
    };
    if scannable as usize > max_hosts {
        return Err(NetError::InvalidInput(format!(
            "CIDR {cidr} expands to {scannable} hosts, exceeding safety limit {max_hosts}"
        )));
    }
    let net_u32 = u32::from(cidr.network());
    let bcast_u32 = u32::from(cidr.broadcast());
    let mut ips = Vec::with_capacity(scannable as usize);
    if cidr.prefix_len() >= 31 {
        for raw in net_u32..=bcast_u32 {
            ips.push(Ipv4Addr::from(raw));
        }
    } else {
        for raw in (net_u32 + 1)..bcast_u32 {
            ips.push(Ipv4Addr::from(raw));
        }
    }
    Ok(ips)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanScanHostRecord {
    pub ip: IpAddr,
    pub mac: Option<MacAddr>,
    pub vendor: String,
    pub hostname: String,
    pub netbios_name: String,
    pub workgroup: String,
    pub alive: bool,
    pub rtt_ms: Option<f64>,
    pub open_ports: Vec<u16>,
    pub discovery_method: String,
}

pub struct SubnetScannerProvider {
    ctx: NetContext,
    cidr: Option<CidrV4>,
    ports: Vec<u16>,
    arp: Arc<dyn ArpBackend>,
    ping: Arc<dyn PingBackend>,
    netbios: Arc<dyn NetbiosBackend>,
    dns: Arc<dyn DnsBackend>,
    tcp: Arc<dyn TcpProbeBackend>,
}

impl SubnetScannerProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self {
            ctx,
            cidr: None,
            ports: DEFAULT_TCP_PROBE_PORTS.to_vec(),
            arp: Arc::new(LiveWin32ArpBackend),
            ping: Arc::new(LivePingBackend),
            netbios: Arc::new(LiveUdpNetbiosBackend),
            dns: Arc::new(LiveWinSockDnsBackend),
            tcp: Arc::new(LiveTcpProbeBackend),
        }
    }

    pub fn with_cidr(mut self, cidr: CidrV4) -> Self {
        self.cidr = Some(cidr);
        self
    }

    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        self.ports = ports;
        self
    }

    pub fn with_backends(
        mut self,
        arp: Arc<dyn ArpBackend>,
        ping: Arc<dyn PingBackend>,
        netbios: Arc<dyn NetbiosBackend>,
        dns: Arc<dyn DnsBackend>,
        tcp: Arc<dyn TcpProbeBackend>,
    ) -> Self {
        self.arp = arp;
        self.ping = ping;
        self.netbios = netbios;
        self.dns = dns;
        self.tcp = tcp;
        self
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "lan.scan",
            "Subnet Host & Port Scanner",
            vec![
                ColumnDef::new("ip", "IP Address", ColumnType::IpAddr).with_width_hint(130),
                ColumnDef::new("mac", "MAC Address", ColumnType::MacAddr).with_width_hint(150),
                ColumnDef::new("vendor", "MAC Vendor", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("hostname", "Hostname", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("netbios_name", "NetBIOS Name", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("workgroup", "Workgroup", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("alive", "Alive", ColumnType::Bool).with_width_hint(70),
                ColumnDef::new("rtt_ms", "RTT (ms)", ColumnType::Float).with_width_hint(90),
                ColumnDef::new("open_ports", "Open Ports", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("discovery_method", "Method", ColumnType::Text).with_width_hint(110),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn collect_records(&self) -> NetResult<Vec<LanScanHostRecord>> {
        if self.ctx.is_offline() && self.cidr.is_none() {
            return fixtures::load_scan_records(&self.ctx);
        }
        let target_cidr = if let Some(c) = self.cidr {
            c
        } else {
            let ifaces = self.arp.local_interfaces()?;
            ifaces
                .into_iter()
                .find(|i| i.cidr.prefix_len() >= 22)
                .map(|i| i.cidr)
                .unwrap_or_else(|| CidrV4::new(Ipv4Addr::new(127, 0, 0, 1), 32).expect("valid /32"))
        };

        let hosts = expand_cidr_hosts(target_cidr, MAX_SCAN_HOSTS)?;
        let oui = OuiDatabase::for_context(&self.ctx)?;
        let timeout = self.ctx.timeout.min(Duration::from_millis(250));
        let arp_cache: BTreeMap<Ipv4Addr, MacAddr> = self
            .arp
            .arp_table()
            .unwrap_or_default()
            .into_iter()
            .map(|e| (e.ip, e.mac))
            .collect();

        let results = run_bounded(&hosts, 32, |&ip| {
            let mac = self
                .arp
                .send_arp(ip)
                .ok()
                .flatten()
                .or_else(|| arp_cache.get(&ip).copied());

            let icmp_res = self.ping.ping_icmp(IpAddr::V4(ip), timeout, None, b"GUAP-SCAN").ok();
            let icmp_alive = icmp_res.as_ref().is_some_and(|r| r.status == PingStatus::Succeeded);
            let rtt_ms = icmp_res.and_then(|r| r.rtt_ms);

            // Only perform deeper NetBIOS/DNS/TCP probes for hosts showing life (or small <=16 host targets).
            let should_probe_deep = mac.is_some() || icmp_alive || hosts.len() <= 16;
            let (netbios_name, workgroup, nb_mac) = if should_probe_deep {
                match self.netbios.query_nbstat(ip, timeout) {
                    Ok(Some((nb, _))) => (
                        nb.computer_name.unwrap_or_default(),
                        nb.workgroup.unwrap_or_default(),
                        nb.mac,
                    ),
                    _ => (String::new(), String::new(), None),
                }
            } else {
                (String::new(), String::new(), None)
            };

            let open_ports = if should_probe_deep && !self.ports.is_empty() {
                self.tcp.probe_ports(IpAddr::V4(ip), &self.ports, timeout)
            } else {
                Vec::new()
            };

            let effective_mac = mac.or(nb_mac);
            let alive = effective_mac.is_some() || icmp_alive || !netbios_name.is_empty() || !open_ports.is_empty();

            if !alive {
                return None;
            }

            let hostname = self
                .dns
                .reverse_lookup(IpAddr::V4(ip))
                .ok()
                .flatten()
                .unwrap_or_default();
            let vendor = effective_mac.map(|m| oui.lookup_or_unknown(m)).unwrap_or_default();

            let discovery_method = match (effective_mac.is_some(), icmp_alive, !open_ports.is_empty()) {
                (true, true, _) => "ARP+ICMP",
                (true, false, _) => "ARP",
                (false, true, _) => "ICMP",
                (false, false, true) => "TCP",
                (false, false, false) => "NetBIOS",
            };

            Some(LanScanHostRecord {
                ip: IpAddr::V4(ip),
                mac: effective_mac,
                vendor,
                hostname,
                netbios_name,
                workgroup,
                alive: true,
                rtt_ms,
                open_ports,
                discovery_method: discovery_method.to_string(),
            })
        });

        Ok(results.into_iter().flatten().collect())
    }
}

impl TableProvider for SubnetScannerProvider {
    fn tool_id(&self) -> &'static str {
        "lan.scan"
    }

    fn description(&self) -> &'static str {
        "Scan IPv4 CIDR subnets via ARP, ICMP, NetBIOS, and TCP port probes"
    }

    fn schema(&self) -> TableSchema {
        Self::schema_def()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let schema = Self::schema_def();
        let mut records = self.collect_records()?;
        self.ctx.apply_row_limit(&mut records);

        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, rec)| {
                let ports_str = rec.open_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
                let detail = json!({
                    "ip": rec.ip.to_string(),
                    "mac": rec.mac.map(|m| m.to_colon_string()),
                    "vendor": rec.vendor,
                    "hostname": rec.hostname,
                    "netbios_name": rec.netbios_name,
                    "workgroup": rec.workgroup,
                    "open_ports": rec.open_ports,
                    "discovery_method": rec.discovery_method,
                });
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.ip.to_string()),
                        rec.mac
                            .map(|m| CellValue::Text(m.to_colon_string()))
                            .unwrap_or(CellValue::Null),
                        CellValue::Text(rec.vendor),
                        CellValue::Text(rec.hostname),
                        CellValue::Text(rec.netbios_name),
                        CellValue::Text(rec.workgroup),
                        CellValue::Bool(rec.alive),
                        rec.rtt_ms.map(CellValue::Float).unwrap_or(CellValue::Null),
                        CellValue::Text(ports_str),
                        CellValue::Text(rec.discovery_method),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        apply_query(&schema, &rows, req)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WnetDeviceRecord {
    pub ip: IpAddr,
    pub device_name: String,
    pub mac: MacAddr,
    pub vendor: String,
    pub active: bool,
    pub detection_count: u64,
    pub first_detected: DateTime<Utc>,
    pub last_detected: DateTime<Utc>,
    pub adapter: String,
}

#[derive(Debug, Clone)]
struct TrackedDevice {
    device_name: String,
    mac: MacAddr,
    vendor: String,
    active: bool,
    detection_count: u64,
    first_detected: DateTime<Utc>,
    last_detected: DateTime<Utc>,
    adapter: String,
}

pub struct ArpWatcherProvider {
    ctx: NetContext,
    arp: Arc<dyn ArpBackend>,
    dns: Arc<dyn DnsBackend>,
    state: Mutex<BTreeMap<IpAddr, TrackedDevice>>,
    sweep_subnet: bool,
}

impl ArpWatcherProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self {
            ctx,
            arp: Arc::new(LiveWin32ArpBackend),
            dns: Arc::new(LiveWinSockDnsBackend),
            state: Mutex::new(BTreeMap::new()),
            sweep_subnet: true,
        }
    }

    pub fn with_backends(mut self, arp: Arc<dyn ArpBackend>, dns: Arc<dyn DnsBackend>, sweep_subnet: bool) -> Self {
        self.arp = arp;
        self.dns = dns;
        self.sweep_subnet = sweep_subnet;
        self
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "lan.wnetwatcher",
            "LAN Device ARP Inventory",
            vec![
                ColumnDef::new("ip", "IP Address", ColumnType::IpAddr).with_width_hint(130),
                ColumnDef::new("device_name", "Device Name", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("mac", "MAC Address", ColumnType::MacAddr).with_width_hint(150),
                ColumnDef::new("vendor", "Network Adapter Company", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("active", "Active", ColumnType::Bool).with_width_hint(70),
                ColumnDef::new("detection_count", "Detection Count", ColumnType::Uint).with_width_hint(110),
                ColumnDef::new("first_detected", "First Detected", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("last_detected", "Last Detected", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("adapter", "Local Adapter", ColumnType::Text).with_width_hint(150),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn collect_records(&self) -> NetResult<Vec<WnetDeviceRecord>> {
        if self.ctx.is_offline() {
            return fixtures::load_wnetwatcher_records(&self.ctx);
        }

        let now = Utc::now();
        let oui = OuiDatabase::for_context(&self.ctx)?;
        let ifaces = self.arp.local_interfaces().unwrap_or_default();
        let iface_names: BTreeMap<u32, String> = ifaces.iter().map(|i| (i.index, i.name.clone())).collect();

        let mut discovered: BTreeMap<IpAddr, (MacAddr, String)> = BTreeMap::new();
        for entry in self.arp.arp_table()? {
            let adapter = iface_names
                .get(&entry.interface_index)
                .cloned()
                .unwrap_or_else(|| format!("if{}", entry.interface_index));
            discovered.insert(IpAddr::V4(entry.ip), (entry.mac, adapter));
        }

        for iface in &ifaces {
            if let Some(mac) = iface.mac {
                discovered.insert(IpAddr::V4(iface.ip), (mac, format!("{} (Self)", iface.name)));
            }
            if self.sweep_subnet
                && iface.cidr.prefix_len() >= 24
                && let Ok(ips) = expand_cidr_hosts(iface.cidr, 256)
            {
                let deadline = Instant::now() + self.ctx.timeout.min(Duration::from_secs(2));
                let swept = run_bounded(&ips, 32, |&ip| {
                    if Instant::now() > deadline {
                        return None;
                    }
                    self.arp.send_arp(ip).ok().flatten().map(|m| (ip, m))
                });
                for (ip, mac) in swept.into_iter().flatten() {
                    discovered
                        .entry(IpAddr::V4(ip))
                        .or_insert_with(|| (mac, iface.name.clone()));
                }
            }
        }

        let entries_vec: Vec<(IpAddr, MacAddr, String)> = discovered
            .into_iter()
            .map(|(ip, (mac, adapter))| (ip, mac, adapter))
            .collect();
        let resolved_names = run_bounded(&entries_vec, 16, |(ip, _, _)| {
            self.dns.reverse_lookup(*ip).ok().flatten().unwrap_or_default()
        });

        let mut guard = self
            .state
            .lock()
            .map_err(|_| NetError::Internal("state lock poisoned".into()))?;
        for item in guard.values_mut() {
            item.active = false;
        }
        for ((ip, mac, adapter), hostname) in entries_vec.into_iter().zip(resolved_names) {
            let vendor = oui.lookup_or_unknown(mac);
            guard
                .entry(ip)
                .and_modify(|rec| {
                    if rec.mac != mac {
                        rec.mac = mac;
                        rec.vendor = vendor.clone();
                    }
                    if !hostname.is_empty() {
                        rec.device_name = hostname.clone();
                    }
                    rec.active = true;
                    rec.detection_count = rec.detection_count.saturating_add(1);
                    rec.last_detected = now;
                    rec.adapter = adapter.clone();
                })
                .or_insert_with(|| TrackedDevice {
                    device_name: hostname,
                    mac,
                    vendor,
                    active: true,
                    detection_count: 1,
                    first_detected: now,
                    last_detected: now,
                    adapter,
                });
        }

        Ok(guard
            .iter()
            .map(|(&ip, d)| WnetDeviceRecord {
                ip,
                device_name: d.device_name.clone(),
                mac: d.mac,
                vendor: d.vendor.clone(),
                active: d.active,
                detection_count: d.detection_count,
                first_detected: d.first_detected,
                last_detected: d.last_detected,
                adapter: d.adapter.clone(),
            })
            .collect())
    }
}

impl TableProvider for ArpWatcherProvider {
    fn tool_id(&self) -> &'static str {
        "lan.wnetwatcher"
    }

    fn description(&self) -> &'static str {
        "Inspect local LAN devices via ARP table, subnet SendARP sweep, and OUI/DNS lookup"
    }

    fn schema(&self) -> TableSchema {
        Self::schema_def()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let schema = Self::schema_def();
        let mut records = self.collect_records()?;
        self.ctx.apply_row_limit(&mut records);

        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, rec)| {
                let detail = json!({
                    "ip": rec.ip.to_string(),
                    "device_name": rec.device_name,
                    "mac": rec.mac.to_colon_string(),
                    "vendor": rec.vendor,
                    "active": rec.active,
                    "detection_count": rec.detection_count,
                    "adapter": rec.adapter,
                });
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.ip.to_string()),
                        CellValue::Text(rec.device_name),
                        CellValue::Text(rec.mac.to_colon_string()),
                        CellValue::Text(rec.vendor),
                        CellValue::Bool(rec.active),
                        CellValue::Uint(rec.detection_count),
                        CellValue::Timestamp(rec.first_detected),
                        CellValue::Timestamp(rec.last_detected),
                        CellValue::Text(rec.adapter),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        apply_query(&schema, &rows, req)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostObservation {
    pub ip: IpAddr,
    pub mac: MacAddr,
    pub device_name: String,
    pub vendor: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectEventKind {
    Connected,
    Disconnected,
    MacChanged,
}

impl ConnectEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "Connected",
            Self::Disconnected => "Disconnected",
            Self::MacChanged => "Changed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectLogEvent {
    pub timestamp: DateTime<Utc>,
    pub event: ConnectEventKind,
    pub ip: IpAddr,
    pub mac: MacAddr,
    pub device_name: String,
    pub vendor: String,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone)]
struct ActiveSession {
    connected_at: DateTime<Utc>,
    host: HostObservation,
}

/// Pure-Rust stateful ARP/subnet snapshot diff engine for `lan.connect-log`.
#[derive(Debug, Default)]
pub struct ConnectLogEngine {
    active: BTreeMap<IpAddr, ActiveSession>,
    events: Vec<ConnectLogEvent>,
}

impl ConnectLogEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_snapshot(&mut self, ts: DateTime<Utc>, hosts: &[HostObservation]) -> Vec<ConnectLogEvent> {
        let mut emitted = Vec::new();
        let mut seen: BTreeMap<IpAddr, &HostObservation> = BTreeMap::new();
        for host in hosts {
            seen.insert(host.ip, host);
        }

        // Detect departures first
        let departed: Vec<IpAddr> = self
            .active
            .keys()
            .filter(|ip| !seen.contains_key(ip))
            .copied()
            .collect();
        for ip in departed {
            if let Some(session) = self.active.remove(&ip) {
                let dur_ms = (ts - session.connected_at).num_milliseconds().max(0) as u64;
                emitted.push(ConnectLogEvent {
                    timestamp: ts,
                    event: ConnectEventKind::Disconnected,
                    ip,
                    mac: session.host.mac,
                    device_name: session.host.device_name,
                    vendor: session.host.vendor,
                    duration_ms: Some(dur_ms),
                });
            }
        }

        // Detect arrivals and MAC changes
        for (&ip, &host) in &seen {
            match self.active.get_mut(&ip) {
                None => {
                    self.active.insert(
                        ip,
                        ActiveSession {
                            connected_at: ts,
                            host: host.clone(),
                        },
                    );
                    emitted.push(ConnectLogEvent {
                        timestamp: ts,
                        event: ConnectEventKind::Connected,
                        ip,
                        mac: host.mac,
                        device_name: host.device_name.clone(),
                        vendor: host.vendor.clone(),
                        duration_ms: None,
                    });
                }
                Some(existing) if existing.host.mac != host.mac => {
                    let dur_ms = (ts - existing.connected_at).num_milliseconds().max(0) as u64;
                    emitted.push(ConnectLogEvent {
                        timestamp: ts,
                        event: ConnectEventKind::MacChanged,
                        ip,
                        mac: host.mac,
                        device_name: host.device_name.clone(),
                        vendor: host.vendor.clone(),
                        duration_ms: Some(dur_ms),
                    });
                    existing.connected_at = ts;
                    existing.host = host.clone();
                }
                Some(existing) => {
                    if !host.device_name.is_empty() {
                        existing.host.device_name = host.device_name.clone();
                    }
                }
            }
        }

        self.events.extend(emitted.iter().cloned());
        emitted
    }

    pub fn events(&self) -> &[ConnectLogEvent] {
        &self.events
    }
}

pub struct ConnectLogProvider {
    ctx: NetContext,
    arp: Arc<dyn ArpBackend>,
    dns: Arc<dyn DnsBackend>,
    engine: Mutex<ConnectLogEngine>,
}

impl ConnectLogProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self {
            ctx,
            arp: Arc::new(LiveWin32ArpBackend),
            dns: Arc::new(LiveWinSockDnsBackend),
            engine: Mutex::new(ConnectLogEngine::new()),
        }
    }

    pub fn with_backends(mut self, arp: Arc<dyn ArpBackend>, dns: Arc<dyn DnsBackend>) -> Self {
        self.arp = arp;
        self.dns = dns;
        self
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "lan.connect-log",
            "LAN Host Arrival & Departure Log",
            vec![
                ColumnDef::new("timestamp", "Event Time", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("event", "Event", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("ip", "IP Address", ColumnType::IpAddr).with_width_hint(130),
                ColumnDef::new("mac", "MAC Address", ColumnType::MacAddr).with_width_hint(150),
                ColumnDef::new("device_name", "Device Name", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("vendor", "Vendor", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("duration_ms", "Duration", ColumnType::Duration).with_width_hint(110),
            ],
        )
        .with_default_sort(0, SortDirection::Desc)
    }

    fn collect_records(&self) -> NetResult<Vec<ConnectLogEvent>> {
        if self.ctx.is_offline() {
            return fixtures::load_connect_log_events(&self.ctx);
        }

        let oui = OuiDatabase::for_context(&self.ctx)?;
        let arp_rows = self.arp.arp_table()?;
        let observations: Vec<HostObservation> = run_bounded(&arp_rows, 16, |entry| {
            let ip = IpAddr::V4(entry.ip);
            let device_name = self.dns.reverse_lookup(ip).ok().flatten().unwrap_or_default();
            let vendor = oui.lookup_or_unknown(entry.mac);
            HostObservation {
                ip,
                mac: entry.mac,
                device_name,
                vendor,
            }
        });

        let mut engine = self
            .engine
            .lock()
            .map_err(|_| NetError::Internal("connect-log lock poisoned".into()))?;
        let _ = engine.apply_snapshot(Utc::now(), &observations);
        Ok(engine.events().to_vec())
    }
}

impl TableProvider for ConnectLogProvider {
    fn tool_id(&self) -> &'static str {
        "lan.connect-log"
    }

    fn description(&self) -> &'static str {
        "Log host connection, disconnection, and MAC-change events from ARP snapshots"
    }

    fn schema(&self) -> TableSchema {
        Self::schema_def()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let schema = Self::schema_def();
        let mut events = self.collect_records()?;
        self.ctx.apply_row_limit(&mut events);

        let rows: Vec<Row> = events
            .into_iter()
            .enumerate()
            .map(|(idx, ev)| {
                let detail = json!({
                    "timestamp": ev.timestamp.to_rfc3339(),
                    "event": ev.event.as_str(),
                    "ip": ev.ip.to_string(),
                    "mac": ev.mac.to_colon_string(),
                    "device_name": ev.device_name,
                    "vendor": ev.vendor,
                    "duration_ms": ev.duration_ms,
                });
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Timestamp(ev.timestamp),
                        CellValue::Text(ev.event.as_str().to_string()),
                        CellValue::Text(ev.ip.to_string()),
                        CellValue::Text(ev.mac.to_colon_string()),
                        CellValue::Text(ev.device_name),
                        CellValue::Text(ev.vendor),
                        ev.duration_ms.map(CellValue::Uint).unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        apply_query(&schema, &rows, req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netbios::NbstatResponse;
    use crate::ping::PingProbeResult;

    #[test]
    fn test_cidr_expansion_and_safety_cap() {
        let c24 = CidrV4::parse("192.168.10.0/24").unwrap();
        let hosts = expand_cidr_hosts(c24, MAX_SCAN_HOSTS).unwrap();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 10, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 10, 254));

        let c32 = CidrV4::parse("192.168.10.42/32").unwrap();
        assert_eq!(
            expand_cidr_hosts(c32, MAX_SCAN_HOSTS).unwrap(),
            vec![Ipv4Addr::new(192, 168, 10, 42)]
        );

        let c16 = CidrV4::parse("10.0.0.0/16").unwrap();
        assert!(expand_cidr_hosts(c16, MAX_SCAN_HOSTS).is_err());
    }

    #[test]
    fn test_connect_log_diff_engine_transitions() {
        let mut engine = ConnectLogEngine::new();
        let t0 = DateTime::parse_from_rfc3339("2026-11-23T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let t1 = DateTime::parse_from_rfc3339("2026-11-23T12:05:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let t2 = DateTime::parse_from_rfc3339("2026-11-23T12:06:30Z")
            .unwrap()
            .with_timezone(&Utc);

        let h1 = HostObservation {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            mac: MacAddr::parse("00:50:56:01:02:03").unwrap(),
            device_name: "workstation-a".into(),
            vendor: "VMware, Inc.".into(),
        };
        let h2 = HostObservation {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 21)),
            mac: MacAddr::parse("b8:27:eb:04:05:06").unwrap(),
            device_name: "pi-sensor".into(),
            vendor: "Raspberry Pi Foundation".into(),
        };

        let e0 = engine.apply_snapshot(t0, &[h1.clone(), h2.clone()]);
        assert_eq!(e0.len(), 2);
        assert!(
            e0.iter()
                .all(|e| e.event == ConnectEventKind::Connected && e.duration_ms.is_none())
        );

        // h2 disconnects at t1 (300_000 ms), h1 changes MAC at t1
        let h1_changed = HostObservation {
            mac: MacAddr::parse("00:15:5d:01:02:03").unwrap(),
            ..h1
        };
        let e1 = engine.apply_snapshot(t1, &[h1_changed]);
        assert_eq!(e1.len(), 2);
        assert_eq!(e1[0].event, ConnectEventKind::Disconnected);
        assert_eq!(e1[0].ip, h2.ip);
        assert_eq!(e1[0].duration_ms, Some(300_000));
        assert_eq!(e1[1].event, ConnectEventKind::MacChanged);
        assert_eq!(e1[1].duration_ms, Some(300_000));

        // h1 disconnects at t2 (90_000 ms after MAC change)
        let e2 = engine.apply_snapshot(t2, &[]);
        assert_eq!(e2.len(), 1);
        assert_eq!(e2[0].event, ConnectEventKind::Disconnected);
        assert_eq!(e2[0].duration_ms, Some(90_000));
    }

    struct MockScanArp;
    impl ArpBackend for MockScanArp {
        fn arp_table(&self) -> NetResult<Vec<ArpEntry>> {
            Ok(vec![ArpEntry {
                ip: Ipv4Addr::new(192, 168, 50, 1),
                mac: MacAddr::parse("04:18:d6:11:22:33").unwrap(),
                interface_index: 1,
                state: "Reachable".into(),
            }])
        }
        fn send_arp(&self, target: Ipv4Addr) -> NetResult<Option<MacAddr>> {
            if target == Ipv4Addr::new(192, 168, 50, 1) {
                Ok(Some(MacAddr::parse("04:18:d6:11:22:33").unwrap()))
            } else {
                Ok(None)
            }
        }
        fn local_interfaces(&self) -> NetResult<Vec<LocalInterfaceInfo>> {
            Ok(vec![])
        }
    }

    struct MockScanPing;
    impl PingBackend for MockScanPing {
        fn ping_icmp(&self, target: IpAddr, _: Duration, _: Option<u8>, _: &[u8]) -> NetResult<PingProbeResult> {
            if target == IpAddr::V4(Ipv4Addr::new(192, 168, 50, 1)) {
                Ok(PingProbeResult {
                    responder: Some(target),
                    status: PingStatus::Succeeded,
                    rtt_ms: Some(1.2),
                    ttl: Some(64),
                    error_detail: None,
                })
            } else {
                Ok(PingProbeResult {
                    responder: None,
                    status: PingStatus::TimedOut,
                    rtt_ms: None,
                    ttl: None,
                    error_detail: None,
                })
            }
        }
        fn ping_tcp(&self, _: IpAddr, _: u16, _: Duration) -> NetResult<PingProbeResult> {
            unreachable!()
        }
    }

    struct MockScanNb;
    impl NetbiosBackend for MockScanNb {
        fn query_nbstat(&self, ip: Ipv4Addr, _: Duration) -> NetResult<Option<(NbstatResponse, f64)>> {
            if ip == Ipv4Addr::new(192, 168, 50, 1) {
                Ok(Some((
                    NbstatResponse {
                        txid: 1,
                        entries: vec![],
                        mac: None,
                        computer_name: Some("ROUTER".into()),
                        workgroup: Some("LAN".into()),
                        user_hint: None,
                        is_master_browser: false,
                        is_domain_controller: false,
                    },
                    1.0,
                )))
            } else {
                Ok(None)
            }
        }
    }

    struct MockScanDns;
    impl DnsBackend for MockScanDns {
        fn forward_lookup(&self, _: &str) -> NetResult<Vec<IpAddr>> {
            Ok(vec![])
        }
        fn reverse_lookup(&self, ip: IpAddr) -> NetResult<Option<String>> {
            if ip == IpAddr::V4(Ipv4Addr::new(192, 168, 50, 1)) {
                Ok(Some("router.lan".into()))
            } else {
                Ok(None)
            }
        }
    }

    struct MockScanTcp;
    impl TcpProbeBackend for MockScanTcp {
        fn probe_ports(&self, ip: IpAddr, _: &[u16], _: Duration) -> Vec<u16> {
            if ip == IpAddr::V4(Ipv4Addr::new(192, 168, 50, 1)) {
                vec![80, 443]
            } else {
                vec![]
            }
        }
    }

    #[test]
    fn test_lan_scan_provider_mock_fusion() {
        let provider = SubnetScannerProvider::new(NetContext::live())
            .with_cidr(CidrV4::parse("192.168.50.0/29").unwrap())
            .with_backends(
                Arc::new(MockScanArp),
                Arc::new(MockScanPing),
                Arc::new(MockScanNb),
                Arc::new(MockScanDns),
                Arc::new(MockScanTcp),
            );
        let data = provider.query(&TableQuery::default()).unwrap();
        assert_eq!(data.total_rows, 1);
        assert_eq!(data.rows[0].cells[0], CellValue::Text("192.168.50.1".into()));
        assert_eq!(data.rows[0].cells[2], CellValue::Text("Ubiquiti Inc.".into()));
        assert_eq!(data.rows[0].cells[3], CellValue::Text("router.lan".into()));
        assert_eq!(data.rows[0].cells[4], CellValue::Text("ROUTER".into()));
        assert_eq!(data.rows[0].cells[8], CellValue::Text("80, 443".into()));
        assert_eq!(data.rows[0].cells[9], CellValue::Text("ARP+ICMP".into()));
    }
}
