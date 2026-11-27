#[cfg(not(windows))]
use std::net::ToSocketAddrs;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
#[cfg(not(windows))]
use net2rust_core::NetError;
use net2rust_core::{MacAddr, NetContext, NetResult};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::common::run_bounded;
use crate::fixtures;
use crate::oui::OuiDatabase;

pub trait DnsBackend: Send + Sync {
    fn forward_lookup(&self, host: &str) -> NetResult<Vec<IpAddr>>;
    fn reverse_lookup(&self, ip: IpAddr) -> NetResult<Option<String>>;
}

#[derive(Debug, Default)]
pub struct LiveWinSockDnsBackend;

impl DnsBackend for LiveWinSockDnsBackend {
    fn forward_lookup(&self, host: &str) -> NetResult<Vec<IpAddr>> {
        if let Ok(ip) = host.trim().parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        #[cfg(windows)]
        {
            win32_dns::forward_lookup_winsock(host)
        }
        #[cfg(not(windows))]
        {
            let mut ips = Vec::new();
            let addrs = (host, 0u16)
                .to_socket_addrs()
                .map_err(|e| NetError::NetworkError(format!("DNS lookup failed for {host}: {e}")))?;
            for sa in addrs {
                if !ips.contains(&sa.ip()) {
                    ips.push(sa.ip());
                }
            }
            Ok(ips)
        }
    }

    fn reverse_lookup(&self, ip: IpAddr) -> NetResult<Option<String>> {
        #[cfg(windows)]
        {
            win32_dns::reverse_lookup_winsock(ip)
        }
        #[cfg(not(windows))]
        {
            let _ = ip;
            Ok(None)
        }
    }
}

#[cfg(windows)]
mod win32_dns {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::net::{IpAddr, Ipv6Addr, ToSocketAddrs};
    use std::ptr;
    use std::sync::OnceLock;

    use net2rust_core::{NetError, NetResult};
    use windows::Win32::Networking::WinSock::{
        ADDRINFOW, AF_INET, AF_INET6, AF_UNSPEC, FreeAddrInfoW, GetAddrInfoW, GetNameInfoW, IN_ADDR, IN_ADDR_0,
        IN6_ADDR, IN6_ADDR_0, NI_MAXHOST, NI_NAMEREQD, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, WSADATA,
        WSAHOST_NOT_FOUND, WSANO_DATA, WSAStartup, socklen_t,
    };
    use windows::core::PCWSTR;

    use crate::common::{ipv4_to_win32_u32, to_wide_null, win32_u32_to_ipv4};

    static WSA_INIT: OnceLock<Result<(), i32>> = OnceLock::new();

    fn ensure_wsa() -> NetResult<()> {
        let res = WSA_INIT.get_or_init(|| {
            let mut wsa = WSADATA::default();
            // SAFETY: `wsa` is zero-initialized and valid for writing by WSAStartup(2.2).
            let rc = unsafe { WSAStartup(0x0202, &mut wsa) };
            if rc == 0 { Ok(()) } else { Err(rc) }
        });
        res.map_err(|rc| NetError::NetworkError(format!("WSAStartup failed with code {rc}")))
    }

    struct AddrInfoGuard(*mut ADDRINFOW);
    impl Drop for AddrInfoGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was allocated by `GetAddrInfoW`.
                unsafe { FreeAddrInfoW(Some(self.0.cast_const())) };
            }
        }
    }

    pub fn forward_lookup_winsock(host: &str) -> NetResult<Vec<IpAddr>> {
        if ensure_wsa().is_err() {
            // Fallback to stdlib ToSocketAddrs if WSAStartup fails unexpectedly.
            let mut out = Vec::new();
            for sa in (host, 0u16)
                .to_socket_addrs()
                .map_err(|e| NetError::NetworkError(format!("forward DNS failed for {host}: {e}")))?
            {
                if !out.contains(&sa.ip()) {
                    out.push(sa.ip());
                }
            }
            return Ok(out);
        }

        let wide_host = to_wide_null(host);
        let hints = ADDRINFOW {
            ai_family: AF_UNSPEC.0 as i32,
            ..Default::default()
        };
        let mut head: *mut ADDRINFOW = ptr::null_mut();

        // SAFETY: `wide_host` is NUL-terminated UTF-16 and outlives the call; `head` is valid out-ptr.
        let rc = unsafe {
            GetAddrInfoW(
                PCWSTR::from_raw(wide_host.as_ptr()),
                PCWSTR::null(),
                Some(&hints),
                &mut head,
            )
        };
        if rc != 0 {
            if rc == WSAHOST_NOT_FOUND.0 || rc == WSANO_DATA.0 {
                return Ok(Vec::new());
            }
            return Err(NetError::NetworkError(format!(
                "GetAddrInfoW failed for '{host}' with WSA error {rc}"
            )));
        }

        let _guard = AddrInfoGuard(head);
        let mut ips = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            // SAFETY: `cur` is a valid node in the linked list allocated by `GetAddrInfoW`.
            let node = unsafe { &*cur };
            if !node.ai_addr.is_null() {
                if node.ai_family == AF_INET.0 as i32 && node.ai_addrlen >= size_of::<SOCKADDR_IN>() {
                    // SAFETY: `ai_addr` points to at least `SOCKADDR_IN` bytes.
                    let sin = unsafe { ptr::read_unaligned(node.ai_addr.cast::<SOCKADDR_IN>()) };
                    // SAFETY: `S_un.S_addr` is a plain `u32` field in `IN_ADDR_0`.
                    let raw = unsafe { sin.sin_addr.S_un.S_addr };
                    let ip = IpAddr::V4(win32_u32_to_ipv4(raw));
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                } else if node.ai_family == AF_INET6.0 as i32 && node.ai_addrlen >= size_of::<SOCKADDR_IN6>() {
                    // SAFETY: `ai_addr` points to at least `SOCKADDR_IN6` bytes.
                    let sin6 = unsafe { ptr::read_unaligned(node.ai_addr.cast::<SOCKADDR_IN6>()) };
                    // SAFETY: `u.Byte` is `[u8; 16]` in `IN6_ADDR_0`.
                    let octets = unsafe { sin6.sin6_addr.u.Byte };
                    let ip = IpAddr::V6(Ipv6Addr::from(octets));
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
            }
            cur = node.ai_next;
        }
        Ok(ips)
    }

    pub fn reverse_lookup_winsock(ip: IpAddr) -> NetResult<Option<String>> {
        ensure_wsa()?;
        let mut host_buf = vec![0u16; NI_MAXHOST as usize];
        let rc = match ip {
            IpAddr::V4(v4) => {
                let sin = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: 0,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: ipv4_to_win32_u32(v4),
                        },
                    },
                    sin_zero: [0; 8],
                };
                let sa_ptr: *const SOCKADDR = (&raw const sin).cast::<SOCKADDR>();
                // SAFETY: `sin` is a valid `SOCKADDR_IN` and `host_buf` is mutable UTF-16 buffer.
                unsafe {
                    GetNameInfoW(
                        sa_ptr,
                        socklen_t(size_of::<SOCKADDR_IN>() as i32),
                        Some(&mut host_buf),
                        None,
                        NI_NAMEREQD as i32,
                    )
                }
            }
            IpAddr::V6(v6) => {
                let mut sin6: SOCKADDR_IN6 = unsafe { zeroed() };
                sin6.sin6_family = AF_INET6;
                sin6.sin6_addr = IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: v6.octets() },
                };
                sin6.Anonymous = SOCKADDR_IN6_0 { sin6_scope_id: 0 };
                let sa_ptr: *const SOCKADDR = (&raw const sin6).cast::<SOCKADDR>();
                // SAFETY: `sin6` is a valid `SOCKADDR_IN6` and `host_buf` is mutable UTF-16 buffer.
                unsafe {
                    GetNameInfoW(
                        sa_ptr,
                        socklen_t(size_of::<SOCKADDR_IN6>() as i32),
                        Some(&mut host_buf),
                        None,
                        NI_NAMEREQD as i32,
                    )
                }
            }
        };

        let _ = core::mem::size_of::<*const c_void>();
        if rc != 0 {
            if rc == WSAHOST_NOT_FOUND.0 || rc == WSANO_DATA.0 {
                return Ok(None);
            }
            // Do not fail entire table query on single unresolvable host; treat lookup miss as None.
            return Ok(None);
        }

        let nul_pos = host_buf.iter().position(|&c| c == 0).unwrap_or(host_buf.len());
        let name = String::from_utf16_lossy(&host_buf[..nul_pos]).trim().to_string();
        if name.is_empty() { Ok(None) } else { Ok(Some(name)) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveInput {
    pub query: String,
    pub mac: Option<MacAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveRecord {
    pub query: String,
    pub ip: Option<IpAddr>,
    pub hostname: String,
    pub mac: Option<MacAddr>,
    pub vendor: String,
    pub status: String,
    pub duration_ms: u64,
}

pub struct BatchResolverProvider {
    ctx: NetContext,
    queries: Vec<ResolveInput>,
    custom_queries: bool,
    dns: Arc<dyn DnsBackend>,
}

impl BatchResolverProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self {
            ctx,
            queries: vec![
                ResolveInput {
                    query: Ipv4Addr::LOCALHOST.to_string(),
                    mac: None,
                },
                ResolveInput {
                    query: "localhost".to_string(),
                    mac: None,
                },
            ],
            custom_queries: false,
            dns: Arc::new(LiveWinSockDnsBackend),
        }
    }

    pub fn with_queries(mut self, queries: Vec<ResolveInput>) -> Self {
        self.queries = queries;
        self.custom_queries = true;
        self
    }

    pub fn with_backend(mut self, dns: Arc<dyn DnsBackend>) -> Self {
        self.dns = dns;
        self
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "lan.resolve",
            "Parallel DNS & MAC OUI Resolver",
            vec![
                ColumnDef::new("query", "Input Query", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("ip", "Resolved IP", ColumnType::IpAddr).with_width_hint(130),
                ColumnDef::new("hostname", "Hostname", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("mac", "MAC Address", ColumnType::MacAddr).with_width_hint(150),
                ColumnDef::new("vendor", "MAC Vendor", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("status", "Status", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("duration_ms", "Duration", ColumnType::Duration).with_width_hint(100),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn resolve_single(&self, item: &ResolveInput, oui: &OuiDatabase) -> ResolveRecord {
        let started = Instant::now();
        let trimmed = item.query.trim();
        let vendor = item.mac.map(|m| oui.lookup_or_unknown(m)).unwrap_or_default();

        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            match self.dns.reverse_lookup(ip) {
                Ok(Some(hostname)) => ResolveRecord {
                    query: item.query.clone(),
                    ip: Some(ip),
                    hostname,
                    mac: item.mac,
                    vendor,
                    status: "Resolved".to_string(),
                    duration_ms: started.elapsed().as_millis() as u64,
                },
                Ok(None) => ResolveRecord {
                    query: item.query.clone(),
                    ip: Some(ip),
                    hostname: String::new(),
                    mac: item.mac,
                    vendor,
                    status: "Not Found".to_string(),
                    duration_ms: started.elapsed().as_millis() as u64,
                },
                Err(_) => ResolveRecord {
                    query: item.query.clone(),
                    ip: Some(ip),
                    hostname: String::new(),
                    mac: item.mac,
                    vendor,
                    status: "Error".to_string(),
                    duration_ms: started.elapsed().as_millis() as u64,
                },
            }
        } else if let Ok(mac) = MacAddr::parse(trimmed) {
            let v = oui.lookup_or_unknown(mac);
            ResolveRecord {
                query: item.query.clone(),
                ip: None,
                hostname: String::new(),
                mac: Some(mac),
                vendor: v,
                status: "Resolved".to_string(),
                duration_ms: started.elapsed().as_millis() as u64,
            }
        } else {
            match self.dns.forward_lookup(trimmed) {
                Ok(ips) if !ips.is_empty() => ResolveRecord {
                    query: item.query.clone(),
                    ip: Some(ips[0]),
                    hostname: trimmed.to_string(),
                    mac: item.mac,
                    vendor,
                    status: "Resolved".to_string(),
                    duration_ms: started.elapsed().as_millis() as u64,
                },
                Ok(_) => ResolveRecord {
                    query: item.query.clone(),
                    ip: None,
                    hostname: trimmed.to_string(),
                    mac: item.mac,
                    vendor,
                    status: "Not Found".to_string(),
                    duration_ms: started.elapsed().as_millis() as u64,
                },
                Err(_) => ResolveRecord {
                    query: item.query.clone(),
                    ip: None,
                    hostname: trimmed.to_string(),
                    mac: item.mac,
                    vendor,
                    status: "Error".to_string(),
                    duration_ms: started.elapsed().as_millis() as u64,
                },
            }
        }
    }

    fn collect_records(&self) -> NetResult<Vec<ResolveRecord>> {
        if self.ctx.is_offline() && !self.custom_queries {
            return fixtures::load_resolve_records(&self.ctx);
        }
        let oui = OuiDatabase::for_context(&self.ctx)?;
        let records = run_bounded(&self.queries, 32, |item| self.resolve_single(item, &oui));
        Ok(records)
    }
}

impl TableProvider for BatchResolverProvider {
    fn tool_id(&self) -> &'static str {
        "lan.resolve"
    }

    fn description(&self) -> &'static str {
        "Resolve hostnames, IP addresses, and MAC OUI vendors in parallel"
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
                let ip_cell = rec
                    .ip
                    .map(|ip| CellValue::Text(ip.to_string()))
                    .unwrap_or(CellValue::Null);
                let mac_cell = rec
                    .mac
                    .map(|m| CellValue::Text(m.to_colon_string()))
                    .unwrap_or(CellValue::Null);
                let detail = json!({
                    "query": rec.query,
                    "ip": rec.ip.map(|ip| ip.to_string()),
                    "hostname": rec.hostname,
                    "mac": rec.mac.map(|m| m.to_colon_string()),
                    "vendor": rec.vendor,
                    "status": rec.status,
                    "duration_ms": rec.duration_ms,
                });
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.query),
                        ip_cell,
                        CellValue::Text(rec.hostname),
                        mac_cell,
                        CellValue::Text(rec.vendor),
                        CellValue::Text(rec.status),
                        CellValue::Uint(rec.duration_ms),
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
    use net2rust_core::NetError;

    use super::*;

    struct MockDnsBackend;
    impl DnsBackend for MockDnsBackend {
        fn forward_lookup(&self, host: &str) -> NetResult<Vec<IpAddr>> {
            match host {
                "gateway.lab.local" => Ok(vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))]),
                "missing.lab.local" => Ok(Vec::new()),
                _ => Err(NetError::NetworkError("mock dns failure".into())),
            }
        }

        fn reverse_lookup(&self, ip: IpAddr) -> NetResult<Option<String>> {
            if ip == IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)) {
                Ok(Some("nas.lab.local".to_string()))
            } else {
                Ok(None)
            }
        }
    }

    #[test]
    fn test_fast_resolver_with_mock_dns_and_oui() {
        let provider = BatchResolverProvider::new(NetContext::live())
            .with_backend(Arc::new(MockDnsBackend))
            .with_queries(vec![
                ResolveInput {
                    query: "gateway.lab.local".into(),
                    mac: Some(MacAddr::parse("00:50:56:11:22:33").unwrap()),
                },
                ResolveInput {
                    query: "192.168.1.10".into(),
                    mac: Some(MacAddr::parse("00:11:32:aa:bb:cc").unwrap()),
                },
                ResolveInput {
                    query: "missing.lab.local".into(),
                    mac: None,
                },
                ResolveInput {
                    query: "b8:27:eb:01:02:03".into(),
                    mac: None,
                },
            ]);

        let data = provider.query(&TableQuery::default()).unwrap();
        assert_eq!(data.total_rows, 4);
        assert_eq!(data.rows[0].cells[0], CellValue::Text("192.168.1.10".into()));
        assert_eq!(data.rows[0].cells[2], CellValue::Text("nas.lab.local".into()));
        assert_eq!(data.rows[0].cells[4], CellValue::Text("Synology Incorporated".into()));
        assert_eq!(data.rows[0].cells[5], CellValue::Text("Resolved".into()));

        // Find gateway row
        let gw = data
            .rows
            .iter()
            .find(|r| r.cells[0] == CellValue::Text("gateway.lab.local".into()))
            .unwrap();
        assert_eq!(gw.cells[1], CellValue::Text("192.168.1.1".into()));
        assert_eq!(gw.cells[4], CellValue::Text("VMware, Inc.".into()));
        assert_eq!(gw.cells[5], CellValue::Text("Resolved".into()));

        let missing = data
            .rows
            .iter()
            .find(|r| r.cells[0] == CellValue::Text("missing.lab.local".into()))
            .unwrap();
        assert_eq!(missing.cells[5], CellValue::Text("Not Found".into()));

        let mac_only = data
            .rows
            .iter()
            .find(|r| r.cells[0] == CellValue::Text("b8:27:eb:01:02:03".into()))
            .unwrap();
        assert_eq!(mac_only.cells[4], CellValue::Text("Raspberry Pi Foundation".into()));
        assert_eq!(mac_only.cells[5], CellValue::Text("Resolved".into()));

        // Custom 2-item queries starting with 127.0.0.1 under offline context still use custom queries.
        let custom_offline = BatchResolverProvider::new(NetContext::offline(Default::default()))
            .with_backend(Arc::new(MockDnsBackend))
            .with_queries(vec![
                ResolveInput {
                    query: "127.0.0.1".into(),
                    mac: None,
                },
                ResolveInput {
                    query: "gateway.lab.local".into(),
                    mac: None,
                },
            ]);
        let offline_data = custom_offline.query(&TableQuery::default()).unwrap();
        assert_eq!(offline_data.total_rows, 2);
        assert!(
            offline_data
                .rows
                .iter()
                .any(|r| r.cells[0] == CellValue::Text("gateway.lab.local".into()))
        );
    }
}
