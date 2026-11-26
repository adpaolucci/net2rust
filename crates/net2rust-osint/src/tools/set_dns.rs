use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use net2rust_core::{ExecutionMode, NetContext, NetError, NetResult, OfflineConfig};
use serde::{Deserialize, Serialize};

use crate::model::{load_fixture_json, parse_guid_flexible};

pub const TOOL_ID: &str = "osint.set-dns";
pub const DESCRIPTION: &str = "QuickSetDNS equivalent: interface DNS server inspector (mutating DNS change gated).";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsInterfaceRecord {
    pub adapter_name: String,
    pub interface_guid: String,
    pub current_dns_v4: Vec<String>,
    pub current_dns_v6: Vec<String>,
    pub dhcp_dns: String,
    pub dhcp_enabled: bool,
    pub if_index: u32,
    pub luid: u64,
    pub oper_status: String,
    pub reg_v4_nameserver: Option<String>,
    pub reg_v4_dhcp_nameserver: Option<String>,
    pub reg_v4_profile_nameserver: Option<String>,
    pub reg_v6_nameserver: Option<String>,
    pub reg_v6_dhcp_nameserver: Option<String>,
    pub reg_v6_profile_nameserver: Option<String>,
    pub api_dns_v4: Vec<String>,
    pub api_dns_v6: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetDnsRequest {
    pub interface: String,
    pub servers: Vec<IpAddr>,
    pub ipv6: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetDnsApplyResult {
    pub applied: bool,
    pub dry_run: bool,
    pub interface_guid: String,
    pub adapter_alias: String,
    pub family: String,
    pub mode: String,
    pub servers: Vec<String>,
    pub planned_api: String,
}

pub trait DnsBackend: Send + Sync {
    fn list_interfaces(&self) -> NetResult<Vec<DnsInterfaceRecord>>;
    fn apply_dns(&self, req: &SetDnsRequest, dry_run: bool) -> NetResult<SetDnsApplyResult>;
}

pub fn schema() -> TableSchema {
    TableSchema::new(
        TOOL_ID,
        "QuickSetDNS — Interface DNS Configuration",
        vec![
            ColumnDef::new("AdapterName", "Adapter Name", ColumnType::Text).with_width_hint(180),
            ColumnDef::new("InterfaceGuid", "Interface GUID", ColumnType::Text).with_width_hint(260),
            ColumnDef::new("CurrentDnsV4", "Current DNS (IPv4)", ColumnType::Text).with_width_hint(190),
            ColumnDef::new("CurrentDnsV6", "Current DNS (IPv6)", ColumnType::Text).with_width_hint(240),
            ColumnDef::new("DhcpDns", "DHCP / Static Mode", ColumnType::Text).with_width_hint(200),
        ],
    )
}

/// Validates and constructs a `SetDnsRequest` from untrusted JSON action arguments.
/// Rejects empty interfaces, malformed IPs, unspecified `0.0.0.0`/`::`, mixed v4+v6 lists,
/// and lists exceeding 8 DNS servers.
pub fn validate_set_dns_args(
    interface: &str,
    raw_servers: &[String],
    ipv6_opt: Option<bool>,
) -> NetResult<SetDnsRequest> {
    let iface = interface.trim();
    if iface.is_empty() {
        return Err(NetError::InvalidInput("'interface' must not be empty".into()));
    }
    if iface.len() > 256 || iface.chars().any(|c| c.is_control()) {
        return Err(NetError::InvalidInput(
            "'interface' contains invalid control characters or exceeds length limit".into(),
        ));
    }
    if raw_servers.len() > 8 {
        return Err(NetError::InvalidInput(
            "'servers' must not contain more than 8 DNS server addresses".into(),
        ));
    }

    let mut parsed_servers = Vec::with_capacity(raw_servers.len());
    let mut saw_v4 = false;
    let mut saw_v6 = false;
    for raw in raw_servers {
        let trimmed = raw.trim();
        let ip =
            IpAddr::from_str(trimmed).map_err(|_| NetError::InvalidInput(format!("invalid DNS server IP '{raw}'")))?;
        if ip.is_unspecified() {
            return Err(NetError::InvalidInput(format!(
                "unspecified DNS server IP '{ip}' is not allowed"
            )));
        }
        match ip {
            IpAddr::V4(_) => saw_v4 = true,
            IpAddr::V6(_) => saw_v6 = true,
        }
        parsed_servers.push(ip);
    }

    if saw_v4 && saw_v6 {
        return Err(NetError::InvalidInput(
            "cannot mix IPv4 and IPv6 addresses in a single 'servers' list".into(),
        ));
    }

    let ipv6 = match ipv6_opt {
        Some(flag) => {
            if flag && saw_v4 {
                return Err(NetError::InvalidInput(
                    "ipv6=true specified, but 'servers' contains IPv4 addresses".into(),
                ));
            }
            if !flag && saw_v6 {
                return Err(NetError::InvalidInput(
                    "ipv6=false specified, but 'servers' contains IPv6 addresses".into(),
                ));
            }
            flag
        }
        None => saw_v6,
    };

    Ok(SetDnsRequest {
        interface: iface.to_string(),
        servers: parsed_servers,
        ipv6,
    })
}

/// Deterministic in-memory DNS backend for `ExecutionMode::Offline` and unit tests.
#[derive(Debug, Clone)]
pub struct MockDnsBackend {
    interfaces: Arc<Mutex<Vec<DnsInterfaceRecord>>>,
}

impl Default for MockDnsBackend {
    fn default() -> Self {
        Self::new(default_offline_interfaces())
    }
}

impl MockDnsBackend {
    pub fn new(records: Vec<DnsInterfaceRecord>) -> Self {
        Self {
            interfaces: Arc::new(Mutex::new(records)),
        }
    }

    pub fn from_offline_config(cfg: &OfflineConfig) -> NetResult<Self> {
        if let Some(loaded) = load_fixture_json::<Vec<DnsInterfaceRecord>>(cfg, "set_dns_interfaces.json")? {
            return Ok(Self::new(loaded));
        }
        Ok(Self::default())
    }
}

impl DnsBackend for MockDnsBackend {
    fn list_interfaces(&self) -> NetResult<Vec<DnsInterfaceRecord>> {
        let guard = self
            .interfaces
            .lock()
            .map_err(|_| NetError::Internal("mock DNS state lock poisoned".into()))?;
        Ok(guard.clone())
    }

    fn apply_dns(&self, req: &SetDnsRequest, dry_run: bool) -> NetResult<SetDnsApplyResult> {
        let mut guard = self
            .interfaces
            .lock()
            .map_err(|_| NetError::Internal("mock DNS state lock poisoned".into()))?;

        let norm_guid = parse_guid_flexible(&req.interface).ok();
        let idx = guard
            .iter()
            .position(|rec| {
                rec.adapter_name.eq_ignore_ascii_case(&req.interface)
                    || rec.interface_guid.eq_ignore_ascii_case(&req.interface)
                    || norm_guid
                        .as_deref()
                        .is_some_and(|g| rec.interface_guid.eq_ignore_ascii_case(g))
            })
            .ok_or_else(|| NetError::HardwareNotFound(format!("network interface '{}' not found", req.interface)))?;

        let server_strings: Vec<String> = req.servers.iter().map(ToString::to_string).collect();
        let family = if req.ipv6 { "ipv6" } else { "ipv4" }.to_string();
        let mode = if server_strings.is_empty() { "dhcp" } else { "static" }.to_string();

        let rec = &mut guard[idx];
        let guid = rec.interface_guid.clone();
        let alias = rec.adapter_name.clone();

        if !dry_run {
            let joined = server_strings.join(",");
            if req.ipv6 {
                rec.current_dns_v6 = server_strings.clone();
                rec.reg_v6_nameserver = (!joined.is_empty()).then_some(joined);
            } else {
                rec.current_dns_v4 = server_strings.clone();
                rec.reg_v4_nameserver = (!joined.is_empty()).then_some(joined);
                rec.dhcp_enabled = server_strings.is_empty();
                rec.dhcp_dns = if server_strings.is_empty() {
                    format!(
                        "DHCP ({})",
                        rec.reg_v4_dhcp_nameserver.as_deref().unwrap_or("automatic")
                    )
                } else {
                    "Static".to_string()
                };
            }
        }

        Ok(SetDnsApplyResult {
            applied: !dry_run,
            dry_run,
            interface_guid: guid,
            adapter_alias: alias,
            family,
            mode,
            servers: server_strings,
            planned_api: "SetInterfaceDnsSettings".to_string(),
        })
    }
}

pub fn default_offline_interfaces() -> Vec<DnsInterfaceRecord> {
    vec![
        DnsInterfaceRecord {
            adapter_name: "Ethernet".to_string(),
            interface_guid: "{11111111-2222-3333-4444-555555555555}".to_string(),
            current_dns_v4: vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
            current_dns_v6: vec!["2606:4700:4700::1111".to_string()],
            dhcp_dns: "Static".to_string(),
            dhcp_enabled: false,
            if_index: 12,
            luid: 0x0006_0000_0001_0000,
            oper_status: "Up".to_string(),
            reg_v4_nameserver: Some("1.1.1.1,1.0.0.1".to_string()),
            reg_v4_dhcp_nameserver: Some("192.168.1.1".to_string()),
            reg_v4_profile_nameserver: None,
            reg_v6_nameserver: Some("2606:4700:4700::1111".to_string()),
            reg_v6_dhcp_nameserver: None,
            reg_v6_profile_nameserver: None,
            api_dns_v4: vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
            api_dns_v6: vec!["2606:4700:4700::1111".to_string()],
        },
        DnsInterfaceRecord {
            adapter_name: "Wi-Fi".to_string(),
            interface_guid: "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}".to_string(),
            current_dns_v4: vec!["192.168.1.1".to_string()],
            current_dns_v6: Vec::new(),
            dhcp_dns: "DHCP (192.168.1.1)".to_string(),
            dhcp_enabled: true,
            if_index: 18,
            luid: 0x0047_0000_0002_0000,
            oper_status: "Up".to_string(),
            reg_v4_nameserver: None,
            reg_v4_dhcp_nameserver: Some("192.168.1.1".to_string()),
            reg_v4_profile_nameserver: None,
            reg_v6_nameserver: None,
            reg_v6_dhcp_nameserver: None,
            reg_v6_profile_nameserver: None,
            api_dns_v4: vec!["192.168.1.1".to_string()],
            api_dns_v6: Vec::new(),
        },
    ]
}

#[cfg(windows)]
pub mod win32_backend {
    use std::io::ErrorKind;
    use std::mem::size_of;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::ptr::{NonNull, read_unaligned};

    use net2rust_core::{NetError, NetResult};
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_BUFFER_OVERFLOW, ERROR_CALL_NOT_IMPLEMENTED, ERROR_INVALID_PARAMETER, ERROR_NO_DATA,
        ERROR_NOT_FOUND, ERROR_NOT_SUPPORTED, ERROR_SUCCESS, WIN32_ERROR,
    };
    use windows::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceGuidToLuid, ConvertInterfaceLuidToAlias,
        ConvertInterfaceLuidToGuid, ConvertInterfaceNameToLuidW, DNS_INTERFACE_SETTINGS,
        DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER, FreeInterfaceDnsSettings,
        GAA_FLAG_INCLUDE_ALL_INTERFACES, GetAdaptersAddresses, GetInterfaceDnsSettings, IP_ADAPTER_ADDRESSES_LH,
        IP_ADAPTER_DHCP_ENABLED, SetInterfaceDnsSettings,
    };
    use windows::Win32::NetworkManagement::Ndis::{IF_OPER_STATUS, NET_LUID_LH};
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
    };
    use windows::core::{GUID, PCWSTR, PWSTR};
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, KEY_WOW64_64KEY};

    use super::{DnsBackend, DnsInterfaceRecord, SetDnsApplyResult, SetDnsRequest};
    use crate::model::{parse_guid_flexible, strip_guid_braces};

    pub struct WindowsDnsBackend;

    pub(crate) fn to_wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub(crate) fn guid_to_braced_upper(guid: &GUID) -> String {
        format!(
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            guid.data1,
            guid.data2,
            guid.data3,
            guid.data4[0],
            guid.data4[1],
            guid.data4[2],
            guid.data4[3],
            guid.data4[4],
            guid.data4[5],
            guid.data4[6],
            guid.data4[7],
        )
    }

    pub(crate) fn parse_win32_guid(input: &str) -> NetResult<GUID> {
        let norm = parse_guid_flexible(input)?;
        let stripped = strip_guid_braces(&norm);
        GUID::try_from(stripped.as_str())
            .map_err(|e| NetError::InvalidInput(format!("invalid Windows GUID '{input}': {e}")))
    }

    /// Converts a WinSock `SOCKET_ADDRESS` into `IpAddr` using `read_unaligned` and length guards.
    pub(crate) fn sockaddr_to_ip(sa: &SOCKET_ADDRESS) -> Option<IpAddr> {
        if sa.lpSockaddr.is_null() || sa.iSockaddrLength < size_of::<SOCKADDR>() as i32 {
            return None;
        }
        // SAFETY: `sa.lpSockaddr` is non-null and `iSockaddrLength >= size_of::<SOCKADDR>()`.
        // Using `read_unaligned` avoids creating unaligned references to WinSock buffers.
        let base = unsafe { read_unaligned(sa.lpSockaddr) };
        if base.sa_family == AF_INET {
            if sa.iSockaddrLength < size_of::<SOCKADDR_IN>() as i32 {
                return None;
            }
            // SAFETY: `sa.lpSockaddr` points to at least `size_of::<SOCKADDR_IN>()` bytes.
            let sin = unsafe { read_unaligned(sa.lpSockaddr as *const SOCKADDR_IN) };
            return Some(IpAddr::V4(Ipv4Addr::from(sin.sin_addr)));
        }
        if base.sa_family == AF_INET6 {
            if sa.iSockaddrLength < size_of::<SOCKADDR_IN6>() as i32 {
                return None;
            }
            // SAFETY: `sa.lpSockaddr` points to at least `size_of::<SOCKADDR_IN6>()` bytes.
            let sin6 = unsafe { read_unaligned(sa.lpSockaddr as *const SOCKADDR_IN6) };
            return Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr)));
        }
        None
    }

    struct DnsInterfaceSettingsGuard {
        settings: DNS_INTERFACE_SETTINGS,
        active: bool,
    }

    impl DnsInterfaceSettingsGuard {
        fn query(guid: GUID, ipv6: bool) -> Option<Self> {
            let mut settings = DNS_INTERFACE_SETTINGS {
                Version: DNS_INTERFACE_SETTINGS_VERSION1,
                Flags: if ipv6 { DNS_SETTING_IPV6 as u64 } else { 0 },
                ..Default::default()
            };
            // SAFETY: `settings` is zero-initialized with `Version = 1` and valid mutable pointer.
            let err = unsafe { GetInterfaceDnsSettings(guid, &mut settings) };
            if err == ERROR_SUCCESS {
                Some(Self { settings, active: true })
            } else {
                None
            }
        }

        fn name_server(&self) -> Option<String> {
            read_pwstr_opt(self.settings.NameServer)
        }

        fn profile_name_server(&self) -> Option<String> {
            read_pwstr_opt(self.settings.ProfileNameServer)
        }
    }

    impl Drop for DnsInterfaceSettingsGuard {
        fn drop(&mut self) {
            if self.active {
                // SAFETY: `GetInterfaceDnsSettings` returned `ERROR_SUCCESS` for `self.settings`.
                unsafe { FreeInterfaceDnsSettings(&mut self.settings) };
            }
        }
    }

    fn read_pwstr_opt(pw: PWSTR) -> Option<String> {
        if pw.is_null() {
            return None;
        }
        // SAFETY: `pw` is non-null and OS-allocated null-terminated UTF-16 string.
        let s = unsafe { pw.to_string().ok()? };
        let trimmed = s.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    }

    fn split_dns_list(raw: &str) -> Vec<String> {
        raw.split([',', ' ', ';'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }

    #[derive(Default)]
    struct RegDnsValues {
        nameserver: Option<String>,
        dhcp_nameserver: Option<String>,
        profile_nameserver: Option<String>,
    }

    fn read_reg_dns_values(family_subpath: &str, guid_braced: &str) -> RegDnsValues {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let full_path =
            format!("SYSTEM\\CurrentControlSet\\Services\\{family_subpath}\\Parameters\\Interfaces\\{guid_braced}");
        let Ok(key) = hklm.open_subkey_with_flags(&full_path, KEY_READ | KEY_WOW64_64KEY) else {
            return RegDnsValues::default();
        };
        let read_opt = |val_name: &str| -> Option<String> {
            key.get_value::<String, _>(val_name)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        RegDnsValues {
            nameserver: read_opt("NameServer"),
            dhcp_nameserver: read_opt("DhcpNameServer"),
            profile_nameserver: read_opt("ProfileNameServer"),
        }
    }

    fn oper_status_str(status: IF_OPER_STATUS) -> String {
        match status.0 {
            1 => "Up".to_string(),
            2 => "Down".to_string(),
            3 => "Testing".to_string(),
            4 => "Unknown".to_string(),
            5 => "Dormant".to_string(),
            6 => "NotPresent".to_string(),
            7 => "LowerLayerDown".to_string(),
            other => format!("Status({other})"),
        }
    }

    pub(crate) fn resolve_interface_guid_luid_alias(iface: &str) -> NetResult<(GUID, NET_LUID_LH, String)> {
        let mut luid = NET_LUID_LH::default();
        let mut guid = GUID::default();

        if let Ok(parsed_guid) = parse_win32_guid(iface) {
            // SAFETY: `parsed_guid` and `luid` are valid stack locals.
            let err = unsafe { ConvertInterfaceGuidToLuid(&parsed_guid, &mut luid) };
            if err != ERROR_SUCCESS {
                return Err(NetError::HardwareNotFound(format!(
                    "network interface GUID '{iface}' not found (Win32 error {})",
                    err.0
                )));
            }
            guid = parsed_guid;
        } else {
            let wide = to_wide_null(iface);
            // SAFETY: `wide` is null-terminated UTF-16 and lives across both FFI calls.
            let err_alias = unsafe { ConvertInterfaceAliasToLuid(PCWSTR(wide.as_ptr()), &mut luid) };
            if err_alias != ERROR_SUCCESS {
                // SAFETY: fallback to NDIS interface name lookup using the same null-terminated buffer.
                let err_name = unsafe { ConvertInterfaceNameToLuidW(PCWSTR(wide.as_ptr()), &mut luid) };
                if err_name != ERROR_SUCCESS {
                    return Err(NetError::HardwareNotFound(format!(
                        "network interface '{iface}' not found"
                    )));
                }
            }
            // SAFETY: `luid` is valid and `guid` is an initialized stack local.
            let err_guid = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
            if err_guid != ERROR_SUCCESS {
                return Err(NetError::HardwareNotFound(format!(
                    "failed to resolve GUID for interface '{iface}' (Win32 error {})",
                    err_guid.0
                )));
            }
        }

        let mut alias_buf = [0u16; 257];
        // SAFETY: `luid` is valid and `alias_buf` provides 257 UTF-16 code units.
        let alias = if unsafe { ConvertInterfaceLuidToAlias(&luid, &mut alias_buf) } == ERROR_SUCCESS {
            let len = alias_buf.iter().position(|&c| c == 0).unwrap_or(alias_buf.len());
            String::from_utf16_lossy(&alias_buf[..len])
        } else {
            iface.to_string()
        };

        Ok((guid, luid, alias))
    }

    pub(crate) fn enumerate_adapters_raw<F>(mut visitor: F) -> NetResult<()>
    where
        F: FnMut(&IP_ADAPTER_ADDRESSES_LH),
    {
        let mut byte_len: u32 = 16 * 1024;
        let mut buf_u64: Vec<u64> = Vec::new();

        for _attempt in 0..3 {
            let words = (byte_len as usize).div_ceil(8).max(1);
            buf_u64.resize(words, 0);
            let ptr = buf_u64.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
            // SAFETY: `buf_u64` provides 8-byte alignment matching `IP_ADAPTER_ADDRESSES_LH`
            // and capacity `words * 8 >= byte_len`.
            let rc = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC.0 as u32,
                    GAA_FLAG_INCLUDE_ALL_INTERFACES,
                    None,
                    Some(ptr),
                    &mut byte_len,
                )
            };
            if rc == ERROR_SUCCESS.0 {
                let buf_start = buf_u64.as_ptr() as usize;
                let buf_end = buf_start + buf_u64.len() * size_of::<u64>();
                let mut cur = ptr as *const IP_ADAPTER_ADDRESSES_LH;
                while let Some(nn) = NonNull::new(cur as *mut IP_ADAPTER_ADDRESSES_LH) {
                    let addr_num = nn.as_ptr() as usize;
                    if addr_num < buf_start || addr_num + size_of::<IP_ADAPTER_ADDRESSES_LH>() > buf_end {
                        break;
                    }
                    // SAFETY: `nn` is aligned (8-byte buffer), non-null, and strictly within `buf_u64`.
                    let item = unsafe { nn.as_ref() };
                    visitor(item);
                    cur = item.Next;
                }
                return Ok(());
            }
            if rc == ERROR_NO_DATA.0 {
                return Ok(());
            }
            if rc != ERROR_BUFFER_OVERFLOW.0 {
                return Err(NetError::Internal(format!(
                    "GetAdaptersAddresses failed with Win32 error {rc}"
                )));
            }
        }

        Err(NetError::Internal(
            "GetAdaptersAddresses buffer overflow persisted after 3 retries".into(),
        ))
    }

    impl DnsBackend for WindowsDnsBackend {
        fn list_interfaces(&self) -> NetResult<Vec<DnsInterfaceRecord>> {
            let mut records = Vec::new();
            enumerate_adapters_raw(|item| {
                let raw_guid = if !item.AdapterName.is_null() {
                    // SAFETY: `AdapterName` is non-null OS-allocated ANSI string within `buf_u64`.
                    unsafe { item.AdapterName.to_string().unwrap_or_default() }
                } else {
                    String::new()
                };
                let interface_guid = parse_guid_flexible(&raw_guid).unwrap_or_else(|_| raw_guid.clone());

                let friendly = read_pwstr_opt(item.FriendlyName);
                let desc = read_pwstr_opt(item.Description);
                let adapter_name = friendly.or(desc).unwrap_or_else(|| interface_guid.clone());

                // SAFETY: `Anonymous1.Anonymous` and `Anonymous2.Flags` are plain integer fields in union.
                let if_index = unsafe { item.Anonymous1.Anonymous.IfIndex };
                let flags = unsafe { item.Anonymous2.Flags };
                let dhcp_enabled = (flags & IP_ADAPTER_DHCP_ENABLED) != 0;
                let luid = unsafe { item.Luid.Value };

                let mut api_dns_v4 = Vec::new();
                let mut api_dns_v6 = Vec::new();
                let mut dns_ptr = item.FirstDnsServerAddress;
                while !dns_ptr.is_null() {
                    // SAFETY: `dns_ptr` is within the `GetAdaptersAddresses` buffer.
                    let dns_entry = unsafe { &*dns_ptr };
                    if let Some(ip) = sockaddr_to_ip(&dns_entry.Address) {
                        match ip {
                            IpAddr::V4(v4) => api_dns_v4.push(v4.to_string()),
                            IpAddr::V6(v6) => api_dns_v6.push(v6.to_string()),
                        }
                    }
                    dns_ptr = dns_entry.Next;
                }

                let reg_v4 = read_reg_dns_values("Tcpip", &interface_guid);
                let reg_v6 = read_reg_dns_values("Tcpip6", &interface_guid);

                let (api_v4_setting, api_v4_prof, api_v6_setting, api_v6_prof) =
                    if let Ok(parsed_guid) = parse_win32_guid(&interface_guid) {
                        let g4 = DnsInterfaceSettingsGuard::query(parsed_guid, false);
                        let g6 = DnsInterfaceSettingsGuard::query(parsed_guid, true);
                        (
                            g4.as_ref().and_then(DnsInterfaceSettingsGuard::name_server),
                            g4.as_ref().and_then(DnsInterfaceSettingsGuard::profile_name_server),
                            g6.as_ref().and_then(DnsInterfaceSettingsGuard::name_server),
                            g6.as_ref().and_then(DnsInterfaceSettingsGuard::profile_name_server),
                        )
                    } else {
                        (None, None, None, None)
                    };

                let current_dns_v4 = if !api_dns_v4.is_empty() {
                    api_dns_v4.clone()
                } else if let Some(s) = reg_v4
                    .nameserver
                    .as_deref()
                    .or(api_v4_setting.as_deref())
                    .or(reg_v4.dhcp_nameserver.as_deref())
                {
                    split_dns_list(s)
                } else {
                    Vec::new()
                };

                let current_dns_v6 = if !api_dns_v6.is_empty() {
                    api_dns_v6.clone()
                } else if let Some(s) = reg_v6
                    .nameserver
                    .as_deref()
                    .or(api_v6_setting.as_deref())
                    .or(reg_v6.dhcp_nameserver.as_deref())
                {
                    split_dns_list(s)
                } else {
                    Vec::new()
                };

                let dhcp_dns = if reg_v4.nameserver.is_some() || api_v4_setting.is_some() {
                    "Static".to_string()
                } else if let Some(dhcp_srv) = &reg_v4.dhcp_nameserver {
                    format!("DHCP ({dhcp_srv})")
                } else if dhcp_enabled {
                    "DHCP".to_string()
                } else {
                    "Static".to_string()
                };

                records.push(DnsInterfaceRecord {
                    adapter_name,
                    interface_guid,
                    current_dns_v4,
                    current_dns_v6,
                    dhcp_dns,
                    dhcp_enabled,
                    if_index,
                    luid,
                    oper_status: oper_status_str(item.OperStatus),
                    reg_v4_nameserver: reg_v4.nameserver.or(api_v4_setting),
                    reg_v4_dhcp_nameserver: reg_v4.dhcp_nameserver,
                    reg_v4_profile_nameserver: reg_v4.profile_nameserver.or(api_v4_prof),
                    reg_v6_nameserver: reg_v6.nameserver.or(api_v6_setting),
                    reg_v6_dhcp_nameserver: reg_v6.dhcp_nameserver,
                    reg_v6_profile_nameserver: reg_v6.profile_nameserver.or(api_v6_prof),
                    api_dns_v4,
                    api_dns_v6,
                });
            })?;
            Ok(records)
        }

        fn apply_dns(&self, req: &SetDnsRequest, dry_run: bool) -> NetResult<SetDnsApplyResult> {
            let (guid, _luid, alias) = resolve_interface_guid_luid_alias(&req.interface)?;
            let interface_guid = guid_to_braced_upper(&guid);
            let server_strings: Vec<String> = req.servers.iter().map(ToString::to_string).collect();
            let family = if req.ipv6 { "ipv6" } else { "ipv4" }.to_string();
            let mode = if server_strings.is_empty() { "dhcp" } else { "static" }.to_string();

            if dry_run {
                return Ok(SetDnsApplyResult {
                    applied: false,
                    dry_run: true,
                    interface_guid,
                    adapter_alias: alias,
                    family,
                    mode,
                    servers: server_strings,
                    planned_api: "SetInterfaceDnsSettings".to_string(),
                });
            }

            let joined = server_strings.join(",");
            let mut wide_nameservers = to_wide_null(&joined);
            let mut flags = DNS_SETTING_NAMESERVER as u64;
            if req.ipv6 {
                flags |= DNS_SETTING_IPV6 as u64;
            }
            let settings = DNS_INTERFACE_SETTINGS {
                Version: DNS_INTERFACE_SETTINGS_VERSION1,
                Flags: flags,
                NameServer: PWSTR(wide_nameservers.as_mut_ptr()),
                ..Default::default()
            };

            // SAFETY: `wide_nameservers` is null-terminated UTF-16 and lives through `SetInterfaceDnsSettings`.
            let err: WIN32_ERROR = unsafe { SetInterfaceDnsSettings(guid, &settings) };
            match err {
                ERROR_SUCCESS => Ok(SetDnsApplyResult {
                    applied: true,
                    dry_run: false,
                    interface_guid,
                    adapter_alias: alias,
                    family,
                    mode,
                    servers: server_strings,
                    planned_api: "SetInterfaceDnsSettings".to_string(),
                }),
                ERROR_ACCESS_DENIED => Err(NetError::PermissionDenied(
                    "Administrator elevation required to modify interface DNS settings".into(),
                )),
                ERROR_NOT_FOUND => Err(NetError::HardwareNotFound(format!(
                    "interface '{interface_guid}' not found"
                ))),
                ERROR_INVALID_PARAMETER => Err(NetError::InvalidInput(
                    "Windows rejected one or more DNS parameters".into(),
                )),
                ERROR_CALL_NOT_IMPLEMENTED | ERROR_NOT_SUPPORTED => {
                    // Safe winreg fallback (zero shell)
                    let sub = if req.ipv6 { "Tcpip6" } else { "Tcpip" };
                    let path =
                        format!("SYSTEM\\CurrentControlSet\\Services\\{sub}\\Parameters\\Interfaces\\{interface_guid}");
                    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
                    let key = hklm
                        .open_subkey_with_flags(&path, KEY_SET_VALUE | KEY_WOW64_64KEY)
                        .map_err(|e| match e.kind() {
                            ErrorKind::PermissionDenied => NetError::PermissionDenied(
                                "elevation required for Tcpip interface registry write".into(),
                            ),
                            ErrorKind::NotFound => {
                                NetError::HardwareNotFound(format!("registry key '{path}' not found"))
                            }
                            _ => NetError::Io(e),
                        })?;
                    key.set_value("NameServer", &joined).map_err(|e| match e.kind() {
                        ErrorKind::PermissionDenied => {
                            NetError::PermissionDenied("elevation required to update NameServer value".into())
                        }
                        _ => NetError::Io(e),
                    })?;
                    Ok(SetDnsApplyResult {
                        applied: true,
                        dry_run: false,
                        interface_guid,
                        adapter_alias: alias,
                        family,
                        mode,
                        servers: server_strings,
                        planned_api: "winreg::NameServer".to_string(),
                    })
                }
                other => Err(NetError::Internal(format!(
                    "SetInterfaceDnsSettings failed with Win32 error {}",
                    other.0
                ))),
            }
        }
    }
}

#[cfg(not(windows))]
pub mod win32_backend {
    use net2rust_core::{NetError, NetResult};

    use super::{DnsBackend, DnsInterfaceRecord, SetDnsApplyResult, SetDnsRequest};

    pub struct WindowsDnsBackend;

    impl DnsBackend for WindowsDnsBackend {
        fn list_interfaces(&self) -> NetResult<Vec<DnsInterfaceRecord>> {
            Err(NetError::NotSupported(
                "live QuickSetDNS interface enumeration requires Windows".into(),
            ))
        }

        fn apply_dns(&self, _req: &SetDnsRequest, _dry_run: bool) -> NetResult<SetDnsApplyResult> {
            Err(NetError::NotSupported(
                "live QuickSetDNS modification requires Windows".into(),
            ))
        }
    }
}

pub fn build_dns_backend(ctx: &NetContext) -> NetResult<Arc<dyn DnsBackend>> {
    match &ctx.mode {
        ExecutionMode::Offline(cfg) => Ok(Arc::new(MockDnsBackend::from_offline_config(cfg)?)),
        ExecutionMode::Live => Ok(Arc::new(win32_backend::WindowsDnsBackend)),
    }
}

pub struct SetDnsProvider {
    ctx: NetContext,
    backend: Arc<dyn DnsBackend>,
    schema: TableSchema,
}

impl SetDnsProvider {
    pub fn new(ctx: NetContext, backend: Arc<dyn DnsBackend>) -> Self {
        Self {
            ctx,
            backend,
            schema: schema(),
        }
    }
}

impl TableProvider for SetDnsProvider {
    fn tool_id(&self) -> &'static str {
        TOOL_ID
    }

    fn description(&self) -> &'static str {
        DESCRIPTION
    }

    fn schema(&self) -> TableSchema {
        self.schema.clone()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let records = self.backend.list_interfaces()?;
        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, rec)| {
                let detail = serde_json::to_value(&rec).unwrap_or(serde_json::Value::Null);
                let v4 = rec.current_dns_v4.join(", ");
                let v6 = rec.current_dns_v6.join(", ");
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.adapter_name),
                        CellValue::Text(rec.interface_guid),
                        if v4.is_empty() {
                            CellValue::Null
                        } else {
                            CellValue::Text(v4)
                        },
                        if v6.is_empty() {
                            CellValue::Null
                        } else {
                            CellValue::Text(v6)
                        },
                        CellValue::Text(rec.dhcp_dns),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        let mut data = apply_query(&self.schema, &rows, req)?;
        if let Some(max) = self.ctx.max_rows {
            data.rows.truncate(max);
        }
        Ok(data)
    }
}

pub fn provider(ctx: &NetContext) -> Arc<dyn TableProvider> {
    let backend: Arc<dyn DnsBackend> = build_dns_backend(ctx).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "failed to load offline set_dns fixture; falling back to default mock backend");
        Arc::new(MockDnsBackend::default())
    });
    Arc::new(SetDnsProvider::new(ctx.clone(), backend))
}
