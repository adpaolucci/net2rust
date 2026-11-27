use std::sync::{Arc, Mutex};

use chrono::{DateTime, TimeZone, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use net2rust_core::{ExecutionMode, MacAddr, NetContext, NetError, NetResult, OfflineConfig};
use serde::{Deserialize, Serialize};

use crate::model::{load_fixture_json, parse_guid_flexible};

pub const TOOL_ID: &str = "osint.net-profiles";
pub const DESCRIPTION: &str = "Windows NetworkList profile inspector (mutating connect/disconnect gated).";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetProfileRecord {
    pub profile_name: String,
    pub profile_guid: String,
    pub category: String,
    pub last_connected: Option<DateTime<Utc>>,
    pub gateway_mac: Option<MacAddr>,
    pub all_gateway_macs: Vec<MacAddr>,
    pub connected: bool,
    pub description: String,
    pub connectivity_flags: u32,
    pub adapter_guids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileTarget {
    pub profile_id: Option<String>,
    pub profile_name: Option<String>,
    pub interface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetProfileActionResult {
    pub applied: bool,
    pub dry_run: bool,
    pub action: String,
    pub profile_guid: String,
    pub profile_name: String,
    pub adapter_index: Option<u32>,
    pub adapter_alias: String,
    pub mechanism: String,
}

pub trait NetProfilesBackend: Send + Sync {
    fn list_profiles(&self) -> NetResult<Vec<NetProfileRecord>>;
    fn set_profile_connection(
        &self,
        target: &ProfileTarget,
        connect: bool,
        dry_run: bool,
    ) -> NetResult<NetProfileActionResult>;
}

pub fn schema() -> TableSchema {
    TableSchema::new(
        TOOL_ID,
        "Windows NetworkList Profiles",
        vec![
            ColumnDef::new("ProfileName", "Profile Name", ColumnType::Text).with_width_hint(180),
            ColumnDef::new("ProfileGuid", "Profile GUID", ColumnType::Text).with_width_hint(260),
            ColumnDef::new("Category", "Category", ColumnType::Text).with_width_hint(100),
            ColumnDef::new("LastConnected", "Last Connected", ColumnType::Timestamp).with_width_hint(180),
            ColumnDef::new("GatewayMac", "Gateway MAC", ColumnType::MacAddr).with_width_hint(150),
            ColumnDef::new("Connected", "Connected", ColumnType::Bool).with_width_hint(90),
        ],
    )
}

pub fn validate_profile_target(
    profile_id: Option<&str>,
    profile_name: Option<&str>,
    interface: Option<&str>,
) -> NetResult<ProfileTarget> {
    let pid = profile_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse_guid_flexible)
        .transpose()?;
    let pname = profile_name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let iface = interface.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);

    if pid.is_none() && pname.is_none() {
        return Err(NetError::InvalidInput(
            "at least one of 'profile_id' or 'profile_name' must be provided".into(),
        ));
    }
    if let Some(ref s) = iface
        && (s.len() > 256 || s.chars().any(|c| c.is_control()))
    {
        return Err(NetError::InvalidInput("'interface' contains invalid characters".into()));
    }

    Ok(ProfileTarget {
        profile_id: pid,
        profile_name: pname,
        interface: iface,
    })
}

/// Deterministic in-memory `NetProfilesBackend` for `ExecutionMode::Offline` and unit tests.
#[derive(Debug, Clone)]
pub struct MockNetProfilesBackend {
    profiles: Arc<Mutex<Vec<NetProfileRecord>>>,
}

impl Default for MockNetProfilesBackend {
    fn default() -> Self {
        Self::new(default_offline_profiles())
    }
}

impl MockNetProfilesBackend {
    pub fn new(profiles: Vec<NetProfileRecord>) -> Self {
        Self {
            profiles: Arc::new(Mutex::new(profiles)),
        }
    }

    pub fn from_offline_config(cfg: &OfflineConfig) -> NetResult<Self> {
        if let Some(loaded) = load_fixture_json::<Vec<NetProfileRecord>>(cfg, "net_profiles.json")? {
            return Ok(Self::new(loaded));
        }
        Ok(Self::default())
    }
}

impl NetProfilesBackend for MockNetProfilesBackend {
    fn list_profiles(&self) -> NetResult<Vec<NetProfileRecord>> {
        let guard = self
            .profiles
            .lock()
            .map_err(|_| NetError::Internal("mock net-profiles state lock poisoned".into()))?;
        Ok(guard.clone())
    }

    fn set_profile_connection(
        &self,
        target: &ProfileTarget,
        connect: bool,
        dry_run: bool,
    ) -> NetResult<NetProfileActionResult> {
        let mut guard = self
            .profiles
            .lock()
            .map_err(|_| NetError::Internal("mock net-profiles state lock poisoned".into()))?;

        let idx = guard
            .iter()
            .position(|p| {
                if let Some(ref id) = target.profile_id {
                    p.profile_guid.eq_ignore_ascii_case(id)
                } else if let Some(ref name) = target.profile_name {
                    p.profile_name.eq_ignore_ascii_case(name)
                } else {
                    false
                }
            })
            .ok_or_else(|| {
                NetError::HardwareNotFound(format!(
                    "network profile '{}' not found",
                    target
                        .profile_id
                        .as_deref()
                        .or(target.profile_name.as_deref())
                        .unwrap_or("<unknown>")
                ))
            })?;

        let rec = &mut guard[idx];
        let guid = rec.profile_guid.clone();
        let name = rec.profile_name.clone();
        let alias = target
            .interface
            .clone()
            .or_else(|| rec.adapter_guids.first().cloned())
            .unwrap_or_else(|| "Ethernet".to_string());

        if !dry_run {
            rec.connected = connect;
            if connect {
                rec.last_connected = Some(Utc::now());
            }
        }

        Ok(NetProfileActionResult {
            applied: !dry_run,
            dry_run,
            action: if connect { "connect" } else { "disconnect" }.to_string(),
            profile_guid: guid,
            profile_name: name,
            adapter_index: Some(12),
            adapter_alias: alias,
            mechanism: "MockNetProfilesBackend".to_string(),
        })
    }
}

pub fn default_offline_profiles() -> Vec<NetProfileRecord> {
    let gw_corp = MacAddr::new([0x00, 0x1b, 0x21, 0xaa, 0xbb, 0x01]);
    let gw_home = MacAddr::new([0x00, 0x0c, 0x29, 0x11, 0x22, 0x33]);
    let gw_cafe = MacAddr::new([0x52, 0x54, 0x00, 0x44, 0x55, 0x66]);
    vec![
        NetProfileRecord {
            profile_name: "CorpNet.internal".to_string(),
            profile_guid: "{10101010-2020-3030-4040-505050505050}".to_string(),
            category: "Domain".to_string(),
            last_connected: Utc.with_ymd_and_hms(2026, 11, 20, 9, 15, 0).single(),
            gateway_mac: Some(gw_corp),
            all_gateway_macs: vec![gw_corp],
            connected: true,
            description: "Corporate Domain Network".to_string(),
            connectivity_flags: 0x0042,
            adapter_guids: vec!["{11111111-2222-3333-4444-555555555555}".to_string()],
        },
        NetProfileRecord {
            profile_name: "HomeLab-LAN".to_string(),
            profile_guid: "{20202020-3030-4040-5050-606060606060}".to_string(),
            category: "Private".to_string(),
            last_connected: Utc.with_ymd_and_hms(2026, 11, 19, 21, 30, 0).single(),
            gateway_mac: Some(gw_home),
            all_gateway_macs: vec![gw_home],
            connected: false,
            description: "Home Private Network".to_string(),
            connectivity_flags: 0x0000,
            adapter_guids: vec!["{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}".to_string()],
        },
        NetProfileRecord {
            profile_name: "Airport-Guest".to_string(),
            profile_guid: "{30303030-4040-5050-6060-707070707070}".to_string(),
            category: "Public".to_string(),
            last_connected: Utc.with_ymd_and_hms(2026, 11, 10, 14, 5, 0).single(),
            gateway_mac: Some(gw_cafe),
            all_gateway_macs: vec![gw_cafe],
            connected: false,
            description: "Public Hotspot".to_string(),
            connectivity_flags: 0x0000,
            adapter_guids: Vec::new(),
        },
    ]
}

#[cfg(windows)]
pub mod win32_backend {
    use std::collections::{BTreeMap, HashMap};
    use std::io::ErrorKind;
    use std::marker::PhantomData;
    use std::process::Command;

    use chrono::{DateTime, Utc};
    use net2rust_core::{MacAddr, NetError, NetResult};
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_GEN_FAILURE, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, ERROR_SUCCESS,
        RPC_E_CHANGED_MODE, S_FALSE, S_OK,
    };
    use windows::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceGuidToLuid, ConvertInterfaceLuidToAlias, ConvertInterfaceLuidToIndex, GetIfEntry,
        MIB_IF_ADMIN_STATUS_DOWN, MIB_IF_ADMIN_STATUS_UP, MIB_IFROW, SetIfEntry,
    };
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows::Win32::Networking::NetworkListManager::{
        INetwork, INetworkConnection, INetworkListManager, NLM_ENUM_NETWORK_ALL,
        NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED, NLM_NETWORK_CATEGORY_PRIVATE, NetworkListManager,
    };
    use windows::Win32::System::Com::{
        CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
    };
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, REG_BINARY};

    use super::{NetProfileActionResult, NetProfileRecord, NetProfilesBackend, ProfileTarget};
    use crate::model::{decode_registry_systemtime, filetime_to_utc, parse_guid_flexible};
    use crate::tools::set_dns::win32_backend::{
        enumerate_adapters_raw, guid_to_braced_upper, parse_win32_guid, resolve_interface_guid_luid_alias,
    };

    pub struct WindowsNetProfilesBackend;

    /// Thread-affine RAII guard for COM apartment initialization.
    struct ComApartmentGuard {
        should_uninit: bool,
        _not_send: PhantomData<*mut ()>,
    }

    impl ComApartmentGuard {
        fn init_multithreaded() -> NetResult<Self> {
            // SAFETY: Initializes COM on the current thread; handles `RPC_E_CHANGED_MODE` gracefully.
            let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            if hr == S_OK || hr == S_FALSE {
                Ok(Self {
                    should_uninit: true,
                    _not_send: PhantomData,
                })
            } else if hr == RPC_E_CHANGED_MODE {
                Ok(Self {
                    should_uninit: false,
                    _not_send: PhantomData,
                })
            } else {
                Err(NetError::Internal(format!("CoInitializeEx failed: {hr:?}")))
            }
        }
    }

    impl Drop for ComApartmentGuard {
        fn drop(&mut self) {
            if self.should_uninit {
                // SAFETY: Paired exclusively with `S_OK` / `S_FALSE` from `CoInitializeEx` on this thread.
                unsafe { CoUninitialize() };
            }
        }
    }

    fn category_from_dword(cat: u32) -> &'static str {
        match cat {
            1 => "Private",
            2 => "Domain",
            _ => "Public",
        }
    }

    fn category_from_nlm(cat: windows::Win32::Networking::NetworkListManager::NLM_NETWORK_CATEGORY) -> &'static str {
        if cat == NLM_NETWORK_CATEGORY_PRIVATE {
            "Private"
        } else if cat == NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED {
            "Domain"
        } else {
            "Public"
        }
    }

    fn collect_signature_macs() -> HashMap<String, Vec<MacAddr>> {
        let mut map: HashMap<String, Vec<MacAddr>> = HashMap::new();
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        for branch in ["Unmanaged", "Managed"] {
            let path = format!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\{branch}");
            let Ok(root) = hklm.open_subkey_with_flags(&path, KEY_READ | KEY_WOW64_64KEY) else {
                continue;
            };
            for subname in root.enum_keys().flatten() {
                let Ok(sub) = root.open_subkey_with_flags(&subname, KEY_READ | KEY_WOW64_64KEY) else {
                    continue;
                };
                let Ok(raw_guid) = sub.get_value::<String, _>("ProfileGuid") else {
                    continue;
                };
                let Ok(guid) = parse_guid_flexible(&raw_guid) else {
                    continue;
                };
                if let Ok(raw_val) = sub.get_raw_value("DefaultGatewayMac")
                    && raw_val.vtype == REG_BINARY
                    && raw_val.bytes.len() == 6
                {
                    let mac = MacAddr::new([
                        raw_val.bytes[0],
                        raw_val.bytes[1],
                        raw_val.bytes[2],
                        raw_val.bytes[3],
                        raw_val.bytes[4],
                        raw_val.bytes[5],
                    ]);
                    map.entry(guid).or_default().push(mac);
                }
            }
        }
        map
    }

    fn collect_registry_profiles(
        sig_macs: &HashMap<String, Vec<MacAddr>>,
    ) -> NetResult<BTreeMap<String, NetProfileRecord>> {
        let mut map = BTreeMap::new();
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles";
        let root = match hklm.open_subkey_with_flags(path, KEY_READ | KEY_WOW64_64KEY) {
            Ok(k) => k,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(map),
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                return Err(NetError::PermissionDenied(
                    "permission denied reading NetworkList\\Profiles registry".into(),
                ));
            }
            Err(e) => return Err(NetError::Io(e)),
        };

        for subname in root.enum_keys().flatten() {
            let Ok(sub) = root.open_subkey_with_flags(&subname, KEY_READ | KEY_WOW64_64KEY) else {
                continue;
            };
            let guid = parse_guid_flexible(&subname).unwrap_or_else(|_| subname.clone());
            let name = sub
                .get_value::<String, _>("ProfileName")
                .unwrap_or_else(|_| guid.clone());
            let description = sub.get_value::<String, _>("Description").unwrap_or_default();
            let category = sub
                .get_value::<u32, _>("Category")
                .map(category_from_dword)
                .unwrap_or("Public")
                .to_string();
            let last_connected = sub
                .get_raw_value("DateLastConnected")
                .ok()
                .filter(|v| v.vtype == REG_BINARY)
                .and_then(|v| decode_registry_systemtime(&v.bytes));

            let macs = sig_macs.get(&guid).cloned().unwrap_or_default();
            let gateway_mac = macs
                .iter()
                .copied()
                .find(|m| !m.is_zero())
                .or_else(|| macs.first().copied());

            map.insert(
                guid.clone(),
                NetProfileRecord {
                    profile_name: name,
                    profile_guid: guid,
                    category,
                    last_connected,
                    gateway_mac,
                    all_gateway_macs: macs,
                    connected: false,
                    description,
                    connectivity_flags: 0,
                    adapter_guids: Vec::new(),
                },
            );
        }

        Ok(map)
    }

    fn collect_com_network_connections(net: &INetwork) -> Vec<String> {
        let mut adapters = Vec::new();
        // SAFETY: `net` is a valid COM interface on the active apartment thread.
        let Ok(enum_conns) = (unsafe { net.GetNetworkConnections() }) else {
            return adapters;
        };
        loop {
            let mut slot: [Option<INetworkConnection>; 1] = [None];
            let mut fetched = 0u32;
            // SAFETY: `slot` and `fetched` are valid stack targets for COM `Next`.
            let res = unsafe { enum_conns.Next(&mut slot, Some(&mut fetched)) };
            if res.is_err() || fetched == 0 {
                break;
            }
            if let Some(conn) = slot[0].take() {
                // SAFETY: `conn` is non-null COM object returned by `Next`.
                if let Ok(adapter_id) = unsafe { conn.GetAdapterId() } {
                    adapters.push(guid_to_braced_upper(&adapter_id));
                }
            }
        }
        adapters
    }

    fn validate_netsh_alias(alias: &str) -> NetResult<()> {
        if alias.is_empty()
            || alias.len() > 256
            || alias
                .chars()
                .any(|c| c.is_control() || matches!(c, '"' | '\'' | ';' | '&' | '|' | '$' | '`' | '<' | '>' | '\0'))
        {
            return Err(NetError::InvalidInput(format!(
                "adapter alias '{alias}' failed safety validation"
            )));
        }
        Ok(())
    }

    impl NetProfilesBackend for WindowsNetProfilesBackend {
        fn list_profiles(&self) -> NetResult<Vec<NetProfileRecord>> {
            let sig_macs = collect_signature_macs();
            let mut merged = collect_registry_profiles(&sig_macs)?;

            let _com_guard = ComApartmentGuard::init_multithreaded()?;
            // SAFETY: COM apartment is initialized by `_com_guard` on this thread.
            let nlm: INetworkListManager = unsafe { CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL) }
                .map_err(|e| NetError::Internal(format!("CoCreateInstance(NetworkListManager) failed: {e}")))?;
            // SAFETY: `nlm` is a valid COM interface on this thread.
            let enum_nets = unsafe { nlm.GetNetworks(NLM_ENUM_NETWORK_ALL) }
                .map_err(|e| NetError::Internal(format!("INetworkListManager::GetNetworks failed: {e}")))?;

            loop {
                let mut slot: [Option<INetwork>; 1] = [None];
                let mut fetched = 0u32;
                // SAFETY: `slot` and `fetched` are valid stack locations; `S_FALSE` yields `fetched == 0`.
                let res = unsafe { enum_nets.Next(&mut slot, Some(&mut fetched)) };
                if res.is_err() || fetched == 0 {
                    break;
                }
                let Some(net) = slot[0].take() else {
                    break;
                };

                // SAFETY: `net` is a valid COM `INetwork` pointer on this thread.
                let Ok(guid_raw) = (unsafe { net.GetNetworkId() }) else {
                    continue;
                };
                let guid = guid_to_braced_upper(&guid_raw);
                let name = unsafe { net.GetName() }
                    .ok()
                    .and_then(|b| String::try_from(&b).ok())
                    .unwrap_or_else(|| guid.clone());
                let desc = unsafe { net.GetDescription() }
                    .ok()
                    .and_then(|b| String::try_from(&b).ok())
                    .unwrap_or_default();
                let category = unsafe { net.GetCategory() }
                    .map(category_from_nlm)
                    .unwrap_or("Public")
                    .to_string();
                let connected = unsafe { net.IsConnected() }.map(|b| b.as_bool()).unwrap_or(false);
                let connectivity_flags = unsafe { net.GetConnectivity() }.map(|c| c.0 as u32).unwrap_or(0);

                let mut c_lo = 0u32;
                let mut c_hi = 0u32;
                let mut conn_lo = 0u32;
                let mut conn_hi = 0u32;
                let com_last_conn: Option<DateTime<Utc>> =
                    if unsafe { net.GetTimeCreatedAndConnected(&mut c_lo, &mut c_hi, &mut conn_lo, &mut conn_hi) }
                        .is_ok()
                    {
                        let ft = ((conn_hi as u64) << 32) | (conn_lo as u64);
                        filetime_to_utc(ft)
                    } else {
                        None
                    };

                let adapter_guids = collect_com_network_connections(&net);
                let macs = sig_macs.get(&guid).cloned().unwrap_or_default();
                let gw = macs
                    .iter()
                    .copied()
                    .find(|m| !m.is_zero())
                    .or_else(|| macs.first().copied());

                merged
                    .entry(guid.clone())
                    .and_modify(|existing| {
                        existing.profile_name = name.clone();
                        if !desc.is_empty() {
                            existing.description = desc.clone();
                        }
                        existing.category = category.clone();
                        existing.connected = connected;
                        existing.connectivity_flags = connectivity_flags;
                        if existing.last_connected.is_none() {
                            existing.last_connected = com_last_conn;
                        }
                        if existing.gateway_mac.is_none() {
                            existing.gateway_mac = gw;
                        }
                        if existing.all_gateway_macs.is_empty() {
                            existing.all_gateway_macs = macs.clone();
                        }
                        existing.adapter_guids = adapter_guids.clone();
                    })
                    .or_insert(NetProfileRecord {
                        profile_name: name,
                        profile_guid: guid,
                        category,
                        last_connected: com_last_conn,
                        gateway_mac: gw,
                        all_gateway_macs: macs,
                        connected,
                        description: desc,
                        connectivity_flags,
                        adapter_guids,
                    });
            }

            Ok(merged.into_values().collect())
        }

        fn set_profile_connection(
            &self,
            target: &ProfileTarget,
            connect: bool,
            dry_run: bool,
        ) -> NetResult<NetProfileActionResult> {
            let _com_guard = ComApartmentGuard::init_multithreaded()?;
            // SAFETY: COM apartment initialized by `_com_guard`.
            let nlm: INetworkListManager = unsafe { CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL) }
                .map_err(|e| NetError::Internal(format!("CoCreateInstance(NetworkListManager) failed: {e}")))?;

            let target_net: INetwork = if let Some(ref pid) = target.profile_id {
                let guid = parse_win32_guid(pid)?;
                // SAFETY: `guid` is a valid `GUID` value passed to `INetworkListManager::GetNetwork`.
                unsafe { nlm.GetNetwork(guid) }
                    .map_err(|_| NetError::HardwareNotFound(format!("network profile '{pid}' not found")))?
            } else {
                let wanted = target.profile_name.as_deref().unwrap_or("");
                // SAFETY: enumerating all networks on active COM apartment.
                let enum_nets = unsafe { nlm.GetNetworks(NLM_ENUM_NETWORK_ALL) }
                    .map_err(|e| NetError::Internal(format!("GetNetworks failed: {e}")))?;
                let mut found: Option<INetwork> = None;
                loop {
                    let mut slot: [Option<INetwork>; 1] = [None];
                    let mut fetched = 0u32;
                    // SAFETY: valid stack buffers for COM `Next`.
                    let res = unsafe { enum_nets.Next(&mut slot, Some(&mut fetched)) };
                    if res.is_err() || fetched == 0 {
                        break;
                    }
                    if let Some(net) = slot[0].take()
                        && let Ok(bstr) = unsafe { net.GetName() }
                        && let Ok(name) = String::try_from(&bstr)
                        && name.eq_ignore_ascii_case(wanted)
                    {
                        found = Some(net);
                        break;
                    }
                }
                found.ok_or_else(|| NetError::HardwareNotFound(format!("network profile '{wanted}' not found")))?
            };

            // SAFETY: `target_net` is a valid COM `INetwork` instance.
            let profile_guid_raw = unsafe { target_net.GetNetworkId() }
                .map_err(|e| NetError::Internal(format!("INetwork::GetNetworkId failed: {e}")))?;
            let profile_guid = guid_to_braced_upper(&profile_guid_raw);
            let profile_name = unsafe { target_net.GetName() }
                .ok()
                .and_then(|b| String::try_from(&b).ok())
                .unwrap_or_else(|| profile_guid.clone());

            // Resolution chain: (1) active INetworkConnection::GetAdapterId -> (2) GetAdaptersAddresses.NetworkGuid -> (3) explicit interface
            let mut luid: Option<NET_LUID_LH> = None;
            let mut explicit_alias: Option<String> = None;

            for adapter_guid_str in collect_com_network_connections(&target_net) {
                if let Ok(aguid) = parse_win32_guid(&adapter_guid_str) {
                    let mut candidate = NET_LUID_LH::default();
                    // SAFETY: `aguid` and `candidate` are valid stack locals.
                    if unsafe { ConvertInterfaceGuidToLuid(&aguid, &mut candidate) } == ERROR_SUCCESS {
                        luid = Some(candidate);
                        break;
                    }
                }
            }

            if luid.is_none() {
                let mut matched_luid: Option<NET_LUID_LH> = None;
                let _ = enumerate_adapters_raw(|item| {
                    if matched_luid.is_none() && item.NetworkGuid == profile_guid_raw {
                        matched_luid = Some(item.Luid);
                    }
                });
                luid = matched_luid;
            }

            if luid.is_none()
                && let Some(ref iface) = target.interface
            {
                let (_g, resolved_luid, alias) = resolve_interface_guid_luid_alias(iface)?;
                luid = Some(resolved_luid);
                explicit_alias = Some(alias);
            }

            let resolved_luid = luid.ok_or_else(|| {
                NetError::NotSupported(format!(
                    "profile '{profile_name}' ({profile_guid}) has no active or cached adapter binding; specify 'interface' explicitly"
                ))
            })?;

            let mut if_index = 0u32;
            // SAFETY: `resolved_luid` and `if_index` are valid stack locals.
            let idx_err = unsafe { ConvertInterfaceLuidToIndex(&resolved_luid, &mut if_index) };
            if idx_err != ERROR_SUCCESS {
                return Err(NetError::Internal(format!(
                    "ConvertInterfaceLuidToIndex failed with Win32 error {}",
                    idx_err.0
                )));
            }

            let adapter_alias = if let Some(a) = explicit_alias {
                a
            } else {
                let mut alias_buf = [0u16; 257];
                // SAFETY: `resolved_luid` is valid and `alias_buf` holds 257 UTF-16 code units.
                if unsafe { ConvertInterfaceLuidToAlias(&resolved_luid, &mut alias_buf) } == ERROR_SUCCESS {
                    let len = alias_buf.iter().position(|&c| c == 0).unwrap_or(alias_buf.len());
                    String::from_utf16_lossy(&alias_buf[..len])
                } else {
                    format!("ifIndex:{if_index}")
                }
            };

            let action = if connect { "connect" } else { "disconnect" }.to_string();
            if dry_run {
                return Ok(NetProfileActionResult {
                    applied: false,
                    dry_run: true,
                    action,
                    profile_guid,
                    profile_name,
                    adapter_index: Some(if_index),
                    adapter_alias,
                    mechanism: "IpHelper::SetIfEntry".to_string(),
                });
            }

            let mut row = MIB_IFROW {
                dwIndex: if_index,
                ..Default::default()
            };
            // SAFETY: `row` is zero-initialized with valid `dwIndex`.
            let get_rc = unsafe { GetIfEntry(&mut row) };
            if get_rc != ERROR_SUCCESS.0 {
                if get_rc == ERROR_ACCESS_DENIED.0 {
                    return Err(NetError::PermissionDenied(
                        "elevation required to inspect/modify interface state".into(),
                    ));
                }
                return Err(NetError::Internal(format!(
                    "GetIfEntry({if_index}) failed with Win32 error {get_rc}"
                )));
            }

            row.dwAdminStatus = if connect {
                MIB_IF_ADMIN_STATUS_UP
            } else {
                MIB_IF_ADMIN_STATUS_DOWN
            };
            // SAFETY: `row` was populated by `GetIfEntry` with updated `dwAdminStatus`.
            let set_rc = unsafe { SetIfEntry(&row) };
            if set_rc == ERROR_SUCCESS.0 {
                return Ok(NetProfileActionResult {
                    applied: true,
                    dry_run: false,
                    action,
                    profile_guid,
                    profile_name,
                    adapter_index: Some(if_index),
                    adapter_alias,
                    mechanism: "IpHelper::SetIfEntry".to_string(),
                });
            }
            if set_rc == ERROR_ACCESS_DENIED.0 {
                return Err(NetError::PermissionDenied(
                    "Administrator elevation required to toggle interface state".into(),
                ));
            }
            if matches!(
                set_rc,
                x if x == ERROR_NOT_SUPPORTED.0 || x == ERROR_INVALID_PARAMETER.0 || x == ERROR_GEN_FAILURE.0
            ) {
                validate_netsh_alias(&adapter_alias)?;
                let admin_arg = if connect { "admin=enabled" } else { "admin=disabled" };
                let output = Command::new("netsh")
                    .args([
                        "interface",
                        "set",
                        "interface",
                        &format!("name={adapter_alias}"),
                        admin_arg,
                    ])
                    .output()
                    .map_err(NetError::Io)?;
                if output.status.success() {
                    return Ok(NetProfileActionResult {
                        applied: true,
                        dry_run: false,
                        action,
                        profile_guid,
                        profile_name,
                        adapter_index: Some(if_index),
                        adapter_alias,
                        mechanism: "netsh".to_string(),
                    });
                }
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                let combined = format!("{stdout} {stderr}").to_ascii_lowercase();
                if combined.contains("elevation")
                    || combined.contains("access is denied")
                    || combined.contains("requires")
                {
                    return Err(NetError::PermissionDenied(format!(
                        "elevation required for netsh interface toggle: {combined}"
                    )));
                }
                return Err(NetError::Internal(format!("netsh failed: {combined}")));
            }

            Err(NetError::Internal(format!(
                "SetIfEntry({if_index}) failed with Win32 error {set_rc}"
            )))
        }
    }
}

#[cfg(not(windows))]
pub mod win32_backend {
    use net2rust_core::{NetError, NetResult};

    use super::{NetProfileActionResult, NetProfileRecord, NetProfilesBackend, ProfileTarget};

    pub struct WindowsNetProfilesBackend;

    impl NetProfilesBackend for WindowsNetProfilesBackend {
        fn list_profiles(&self) -> NetResult<Vec<NetProfileRecord>> {
            Err(NetError::NotSupported(
                "live NetworkList profile enumeration requires Windows".into(),
            ))
        }

        fn set_profile_connection(
            &self,
            _target: &ProfileTarget,
            _connect: bool,
            _dry_run: bool,
        ) -> NetResult<NetProfileActionResult> {
            Err(NetError::NotSupported(
                "live NetworkList connect/disconnect requires Windows".into(),
            ))
        }
    }
}

pub fn build_net_profiles_backend(ctx: &NetContext) -> NetResult<Arc<dyn NetProfilesBackend>> {
    match &ctx.mode {
        ExecutionMode::Offline(cfg) => Ok(Arc::new(MockNetProfilesBackend::from_offline_config(cfg)?)),
        ExecutionMode::Live => Ok(Arc::new(win32_backend::WindowsNetProfilesBackend)),
    }
}

pub struct NetProfilesProvider {
    ctx: NetContext,
    backend: Arc<dyn NetProfilesBackend>,
    schema: TableSchema,
}

impl NetProfilesProvider {
    pub fn new(ctx: NetContext, backend: Arc<dyn NetProfilesBackend>) -> Self {
        Self {
            ctx,
            backend,
            schema: schema(),
        }
    }
}

impl TableProvider for NetProfilesProvider {
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
        let records = self.backend.list_profiles()?;
        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, rec)| {
                let detail = serde_json::to_value(&rec).unwrap_or(serde_json::Value::Null);
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.profile_name),
                        CellValue::Text(rec.profile_guid),
                        CellValue::Text(rec.category),
                        rec.last_connected.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        rec.gateway_mac
                            .map(|m| CellValue::Text(m.to_colon_string()))
                            .unwrap_or(CellValue::Null),
                        CellValue::Bool(rec.connected),
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
    let backend: Arc<dyn NetProfilesBackend> = build_net_profiles_backend(ctx).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "failed to load offline net_profiles fixture; falling back to default mock backend");
        Arc::new(MockNetProfilesBackend::default())
    });
    Arc::new(NetProfilesProvider::new(ctx.clone(), backend))
}
