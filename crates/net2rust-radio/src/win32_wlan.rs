use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::null_mut;

use chrono::Utc;
use net2rust_core::{MacAddr, NetError, NetResult, sanitize_wlan_profile_xml};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BAD_PROFILE, ERROR_BUSY, ERROR_DEVICE_NOT_AVAILABLE, ERROR_DEVICE_NOT_CONNECTED,
    ERROR_GEN_FAILURE, ERROR_INVALID_PARAMETER, ERROR_INVALID_STATE, ERROR_MEDIA_OFFLINE, ERROR_NO_MORE_ITEMS,
    ERROR_NO_SYSTEM_RESOURCES, ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_FOUND, ERROR_NOT_READY, ERROR_NOT_SUPPORTED,
    ERROR_OPERATION_ABORTED, ERROR_REQUEST_ABORTED, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE,
    ERROR_SUCCESS, HANDLE,
};
use windows::Win32::NetworkManagement::WiFi::{
    DOT11_AUTH_ALGO_80211_OPEN, DOT11_AUTH_ALGO_80211_SHARED_KEY, DOT11_AUTH_ALGO_OWE, DOT11_AUTH_ALGO_RSNA,
    DOT11_AUTH_ALGO_RSNA_PSK, DOT11_AUTH_ALGO_WPA, DOT11_AUTH_ALGO_WPA_NONE, DOT11_AUTH_ALGO_WPA_PSK,
    DOT11_AUTH_ALGO_WPA3, DOT11_AUTH_ALGO_WPA3_ENT, DOT11_AUTH_ALGO_WPA3_SAE, DOT11_AUTH_ALGORITHM, DOT11_BSS_TYPE,
    DOT11_CIPHER_ALGO_BIP, DOT11_CIPHER_ALGO_BIP_CMAC_256, DOT11_CIPHER_ALGO_BIP_GMAC_128,
    DOT11_CIPHER_ALGO_BIP_GMAC_256, DOT11_CIPHER_ALGO_CCMP, DOT11_CIPHER_ALGO_CCMP_256, DOT11_CIPHER_ALGO_GCMP,
    DOT11_CIPHER_ALGO_GCMP_256, DOT11_CIPHER_ALGO_NONE, DOT11_CIPHER_ALGO_TKIP, DOT11_CIPHER_ALGO_WEP,
    DOT11_CIPHER_ALGO_WEP40, DOT11_CIPHER_ALGO_WEP104, DOT11_CIPHER_ALGORITHM, DOT11_PHY_TYPE, DOT11_SSID,
    WLAN_API_VERSION, WLAN_AVAILABLE_NETWORK_CONNECTED, WLAN_AVAILABLE_NETWORK_HAS_PROFILE,
    WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES, WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES,
    WLAN_AVAILABLE_NETWORK_LIST, WLAN_BSS_ENTRY, WLAN_BSS_LIST, WLAN_CONNECTION_ATTRIBUTES,
    WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS, WLAN_HOSTED_NETWORK_REASON, WLAN_HOSTED_NETWORK_STATUS,
    WLAN_INTERFACE_INFO_LIST, WLAN_INTERFACE_STATE, WLAN_OPCODE_VALUE_TYPE, WLAN_PROFILE_INFO_LIST, WLAN_STATISTICS,
    WlanCloseHandle, WlanDeleteProfile, WlanEnumInterfaces, WlanFreeMemory, WlanGetAvailableNetworkList,
    WlanGetNetworkBssList, WlanGetProfile, WlanGetProfileList, WlanHostedNetworkForceStop,
    WlanHostedNetworkInitSettings, WlanHostedNetworkQueryProperty, WlanHostedNetworkQueryStatus,
    WlanHostedNetworkSetProperty, WlanHostedNetworkStartUsing, WlanHostedNetworkStopUsing, WlanOpenHandle,
    WlanQueryInterface, WlanReasonCodeToString, WlanScan, WlanSetProfile, WlanSetProfilePosition, dot11_BSS_type_any,
    dot11_BSS_type_independent, dot11_BSS_type_infrastructure, dot11_phy_type_dmg, dot11_phy_type_dsss,
    dot11_phy_type_eht, dot11_phy_type_erp, dot11_phy_type_fhss, dot11_phy_type_he, dot11_phy_type_hrdsss,
    dot11_phy_type_ht, dot11_phy_type_irbaseband, dot11_phy_type_ofdm, dot11_phy_type_vht, wlan_connection_mode_auto,
    wlan_connection_mode_discovery_secure, wlan_connection_mode_discovery_unsecure, wlan_connection_mode_profile,
    wlan_connection_mode_temporary_profile, wlan_hosted_network_active, wlan_hosted_network_idle,
    wlan_hosted_network_opcode_connection_settings, wlan_hosted_network_peer_state_authenticated,
    wlan_hosted_network_reason_elevation_required, wlan_hosted_network_reason_gp_denied,
    wlan_hosted_network_reason_service_unavailable, wlan_hosted_network_reason_success,
    wlan_interface_state_ad_hoc_network_formed, wlan_interface_state_associating, wlan_interface_state_authenticating,
    wlan_interface_state_connected, wlan_interface_state_disconnected, wlan_interface_state_disconnecting,
    wlan_interface_state_discovering, wlan_interface_state_not_ready, wlan_intf_opcode_channel_number,
    wlan_intf_opcode_current_connection, wlan_intf_opcode_rssi, wlan_intf_opcode_statistics,
};
use windows::core::{GUID, HSTRING, PCWSTR, PWSTR};

use crate::backend::{
    HostedNetworkPeer, HostedNetworkStatus, WlanAvailableNetwork, WlanBackend, WlanBssRecord, WlanConnectionRecord,
    WlanInterfaceInfo, WlanProfileRecord, normalize_guid_str,
};
use crate::ie_parser::channel_from_freq_khz;
use crate::wlan_xml;

/// STRICT R4: Always pass 0 to `WlanGetProfile` so plaintext key material is never requested.
pub const WLAN_PROFILE_READ_FLAGS: u32 = 0;

struct WlanClient {
    handle: HANDLE,
}

impl WlanClient {
    fn open() -> NetResult<Self> {
        let mut negotiated = 0u32;
        let mut handle = HANDLE::default();
        let rc = unsafe { WlanOpenHandle(WLAN_API_VERSION, None, &mut negotiated, &mut handle) };
        if rc != ERROR_SUCCESS.0 {
            return Err(map_wlan_error(rc, "WlanOpenHandle"));
        }
        Ok(Self { handle })
    }

    fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for WlanClient {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = WlanCloseHandle(self.handle, None);
            }
        }
    }
}

struct WlanMem<T> {
    ptr: *mut T,
}

impl<T> WlanMem<T> {
    fn from_raw(ptr: *mut T) -> Option<Self> {
        if ptr.is_null() { None } else { Some(Self { ptr }) }
    }

    fn as_ptr(&self) -> *const T {
        self.ptr
    }
}

impl<T> Drop for WlanMem<T> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { WlanFreeMemory(self.ptr as *const c_void) };
        }
    }
}

struct WlanPwstr {
    ptr: PWSTR,
}

impl WlanPwstr {
    fn to_string_lossy(&self) -> String {
        if self.ptr.is_null() {
            return String::new();
        }
        unsafe { self.ptr.to_string().unwrap_or_default() }
    }
}

impl Drop for WlanPwstr {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { WlanFreeMemory(self.ptr.as_ptr() as *const c_void) };
        }
    }
}

pub fn map_wlan_error(code: u32, context: &str) -> NetError {
    if code == ERROR_ACCESS_DENIED.0 {
        return NetError::PermissionDenied(format!(
            "{context}: access denied (Win32 error {code}); check elevation or Windows Location privacy settings"
        ));
    }
    if code == ERROR_SERVICE_NOT_ACTIVE.0 || code == ERROR_SERVICE_DOES_NOT_EXIST.0 {
        return NetError::DriverUnavailable(format!(
            "{context}: WLAN AutoConfig service (wlansvc) unavailable (Win32 error {code})"
        ));
    }
    if code == ERROR_NOT_FOUND.0
        || code == ERROR_DEVICE_NOT_CONNECTED.0
        || code == ERROR_DEVICE_NOT_AVAILABLE.0
        || code == ERROR_NO_MORE_ITEMS.0
    {
        return NetError::HardwareNotFound(format!(
            "{context}: wireless interface or profile not found (Win32 error {code})"
        ));
    }
    if code == ERROR_NOT_SUPPORTED.0 || code == ERROR_INVALID_STATE.0 {
        return NetError::NotSupported(format!(
            "{context}: operation unsupported or invalid interface state (Win32 error {code})"
        ));
    }
    if code == ERROR_NOT_READY.0 || code == ERROR_MEDIA_OFFLINE.0 {
        return NetError::NetworkUnavailable(format!(
            "{context}: wireless radio or media offline (Win32 error {code})"
        ));
    }
    if code == ERROR_INVALID_PARAMETER.0 || code == ERROR_BAD_PROFILE.0 {
        return NetError::InvalidInput(format!("{context}: invalid parameter or profile (Win32 error {code})"));
    }
    if code == ERROR_BUSY.0
        || code == ERROR_GEN_FAILURE.0
        || code == ERROR_NOT_ENOUGH_MEMORY.0
        || code == ERROR_NO_SYSTEM_RESOURCES.0
        || code == ERROR_OPERATION_ABORTED.0
        || code == ERROR_REQUEST_ABORTED.0
    {
        return NetError::DriverUnavailable(format!(
            "{context}: transient WLAN driver or resource error (Win32 error {code})"
        ));
    }
    NetError::Internal(format!("{context}: Win32 WLAN error {code}"))
}

fn reason_code_string(reason_code: u32) -> String {
    if reason_code == 0 {
        return String::new();
    }
    let buf = vec![0u16; 512];
    let rc = unsafe { WlanReasonCodeToString(reason_code, &buf, None) };
    if rc == ERROR_SUCCESS.0 {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    } else {
        format!("reason_code={reason_code}")
    }
}

fn map_wlan_error_with_reason(code: u32, reason: u32, context: &str) -> NetError {
    let base = map_wlan_error(code, context);
    if reason == 0 {
        return base;
    }
    let reason_text = reason_code_string(reason);
    match base {
        NetError::PermissionDenied(m) => NetError::PermissionDenied(format!("{m} [{reason_text}]")),
        NetError::DriverUnavailable(m) => NetError::DriverUnavailable(format!("{m} [{reason_text}]")),
        NetError::HardwareNotFound(m) => NetError::HardwareNotFound(format!("{m} [{reason_text}]")),
        NetError::NetworkUnavailable(m) => NetError::NetworkUnavailable(format!("{m} [{reason_text}]")),
        NetError::InvalidInput(m) => NetError::InvalidInput(format!("{m} [{reason_text}]")),
        NetError::NotSupported(m) => NetError::NotSupported(format!("{m} [{reason_text}]")),
        NetError::Internal(m) => NetError::Internal(format!("{m} [{reason_text}]")),
        other => other,
    }
}

fn guid_to_string(g: &GUID) -> String {
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7]
    )
}

fn parse_guid_str(s: &str) -> NetResult<GUID> {
    let clean = normalize_guid_str(s).replace('-', "");
    if clean.len() != 32 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NetError::InvalidInput(format!("invalid interface GUID: {s}")));
    }
    let data1 = u32::from_str_radix(&clean[0..8], 16).map_err(|e| NetError::InvalidInput(e.to_string()))?;
    let data2 = u16::from_str_radix(&clean[8..12], 16).map_err(|e| NetError::InvalidInput(e.to_string()))?;
    let data3 = u16::from_str_radix(&clean[12..16], 16).map_err(|e| NetError::InvalidInput(e.to_string()))?;
    let mut data4 = [0u8; 8];
    for i in 0..8 {
        data4[i] = u8::from_str_radix(&clean[16 + i * 2..18 + i * 2], 16)
            .map_err(|e| NetError::InvalidInput(e.to_string()))?;
    }
    Ok(GUID::from_values(data1, data2, data3, data4))
}

fn utf16_array_to_string(arr: &[u16]) -> String {
    let len = arr.iter().position(|&c| c == 0).unwrap_or(arr.len());
    String::from_utf16_lossy(&arr[..len])
}

fn dot11_ssid_to_string(ssid: &DOT11_SSID) -> String {
    let len = (ssid.uSSIDLength as usize).min(ssid.ucSSID.len());
    String::from_utf8_lossy(&ssid.ucSSID[..len]).into_owned()
}

fn interface_state_label(state: WLAN_INTERFACE_STATE) -> &'static str {
    if state == wlan_interface_state_not_ready {
        "not_ready"
    } else if state == wlan_interface_state_connected {
        "connected"
    } else if state == wlan_interface_state_ad_hoc_network_formed {
        "ad_hoc_formed"
    } else if state == wlan_interface_state_disconnecting {
        "disconnecting"
    } else if state == wlan_interface_state_disconnected {
        "disconnected"
    } else if state == wlan_interface_state_associating {
        "associating"
    } else if state == wlan_interface_state_discovering {
        "discovering"
    } else if state == wlan_interface_state_authenticating {
        "authenticating"
    } else {
        "unknown"
    }
}

fn bss_type_label(t: DOT11_BSS_TYPE) -> &'static str {
    if t == dot11_BSS_type_infrastructure {
        "Infrastructure"
    } else if t == dot11_BSS_type_independent {
        "Independent"
    } else if t == dot11_BSS_type_any {
        "Any"
    } else {
        "Unknown"
    }
}

fn phy_type_label(p: DOT11_PHY_TYPE) -> &'static str {
    if p == dot11_phy_type_fhss {
        "FHSS (802.11)"
    } else if p == dot11_phy_type_dsss {
        "DSSS (802.11)"
    } else if p == dot11_phy_type_irbaseband {
        "IR Baseband"
    } else if p == dot11_phy_type_ofdm {
        "OFDM (802.11a)"
    } else if p == dot11_phy_type_hrdsss {
        "HRDSSS (802.11b)"
    } else if p == dot11_phy_type_erp {
        "ERP (802.11g)"
    } else if p == dot11_phy_type_ht {
        "HT (802.11n)"
    } else if p == dot11_phy_type_vht {
        "VHT (802.11ac)"
    } else if p == dot11_phy_type_dmg {
        "DMG (802.11ad)"
    } else if p == dot11_phy_type_he {
        "HE (802.11ax)"
    } else if p == dot11_phy_type_eht {
        "EHT (802.11be)"
    } else {
        "Unknown"
    }
}

fn auth_algo_label(a: DOT11_AUTH_ALGORITHM) -> String {
    if a == DOT11_AUTH_ALGO_80211_OPEN {
        "Open".to_string()
    } else if a == DOT11_AUTH_ALGO_80211_SHARED_KEY {
        "Shared Key (WEP)".to_string()
    } else if a == DOT11_AUTH_ALGO_WPA {
        "WPA-Enterprise".to_string()
    } else if a == DOT11_AUTH_ALGO_WPA_PSK {
        "WPA-PSK".to_string()
    } else if a == DOT11_AUTH_ALGO_WPA_NONE {
        "WPA-None".to_string()
    } else if a == DOT11_AUTH_ALGO_RSNA {
        "WPA2-Enterprise".to_string()
    } else if a == DOT11_AUTH_ALGO_RSNA_PSK {
        "WPA2-PSK".to_string()
    } else if a == DOT11_AUTH_ALGO_WPA3 || a == DOT11_AUTH_ALGO_WPA3_ENT {
        "WPA3-Enterprise".to_string()
    } else if a == DOT11_AUTH_ALGO_WPA3_SAE {
        "WPA3-SAE".to_string()
    } else if a == DOT11_AUTH_ALGO_OWE {
        "OWE".to_string()
    } else {
        format!("Auth({})", a.0)
    }
}

fn cipher_algo_label(c: DOT11_CIPHER_ALGORITHM) -> String {
    if c == DOT11_CIPHER_ALGO_NONE {
        "None".to_string()
    } else if c == DOT11_CIPHER_ALGO_WEP40 {
        "WEP-40".to_string()
    } else if c == DOT11_CIPHER_ALGO_TKIP {
        "TKIP".to_string()
    } else if c == DOT11_CIPHER_ALGO_CCMP {
        "CCMP-128".to_string()
    } else if c == DOT11_CIPHER_ALGO_WEP104 {
        "WEP-104".to_string()
    } else if c == DOT11_CIPHER_ALGO_BIP {
        "BIP-CMAC-128".to_string()
    } else if c == DOT11_CIPHER_ALGO_GCMP {
        "GCMP-128".to_string()
    } else if c == DOT11_CIPHER_ALGO_GCMP_256 {
        "GCMP-256".to_string()
    } else if c == DOT11_CIPHER_ALGO_CCMP_256 {
        "CCMP-256".to_string()
    } else if c == DOT11_CIPHER_ALGO_BIP_GMAC_128 {
        "BIP-GMAC-128".to_string()
    } else if c == DOT11_CIPHER_ALGO_BIP_GMAC_256 {
        "BIP-GMAC-256".to_string()
    } else if c == DOT11_CIPHER_ALGO_BIP_CMAC_256 {
        "BIP-CMAC-256".to_string()
    } else if c == DOT11_CIPHER_ALGO_WEP {
        "WEP".to_string()
    } else {
        format!("Cipher({})", c.0)
    }
}

#[derive(Debug, Default)]
pub struct Win32WlanBackend;

impl Win32WlanBackend {
    pub fn new() -> Self {
        Self
    }

    fn enum_interfaces_raw(&self, client: &WlanClient) -> NetResult<Vec<(GUID, WlanInterfaceInfo)>> {
        let mut ptr: *mut WLAN_INTERFACE_INFO_LIST = null_mut();
        let rc = unsafe { WlanEnumInterfaces(client.handle(), None, &mut ptr) };
        if rc != ERROR_SUCCESS.0 {
            return Err(map_wlan_error(rc, "WlanEnumInterfaces"));
        }
        let Some(mem) = WlanMem::from_raw(ptr) else {
            return Ok(Vec::new());
        };
        let list = unsafe { &*mem.as_ptr() };
        let count = list.dwNumberOfItems as usize;
        if count == 0 {
            return Ok(Vec::new());
        }
        let slice = unsafe { std::slice::from_raw_parts(list.InterfaceInfo.as_ptr(), count) };
        let mut out = Vec::with_capacity(count);
        for info in slice {
            let guid = info.InterfaceGuid;
            out.push((
                guid,
                WlanInterfaceInfo {
                    guid: guid_to_string(&guid),
                    description: utf16_array_to_string(&info.strInterfaceDescription),
                    state: interface_state_label(info.isState).to_string(),
                    mac_address: None,
                },
            ));
        }
        Ok(out)
    }
}

impl WlanBackend for Win32WlanBackend {
    fn list_interfaces(&self) -> NetResult<Vec<WlanInterfaceInfo>> {
        let client = WlanClient::open()?;
        let items = self.enum_interfaces_raw(&client)?;
        if items.is_empty() {
            return Err(NetError::HardwareNotFound(
                "no wireless LAN interfaces found".to_string(),
            ));
        }
        Ok(items.into_iter().map(|(_, info)| info).collect())
    }

    fn scan_and_list_bss(&self, trigger_scan: bool) -> NetResult<Vec<WlanBssRecord>> {
        let client = WlanClient::open()?;
        let interfaces = self.enum_interfaces_raw(&client)?;
        if interfaces.is_empty() {
            return Err(NetError::HardwareNotFound(
                "no wireless LAN interfaces found".to_string(),
            ));
        }

        let mut records = Vec::new();
        for (guid, iface) in interfaces {
            if trigger_scan {
                let scan_rc = unsafe { WlanScan(client.handle(), &guid, None, None, None) };
                if scan_rc != ERROR_SUCCESS.0 && scan_rc != ERROR_BUSY.0 {
                    // Best-effort scan; return permission denied immediately if blocked by OS/Location.
                    if scan_rc == ERROR_ACCESS_DENIED.0 {
                        return Err(map_wlan_error(scan_rc, "WlanScan"));
                    }
                }
            }

            let mut bss_ptr: *mut WLAN_BSS_LIST = null_mut();
            let rc = unsafe {
                WlanGetNetworkBssList(
                    client.handle(),
                    &guid,
                    None,
                    dot11_BSS_type_any,
                    false,
                    None,
                    &mut bss_ptr,
                )
            };
            if rc != ERROR_SUCCESS.0 {
                return Err(map_wlan_error(rc, "WlanGetNetworkBssList"));
            }
            let Some(mem) = WlanMem::from_raw(bss_ptr) else {
                continue;
            };
            let list = unsafe { &*mem.as_ptr() };
            let list_start = mem.as_ptr() as usize;
            let Some(list_end) = list_start.checked_add(list.dwTotalSize as usize) else {
                continue;
            };
            let count = list.dwNumberOfItems as usize;
            let entries_base = list.wlanBssEntries.as_ptr();

            for i in 0..count {
                let entry_ptr = unsafe { entries_base.add(i) };
                let entry_addr = entry_ptr as usize;
                let Some(entry_end) = entry_addr.checked_add(size_of::<WLAN_BSS_ENTRY>()) else {
                    break;
                };
                if entry_end > list_end {
                    break;
                }
                let entry = unsafe { &*entry_ptr };

                let raw_ies = if entry.ulIeSize > 0 && (entry.ulIeOffset as usize) >= size_of::<WLAN_BSS_ENTRY>() {
                    if let Some(ie_start) = entry_addr.checked_add(entry.ulIeOffset as usize) {
                        if let Some(ie_end) = ie_start.checked_add(entry.ulIeSize as usize) {
                            if ie_end <= list_end {
                                unsafe { std::slice::from_raw_parts(ie_start as *const u8, entry.ulIeSize as usize) }
                                    .to_vec()
                            } else {
                                Vec::new()
                            }
                        } else {
                            Vec::new()
                        }
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };

                let rate_len = (entry.wlanRateSet.uRateSetLength as usize).min(entry.wlanRateSet.usRateSet.len());
                let rate_set_kbps: Vec<u32> = entry.wlanRateSet.usRateSet[..rate_len]
                    .iter()
                    .map(|&r| u32::from(r & 0x7FFF) * 500)
                    .collect();

                records.push(WlanBssRecord {
                    interface_guid: iface.guid.clone(),
                    interface_name: iface.description.clone(),
                    ssid: dot11_ssid_to_string(&entry.dot11Ssid),
                    bssid: MacAddr::new(entry.dot11Bssid),
                    bss_type: bss_type_label(entry.dot11BssType).to_string(),
                    phy_type: phy_type_label(entry.dot11BssPhyType).to_string(),
                    rssi_dbm: entry.lRssi,
                    signal_pct: entry.uLinkQuality,
                    in_reg_domain: entry.bInRegDomain,
                    beacon_period_tu: entry.usBeaconPeriod,
                    capability_info: entry.usCapabilityInformation,
                    center_freq_khz: entry.ulChCenterFrequency,
                    rate_set_kbps,
                    raw_ies,
                });
            }
        }

        Ok(records)
    }

    fn list_available_networks(&self, trigger_scan: bool) -> NetResult<Vec<WlanAvailableNetwork>> {
        let client = WlanClient::open()?;
        let interfaces = self.enum_interfaces_raw(&client)?;
        if interfaces.is_empty() {
            return Err(NetError::HardwareNotFound(
                "no wireless LAN interfaces found".to_string(),
            ));
        }

        let now = Utc::now();
        let mut out = Vec::new();
        let flags = WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES
            | WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES;

        for (guid, iface) in interfaces {
            if trigger_scan {
                let scan_rc = unsafe { WlanScan(client.handle(), &guid, None, None, None) };
                if scan_rc == ERROR_ACCESS_DENIED.0 {
                    return Err(map_wlan_error(scan_rc, "WlanScan"));
                }
            }

            let mut net_ptr: *mut WLAN_AVAILABLE_NETWORK_LIST = null_mut();
            let rc = unsafe { WlanGetAvailableNetworkList(client.handle(), &guid, flags, None, &mut net_ptr) };
            if rc != ERROR_SUCCESS.0 {
                return Err(map_wlan_error(rc, "WlanGetAvailableNetworkList"));
            }
            let Some(mem) = WlanMem::from_raw(net_ptr) else {
                continue;
            };
            let list = unsafe { &*mem.as_ptr() };
            let count = list.dwNumberOfItems as usize;
            let nets = unsafe { std::slice::from_raw_parts(list.Network.as_ptr(), count) };

            for n in nets {
                let phy_cnt = (n.uNumberOfPhyTypes as usize).min(n.dot11PhyTypes.len());
                let phy_types = n.dot11PhyTypes[..phy_cnt]
                    .iter()
                    .map(|&p| phy_type_label(p).to_string())
                    .collect();

                out.push(WlanAvailableNetwork {
                    interface_guid: iface.guid.clone(),
                    interface_name: iface.description.clone(),
                    profile_name: utf16_array_to_string(&n.strProfileName),
                    ssid: dot11_ssid_to_string(&n.dot11Ssid),
                    bss_type: bss_type_label(n.dot11BssType).to_string(),
                    number_of_bssids: n.uNumberOfBssids,
                    connectable: n.bNetworkConnectable.as_bool(),
                    not_connectable_reason: n.wlanNotConnectableReason,
                    phy_types,
                    signal_quality_pct: n.wlanSignalQuality,
                    security_enabled: n.bSecurityEnabled.as_bool(),
                    default_auth_algo: auth_algo_label(n.dot11DefaultAuthAlgorithm),
                    default_cipher_algo: cipher_algo_label(n.dot11DefaultCipherAlgorithm),
                    connected: (n.dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED) != 0,
                    has_profile: (n.dwFlags & WLAN_AVAILABLE_NETWORK_HAS_PROFILE) != 0,
                    detected_at: now,
                });
            }
        }

        Ok(out)
    }

    fn current_connections(&self) -> NetResult<Vec<WlanConnectionRecord>> {
        let client = WlanClient::open()?;
        let interfaces = self.enum_interfaces_raw(&client)?;
        if interfaces.is_empty() {
            return Err(NetError::HardwareNotFound(
                "no wireless LAN interfaces found".to_string(),
            ));
        }

        let mut out = Vec::new();
        for (guid, iface) in interfaces {
            let mut size = 0u32;
            let mut data_ptr: *mut c_void = null_mut();
            let rc = unsafe {
                WlanQueryInterface(
                    client.handle(),
                    &guid,
                    wlan_intf_opcode_current_connection,
                    None,
                    &mut size,
                    &mut data_ptr,
                    None,
                )
            };
            if rc == ERROR_INVALID_STATE.0 {
                // Adapter disconnected; not a fatal error.
                continue;
            }
            if rc != ERROR_SUCCESS.0 {
                return Err(map_wlan_error(rc, "WlanQueryInterface(current_connection)"));
            }
            let Some(mem) = WlanMem::from_raw(data_ptr as *mut WLAN_CONNECTION_ATTRIBUTES) else {
                continue;
            };
            if (size as usize) < size_of::<WLAN_CONNECTION_ATTRIBUTES>() {
                continue;
            }
            let attrs = unsafe { &*mem.as_ptr() };

            let mut ch_size = 0u32;
            let mut ch_ptr: *mut c_void = null_mut();
            let channel = if unsafe {
                WlanQueryInterface(
                    client.handle(),
                    &guid,
                    wlan_intf_opcode_channel_number,
                    None,
                    &mut ch_size,
                    &mut ch_ptr,
                    None,
                )
            } == ERROR_SUCCESS.0
            {
                WlanMem::from_raw(ch_ptr as *mut u32)
                    .filter(|_| (ch_size as usize) >= size_of::<u32>())
                    .map(|m| unsafe { *m.as_ptr() })
                    .unwrap_or(0)
            } else {
                0
            };

            let mut rssi_size = 0u32;
            let mut rssi_ptr: *mut c_void = null_mut();
            let rssi_dbm = if unsafe {
                WlanQueryInterface(
                    client.handle(),
                    &guid,
                    wlan_intf_opcode_rssi,
                    None,
                    &mut rssi_size,
                    &mut rssi_ptr,
                    None,
                )
            } == ERROR_SUCCESS.0
            {
                WlanMem::from_raw(rssi_ptr as *mut i32)
                    .filter(|_| (rssi_size as usize) >= size_of::<i32>())
                    .map(|m| unsafe { *m.as_ptr() })
            } else {
                None
            };

            let mut stat_size = 0u32;
            let mut stat_ptr: *mut c_void = null_mut();
            let (tx_packets, rx_packets) = if unsafe {
                WlanQueryInterface(
                    client.handle(),
                    &guid,
                    wlan_intf_opcode_statistics,
                    None,
                    &mut stat_size,
                    &mut stat_ptr,
                    None,
                )
            } == ERROR_SUCCESS.0
            {
                WlanMem::from_raw(stat_ptr as *mut WLAN_STATISTICS)
                    .filter(|_| (stat_size as usize) >= size_of::<WLAN_STATISTICS>())
                    .map(|m| {
                        let st = unsafe { &*m.as_ptr() };
                        (
                            Some(st.MacUcastCounters.ullTransmittedFrameCount),
                            Some(st.MacUcastCounters.ullReceivedFrameCount),
                        )
                    })
                    .unwrap_or((None, None))
            } else {
                (None, None)
            };

            let mode_label = if attrs.wlanConnectionMode == wlan_connection_mode_profile {
                "Profile"
            } else if attrs.wlanConnectionMode == wlan_connection_mode_temporary_profile {
                "TemporaryProfile"
            } else if attrs.wlanConnectionMode == wlan_connection_mode_discovery_secure {
                "DiscoverySecure"
            } else if attrs.wlanConnectionMode == wlan_connection_mode_discovery_unsecure {
                "DiscoveryUnsecure"
            } else if attrs.wlanConnectionMode == wlan_connection_mode_auto {
                "Auto"
            } else {
                "Unknown"
            };

            let center_freq_mhz = crate::ie_parser::freq_mhz_from_channel(channel, false).unwrap_or(0);

            out.push(WlanConnectionRecord {
                interface_guid: iface.guid,
                interface_name: iface.description,
                state: interface_state_label(attrs.isState).to_string(),
                connection_mode: mode_label.to_string(),
                profile_name: utf16_array_to_string(&attrs.strProfileName),
                ssid: dot11_ssid_to_string(&attrs.wlanAssociationAttributes.dot11Ssid),
                bssid: MacAddr::new(attrs.wlanAssociationAttributes.dot11Bssid),
                bss_type: bss_type_label(attrs.wlanAssociationAttributes.dot11BssType).to_string(),
                phy_type: phy_type_label(attrs.wlanAssociationAttributes.dot11PhyType).to_string(),
                channel,
                center_freq_mhz,
                rx_rate_kbps: attrs.wlanAssociationAttributes.ulRxRate,
                tx_rate_kbps: attrs.wlanAssociationAttributes.ulTxRate,
                signal_quality_pct: attrs.wlanAssociationAttributes.wlanSignalQuality,
                rssi_dbm,
                security_enabled: attrs.wlanSecurityAttributes.bSecurityEnabled.as_bool(),
                one_x_enabled: attrs.wlanSecurityAttributes.bOneXEnabled.as_bool(),
                auth_algo: auth_algo_label(attrs.wlanSecurityAttributes.dot11AuthAlgorithm),
                cipher_algo: cipher_algo_label(attrs.wlanSecurityAttributes.dot11CipherAlgorithm),
                tx_packets,
                rx_packets,
            });
        }

        Ok(out)
    }

    fn list_profiles(&self) -> NetResult<Vec<WlanProfileRecord>> {
        let client = WlanClient::open()?;
        let interfaces = self.enum_interfaces_raw(&client)?;
        if interfaces.is_empty() {
            return Err(NetError::HardwareNotFound(
                "no wireless LAN interfaces found".to_string(),
            ));
        }

        let mut out = Vec::new();
        for (guid, iface) in interfaces {
            let mut list_ptr: *mut WLAN_PROFILE_INFO_LIST = null_mut();
            let rc = unsafe { WlanGetProfileList(client.handle(), &guid, None, &mut list_ptr) };
            if rc != ERROR_SUCCESS.0 {
                return Err(map_wlan_error(rc, "WlanGetProfileList"));
            }
            let Some(mem) = WlanMem::from_raw(list_ptr) else {
                continue;
            };
            let list = unsafe { &*mem.as_ptr() };
            let count = list.dwNumberOfItems as usize;
            let items = unsafe { std::slice::from_raw_parts(list.ProfileInfo.as_ptr(), count) };

            for (pos, pinfo) in items.iter().enumerate() {
                let pname = utf16_array_to_string(&pinfo.strProfileName);
                let pname_w = HSTRING::from(pname.as_str());
                let mut xml_ptr = PWSTR::null();
                // STRICT R4: flags initialized to 0 (WLAN_PROFILE_READ_FLAGS), never requesting plaintext keys.
                let mut flags = WLAN_PROFILE_READ_FLAGS;
                let get_rc = unsafe {
                    WlanGetProfile(
                        client.handle(),
                        &guid,
                        &pname_w,
                        None,
                        &mut xml_ptr,
                        Some(&mut flags),
                        None,
                    )
                };
                if get_rc != ERROR_SUCCESS.0 {
                    continue;
                }
                let xml_guard = WlanPwstr { ptr: xml_ptr };
                let raw_xml = xml_guard.to_string_lossy();
                let sanitized_xml = sanitize_wlan_profile_xml(&raw_xml);

                out.push(WlanProfileRecord {
                    interface_guid: iface.guid.clone(),
                    interface_name: iface.description.clone(),
                    profile_name: pname,
                    flags: pinfo.dwFlags,
                    position: pos as u32,
                    sanitized_xml,
                });
            }
        }

        Ok(out)
    }

    fn set_profile_position(&self, interface_guid: &str, profile_name: &str, position: u32) -> NetResult<()> {
        let client = WlanClient::open()?;
        let guid = parse_guid_str(interface_guid)?;
        let pname_w = HSTRING::from(profile_name);
        let rc = unsafe { WlanSetProfilePosition(client.handle(), &guid, &pname_w, position, None) };
        if rc != ERROR_SUCCESS.0 {
            return Err(map_wlan_error(rc, "WlanSetProfilePosition"));
        }
        Ok(())
    }

    fn delete_profile(&self, interface_guid: &str, profile_name: &str) -> NetResult<()> {
        let client = WlanClient::open()?;
        let guid = parse_guid_str(interface_guid)?;
        let pname_w = HSTRING::from(profile_name);
        let rc = unsafe { WlanDeleteProfile(client.handle(), &guid, &pname_w, None) };
        if rc != ERROR_SUCCESS.0 {
            return Err(map_wlan_error(rc, "WlanDeleteProfile"));
        }
        Ok(())
    }

    fn set_profile_auto_connect(
        &self,
        interface_guid: &str,
        profile_name: &str,
        auto_connect: bool,
    ) -> NetResult<String> {
        let client = WlanClient::open()?;
        let guid = parse_guid_str(interface_guid)?;
        let pname_w = HSTRING::from(profile_name);

        let mut xml_ptr = PWSTR::null();
        // STRICT R4: flags initialized to 0 (WLAN_PROFILE_READ_FLAGS), never requesting plaintext keys.
        let mut scope_flags = WLAN_PROFILE_READ_FLAGS;
        let rc = unsafe {
            WlanGetProfile(
                client.handle(),
                &guid,
                &pname_w,
                None,
                &mut xml_ptr,
                Some(&mut scope_flags),
                None,
            )
        };
        if rc != ERROR_SUCCESS.0 {
            return Err(map_wlan_error(rc, "WlanGetProfile"));
        }
        let xml_guard = WlanPwstr { ptr: xml_ptr };
        let transient_xml = xml_guard.to_string_lossy();
        drop(xml_guard);

        let updated_transient =
            wlan_xml::patch_connection_mode_transient_for_set_profile(&transient_xml, auto_connect)?;
        let sanitized = sanitize_wlan_profile_xml(&updated_transient);

        let updated_w = HSTRING::from(updated_transient.as_str());
        let mut reason_code = 0u32;
        let set_rc = unsafe {
            WlanSetProfile(
                client.handle(),
                &guid,
                scope_flags,
                &updated_w,
                PCWSTR::null(),
                true,
                None,
                &mut reason_code,
            )
        };
        drop(updated_transient);

        if set_rc != ERROR_SUCCESS.0 {
            return Err(map_wlan_error_with_reason(set_rc, reason_code, "WlanSetProfile"));
        }

        Ok(sanitized)
    }

    fn hosted_network_status(&self) -> NetResult<HostedNetworkStatus> {
        let client = WlanClient::open()?;
        let mut status_ptr: *mut WLAN_HOSTED_NETWORK_STATUS = null_mut();
        let rc = unsafe { WlanHostedNetworkQueryStatus(client.handle(), &mut status_ptr, None) };
        if rc != ERROR_SUCCESS.0 {
            return Err(map_wlan_error(rc, "WlanHostedNetworkQueryStatus"));
        }
        let Some(mem) = WlanMem::from_raw(status_ptr) else {
            return Err(NetError::NotSupported(
                "WlanHostedNetworkQueryStatus returned null".to_string(),
            ));
        };
        let status = unsafe { &*mem.as_ptr() };

        let state_str = if status.HostedNetworkState == wlan_hosted_network_active {
            "Active"
        } else if status.HostedNetworkState == wlan_hosted_network_idle {
            "Idle"
        } else {
            "Unavailable"
        };

        // Query connection settings (SSID & max peers). Never query secondary key (R4).
        let mut prop_size = 0u32;
        let mut prop_ptr: *mut c_void = null_mut();
        let mut val_type = WLAN_OPCODE_VALUE_TYPE::default();
        let (ssid, max_peers) = if unsafe {
            WlanHostedNetworkQueryProperty(
                client.handle(),
                wlan_hosted_network_opcode_connection_settings,
                &mut prop_size,
                &mut prop_ptr,
                &mut val_type,
                None,
            )
        } == ERROR_SUCCESS.0
        {
            WlanMem::from_raw(prop_ptr as *mut WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS)
                .filter(|_| (prop_size as usize) >= size_of::<WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS>())
                .map(|m| {
                    let cs = unsafe { &*m.as_ptr() };
                    (Some(dot11_ssid_to_string(&cs.hostedNetworkSSID)), cs.dwMaxNumberOfPeers)
                })
                .unwrap_or((None, 0))
        } else {
            (None, 0)
        };

        let peer_count = status.dwNumberOfPeers as usize;
        let peers_slice = if peer_count > 0 {
            unsafe { std::slice::from_raw_parts(status.PeerList.as_ptr(), peer_count) }
        } else {
            &[]
        };
        let peers = peers_slice
            .iter()
            .map(|p| HostedNetworkPeer {
                mac_address: MacAddr::new(p.PeerMacAddress),
                auth_state: if p.PeerAuthState == wlan_hosted_network_peer_state_authenticated {
                    "Authenticated".to_string()
                } else {
                    "Invalid".to_string()
                },
            })
            .collect();

        let bssid = if status.wlanHostedNetworkBSSID == [0; 6] {
            None
        } else {
            Some(MacAddr::new(status.wlanHostedNetworkBSSID))
        };

        let adapter_guid = if status.IPDeviceID == GUID::zeroed() {
            None
        } else {
            Some(guid_to_string(&status.IPDeviceID))
        };

        let _ = channel_from_freq_khz(status.ulChannelFrequency);

        Ok(HostedNetworkStatus {
            state: state_str.to_string(),
            adapter_guid,
            bssid,
            ssid,
            max_peers,
            active_peers: status.dwNumberOfPeers,
            phy_type: Some(phy_type_label(status.dot11PhyType).to_string()),
            channel_freq_khz: if status.ulChannelFrequency > 0 {
                Some(status.ulChannelFrequency)
            } else {
                None
            },
            peers,
        })
    }

    fn start_hosted_network(&self, ssid: Option<&str>, max_peers: Option<u32>) -> NetResult<HostedNetworkStatus> {
        let client = WlanClient::open()?;

        if ssid.is_some() || max_peers.is_some() {
            let mut settings = WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS::default();
            let mut prop_size = 0u32;
            let mut prop_ptr: *mut c_void = null_mut();
            let mut val_type = WLAN_OPCODE_VALUE_TYPE::default();
            if unsafe {
                WlanHostedNetworkQueryProperty(
                    client.handle(),
                    wlan_hosted_network_opcode_connection_settings,
                    &mut prop_size,
                    &mut prop_ptr,
                    &mut val_type,
                    None,
                )
            } == ERROR_SUCCESS.0
                && let Some(m) = WlanMem::from_raw(prop_ptr as *mut WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS)
                    .filter(|_| (prop_size as usize) >= size_of::<WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS>())
            {
                settings = unsafe { *m.as_ptr() };
            }

            if let Some(s) = ssid {
                let bytes = s.as_bytes();
                if bytes.is_empty() || bytes.len() > 32 {
                    return Err(NetError::InvalidInput(
                        "hosted network SSID must be 1..=32 bytes".to_string(),
                    ));
                }
                settings.hostedNetworkSSID.uSSIDLength = bytes.len() as u32;
                settings.hostedNetworkSSID.ucSSID = [0u8; 32];
                settings.hostedNetworkSSID.ucSSID[..bytes.len()].copy_from_slice(bytes);
            }
            if let Some(mp) = max_peers {
                if mp == 0 || mp > 100 {
                    return Err(NetError::InvalidInput(
                        "hosted network max_peers must be 1..=100".to_string(),
                    ));
                }
                settings.dwMaxNumberOfPeers = mp;
            } else if settings.dwMaxNumberOfPeers == 0 {
                settings.dwMaxNumberOfPeers = 10;
            }

            let mut fail_reason = WLAN_HOSTED_NETWORK_REASON::default();
            let prop_rc = unsafe {
                WlanHostedNetworkSetProperty(
                    client.handle(),
                    wlan_hosted_network_opcode_connection_settings,
                    size_of::<WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS>() as u32,
                    &settings as *const _ as *const c_void,
                    Some(&mut fail_reason),
                    None,
                )
            };
            if prop_rc != ERROR_SUCCESS.0 {
                return Err(map_hosted_reason(prop_rc, fail_reason, "WlanHostedNetworkSetProperty"));
            }
        }

        let mut init_reason = WLAN_HOSTED_NETWORK_REASON::default();
        let init_rc = unsafe { WlanHostedNetworkInitSettings(client.handle(), Some(&mut init_reason), None) };
        if init_rc != ERROR_SUCCESS.0 {
            return Err(map_hosted_reason(init_rc, init_reason, "WlanHostedNetworkInitSettings"));
        }

        let mut start_reason = WLAN_HOSTED_NETWORK_REASON::default();
        let start_rc = unsafe { WlanHostedNetworkStartUsing(client.handle(), Some(&mut start_reason), None) };
        if start_rc != ERROR_SUCCESS.0 {
            return Err(map_hosted_reason(start_rc, start_reason, "WlanHostedNetworkStartUsing"));
        }

        self.hosted_network_status()
    }

    fn stop_hosted_network(&self, force: bool) -> NetResult<HostedNetworkStatus> {
        let client = WlanClient::open()?;
        let mut reason = WLAN_HOSTED_NETWORK_REASON::default();
        let rc = unsafe {
            if force {
                WlanHostedNetworkForceStop(client.handle(), Some(&mut reason), None)
            } else {
                WlanHostedNetworkStopUsing(client.handle(), Some(&mut reason), None)
            }
        };
        if rc != ERROR_SUCCESS.0 {
            return Err(map_hosted_reason(rc, reason, "WlanHostedNetworkStopUsing"));
        }
        self.hosted_network_status()
    }
}

fn map_hosted_reason(code: u32, reason: WLAN_HOSTED_NETWORK_REASON, context: &str) -> NetError {
    if reason == wlan_hosted_network_reason_elevation_required {
        return NetError::PermissionDenied(format!("{context}: elevation required for hosted network"));
    }
    if reason == wlan_hosted_network_reason_gp_denied {
        return NetError::PermissionDenied(format!("{context}: hosted network blocked by Group Policy"));
    }
    if reason == wlan_hosted_network_reason_service_unavailable {
        return NetError::DriverUnavailable(format!("{context}: hosted network service unavailable"));
    }
    if reason != wlan_hosted_network_reason_success {
        let base = map_wlan_error(code, context);
        return match base {
            NetError::Internal(m) => NetError::NotSupported(format!("{m} (hosted_reason={})", reason.0)),
            other => other,
        };
    }
    map_wlan_error(code, context)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_win32_wlan_error_mapping() {
        assert!(matches!(
            map_wlan_error(ERROR_ACCESS_DENIED.0, "test"),
            NetError::PermissionDenied(_)
        ));
        assert!(matches!(
            map_wlan_error(ERROR_SERVICE_NOT_ACTIVE.0, "test"),
            NetError::DriverUnavailable(_)
        ));
        assert!(matches!(
            map_wlan_error(ERROR_SERVICE_DOES_NOT_EXIST.0, "test"),
            NetError::DriverUnavailable(_)
        ));
        assert!(matches!(
            map_wlan_error(ERROR_NOT_FOUND.0, "test"),
            NetError::HardwareNotFound(_)
        ));
        assert!(matches!(
            map_wlan_error(ERROR_DEVICE_NOT_CONNECTED.0, "test"),
            NetError::HardwareNotFound(_)
        ));
        assert!(matches!(
            map_wlan_error(ERROR_NOT_SUPPORTED.0, "test"),
            NetError::NotSupported(_)
        ));
        assert!(matches!(
            map_wlan_error(ERROR_MEDIA_OFFLINE.0, "test"),
            NetError::NetworkUnavailable(_)
        ));
        assert!(matches!(
            map_wlan_error(ERROR_BAD_PROFILE.0, "test"),
            NetError::InvalidInput(_)
        ));
    }

    #[test]
    fn test_r4_wlan_profile_read_flags_zero() {
        assert_eq!(WLAN_PROFILE_READ_FLAGS, 0);
        assert_eq!(WLAN_PROFILE_READ_FLAGS & net2rust_core::FORBIDDEN_WLAN_PROFILE_FLAG, 0);
    }
}
