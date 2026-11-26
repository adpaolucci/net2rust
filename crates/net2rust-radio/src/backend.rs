use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use net2rust_core::{MacAddr, NetError, NetResult, OfflineConfig, sanitize_wlan_profile_xml};
use serde::{Deserialize, Serialize};

use crate::fixtures;
use crate::wlan_xml;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WlanInterfaceInfo {
    pub guid: String,
    pub description: String,
    pub state: String,
    pub mac_address: Option<MacAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WlanBssRecord {
    pub interface_guid: String,
    pub interface_name: String,
    pub ssid: String,
    pub bssid: MacAddr,
    pub bss_type: String,
    pub phy_type: String,
    pub rssi_dbm: i32,
    pub signal_pct: u32,
    pub in_reg_domain: bool,
    pub beacon_period_tu: u16,
    pub capability_info: u16,
    pub center_freq_khz: u32,
    pub rate_set_kbps: Vec<u32>,
    pub raw_ies: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WlanAvailableNetwork {
    pub interface_guid: String,
    pub interface_name: String,
    pub profile_name: String,
    pub ssid: String,
    pub bss_type: String,
    pub number_of_bssids: u32,
    pub connectable: bool,
    pub not_connectable_reason: u32,
    pub phy_types: Vec<String>,
    pub signal_quality_pct: u32,
    pub security_enabled: bool,
    pub default_auth_algo: String,
    pub default_cipher_algo: String,
    pub connected: bool,
    pub has_profile: bool,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WlanConnectionRecord {
    pub interface_guid: String,
    pub interface_name: String,
    pub state: String,
    pub connection_mode: String,
    pub profile_name: String,
    pub ssid: String,
    pub bssid: MacAddr,
    pub bss_type: String,
    pub phy_type: String,
    pub channel: u32,
    pub center_freq_mhz: u32,
    pub rx_rate_kbps: u32,
    pub tx_rate_kbps: u32,
    pub signal_quality_pct: u32,
    pub rssi_dbm: Option<i32>,
    pub security_enabled: bool,
    pub one_x_enabled: bool,
    pub auth_algo: String,
    pub cipher_algo: String,
    pub tx_packets: Option<u64>,
    pub rx_packets: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WlanProfileRecord {
    pub interface_guid: String,
    pub interface_name: String,
    pub profile_name: String,
    pub flags: u32,
    pub position: u32,
    pub sanitized_xml: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedNetworkPeer {
    pub mac_address: MacAddr,
    pub auth_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedNetworkStatus {
    pub state: String,
    pub adapter_guid: Option<String>,
    pub bssid: Option<MacAddr>,
    pub ssid: Option<String>,
    pub max_peers: u32,
    pub active_peers: u32,
    pub phy_type: Option<String>,
    pub channel_freq_khz: Option<u32>,
    pub peers: Vec<HostedNetworkPeer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BluetoothRadioInfo {
    pub name: String,
    pub address: MacAddr,
    pub class_of_device: u32,
    pub lmp_subversion: u16,
    pub manufacturer_id: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BluetoothClassicDevice {
    pub name: String,
    pub address: MacAddr,
    pub class_of_device: u32,
    pub connected: bool,
    pub remembered: bool,
    pub authenticated: bool,
    pub last_seen: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleAdvertisementRecord {
    pub address: MacAddr,
    pub address_type: String,
    pub advertisement_type: String,
    pub rssi_dbm: i16,
    pub tx_power_dbm: Option<i16>,
    pub local_name: String,
    pub flags: Option<u8>,
    pub service_uuids: Vec<String>,
    pub manufacturer_data: Vec<(u16, Vec<u8>)>,
    pub data_sections: Vec<(u8, Vec<u8>)>,
    pub last_seen: DateTime<Utc>,
}

pub trait WlanBackend: Send + Sync {
    fn list_interfaces(&self) -> NetResult<Vec<WlanInterfaceInfo>>;
    fn scan_and_list_bss(&self, trigger_scan: bool) -> NetResult<Vec<WlanBssRecord>>;
    fn list_available_networks(&self, trigger_scan: bool) -> NetResult<Vec<WlanAvailableNetwork>>;
    fn current_connections(&self) -> NetResult<Vec<WlanConnectionRecord>>;
    fn list_profiles(&self) -> NetResult<Vec<WlanProfileRecord>>;
    fn set_profile_position(&self, interface_guid: &str, profile_name: &str, position: u32) -> NetResult<()>;
    fn delete_profile(&self, interface_guid: &str, profile_name: &str) -> NetResult<()>;
    fn set_profile_auto_connect(
        &self,
        interface_guid: &str,
        profile_name: &str,
        auto_connect: bool,
    ) -> NetResult<String>;
    fn hosted_network_status(&self) -> NetResult<HostedNetworkStatus>;
    fn start_hosted_network(&self, ssid: Option<&str>, max_peers: Option<u32>) -> NetResult<HostedNetworkStatus>;
    fn stop_hosted_network(&self, force: bool) -> NetResult<HostedNetworkStatus>;
}

pub trait BluetoothBackend: Send + Sync {
    fn list_radios(&self) -> NetResult<Vec<BluetoothRadioInfo>>;
    fn list_classic_devices(&self) -> NetResult<Vec<BluetoothClassicDevice>>;
    fn offline_log_snapshots(&self) -> Option<Vec<(DateTime<Utc>, Vec<BluetoothClassicDevice>)>> {
        None
    }
    fn scan_ble_advertisements(&self, duration: Duration) -> NetResult<Vec<BleAdvertisementRecord>>;
}

#[derive(Debug, Default)]
pub struct UnsupportedRadioBackend {
    pub reason: String,
}

impl UnsupportedRadioBackend {
    pub fn new(reason: impl Into<String>) -> Self {
        Self { reason: reason.into() }
    }

    fn err<T>(&self) -> NetResult<T> {
        Err(NetError::NotSupported(self.reason.clone()))
    }
}

impl WlanBackend for UnsupportedRadioBackend {
    fn list_interfaces(&self) -> NetResult<Vec<WlanInterfaceInfo>> {
        self.err()
    }

    fn scan_and_list_bss(&self, _trigger_scan: bool) -> NetResult<Vec<WlanBssRecord>> {
        self.err()
    }

    fn list_available_networks(&self, _trigger_scan: bool) -> NetResult<Vec<WlanAvailableNetwork>> {
        self.err()
    }

    fn current_connections(&self) -> NetResult<Vec<WlanConnectionRecord>> {
        self.err()
    }

    fn list_profiles(&self) -> NetResult<Vec<WlanProfileRecord>> {
        self.err()
    }

    fn set_profile_position(&self, _interface_guid: &str, _profile_name: &str, _position: u32) -> NetResult<()> {
        self.err()
    }

    fn delete_profile(&self, _interface_guid: &str, _profile_name: &str) -> NetResult<()> {
        self.err()
    }

    fn set_profile_auto_connect(
        &self,
        _interface_guid: &str,
        _profile_name: &str,
        _auto_connect: bool,
    ) -> NetResult<String> {
        self.err()
    }

    fn hosted_network_status(&self) -> NetResult<HostedNetworkStatus> {
        self.err()
    }

    fn start_hosted_network(&self, _ssid: Option<&str>, _max_peers: Option<u32>) -> NetResult<HostedNetworkStatus> {
        self.err()
    }

    fn stop_hosted_network(&self, _force: bool) -> NetResult<HostedNetworkStatus> {
        self.err()
    }
}

impl BluetoothBackend for UnsupportedRadioBackend {
    fn list_radios(&self) -> NetResult<Vec<BluetoothRadioInfo>> {
        self.err()
    }

    fn list_classic_devices(&self) -> NetResult<Vec<BluetoothClassicDevice>> {
        self.err()
    }

    fn scan_ble_advertisements(&self, _duration: Duration) -> NetResult<Vec<BleAdvertisementRecord>> {
        self.err()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MockFaultMode {
    #[default]
    None,
    HardwareAbsent,
    PermissionDenied,
    DriverUnavailable,
    NotSupported,
}

impl MockFaultMode {
    pub fn from_scenario(scenario: Option<&str>) -> Self {
        match scenario.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
            Some("hardware_absent") | Some("no_hardware") => Self::HardwareAbsent,
            Some("permission_denied") | Some("denied") => Self::PermissionDenied,
            Some("driver_unavailable") | Some("no_driver") => Self::DriverUnavailable,
            Some("not_supported") | Some("unsupported") => Self::NotSupported,
            _ => Self::None,
        }
    }

    fn check(&self, context: &str) -> NetResult<()> {
        match self {
            Self::None => Ok(()),
            Self::HardwareAbsent => Err(NetError::HardwareNotFound(format!("{context}: mock hardware absent"))),
            Self::PermissionDenied => Err(NetError::PermissionDenied(format!("{context}: mock permission denied"))),
            Self::DriverUnavailable => Err(NetError::DriverUnavailable(format!(
                "{context}: mock driver unavailable"
            ))),
            Self::NotSupported => Err(NetError::NotSupported(format!("{context}: mock operation unsupported"))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineRadioFixtures {
    pub interfaces: Vec<WlanInterfaceInfo>,
    pub bss_list: Vec<WlanBssRecord>,
    pub available_networks: Vec<WlanAvailableNetwork>,
    pub connections: Vec<WlanConnectionRecord>,
    pub profiles: Vec<WlanProfileRecord>,
    pub hosted_network: HostedNetworkStatus,
    pub bt_radios: Vec<BluetoothRadioInfo>,
    pub bt_devices: Vec<BluetoothClassicDevice>,
    pub bt_log_snapshots: Vec<(DateTime<Utc>, Vec<BluetoothClassicDevice>)>,
    pub ble_advertisements: Vec<BleAdvertisementRecord>,
}

#[derive(Debug)]
struct OfflineRadioState {
    fault: MockFaultMode,
    fixtures: OfflineRadioFixtures,
    mutation_log: Vec<String>,
}

#[derive(Debug)]
pub struct OfflineMockRadioBackend {
    state: Mutex<OfflineRadioState>,
}

impl Default for OfflineMockRadioBackend {
    fn default() -> Self {
        Self::new(OfflineRadioFixtures::default_synthetic())
    }
}

impl OfflineMockRadioBackend {
    pub fn new(mut fixtures: OfflineRadioFixtures) -> Self {
        for profile in &mut fixtures.profiles {
            profile.sanitized_xml = sanitize_wlan_profile_xml(&profile.sanitized_xml);
        }
        Self {
            state: Mutex::new(OfflineRadioState {
                fault: MockFaultMode::None,
                fixtures,
                mutation_log: Vec::new(),
            }),
        }
    }

    pub fn from_config(config: &OfflineConfig) -> Self {
        let scenario = config.scenario.as_deref();
        let fault = MockFaultMode::from_scenario(scenario);
        let mut fixtures = if scenario == Some("empty") {
            OfflineRadioFixtures::empty()
        } else {
            OfflineRadioFixtures::default_synthetic()
        };

        if let Some(dir) = &config.fixture_dir {
            let candidate = dir.join("radio_fixtures.json");
            if candidate.exists()
                && let Ok(raw) = std::fs::read_to_string(&candidate)
                && let Ok(loaded) = serde_json::from_str::<OfflineRadioFixtures>(&raw)
            {
                fixtures = loaded;
            }
        }

        for profile in &mut fixtures.profiles {
            profile.sanitized_xml = sanitize_wlan_profile_xml(&profile.sanitized_xml);
        }

        Self {
            state: Mutex::new(OfflineRadioState {
                fault,
                fixtures,
                mutation_log: Vec::new(),
            }),
        }
    }

    pub fn set_fault_mode(&self, fault: MockFaultMode) {
        if let Ok(mut guard) = self.state.lock() {
            guard.fault = fault;
        }
    }

    pub fn mutation_log(&self) -> Vec<String> {
        self.state.lock().map(|g| g.mutation_log.clone()).unwrap_or_default()
    }

    pub fn push_bt_devices(&self, devices: Vec<BluetoothClassicDevice>) {
        if let Ok(mut guard) = self.state.lock() {
            guard.fixtures.bt_devices = devices;
        }
    }

    fn lock_state(&self) -> NetResult<std::sync::MutexGuard<'_, OfflineRadioState>> {
        self.state
            .lock()
            .map_err(|_| NetError::Internal("offline radio state lock poisoned".to_string()))
    }
}

impl WlanBackend for OfflineMockRadioBackend {
    fn list_interfaces(&self) -> NetResult<Vec<WlanInterfaceInfo>> {
        let guard = self.lock_state()?;
        guard.fault.check("list_interfaces")?;
        Ok(guard.fixtures.interfaces.clone())
    }

    fn scan_and_list_bss(&self, _trigger_scan: bool) -> NetResult<Vec<WlanBssRecord>> {
        let guard = self.lock_state()?;
        guard.fault.check("scan_and_list_bss")?;
        Ok(guard.fixtures.bss_list.clone())
    }

    fn list_available_networks(&self, _trigger_scan: bool) -> NetResult<Vec<WlanAvailableNetwork>> {
        let guard = self.lock_state()?;
        guard.fault.check("list_available_networks")?;
        Ok(guard.fixtures.available_networks.clone())
    }

    fn current_connections(&self) -> NetResult<Vec<WlanConnectionRecord>> {
        let guard = self.lock_state()?;
        guard.fault.check("current_connections")?;
        Ok(guard.fixtures.connections.clone())
    }

    fn list_profiles(&self) -> NetResult<Vec<WlanProfileRecord>> {
        let guard = self.lock_state()?;
        guard.fault.check("list_profiles")?;
        Ok(guard
            .fixtures
            .profiles
            .iter()
            .cloned()
            .map(|mut p| {
                p.sanitized_xml = sanitize_wlan_profile_xml(&p.sanitized_xml);
                p
            })
            .collect())
    }

    fn set_profile_position(&self, interface_guid: &str, profile_name: &str, position: u32) -> NetResult<()> {
        let mut guard = self.lock_state()?;
        guard.fault.check("set_profile_position")?;

        let mut matching_indices: Vec<usize> = guard
            .fixtures
            .profiles
            .iter()
            .enumerate()
            .filter(|(_, p)| p.interface_guid.eq_ignore_ascii_case(interface_guid))
            .map(|(idx, _)| idx)
            .collect();

        matching_indices.sort_by_key(|&idx| guard.fixtures.profiles[idx].position);

        let Some(pos_in_iface) = matching_indices
            .iter()
            .position(|&idx| guard.fixtures.profiles[idx].profile_name == profile_name)
        else {
            return Err(NetError::HardwareNotFound(format!(
                "WLAN profile '{profile_name}' not found on interface {interface_guid}"
            )));
        };

        let target_idx = matching_indices.remove(pos_in_iface);
        let insert_at = (position as usize).min(matching_indices.len());
        matching_indices.insert(insert_at, target_idx);

        for (new_pos, idx) in matching_indices.into_iter().enumerate() {
            guard.fixtures.profiles[idx].position = new_pos as u32;
        }
        guard
            .mutation_log
            .push(format!("set-order:{interface_guid}:{profile_name}:{position}"));
        Ok(())
    }

    fn delete_profile(&self, interface_guid: &str, profile_name: &str) -> NetResult<()> {
        let mut guard = self.lock_state()?;
        guard.fault.check("delete_profile")?;

        let before = guard.fixtures.profiles.len();
        guard
            .fixtures
            .profiles
            .retain(|p| !(p.interface_guid.eq_ignore_ascii_case(interface_guid) && p.profile_name == profile_name));
        if guard.fixtures.profiles.len() == before {
            return Err(NetError::HardwareNotFound(format!(
                "WLAN profile '{profile_name}' not found on interface {interface_guid}"
            )));
        }

        // Re-compact positions for that interface
        let mut per_iface: Vec<usize> = guard
            .fixtures
            .profiles
            .iter()
            .enumerate()
            .filter(|(_, p)| p.interface_guid.eq_ignore_ascii_case(interface_guid))
            .map(|(i, _)| i)
            .collect();
        per_iface.sort_by_key(|&i| guard.fixtures.profiles[i].position);
        for (new_pos, idx) in per_iface.into_iter().enumerate() {
            guard.fixtures.profiles[idx].position = new_pos as u32;
        }

        guard
            .mutation_log
            .push(format!("delete:{interface_guid}:{profile_name}"));
        Ok(())
    }

    fn set_profile_auto_connect(
        &self,
        interface_guid: &str,
        profile_name: &str,
        auto_connect: bool,
    ) -> NetResult<String> {
        let mut guard = self.lock_state()?;
        guard.fault.check("set_profile_auto_connect")?;

        let Some(profile) = guard
            .fixtures
            .profiles
            .iter_mut()
            .find(|p| p.interface_guid.eq_ignore_ascii_case(interface_guid) && p.profile_name == profile_name)
        else {
            return Err(NetError::HardwareNotFound(format!(
                "WLAN profile '{profile_name}' not found on interface {interface_guid}"
            )));
        };

        let updated = wlan_xml::set_connection_mode_xml(&profile.sanitized_xml, auto_connect)?;
        profile.sanitized_xml = updated.clone();
        guard
            .mutation_log
            .push(format!("toggle-auto:{interface_guid}:{profile_name}:{auto_connect}"));
        Ok(updated)
    }

    fn hosted_network_status(&self) -> NetResult<HostedNetworkStatus> {
        let guard = self.lock_state()?;
        guard.fault.check("hosted_network_status")?;
        Ok(guard.fixtures.hosted_network.clone())
    }

    fn start_hosted_network(&self, ssid: Option<&str>, max_peers: Option<u32>) -> NetResult<HostedNetworkStatus> {
        let mut guard = self.lock_state()?;
        guard.fault.check("start_hosted_network")?;

        if let Some(s) = ssid {
            if s.is_empty() || s.len() > 32 {
                return Err(NetError::InvalidInput(
                    "hosted network SSID must be 1..=32 bytes".to_string(),
                ));
            }
            guard.fixtures.hosted_network.ssid = Some(s.to_string());
        } else if guard.fixtures.hosted_network.ssid.is_none() {
            guard.fixtures.hosted_network.ssid = Some("GUAP-Hotspot".to_string());
        }

        if let Some(mp) = max_peers {
            if mp == 0 || mp > 100 {
                return Err(NetError::InvalidInput(
                    "hosted network max_peers must be 1..=100".to_string(),
                ));
            }
            guard.fixtures.hosted_network.max_peers = mp;
        } else if guard.fixtures.hosted_network.max_peers == 0 {
            guard.fixtures.hosted_network.max_peers = 10;
        }

        guard.fixtures.hosted_network.state = "Active".to_string();
        if guard.fixtures.hosted_network.adapter_guid.is_none() {
            guard.fixtures.hosted_network.adapter_guid = Some("{33333333-4444-5555-6666-777777777777}".to_string());
        }
        if guard.fixtures.hosted_network.bssid.is_none() {
            guard.fixtures.hosted_network.bssid = Some(MacAddr::new([0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]));
        }
        if guard.fixtures.hosted_network.phy_type.is_none() {
            guard.fixtures.hosted_network.phy_type = Some("HT (802.11n)".to_string());
        }
        if guard.fixtures.hosted_network.channel_freq_khz.is_none() {
            guard.fixtures.hosted_network.channel_freq_khz = Some(2_437_000);
        }

        guard.mutation_log.push("hosted.start".to_string());
        Ok(guard.fixtures.hosted_network.clone())
    }

    fn stop_hosted_network(&self, force: bool) -> NetResult<HostedNetworkStatus> {
        let mut guard = self.lock_state()?;
        guard.fault.check("stop_hosted_network")?;

        guard.fixtures.hosted_network.state = "Idle".to_string();
        guard.fixtures.hosted_network.active_peers = 0;
        guard.fixtures.hosted_network.peers.clear();
        guard.mutation_log.push(format!("hosted.stop:force={force}"));
        Ok(guard.fixtures.hosted_network.clone())
    }
}

impl BluetoothBackend for OfflineMockRadioBackend {
    fn list_radios(&self) -> NetResult<Vec<BluetoothRadioInfo>> {
        let guard = self.lock_state()?;
        guard.fault.check("list_radios")?;
        Ok(guard.fixtures.bt_radios.clone())
    }

    fn list_classic_devices(&self) -> NetResult<Vec<BluetoothClassicDevice>> {
        let guard = self.lock_state()?;
        guard.fault.check("list_classic_devices")?;
        Ok(guard.fixtures.bt_devices.clone())
    }

    fn offline_log_snapshots(&self) -> Option<Vec<(DateTime<Utc>, Vec<BluetoothClassicDevice>)>> {
        let guard = self.state.lock().ok()?;
        if guard.fault != MockFaultMode::None {
            return None;
        }
        Some(guard.fixtures.bt_log_snapshots.clone())
    }

    fn scan_ble_advertisements(&self, _duration: Duration) -> NetResult<Vec<BleAdvertisementRecord>> {
        let guard = self.lock_state()?;
        guard.fault.check("scan_ble_advertisements")?;
        Ok(guard.fixtures.ble_advertisements.clone())
    }
}

impl OfflineRadioFixtures {
    pub fn empty() -> Self {
        Self {
            interfaces: Vec::new(),
            bss_list: Vec::new(),
            available_networks: Vec::new(),
            connections: Vec::new(),
            profiles: Vec::new(),
            hosted_network: HostedNetworkStatus {
                state: "Unavailable".to_string(),
                adapter_guid: None,
                bssid: None,
                ssid: None,
                max_peers: 0,
                active_peers: 0,
                phy_type: None,
                channel_freq_khz: None,
                peers: Vec::new(),
            },
            bt_radios: Vec::new(),
            bt_devices: Vec::new(),
            bt_log_snapshots: Vec::new(),
            ble_advertisements: Vec::new(),
        }
    }

    pub fn default_synthetic() -> Self {
        fixtures::build_default_radio_fixtures()
    }
}

pub fn normalize_guid_str(s: &str) -> String {
    s.trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .to_ascii_lowercase()
}

pub fn resolve_interface<'a>(
    interfaces: &'a [WlanInterfaceInfo],
    guid: Option<&str>,
    name: Option<&str>,
) -> Result<&'a WlanInterfaceInfo, NetError> {
    if interfaces.is_empty() {
        return Err(NetError::HardwareNotFound("no wireless interfaces found".to_string()));
    }

    if let Some(g) = guid.map(str::trim).filter(|s| !s.is_empty()) {
        let target = normalize_guid_str(g);
        return interfaces
            .iter()
            .find(|i| normalize_guid_str(&i.guid) == target)
            .ok_or_else(|| NetError::HardwareNotFound(format!("wireless interface GUID '{g}' not found")));
    }

    if let Some(n) = name.map(str::trim).filter(|s| !s.is_empty()) {
        return interfaces
            .iter()
            .find(|i| i.description.eq_ignore_ascii_case(n))
            .ok_or_else(|| NetError::HardwareNotFound(format!("wireless interface '{n}' not found")));
    }

    if interfaces.len() == 1 {
        return Ok(&interfaces[0]);
    }

    Err(NetError::InvalidInput(format!(
        "multiple wireless interfaces present ({}); specify 'interface_guid' or 'interface_name'",
        interfaces.len()
    )))
}

pub type BtSnapshot = BTreeMap<MacAddr, BluetoothClassicDevice>;
