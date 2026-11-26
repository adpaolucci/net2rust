use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use guap_mcp::{ActionCommand, ActionRiskLevel, McpToolError};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use net2rust_core::{NetContext, NetError, sanitize_wlan_profile_xml};
use serde_json::{Value, json};

use crate::backend::{WlanBackend, resolve_interface};
use crate::bt_lookup::lookup_oui;
use crate::ie_parser::{channel_from_freq_khz, parse_ie_stream};
use crate::wlan_xml::parse_wlan_profile_xml;

pub fn wifi_providers(ctx: &NetContext, backend: Arc<dyn WlanBackend>) -> Vec<Arc<dyn TableProvider>> {
    vec![
        Arc::new(WifiInfoProvider::new(ctx.clone(), Arc::clone(&backend))),
        Arc::new(WifiScanProvider::new(ctx.clone(), Arc::clone(&backend))),
        Arc::new(WifiConsoleProvider::new(ctx.clone(), Arc::clone(&backend))),
        Arc::new(WifiConnProvider::new(ctx.clone(), Arc::clone(&backend))),
        Arc::new(WifiProfilesProvider::new(ctx.clone(), Arc::clone(&backend))),
        Arc::new(WifiHostedProvider::new(ctx.clone(), backend)),
    ]
}

pub fn wifi_actions(backend: Arc<dyn WlanBackend>) -> Vec<Arc<dyn ActionCommand>> {
    vec![
        Arc::new(SetProfileOrderAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(DeleteProfileAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ToggleAutoConnectAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(HostedNetworkStartAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(HostedNetworkStopAction { backend }),
    ]
}

pub struct WifiInfoProvider {
    ctx: NetContext,
    backend: Arc<dyn WlanBackend>,
}

impl WifiInfoProvider {
    pub fn new(ctx: NetContext, backend: Arc<dyn WlanBackend>) -> Self {
        Self { ctx, backend }
    }
}

impl TableProvider for WifiInfoProvider {
    fn tool_id(&self) -> &'static str {
        "radio.wifi-info"
    }

    fn description(&self) -> &'static str {
        "802.11 BSS/IE scanner (HT/VHT/HE/EHT, channel, RSSI, security mode, zero key extraction)."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Wi-Fi BSS & Information Elements",
            vec![
                ColumnDef::new("ssid", "SSID", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("bssid", "BSSID", ColumnType::MacAddr).with_width_hint(140),
                ColumnDef::new("rssi", "RSSI (dBm)", ColumnType::Int).with_width_hint(90),
                ColumnDef::new("signal_pct", "Signal (%)", ColumnType::Uint).with_width_hint(90),
                ColumnDef::new("channel", "Channel", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("frequency_mhz", "Frequency (MHz)", ColumnType::Uint).with_width_hint(115),
                ColumnDef::new("phy_type", "PHY Type", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("max_speed_mbps", "Max Speed (Mbps)", ColumnType::Float).with_width_hint(125),
                ColumnDef::new("security", "Security", ColumnType::Text).with_width_hint(190),
                ColumnDef::new("router_vendor", "Router Vendor", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("country", "Country", ColumnType::Text).with_width_hint(80),
                ColumnDef::new("wps", "WPS", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("interface", "Interface", ColumnType::Text).with_width_hint(170),
            ],
        )
        .with_default_sort(2, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let bss_list = self.backend.scan_and_list_bss(false)?;
        let schema = self.schema();
        let mut rows = Vec::with_capacity(bss_list.len());

        for (idx, bss) in bss_list.into_iter().enumerate() {
            let parsed = parse_ie_stream(&bss.raw_ies);
            let ssid = if !bss.ssid.is_empty() {
                bss.ssid.clone()
            } else if parsed.hidden_ssid {
                "<Hidden>".to_string()
            } else {
                parsed.ssid.clone().unwrap_or_default()
            };

            let channel = parsed.effective_channel(bss.center_freq_khz).unwrap_or(0);
            let freq_mhz = bss.center_freq_khz / 1000;
            let phy = if bss.raw_ies.is_empty() {
                bss.phy_type.clone()
            } else {
                let ie_phy = parsed.phy_generation();
                if ie_phy != "HRDSSS (802.11b)" {
                    ie_phy.to_string()
                } else {
                    bss.phy_type.clone()
                }
            };
            let max_speed = parsed.max_speed_mbps(&bss.rate_set_kbps);
            let security = parsed.security_summary(bss.capability_info);
            let vendor = lookup_oui(&bss.bssid);
            let country = parsed.country_code.clone().unwrap_or_default();
            let wps = parsed
                .wps
                .as_ref()
                .and_then(|w| w.state.clone())
                .unwrap_or_else(|| "None".to_string());

            let detail = json!({
                "interface_guid": bss.interface_guid,
                "interface_name": bss.interface_name,
                "ssid": ssid,
                "bssid": bss.bssid.to_colon_string(),
                "bss_type": bss.bss_type,
                "rssi_dbm": bss.rssi_dbm,
                "signal_pct": bss.signal_pct,
                "channel": channel,
                "channel_width_mhz": parsed.channel_width_mhz(),
                "center_freq_khz": bss.center_freq_khz,
                "phy_type": phy,
                "max_speed_mbps": max_speed,
                "security": security,
                "router_vendor": vendor,
                "parsed_ies": parsed,
            });

            rows.push(
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(ssid),
                        CellValue::Text(bss.bssid.to_colon_string()),
                        CellValue::Int(i64::from(bss.rssi_dbm)),
                        CellValue::Uint(u64::from(bss.signal_pct)),
                        CellValue::Uint(u64::from(channel)),
                        CellValue::Uint(u64::from(freq_mhz)),
                        CellValue::Text(phy),
                        CellValue::Float(max_speed),
                        CellValue::Text(security),
                        CellValue::Text(vendor),
                        CellValue::Text(country),
                        CellValue::Text(wps),
                        CellValue::Text(bss.interface_name),
                    ],
                )
                .with_detail_json(detail)
                .with_raw_bytes(bss.raw_ies),
            );
        }

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&schema, &rows, req)
    }
}

#[derive(Debug, Clone)]
struct ScanHistoryEntry {
    detection_count: u64,
    signal_sum: u64,
    first_detected: DateTime<Utc>,
    last_detected: DateTime<Utc>,
}

pub struct WifiScanProvider {
    ctx: NetContext,
    backend: Arc<dyn WlanBackend>,
    history: Mutex<HashMap<String, ScanHistoryEntry>>,
}

impl WifiScanProvider {
    pub fn new(ctx: NetContext, backend: Arc<dyn WlanBackend>) -> Self {
        Self {
            ctx,
            backend,
            history: Mutex::new(HashMap::new()),
        }
    }
}

impl TableProvider for WifiScanProvider {
    fn tool_id(&self) -> &'static str {
        "radio.wifi-scan"
    }

    fn description(&self) -> &'static str {
        "Continuous Wi-Fi availability, signal average, and detection counter."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Wireless Network Availability Scanner",
            vec![
                ColumnDef::new("ssid", "SSID", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("last_signal_pct", "Last Signal (%)", ColumnType::Uint).with_width_hint(110),
                ColumnDef::new("avg_signal_pct", "Avg Signal (%)", ColumnType::Float).with_width_hint(110),
                ColumnDef::new("detection_count", "Detections", ColumnType::Uint).with_width_hint(95),
                ColumnDef::new("security", "Security", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("auth_algo", "Authentication", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("cipher_algo", "Cipher", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("connected", "Connected", ColumnType::Bool).with_width_hint(90),
                ColumnDef::new("has_profile", "Has Profile", ColumnType::Bool).with_width_hint(95),
                ColumnDef::new("first_detected", "First Detected", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("last_detected", "Last Detected", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("interface", "Interface", ColumnType::Text).with_width_hint(170),
            ],
        )
        .with_default_sort(1, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let networks = self.backend.list_available_networks(true)?;
        let schema = self.schema();
        let mut hist_guard = self
            .history
            .lock()
            .map_err(|_| TableError::Provider("wifi scan history lock poisoned".to_string()))?;

        let mut rows = Vec::with_capacity(networks.len());
        for (idx, net) in networks.into_iter().enumerate() {
            let key = format!("{}::{}::{}", net.interface_guid, net.ssid, net.bss_type);
            let entry = hist_guard
                .entry(key)
                .and_modify(|e| {
                    e.detection_count += 1;
                    e.signal_sum += u64::from(net.signal_quality_pct);
                    e.last_detected = net.detected_at;
                })
                .or_insert_with(|| ScanHistoryEntry {
                    detection_count: 1,
                    signal_sum: u64::from(net.signal_quality_pct),
                    first_detected: net.detected_at,
                    last_detected: net.detected_at,
                })
                .clone();

            let avg_sig = ((entry.signal_sum as f64) / (entry.detection_count as f64) * 10.0).round() / 10.0;
            let security_str = if net.security_enabled {
                format!("{}/{}", net.default_auth_algo, net.default_cipher_algo)
            } else {
                "Open".to_string()
            };
            let ssid_display = if net.ssid.is_empty() {
                "<Hidden>".to_string()
            } else {
                net.ssid.clone()
            };

            let detail = json!({
                "interface_guid": net.interface_guid,
                "interface_name": net.interface_name,
                "profile_name": net.profile_name,
                "ssid": ssid_display,
                "bss_type": net.bss_type,
                "number_of_bssids": net.number_of_bssids,
                "connectable": net.connectable,
                "not_connectable_reason": net.not_connectable_reason,
                "phy_types": net.phy_types,
                "detection_count": entry.detection_count,
                "avg_signal_pct": avg_sig,
            });

            rows.push(
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(ssid_display),
                        CellValue::Uint(u64::from(net.signal_quality_pct)),
                        CellValue::Float(avg_sig),
                        CellValue::Uint(entry.detection_count),
                        CellValue::Text(security_str),
                        CellValue::Text(net.default_auth_algo),
                        CellValue::Text(net.default_cipher_algo),
                        CellValue::Bool(net.connected),
                        CellValue::Bool(net.has_profile),
                        CellValue::Timestamp(entry.first_detected),
                        CellValue::Timestamp(entry.last_detected),
                        CellValue::Text(net.interface_name),
                    ],
                )
                .with_detail_json(detail),
            );
        }

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&schema, &rows, req)
    }
}

pub struct WifiConsoleProvider {
    ctx: NetContext,
    backend: Arc<dyn WlanBackend>,
}

impl WifiConsoleProvider {
    pub fn new(ctx: NetContext, backend: Arc<dyn WlanBackend>) -> Self {
        Self { ctx, backend }
    }
}

impl TableProvider for WifiConsoleProvider {
    fn tool_id(&self) -> &'static str {
        "radio.wifi-console"
    }

    fn description(&self) -> &'static str {
        "Streaming console Wi-Fi scan table."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Wireless Console Scan",
            vec![
                ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("ssid", "SSID", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("bssid", "BSSID", ColumnType::MacAddr).with_width_hint(140),
                ColumnDef::new("signal_pct", "Signal (%)", ColumnType::Uint).with_width_hint(90),
                ColumnDef::new("channel", "Channel", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("frequency_mhz", "Frequency (MHz)", ColumnType::Uint).with_width_hint(115),
                ColumnDef::new("phy_type", "PHY Type", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("security", "Security", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("rssi", "RSSI (dBm)", ColumnType::Int).with_width_hint(90),
            ],
        )
        .with_default_sort(3, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let bss_list = self.backend.scan_and_list_bss(true)?;
        let now = Utc::now();
        let schema = self.schema();
        let mut rows = Vec::with_capacity(bss_list.len());

        for (idx, bss) in bss_list.into_iter().enumerate() {
            let parsed = parse_ie_stream(&bss.raw_ies);
            let ssid = if !bss.ssid.is_empty() {
                bss.ssid.clone()
            } else if parsed.hidden_ssid {
                "<Hidden>".to_string()
            } else {
                parsed.ssid.clone().unwrap_or_default()
            };
            let channel = parsed.effective_channel(bss.center_freq_khz).unwrap_or(0);
            let freq_mhz = bss.center_freq_khz / 1000;
            let security = parsed.security_summary(bss.capability_info);

            let detail = json!({
                "interface_guid": bss.interface_guid,
                "interface_name": bss.interface_name,
                "ssid": ssid,
                "bssid": bss.bssid.to_colon_string(),
                "channel": channel,
                "frequency_mhz": freq_mhz,
                "phy_type": bss.phy_type,
                "security": security,
                "rssi_dbm": bss.rssi_dbm,
            });

            rows.push(
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Timestamp(now),
                        CellValue::Text(ssid),
                        CellValue::Text(bss.bssid.to_colon_string()),
                        CellValue::Uint(u64::from(bss.signal_pct)),
                        CellValue::Uint(u64::from(channel)),
                        CellValue::Uint(u64::from(freq_mhz)),
                        CellValue::Text(bss.phy_type),
                        CellValue::Text(security),
                        CellValue::Int(i64::from(bss.rssi_dbm)),
                    ],
                )
                .with_detail_json(detail)
                .with_raw_bytes(bss.raw_ies),
            );
        }

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&schema, &rows, req)
    }
}

pub struct WifiConnProvider {
    ctx: NetContext,
    backend: Arc<dyn WlanBackend>,
}

impl WifiConnProvider {
    pub fn new(ctx: NetContext, backend: Arc<dyn WlanBackend>) -> Self {
        Self { ctx, backend }
    }
}

impl TableProvider for WifiConnProvider {
    fn tool_id(&self) -> &'static str {
        "radio.wifi-conn"
    }

    fn description(&self) -> &'static str {
        "Active Wi-Fi association PHY, channel, Tx/Rx rates, and RSSI."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Active Wi-Fi Connection Info",
            vec![
                ColumnDef::new("interface_name", "Interface", ColumnType::Text).with_width_hint(170),
                ColumnDef::new("interface_guid", "Interface GUID", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("ssid", "SSID", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("bssid", "BSSID", ColumnType::MacAddr).with_width_hint(140),
                ColumnDef::new("state", "State", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("phy_type", "PHY Type", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("channel", "Channel", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("rx_rate_mbps", "Rx Rate (Mbps)", ColumnType::Float).with_width_hint(115),
                ColumnDef::new("tx_rate_mbps", "Tx Rate (Mbps)", ColumnType::Float).with_width_hint(115),
                ColumnDef::new("signal_pct", "Signal (%)", ColumnType::Uint).with_width_hint(90),
                ColumnDef::new("rssi", "RSSI (dBm)", ColumnType::Int).with_width_hint(90),
                ColumnDef::new("auth", "Authentication", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("cipher", "Cipher", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("one_x", "802.1X", ColumnType::Bool).with_width_hint(80),
            ],
        )
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let conns = self.backend.current_connections()?;
        let schema = self.schema();
        let mut rows = Vec::with_capacity(conns.len());

        for (idx, conn) in conns.into_iter().enumerate() {
            let rx_mbps = (f64::from(conn.rx_rate_kbps) / 1000.0 * 10.0).round() / 10.0;
            let tx_mbps = (f64::from(conn.tx_rate_kbps) / 1000.0 * 10.0).round() / 10.0;
            let rssi_cell = conn
                .rssi_dbm
                .map(|r| CellValue::Int(i64::from(r)))
                .unwrap_or(CellValue::Null);

            let detail = json!({
                "interface_guid": conn.interface_guid,
                "interface_name": conn.interface_name,
                "connection_mode": conn.connection_mode,
                "profile_name": conn.profile_name,
                "bss_type": conn.bss_type,
                "center_freq_mhz": conn.center_freq_mhz,
                "security_enabled": conn.security_enabled,
                "one_x_enabled": conn.one_x_enabled,
                "tx_packets": conn.tx_packets,
                "rx_packets": conn.rx_packets,
            });

            rows.push(
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(conn.interface_name),
                        CellValue::Text(conn.interface_guid),
                        CellValue::Text(conn.ssid),
                        CellValue::Text(conn.bssid.to_colon_string()),
                        CellValue::Text(conn.state),
                        CellValue::Text(conn.phy_type),
                        CellValue::Uint(u64::from(conn.channel)),
                        CellValue::Float(rx_mbps),
                        CellValue::Float(tx_mbps),
                        CellValue::Uint(u64::from(conn.signal_quality_pct)),
                        rssi_cell,
                        CellValue::Text(conn.auth_algo),
                        CellValue::Text(conn.cipher_algo),
                        CellValue::Bool(conn.one_x_enabled),
                    ],
                )
                .with_detail_json(detail),
            );
        }

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&schema, &rows, req)
    }
}

pub struct WifiProfilesProvider {
    ctx: NetContext,
    backend: Arc<dyn WlanBackend>,
}

impl WifiProfilesProvider {
    pub fn new(ctx: NetContext, backend: Arc<dyn WlanBackend>) -> Self {
        Self { ctx, backend }
    }
}

impl TableProvider for WifiProfilesProvider {
    fn tool_id(&self) -> &'static str {
        "radio.wifi-profiles"
    }

    fn description(&self) -> &'static str {
        "Saved WLAN profile metadata with R4 keyMaterial redaction (mutating reorder/delete/toggle-auto actions gated)."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Saved WLAN Profiles (R4 Redacted)",
            vec![
                ColumnDef::new("profile_name", "Profile Name", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("interface", "Interface", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("interface_guid", "Interface GUID", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("ssid", "SSID", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("connection_mode", "Connection Mode", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("connection_type", "Connection Type", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("auth", "Authentication", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("cipher", "Cipher", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("non_broadcast", "Hidden (Non-Broadcast)", ColumnType::Bool).with_width_hint(130),
                ColumnDef::new("random_mac", "MAC Randomization", ColumnType::Bool).with_width_hint(130),
                ColumnDef::new("position", "Order", ColumnType::Uint).with_width_hint(70),
                ColumnDef::new("flags", "Scope", ColumnType::Text).with_width_hint(100),
            ],
        )
        .with_default_sort(10, SortDirection::Asc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let profiles = self.backend.list_profiles()?;
        let schema = self.schema();
        let mut rows = Vec::with_capacity(profiles.len());

        for (idx, prof) in profiles.into_iter().enumerate() {
            // Defense-in-depth: always sanitize before parsing, detail_json, or raw_bytes.
            let sanitized = sanitize_wlan_profile_xml(&prof.sanitized_xml);
            let meta = parse_wlan_profile_xml(&sanitized).map_err(TableError::from)?;
            let random_mac_cell = meta.mac_randomization.map(CellValue::Bool).unwrap_or(CellValue::Null);
            let scope = match prof.flags {
                1 => "GroupPolicy".to_string(),
                2 => "PerUser".to_string(),
                _ => "AllUsers".to_string(),
            };

            let detail = json!({
                "profile_name": prof.profile_name,
                "interface_guid": prof.interface_guid,
                "interface_name": prof.interface_name,
                "position": prof.position,
                "flags": prof.flags,
                "scope": scope,
                "metadata": {
                    "ssid": meta.ssid,
                    "connection_type": meta.connection_type,
                    "connection_mode": meta.connection_mode,
                    "non_broadcast": meta.non_broadcast,
                    "authentication": meta.authentication,
                    "encryption": meta.encryption,
                    "use_one_x": meta.use_one_x,
                    "mac_randomization": meta.mac_randomization,
                },
                "sanitized_xml": meta.sanitized_xml,
            });

            rows.push(
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(prof.profile_name),
                        CellValue::Text(prof.interface_name),
                        CellValue::Text(prof.interface_guid),
                        CellValue::Text(meta.ssid),
                        CellValue::Text(meta.connection_mode),
                        CellValue::Text(meta.connection_type),
                        CellValue::Text(meta.authentication),
                        CellValue::Text(meta.encryption),
                        CellValue::Bool(meta.non_broadcast),
                        random_mac_cell,
                        CellValue::Uint(u64::from(prof.position)),
                        CellValue::Text(scope),
                    ],
                )
                .with_detail_json(detail)
                .with_raw_bytes(meta.sanitized_xml.into_bytes()),
            );
        }

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&schema, &rows, req)
    }
}

pub struct WifiHostedProvider {
    ctx: NetContext,
    backend: Arc<dyn WlanBackend>,
}

impl WifiHostedProvider {
    pub fn new(ctx: NetContext, backend: Arc<dyn WlanBackend>) -> Self {
        Self { ctx, backend }
    }
}

impl TableProvider for WifiHostedProvider {
    fn tool_id(&self) -> &'static str {
        "radio.wifi-hosted"
    }

    fn description(&self) -> &'static str {
        "Windows Hosted Network status inspector (mutating start/stop gated)."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Wi-Fi Hosted Network Status",
            vec![
                ColumnDef::new("hosted_ssid", "Hosted SSID", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("state", "State", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("max_peers", "Max Peers", ColumnType::Uint).with_width_hint(90),
                ColumnDef::new("active_peers", "Active Peers", ColumnType::Uint).with_width_hint(100),
                ColumnDef::new("adapter_guid", "Adapter GUID", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("bssid", "BSSID", ColumnType::MacAddr).with_width_hint(140),
                ColumnDef::new("phy_type", "PHY Type", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("channel_mhz", "Channel (MHz)", ColumnType::Uint).with_width_hint(110),
            ],
        )
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let status = self.backend.hosted_network_status()?;
        let schema = self.schema();
        let channel_mhz = status.channel_freq_khz.map(|khz| u64::from(khz / 1000));
        let channel_num = status.channel_freq_khz.and_then(channel_from_freq_khz);

        let detail = json!({
            "status": status,
            "channel": channel_num,
        });

        let mut rows = vec![
            Row::new(
                1,
                vec![
                    CellValue::Text(status.ssid.unwrap_or_default()),
                    CellValue::Text(status.state),
                    CellValue::Uint(u64::from(status.max_peers)),
                    CellValue::Uint(u64::from(status.active_peers)),
                    CellValue::Text(status.adapter_guid.unwrap_or_default()),
                    status
                        .bssid
                        .map(|m| CellValue::Text(m.to_colon_string()))
                        .unwrap_or(CellValue::Null),
                    status.phy_type.map(CellValue::Text).unwrap_or(CellValue::Null),
                    channel_mhz.map(CellValue::Uint).unwrap_or(CellValue::Null),
                ],
            )
            .with_detail_json(detail),
        ];

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&schema, &rows, req)
    }
}

fn required_nonempty_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, McpToolError> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| McpToolError::InvalidParams(format!("missing or empty '{key}' string parameter")))
}

fn optional_nonempty_str<'a>(args: &'a Value, key: &str) -> Result<Option<&'a str>, McpToolError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Err(McpToolError::InvalidParams(format!("'{key}' must not be empty")))
            } else {
                Ok(Some(trimmed))
            }
        }
        Some(_) => Err(McpToolError::InvalidParams(format!("'{key}' must be a string"))),
    }
}

pub struct SetProfileOrderAction {
    backend: Arc<dyn WlanBackend>,
}

impl ActionCommand for SetProfileOrderAction {
    fn command_id(&self) -> &'static str {
        "radio.wifi-profiles.set-order"
    }

    fn description(&self) -> &'static str {
        "Set the preference position (0-based) of a saved WLAN profile on a wireless interface."
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "interface_guid": { "type": "string", "description": "Wireless interface GUID" },
                "interface_name": { "type": "string", "description": "Wireless interface description" },
                "profile_name": { "type": "string", "description": "Saved WLAN profile name" },
                "position": { "type": "integer", "minimum": 0, "description": "0-based priority position" }
            },
            "required": ["profile_name", "position"]
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let profile_name = required_nonempty_str(args, "profile_name")?;
        let position_u64 = args
            .get("position")
            .and_then(Value::as_u64)
            .ok_or_else(|| McpToolError::InvalidParams("missing or non-negative integer 'position'".to_string()))?;
        let position = u32::try_from(position_u64)
            .map_err(|_| McpToolError::InvalidParams("'position' exceeds u32 range".to_string()))?;

        let iface_guid_arg = optional_nonempty_str(args, "interface_guid")?;
        let iface_name_arg = optional_nonempty_str(args, "interface_name")?;

        let interfaces = self.backend.list_interfaces()?;
        let iface = resolve_interface(&interfaces, iface_guid_arg, iface_name_arg)?;
        let profiles = self.backend.list_profiles()?;
        let existing = profiles
            .iter()
            .find(|p| p.interface_guid.eq_ignore_ascii_case(&iface.guid) && p.profile_name == profile_name)
            .ok_or_else(|| {
                McpToolError::NotFound(format!(
                    "WLAN profile '{profile_name}' not found on interface {}",
                    iface.guid
                ))
            })?;

        if dry_run {
            return Ok(json!({
                "command": self.command_id(),
                "dry_run": true,
                "applied": false,
                "preview": {
                    "interface_guid": iface.guid,
                    "interface_name": iface.description,
                    "profile_name": profile_name,
                    "current_position": existing.position,
                    "target_position": position,
                }
            }));
        }

        self.backend.set_profile_position(&iface.guid, profile_name, position)?;

        Ok(json!({
            "command": self.command_id(),
            "dry_run": false,
            "applied": true,
            "result": {
                "interface_guid": iface.guid,
                "interface_name": iface.description,
                "profile_name": profile_name,
                "position": position,
            }
        }))
    }
}

pub struct DeleteProfileAction {
    backend: Arc<dyn WlanBackend>,
}

impl ActionCommand for DeleteProfileAction {
    fn command_id(&self) -> &'static str {
        "radio.wifi-profiles.delete"
    }

    fn description(&self) -> &'static str {
        "Delete a saved WLAN profile from a wireless interface."
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "interface_guid": { "type": "string", "description": "Wireless interface GUID" },
                "interface_name": { "type": "string", "description": "Wireless interface description" },
                "profile_name": { "type": "string", "description": "Saved WLAN profile name to delete" }
            },
            "required": ["profile_name"]
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let profile_name = required_nonempty_str(args, "profile_name")?;
        let iface_guid_arg = optional_nonempty_str(args, "interface_guid")?;
        let iface_name_arg = optional_nonempty_str(args, "interface_name")?;

        let interfaces = self.backend.list_interfaces()?;
        let iface = resolve_interface(&interfaces, iface_guid_arg, iface_name_arg)?;
        let profiles = self.backend.list_profiles()?;
        let existing = profiles
            .iter()
            .find(|p| p.interface_guid.eq_ignore_ascii_case(&iface.guid) && p.profile_name == profile_name)
            .ok_or_else(|| {
                McpToolError::NotFound(format!(
                    "WLAN profile '{profile_name}' not found on interface {}",
                    iface.guid
                ))
            })?;

        if dry_run {
            return Ok(json!({
                "command": self.command_id(),
                "dry_run": true,
                "applied": false,
                "preview": {
                    "interface_guid": iface.guid,
                    "interface_name": iface.description,
                    "profile_name": existing.profile_name,
                    "action": "delete_profile",
                }
            }));
        }

        self.backend.delete_profile(&iface.guid, profile_name)?;

        Ok(json!({
            "command": self.command_id(),
            "dry_run": false,
            "applied": true,
            "result": {
                "interface_guid": iface.guid,
                "interface_name": iface.description,
                "profile_name": profile_name,
                "deleted": true,
            }
        }))
    }
}

pub struct ToggleAutoConnectAction {
    backend: Arc<dyn WlanBackend>,
}

impl ActionCommand for ToggleAutoConnectAction {
    fn command_id(&self) -> &'static str {
        "radio.wifi-profiles.toggle-auto"
    }

    fn description(&self) -> &'static str {
        "Toggle or set <connectionMode> ('auto' / 'manual') on a saved WLAN profile."
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "interface_guid": { "type": "string", "description": "Wireless interface GUID" },
                "interface_name": { "type": "string", "description": "Wireless interface description" },
                "profile_name": { "type": "string", "description": "Saved WLAN profile name" },
                "auto_connect": { "type": "boolean", "description": "Explicit target mode; flips current mode if omitted" }
            },
            "required": ["profile_name"]
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let profile_name = required_nonempty_str(args, "profile_name")?;
        let iface_guid_arg = optional_nonempty_str(args, "interface_guid")?;
        let iface_name_arg = optional_nonempty_str(args, "interface_name")?;
        let explicit_auto = match args.get("auto_connect") {
            None | Some(Value::Null) => None,
            Some(Value::Bool(b)) => Some(*b),
            Some(_) => {
                return Err(McpToolError::InvalidParams(
                    "'auto_connect' must be a boolean".to_string(),
                ));
            }
        };

        let interfaces = self.backend.list_interfaces()?;
        let iface = resolve_interface(&interfaces, iface_guid_arg, iface_name_arg)?;
        let profiles = self.backend.list_profiles()?;
        let existing = profiles
            .iter()
            .find(|p| p.interface_guid.eq_ignore_ascii_case(&iface.guid) && p.profile_name == profile_name)
            .ok_or_else(|| {
                McpToolError::NotFound(format!(
                    "WLAN profile '{profile_name}' not found on interface {}",
                    iface.guid
                ))
            })?;

        let current_meta = parse_wlan_profile_xml(&existing.sanitized_xml)?;
        let current_auto = current_meta.connection_mode.eq_ignore_ascii_case("auto");
        let target_auto = explicit_auto.unwrap_or(!current_auto);
        let target_mode = if target_auto { "auto" } else { "manual" };

        if dry_run {
            return Ok(json!({
                "command": self.command_id(),
                "dry_run": true,
                "applied": false,
                "preview": {
                    "interface_guid": iface.guid,
                    "interface_name": iface.description,
                    "profile_name": profile_name,
                    "current_mode": current_meta.connection_mode,
                    "target_mode": target_mode,
                }
            }));
        }

        let updated_sanitized = self
            .backend
            .set_profile_auto_connect(&iface.guid, profile_name, target_auto)?;
        let safe_xml = sanitize_wlan_profile_xml(&updated_sanitized);
        let updated_meta = parse_wlan_profile_xml(&safe_xml)?;

        Ok(json!({
            "command": self.command_id(),
            "dry_run": false,
            "applied": true,
            "result": {
                "interface_guid": iface.guid,
                "interface_name": iface.description,
                "profile_name": profile_name,
                "previous_mode": current_meta.connection_mode,
                "connection_mode": updated_meta.connection_mode,
                "sanitized_xml": updated_meta.sanitized_xml,
            }
        }))
    }
}

pub struct HostedNetworkStartAction {
    backend: Arc<dyn WlanBackend>,
}

impl ActionCommand for HostedNetworkStartAction {
    fn command_id(&self) -> &'static str {
        "radio.wifi-hosted.start"
    }

    fn description(&self) -> &'static str {
        "Initialize and start the Windows Wireless Hosted Network (SoftAP) without querying or exposing keys."
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::PrivilegedMutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "ssid": { "type": "string", "minLength": 1, "maxLength": 32, "description": "Optional SoftAP SSID (1..=32 bytes)" },
                "max_peers": { "type": "integer", "minimum": 1, "maximum": 100, "description": "Optional max peers (1..=100)" }
            }
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let ssid = optional_nonempty_str(args, "ssid")?;
        if let Some(s) = ssid
            && s.len() > 32
        {
            return Err(McpToolError::InvalidParams(
                "hosted network 'ssid' must not exceed 32 bytes".to_string(),
            ));
        }

        let max_peers = match args.get("max_peers") {
            None | Some(Value::Null) => None,
            Some(v) => {
                let n = v
                    .as_u64()
                    .ok_or_else(|| McpToolError::InvalidParams("'max_peers' must be a positive integer".to_string()))?;
                if n == 0 || n > 100 {
                    return Err(McpToolError::InvalidParams(
                        "'max_peers' must be in range 1..=100".to_string(),
                    ));
                }
                Some(n as u32)
            }
        };

        if dry_run {
            let current = match self.backend.hosted_network_status() {
                Ok(s) => serde_json::to_value(s).unwrap_or(Value::Null),
                Err(NetError::NotSupported(msg)) => json!({ "state": "NotSupported", "detail": msg }),
                Err(e) => return Err(e.into()),
            };
            return Ok(json!({
                "command": self.command_id(),
                "dry_run": true,
                "applied": false,
                "preview": {
                    "target_ssid": ssid,
                    "target_max_peers": max_peers,
                    "current_status": current,
                }
            }));
        }

        let status = self.backend.start_hosted_network(ssid, max_peers)?;
        Ok(json!({
            "command": self.command_id(),
            "dry_run": false,
            "applied": true,
            "result": status,
        }))
    }
}

pub struct HostedNetworkStopAction {
    backend: Arc<dyn WlanBackend>,
}

impl ActionCommand for HostedNetworkStopAction {
    fn command_id(&self) -> &'static str {
        "radio.wifi-hosted.stop"
    }

    fn description(&self) -> &'static str {
        "Stop the Windows Wireless Hosted Network (SoftAP)."
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::PrivilegedMutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "force": { "type": "boolean", "description": "Use WlanHostedNetworkForceStop instead of StopUsing" }
            }
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let force = match args.get("force") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(McpToolError::InvalidParams("'force' must be a boolean".to_string())),
        };

        if dry_run {
            let current = match self.backend.hosted_network_status() {
                Ok(s) => serde_json::to_value(s).unwrap_or(Value::Null),
                Err(NetError::NotSupported(msg)) => json!({ "state": "NotSupported", "detail": msg }),
                Err(e) => return Err(e.into()),
            };
            return Ok(json!({
                "command": self.command_id(),
                "dry_run": true,
                "applied": false,
                "preview": {
                    "force": force,
                    "current_status": current,
                }
            }));
        }

        let status = self.backend.stop_hosted_network(force)?;
        Ok(json!({
            "command": self.command_id(),
            "dry_run": false,
            "applied": true,
            "result": status,
        }))
    }
}
