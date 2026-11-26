#![deny(unsafe_code)]

use std::sync::Arc;

use guap_mcp::ActionCommand;
use guap_table::TableProvider;
use net2rust_core::{DomainCrateExport, ExecutionMode, NetContext, ToolCategory, ToolDescriptor};

pub mod backend;
pub mod ble_ad;
pub mod bt_cod;
pub mod bt_lookup;
pub mod bt_tools;
pub mod fixtures;
pub mod ie_parser;
pub mod wifi_tools;
pub mod wlan_xml;

#[cfg(windows)]
#[allow(unsafe_code)]
pub mod win32_bt;
#[cfg(windows)]
#[allow(unsafe_code)]
pub mod win32_wlan;

#[cfg(not(windows))]
use backend::UnsupportedRadioBackend;
use backend::{BluetoothBackend, OfflineMockRadioBackend, WlanBackend};

pub struct RadioDomain;

impl DomainCrateExport for RadioDomain {
    fn category() -> ToolCategory {
        ToolCategory::Radio
    }

    fn tool_descriptors() -> Vec<ToolDescriptor> {
        tool_descriptors()
    }

    fn providers(ctx: &NetContext) -> Vec<Arc<dyn TableProvider>> {
        providers(ctx)
    }

    fn actions(ctx: &NetContext) -> Vec<Arc<dyn ActionCommand>> {
        actions(ctx)
    }
}

pub fn tool_descriptors() -> Vec<ToolDescriptor> {
    vec![
        ToolDescriptor {
            id: "radio.wifi-info",
            category: ToolCategory::Radio,
            subcommand: "wifi-info",
            display_name: "Wi-Fi BSS & Information Elements",
            description: "802.11 BSS/IE scanner (HT/VHT/HE/EHT, channel, RSSI, security mode, zero key extraction).",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: "radio.wifi-scan",
            category: ToolCategory::Radio,
            subcommand: "wifi-scan",
            display_name: "Wireless Network Availability Scanner",
            description: "Continuous Wi-Fi availability, signal average, and detection counter.",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: "radio.wifi-console",
            category: ToolCategory::Radio,
            subcommand: "wifi-console",
            display_name: "Streaming Wi-Fi Scan Table",
            description: "Streaming console Wi-Fi scan table.",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: "radio.wifi-conn",
            category: ToolCategory::Radio,
            subcommand: "wifi-conn",
            display_name: "Active Wi-Fi Connection Info",
            description: "Active Wi-Fi association PHY, channel, Tx/Rx rates, and RSSI.",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: "radio.wifi-profiles",
            category: ToolCategory::Radio,
            subcommand: "wifi-profiles",
            display_name: "Saved WLAN Profiles (R4 Redacted)",
            description: "Saved WLAN profile metadata with R4 keyMaterial redaction (mutating reorder/delete/toggle-auto gated).",
            read_only: true,
            has_mutating_action: true,
        },
        ToolDescriptor {
            id: "radio.wifi-hosted",
            category: ToolCategory::Radio,
            subcommand: "wifi-hosted",
            display_name: "Wi-Fi Hosted Network Status",
            description: "Windows Hosted Network status inspector (mutating start/stop gated).",
            read_only: true,
            has_mutating_action: true,
        },
        ToolDescriptor {
            id: "radio.bt-view",
            category: ToolCategory::Radio,
            subcommand: "bt-view",
            display_name: "Bluetooth Classic Device Discovery",
            description: "Bluetooth Classic device discovery monitor.",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: "radio.bt-log",
            category: ToolCategory::Radio,
            subcommand: "bt-log",
            display_name: "Bluetooth Arrival & Departure Log",
            description: "Bluetooth device arrival and departure event log.",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: "radio.bt-cl",
            category: ToolCategory::Radio,
            subcommand: "bt-cl",
            display_name: "Bluetooth Classic Enumeration",
            description: "Deterministic Bluetooth Classic enumeration.",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: "radio.ble",
            category: ToolCategory::Radio,
            subcommand: "ble",
            display_name: "Bluetooth Low Energy (BLE) Scanner",
            description: "Bluetooth Low Energy (BLE) advertisement, RSSI, service UUID, and manufacturer data scanner.",
            read_only: true,
            has_mutating_action: false,
        },
    ]
}

fn build_wlan_backend(ctx: &NetContext) -> Arc<dyn WlanBackend> {
    match &ctx.mode {
        ExecutionMode::Offline(cfg) => Arc::new(OfflineMockRadioBackend::from_config(cfg)),
        ExecutionMode::Live => {
            #[cfg(windows)]
            {
                Arc::new(win32_wlan::Win32WlanBackend::new())
            }
            #[cfg(not(windows))]
            {
                Arc::new(UnsupportedRadioBackend::new(
                    "Wi-Fi wlanapi.dll is only supported on Windows",
                ))
            }
        }
    }
}

fn build_bt_backend(ctx: &NetContext) -> Arc<dyn BluetoothBackend> {
    match &ctx.mode {
        ExecutionMode::Offline(cfg) => Arc::new(OfflineMockRadioBackend::from_config(cfg)),
        ExecutionMode::Live => {
            #[cfg(windows)]
            {
                Arc::new(win32_bt::Win32BluetoothBackend::new())
            }
            #[cfg(not(windows))]
            {
                Arc::new(UnsupportedRadioBackend::new(
                    "Windows Bluetooth/BLE APIs are only supported on Windows",
                ))
            }
        }
    }
}

pub fn providers(ctx: &NetContext) -> Vec<Arc<dyn TableProvider>> {
    let wlan_backend = build_wlan_backend(ctx);
    let bt_backend = build_bt_backend(ctx);
    providers_with_backends(ctx, wlan_backend, bt_backend)
}

pub fn providers_with_backends(
    ctx: &NetContext,
    wlan_backend: Arc<dyn WlanBackend>,
    bt_backend: Arc<dyn BluetoothBackend>,
) -> Vec<Arc<dyn TableProvider>> {
    let mut all = wifi_tools::wifi_providers(ctx, wlan_backend);
    all.extend(bt_tools::bt_providers(ctx, bt_backend));
    all
}

pub fn actions(ctx: &NetContext) -> Vec<Arc<dyn ActionCommand>> {
    let wlan_backend = build_wlan_backend(ctx);
    actions_with_backend(wlan_backend)
}

pub fn actions_with_backend(wlan_backend: Arc<dyn WlanBackend>) -> Vec<Arc<dyn ActionCommand>> {
    wifi_tools::wifi_actions(wlan_backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_radio_domain_exports_counts() {
        let ctx = NetContext::offline(Default::default());
        assert_eq!(RadioDomain::category(), ToolCategory::Radio);
        let descs = RadioDomain::tool_descriptors();
        assert_eq!(descs.len(), 10);
        assert_eq!(RadioDomain::providers(&ctx).len(), 10);
        assert_eq!(RadioDomain::actions(&ctx).len(), 5);
    }

    #[test]
    fn test_unsupported_backend_returns_not_supported() {
        let unsupported = backend::UnsupportedRadioBackend::new("non-windows");
        assert!(matches!(
            unsupported.list_interfaces(),
            Err(net2rust_core::NetError::NotSupported(_))
        ));
        assert!(matches!(
            unsupported.list_classic_devices(),
            Err(net2rust_core::NetError::NotSupported(_))
        ));
    }
}
