//! `net2rust-lan` — 11 LAN diagnostics, scanning, Wake-on-LAN, NetBIOS, SMB, DNS/OUI,
//! and download benchmark tools plus 2 policy-gated mutating actions.

pub mod common;
pub mod fixtures;
pub mod geoip;
pub mod netbios;
pub mod oui;
pub mod ping;
pub mod resolve;
pub mod scan;
pub mod smb;
pub mod speedtest;
pub mod trace;
pub mod wol;

use std::sync::Arc;

use guap_mcp::ActionCommand;
use guap_table::TableProvider;
use net2rust_core::{DomainCrateExport, NetContext, ToolCategory, ToolDescriptor};

use crate::netbios::NetBScannerProvider;
use crate::ping::PingInfoViewProvider;
use crate::resolve::FastResolverProvider;
use crate::scan::{LanIpScannerProvider, NetworkConnectLogProvider, WirelessNetWatcherProvider};
use crate::smb::{NetResViewProvider, NetworkOpenedFilesProvider, OpenFilesCloseAction};
use crate::speedtest::DownTesterProvider;
use crate::trace::CountryTraceRouteProvider;
use crate::wol::{WakeMeOnLanProvider, WolSendAction};

pub struct LanDomain;

impl DomainCrateExport for LanDomain {
    fn category() -> ToolCategory {
        ToolCategory::Lan
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
            id: "lan.ping",
            category: ToolCategory::Lan,
            subcommand: "ping",
            nirsoft_name: "PingInfoView",
            description: "Monitor multiple hosts via ICMP/ICMPv6 echo and TCP connect fallback",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: "lan.trace",
            category: ToolCategory::Lan,
            subcommand: "trace",
            nirsoft_name: "CountryTraceRoute",
            description: "Traceroute with ICMP TTL probes and offline GeoIP country/ASN lookup",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: "lan.scan",
            category: ToolCategory::Lan,
            subcommand: "scan",
            nirsoft_name: "LANIPScanner",
            description: "Concurrent ARP, ICMP, NetBIOS, and TCP port scanner over IPv4 CIDR",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: "lan.wnetwatcher",
            category: ToolCategory::Lan,
            subcommand: "wnetwatcher",
            nirsoft_name: "Wireless Network Watcher",
            description: "ARP table and subnet sweep inventory with hostname and OUI vendor lookup",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: "lan.connect-log",
            category: ToolCategory::Lan,
            subcommand: "connect-log",
            nirsoft_name: "NetworkConnectLog",
            description: "Stateful ARP snapshot diff logger for host connect and disconnect events",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: "lan.wol",
            category: ToolCategory::Lan,
            subcommand: "wol",
            nirsoft_name: "WakeMeOnLan",
            description: "LAN host Wake-on-LAN inventory paired with lan.wol.send action",
            read_only: true,
            has_mutating_action: true,
        },
        ToolDescriptor {
            id: "lan.netbios",
            category: ToolCategory::Lan,
            subcommand: "netbios",
            nirsoft_name: "NetBScanner",
            description: "Pure-Rust RFC 1001/1002 UDP port 137 NBSTAT NetBIOS scanner",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: "lan.shares",
            category: ToolCategory::Lan,
            subcommand: "shares",
            nirsoft_name: "NetResView",
            description: "SMB share and WNet shared network resource enumerator",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: "lan.openfiles",
            category: ToolCategory::Lan,
            subcommand: "openfiles",
            nirsoft_name: "NetworkOpenedFiles",
            description: "SMB open file enumerator (NetFileEnum) paired with lan.openfiles.close",
            read_only: true,
            has_mutating_action: true,
        },
        ToolDescriptor {
            id: "lan.resolve",
            category: ToolCategory::Lan,
            subcommand: "resolve",
            nirsoft_name: "FastResolver",
            description: "Parallel forward/reverse DNS and IEEE MAC OUI resolver",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: "lan.speedtest",
            category: ToolCategory::Lan,
            subcommand: "speedtest",
            nirsoft_name: "DownTester",
            description: "Streaming HTTP/HTTPS download throughput benchmark",
            read_only: true,
            has_mutating_action: false,
        },
    ]
}

pub fn providers(ctx: &NetContext) -> Vec<Arc<dyn TableProvider>> {
    vec![
        Arc::new(PingInfoViewProvider::new(ctx.clone())),
        Arc::new(CountryTraceRouteProvider::new(ctx.clone())),
        Arc::new(LanIpScannerProvider::new(ctx.clone())),
        Arc::new(WirelessNetWatcherProvider::new(ctx.clone())),
        Arc::new(NetworkConnectLogProvider::new(ctx.clone())),
        Arc::new(WakeMeOnLanProvider::new(ctx.clone())),
        Arc::new(NetBScannerProvider::new(ctx.clone())),
        Arc::new(NetResViewProvider::new(ctx.clone())),
        Arc::new(NetworkOpenedFilesProvider::new(ctx.clone())),
        Arc::new(FastResolverProvider::new(ctx.clone())),
        Arc::new(DownTesterProvider::new(ctx.clone())),
    ]
}

pub fn actions(ctx: &NetContext) -> Vec<Arc<dyn ActionCommand>> {
    vec![
        Arc::new(WolSendAction::new(ctx.clone())),
        Arc::new(OpenFilesCloseAction::new(ctx.clone())),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lan_domain_exports_all_11_tools_and_2_actions() {
        let ctx = NetContext::offline(Default::default());
        assert_eq!(LanDomain::category(), ToolCategory::Lan);

        let descs = LanDomain::tool_descriptors();
        assert_eq!(descs.len(), 11);
        assert!(descs.iter().all(|d| d.category == ToolCategory::Lan && d.read_only));

        let provs = LanDomain::providers(&ctx);
        assert_eq!(provs.len(), 11);
        for (desc, prov) in descs.iter().zip(provs.iter()) {
            assert_eq!(desc.id, prov.tool_id());
            assert!(prov.is_read_only());
        }

        let acts = LanDomain::actions(&ctx);
        assert_eq!(acts.len(), 2);
        assert_eq!(acts[0].command_id(), "lan.wol.send");
        assert_eq!(acts[1].command_id(), "lan.openfiles.close");
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_feature_linkage() {
        use windows::Win32::NetworkManagement::IpHelper::{ICMPV6_ECHO_REPLY_LH, IP_OPTION_INFORMATION};
        use windows::Win32::NetworkManagement::WNet::NETRESOURCEW;
        use windows::Win32::Storage::FileSystem::{FILE_INFO_3, SHARE_INFO_1, SHARE_INFO_2};

        assert!(std::mem::size_of::<IP_OPTION_INFORMATION>() > 0);
        assert!(std::mem::size_of::<ICMPV6_ECHO_REPLY_LH>() > 0);
        assert!(std::mem::size_of::<FILE_INFO_3>() > 0);
        assert!(std::mem::size_of::<SHARE_INFO_1>() > 0);
        assert!(std::mem::size_of::<SHARE_INFO_2>() > 0);
        assert!(std::mem::size_of::<NETRESOURCEW>() > 0);
    }
}
