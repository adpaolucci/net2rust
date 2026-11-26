pub mod dns;
pub mod hosting;
pub mod ipnet;
pub mod ipoffline;
pub mod net_profiles;
pub mod oui;
pub mod set_dns;
pub mod whois_domain;
pub mod whoiscl;
pub mod whosip;

use std::sync::Arc;

use guap_table::TableProvider;
use net2rust_core::{NetContext, ToolCategory, ToolDescriptor};

pub fn tool_descriptors() -> Vec<ToolDescriptor> {
    vec![
        ToolDescriptor {
            id: ipnet::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "ipnet",
            nirsoft_name: "IPNetInfo",
            description: ipnet::DESCRIPTION,
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: whosip::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "whosip",
            nirsoft_name: "WhosIP",
            description: whosip::DESCRIPTION,
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: ipoffline::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "ipoffline",
            nirsoft_name: "IPInfoOffline",
            description: ipoffline::DESCRIPTION,
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: whois_domain::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "whois-domain",
            nirsoft_name: "WhoisThisDomain",
            description: whois_domain::DESCRIPTION,
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: whoiscl::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "whoiscl",
            nirsoft_name: "WhoisCL",
            description: whoiscl::DESCRIPTION,
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: dns::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "dns",
            nirsoft_name: "DNSDataView",
            description: dns::DESCRIPTION,
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: hosting::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "hosting",
            nirsoft_name: "DomainHostingView",
            description: hosting::DESCRIPTION,
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: oui::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "oui",
            nirsoft_name: "MACAddressView",
            description: oui::DESCRIPTION,
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: set_dns::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "set-dns",
            nirsoft_name: "QuickSetDNS",
            description: set_dns::DESCRIPTION,
            read_only: true,
            has_mutating_action: true,
        },
        ToolDescriptor {
            id: net_profiles::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "net-profiles",
            nirsoft_name: "NetConnectChoose",
            description: net_profiles::DESCRIPTION,
            read_only: true,
            has_mutating_action: true,
        },
    ]
}

pub fn providers(ctx: &NetContext) -> Vec<Arc<dyn TableProvider>> {
    vec![
        ipnet::provider(ctx),
        whosip::provider(ctx),
        ipoffline::provider(ctx),
        whois_domain::provider(ctx),
        whoiscl::provider(ctx),
        dns::provider(ctx),
        hosting::provider(ctx),
        oui::provider(ctx),
        set_dns::provider(ctx),
        net_profiles::provider(ctx),
    ]
}
