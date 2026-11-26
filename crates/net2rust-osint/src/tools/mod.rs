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
            display_name: "RIR WHOIS / RDAP IP Ownership",
            description: ipnet::DESCRIPTION,
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: whosip::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "whosip",
            display_name: "IP WHOIS & Referral Chasing",
            description: whosip::DESCRIPTION,
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: ipoffline::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "ipoffline",
            display_name: "Embedded GeoIP & ASN Lookup",
            description: ipoffline::DESCRIPTION,
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: whois_domain::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "whois-domain",
            display_name: "Domain WHOIS & RDAP",
            description: whois_domain::DESCRIPTION,
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: whoiscl::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "whoiscl",
            display_name: "Batch WHOIS Query Runner",
            description: whoiscl::DESCRIPTION,
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: dns::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "dns",
            display_name: "RFC 1035 DNS Record Resolver",
            description: dns::DESCRIPTION,
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: hosting::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "hosting",
            display_name: "Domain Infrastructure & Hosting Profiler",
            description: hosting::DESCRIPTION,
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: oui::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "oui",
            display_name: "IEEE MAC OUI Vendor Lookup",
            description: oui::DESCRIPTION,
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: set_dns::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "set-dns",
            display_name: "Interface DNS Configuration",
            description: set_dns::DESCRIPTION,
            read_only: true,
            has_mutating_action: true,
        },
        ToolDescriptor {
            id: net_profiles::TOOL_ID,
            category: ToolCategory::Osint,
            subcommand: "net-profiles",
            display_name: "Windows NetworkList Profiles",
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
