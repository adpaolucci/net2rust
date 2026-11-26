//! 10 WHOIS/RDAP, offline GeoIP/OUI, DNS, hosting, and Windows DNS/network profile tools for `net2rust`.

pub mod actions;
pub mod dns_wire;
pub mod geoip_db;
pub mod model;
pub mod oui_db;
pub mod tools;
pub mod transport;
pub mod whois;

use std::sync::Arc;

use guap_mcp::ActionCommand;
use guap_table::TableProvider;
use net2rust_core::{DomainCrateExport, NetContext, ToolCategory, ToolDescriptor};

pub struct OsintDomain;

impl DomainCrateExport for OsintDomain {
    fn category() -> ToolCategory {
        ToolCategory::Osint
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
    tools::tool_descriptors()
}

pub fn providers(ctx: &NetContext) -> Vec<Arc<dyn TableProvider>> {
    tools::providers(ctx)
}

pub fn actions(ctx: &NetContext) -> Vec<Arc<dyn ActionCommand>> {
    actions::actions(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osint_domain_metadata_counts() {
        let ctx = NetContext::offline(net2rust_core::OfflineConfig::default());
        assert_eq!(OsintDomain::category(), ToolCategory::Osint);
        assert_eq!(OsintDomain::tool_descriptors().len(), 10);
        assert_eq!(OsintDomain::providers(&ctx).len(), 10);
        assert_eq!(OsintDomain::actions(&ctx).len(), 3);
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_feature_linkage() {
        use windows::Win32::NetworkManagement::Dns::DNS_TYPE_A;
        use windows::Win32::Networking::NetworkListManager::NetworkListManager;

        assert_eq!(DNS_TYPE_A.0, 1);
        let _clsid = NetworkListManager;
    }
}
