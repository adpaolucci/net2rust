//! `net2rust-capture` — 11 zero-driver NDIS ETW, optional Npcap, and offline PCAP/PCAPNG/ETL
//! packet capture & protocol analyzer `TableProvider`s (R4 credential-free).

pub mod capture;
pub mod catalog;
pub mod decode;
pub mod r4_guard;
pub mod sha256;
pub mod tools;

use std::sync::Arc;

use guap_mcp::ActionCommand;
use guap_table::TableProvider;
use net2rust_core::{DomainCrateExport, NetContext, ToolCategory, ToolDescriptor};

pub struct CaptureDomain;

impl DomainCrateExport for CaptureDomain {
    fn category() -> ToolCategory {
        ToolCategory::Capture
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
    catalog::tool_descriptors()
}

pub fn providers(ctx: &NetContext) -> Vec<Arc<dyn TableProvider>> {
    tools::providers(ctx)
}

pub fn actions(_ctx: &NetContext) -> Vec<Arc<dyn ActionCommand>> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use guap_table::TableQuery;

    use super::*;
    use crate::capture::etw_ndis::{
        NDIS_EVENT_ID_PACKET_FRAGMENT, NDIS_PACKET_CAPTURE_GUID_BYTES, SyntheticEtwRecord, decode_ndis_packet_fragment,
        encode_synthetic_etl, parse_synthetic_etl,
    };
    use crate::capture::pcap::Endianness;
    use crate::capture::pcap::{encode_pcap_be_ns, encode_pcap_le_us, parse_pcap};
    use crate::capture::pcapng::{encode_pcapng, parse_pcapng};
    use crate::capture::{CapturedPacket, LinkType};

    #[test]
    fn test_capture_domain_exports_11_readonly_tools() {
        let ctx = NetContext::offline(Default::default());
        assert_eq!(CaptureDomain::category(), ToolCategory::Capture);
        let descriptors = CaptureDomain::tool_descriptors();
        let provs = CaptureDomain::providers(&ctx);
        assert_eq!(descriptors.len(), 11);
        assert_eq!(provs.len(), 11);
        assert!(CaptureDomain::actions(&ctx).is_empty());

        for (desc, prov) in descriptors.iter().zip(provs.iter()) {
            assert_eq!(desc.id, prov.tool_id());
            assert!(desc.read_only);
            assert!(!desc.has_mutating_action);
            assert!(prov.is_read_only());
            let table = prov.query(&TableQuery::default()).unwrap();
            assert!(!table.rows.is_empty(), "provider {} returned 0 rows", prov.tool_id());
        }
    }

    #[test]
    fn test_pcap_le_be_and_bounds() {
        let pkt = CapturedPacket {
            packet_no: 1,
            timestamp: Some(crate::capture::fixtures::base_timestamp()),
            link_type: LinkType::Ethernet,
            original_len: 4,
            interface_id: Some(0),
            interface_name: None,
            data: vec![1, 2, 3, 4],
        };

        let le_bytes = encode_pcap_le_us(LinkType::Ethernet, std::slice::from_ref(&pkt));
        let (hdr_le, pkts_le) = parse_pcap(&le_bytes).unwrap();
        assert_eq!(hdr_le.link_type, LinkType::Ethernet);
        assert_eq!(pkts_le.len(), 1);
        assert_eq!(pkts_le[0].data, vec![1, 2, 3, 4]);

        let be_bytes = encode_pcap_be_ns(LinkType::RawIp, std::slice::from_ref(&pkt));
        let (hdr_be, pkts_be) = parse_pcap(&be_bytes).unwrap();
        assert_eq!(hdr_be.link_type, LinkType::RawIp);
        assert_eq!(pkts_be.len(), 1);

        // Truncated header & zero snaplen & forged incl_len
        assert!(parse_pcap(&[0u8; 10]).is_err());
        let mut zero_snap = le_bytes.clone();
        zero_snap[16..20].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse_pcap(&zero_snap).is_err());

        let mut forged = le_bytes.clone();
        forged[32..36].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        assert!(parse_pcap(&forged).is_err());
    }

    #[test]
    fn test_pcapng_le_be_tsresol_and_trailing_mismatch() {
        let pkt = CapturedPacket {
            packet_no: 1,
            timestamp: Some(crate::capture::fixtures::base_timestamp()),
            link_type: LinkType::Ieee80211Radiotap,
            original_len: 5,
            interface_id: Some(0),
            interface_name: Some("wlan0mon".to_string()),
            data: vec![0, 0, 8, 0, 1],
        };

        let le_ng = encode_pcapng(
            &[(LinkType::Ieee80211Radiotap, "wlan0mon", 9)],
            std::slice::from_ref(&pkt),
            Endianness::Little,
        );
        let parsed_le = parse_pcapng(&le_ng).unwrap();
        assert_eq!(parsed_le.len(), 1);
        assert_eq!(parsed_le[0].link_type, LinkType::Ieee80211Radiotap);
        assert_eq!(parsed_le[0].interface_name.as_deref(), Some("wlan0mon"));

        // Binary ts_resol = 0x80 | 20 (2^-20 s) in Big Endian
        let be_ng = encode_pcapng(
            &[(LinkType::Ethernet, "eth0", 0x80 | 20)],
            std::slice::from_ref(&pkt),
            Endianness::Big,
        );
        let parsed_be = parse_pcapng(&be_ng).unwrap();
        assert_eq!(parsed_be.len(), 1);
        assert!(parsed_be[0].timestamp.is_some());

        // Trailing block length mismatch on SHB must fail cleanly
        let mut bad_ng = le_ng;
        let shb_len = u32::from_le_bytes([bad_ng[4], bad_ng[5], bad_ng[6], bad_ng[7]]) as usize;
        bad_ng[shb_len - 4..shb_len].copy_from_slice(&999u32.to_le_bytes());
        assert!(parse_pcapng(&bad_ng).is_err());
    }

    #[test]
    fn test_synthetic_etl_and_ndis_fragment_bounds() {
        let bytes = crate::capture::fixtures::build_default_synthetic_etl_bytes();
        let pkts = parse_synthetic_etl(&bytes).unwrap();
        assert!(!pkts.is_empty());

        // Truncated UserData (FragmentSize = 100, only 4 bytes available)
        let mut bad_ud = vec![1, 0, 0, 0, 1, 0, 0, 0, 100, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd];
        assert!(
            decode_ndis_packet_fragment(NDIS_EVENT_ID_PACKET_FRAGMENT, 133_000_000_000_000_000, &bad_ud, 1).is_err()
        );

        // Non-1001 event returns Ok(None)
        bad_ud[8] = 4;
        assert!(decode_ndis_packet_fragment(999, 0, &bad_ud, 1).unwrap().is_none());

        let rec = SyntheticEtwRecord {
            provider_guid: NDIS_PACKET_CAPTURE_GUID_BYTES,
            event_id: NDIS_EVENT_ID_PACKET_FRAGMENT,
            timestamp_filetime: 134_000_000_000_000_000,
            user_data: bad_ud,
        };
        let encoded = encode_synthetic_etl(&[rec]);
        let decoded = parse_synthetic_etl(&encoded).unwrap();
        assert_eq!(decoded.len(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_feature_linkage() {
        use windows::Win32::System::Diagnostics::Etw::{EVENT_TRACE_LOGFILEW, EVENT_TRACE_REAL_TIME_MODE};
        use windows::Win32::System::Time::TIME_ZONE_INFORMATION;

        assert_ne!(EVENT_TRACE_REAL_TIME_MODE, 0);
        assert!(std::mem::size_of::<EVENT_TRACE_LOGFILEW>() > 0);
        assert!(std::mem::size_of::<TIME_ZONE_INFORMATION>() > 0);
    }
}
