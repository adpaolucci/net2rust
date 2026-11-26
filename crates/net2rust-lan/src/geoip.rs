use std::cmp::Ordering;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::OnceLock;

use net2rust_core::{CidrV4, CidrV6, NetContext, NetError, NetResult};

use crate::common::parse_csv_fields;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoIpInfo {
    pub country_code: String,
    pub country_name: String,
    pub asn: String,
    pub as_org: String,
}

impl Default for GeoIpInfo {
    fn default() -> Self {
        Self {
            country_code: "--".to_string(),
            country_name: "Unknown".to_string(),
            asn: "AS0".to_string(),
            as_org: "Unassigned / Unknown".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4GeoEntry {
    pub start: u32,
    pub end: u32,
    pub country_code: &'static str,
    pub country_name: &'static str,
    pub asn: &'static str,
    pub as_org: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6GeoEntry {
    pub start: u128,
    pub end: u128,
    pub country_code: &'static str,
    pub country_name: &'static str,
    pub asn: &'static str,
    pub as_org: &'static str,
}

/// Strictly sorted, non-overlapping embedded IPv4 GeoIP/ASN ranges.
pub const GEOIP_V4: &[Ipv4GeoEntry] = &[
    // 0.0.0.0/8
    Ipv4GeoEntry {
        start: 0x0000_0000,
        end: 0x00FF_FFFF,
        country_code: "--",
        country_name: "Private/Unspecified",
        asn: "AS0",
        as_org: "IANA Unspecified",
    },
    // 1.0.0.0/24
    Ipv4GeoEntry {
        start: 0x0100_0000,
        end: 0x0100_00FF,
        country_code: "AU",
        country_name: "Australia",
        asn: "AS13335",
        as_org: "Cloudflare, Inc.",
    },
    // 1.1.1.0/24
    Ipv4GeoEntry {
        start: 0x0101_0100,
        end: 0x0101_01FF,
        country_code: "AU",
        country_name: "Australia",
        asn: "AS13335",
        as_org: "Cloudflare, Inc.",
    },
    // 8.8.4.0/24
    Ipv4GeoEntry {
        start: 0x0808_0400,
        end: 0x0808_04FF,
        country_code: "US",
        country_name: "United States",
        asn: "AS15169",
        as_org: "Google LLC",
    },
    // 8.8.8.0/24
    Ipv4GeoEntry {
        start: 0x0808_0800,
        end: 0x0808_08FF,
        country_code: "US",
        country_name: "United States",
        asn: "AS15169",
        as_org: "Google LLC",
    },
    // 9.9.9.0/24
    Ipv4GeoEntry {
        start: 0x0909_0900,
        end: 0x0909_09FF,
        country_code: "CH",
        country_name: "Switzerland",
        asn: "AS19281",
        as_org: "Quad9",
    },
    // 10.0.0.0/8
    Ipv4GeoEntry {
        start: 0x0A00_0000,
        end: 0x0AFF_FFFF,
        country_code: "--",
        country_name: "Private/LAN",
        asn: "AS0",
        as_org: "RFC 1918 Private",
    },
    // 100.64.0.0/10
    Ipv4GeoEntry {
        start: 0x6440_0000,
        end: 0x647F_FFFF,
        country_code: "--",
        country_name: "Shared/CGNAT",
        asn: "AS0",
        as_org: "RFC 6598 CGNAT",
    },
    // 127.0.0.0/8
    Ipv4GeoEntry {
        start: 0x7F00_0000,
        end: 0x7FFF_FFFF,
        country_code: "--",
        country_name: "Loopback",
        asn: "AS0",
        as_org: "Loopback",
    },
    // 169.254.0.0/16
    Ipv4GeoEntry {
        start: 0xA9FE_0000,
        end: 0xA9FE_FFFF,
        country_code: "--",
        country_name: "Link-Local",
        asn: "AS0",
        as_org: "RFC 3927 Link-Local",
    },
    // 172.16.0.0/12
    Ipv4GeoEntry {
        start: 0xAC10_0000,
        end: 0xAC1F_FFFF,
        country_code: "--",
        country_name: "Private/LAN",
        asn: "AS0",
        as_org: "RFC 1918 Private",
    },
    // 192.0.2.0/24
    Ipv4GeoEntry {
        start: 0xC000_0200,
        end: 0xC000_02FF,
        country_code: "--",
        country_name: "Documentation",
        asn: "AS0",
        as_org: "TEST-NET-1",
    },
    // 192.168.0.0/16
    Ipv4GeoEntry {
        start: 0xC0A8_0000,
        end: 0xC0A8_FFFF,
        country_code: "--",
        country_name: "Private/LAN",
        asn: "AS0",
        as_org: "RFC 1918 Private",
    },
    // 198.51.100.0/24
    Ipv4GeoEntry {
        start: 0xC633_6400,
        end: 0xC633_64FF,
        country_code: "--",
        country_name: "Documentation",
        asn: "AS0",
        as_org: "TEST-NET-2",
    },
    // 203.0.113.0/24
    Ipv4GeoEntry {
        start: 0xCB00_7100,
        end: 0xCB00_71FF,
        country_code: "--",
        country_name: "Documentation",
        asn: "AS0",
        as_org: "TEST-NET-3",
    },
    // 208.67.222.0/24
    Ipv4GeoEntry {
        start: 0xD043_DE00,
        end: 0xD043_DEFF,
        country_code: "US",
        country_name: "United States",
        asn: "AS36692",
        as_org: "Cisco OpenDNS, LLC",
    },
    // 224.0.0.0/4
    Ipv4GeoEntry {
        start: 0xE000_0000,
        end: 0xEFFF_FFFF,
        country_code: "--",
        country_name: "Multicast",
        asn: "AS0",
        as_org: "IANA Multicast",
    },
    // 240.0.0.0/4
    Ipv4GeoEntry {
        start: 0xF000_0000,
        end: 0xFFFF_FFFF,
        country_code: "--",
        country_name: "Reserved",
        asn: "AS0",
        as_org: "Reserved / Broadcast",
    },
];

/// Strictly sorted, non-overlapping embedded IPv6 GeoIP/ASN ranges.
pub const GEOIP_V6: &[Ipv6GeoEntry] = &[
    // ::/128
    Ipv6GeoEntry {
        start: 0,
        end: 0,
        country_code: "--",
        country_name: "Unspecified",
        asn: "AS0",
        as_org: "Unspecified",
    },
    // ::1/128
    Ipv6GeoEntry {
        start: 1,
        end: 1,
        country_code: "--",
        country_name: "Loopback",
        asn: "AS0",
        as_org: "Loopback",
    },
    // 2001:db8::/32
    Ipv6GeoEntry {
        start: 0x2001_0DB8_0000_0000_0000_0000_0000_0000,
        end: 0x2001_0DB8_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
        country_code: "--",
        country_name: "Documentation",
        asn: "AS0",
        as_org: "RFC 3849 Documentation",
    },
    // 2001:4860:4860::/48
    Ipv6GeoEntry {
        start: 0x2001_4860_4860_0000_0000_0000_0000_0000,
        end: 0x2001_4860_4860_FFFF_FFFF_FFFF_FFFF_FFFF,
        country_code: "US",
        country_name: "United States",
        asn: "AS15169",
        as_org: "Google LLC",
    },
    // 2606:4700:4700::/48
    Ipv6GeoEntry {
        start: 0x2606_4700_4700_0000_0000_0000_0000_0000,
        end: 0x2606_4700_4700_FFFF_FFFF_FFFF_FFFF_FFFF,
        country_code: "US",
        country_name: "United States",
        asn: "AS13335",
        as_org: "Cloudflare, Inc.",
    },
    // fc00::/7
    Ipv6GeoEntry {
        start: 0xFC00_0000_0000_0000_0000_0000_0000_0000,
        end: 0xFDFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
        country_code: "--",
        country_name: "Private/ULA",
        asn: "AS0",
        as_org: "RFC 4193 Unique Local",
    },
    // fe80::/10
    Ipv6GeoEntry {
        start: 0xFE80_0000_0000_0000_0000_0000_0000_0000,
        end: 0xFEBF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
        country_code: "--",
        country_name: "Link-Local",
        asn: "AS0",
        as_org: "RFC 4291 Link-Local",
    },
    // ff00::/8
    Ipv6GeoEntry {
        start: 0xFF00_0000_0000_0000_0000_0000_0000_0000,
        end: 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
        country_code: "--",
        country_name: "Multicast",
        asn: "AS0",
        as_org: "IPv6 Multicast",
    },
];

static EMBEDDED_READY: OnceLock<()> = OnceLock::new();

#[derive(Debug, Clone)]
struct CustomV4Rule {
    cidr: CidrV4,
    info: GeoIpInfo,
}

#[derive(Debug, Clone)]
struct CustomV6Rule {
    cidr: CidrV6,
    info: GeoIpInfo,
}

#[derive(Debug, Clone, Default)]
pub struct GeoIpDatabase {
    v4_overrides: Vec<CustomV4Rule>,
    v6_overrides: Vec<CustomV6Rule>,
}

impl GeoIpDatabase {
    pub fn embedded() -> Self {
        EMBEDDED_READY.get_or_init(|| ());
        Self::default()
    }

    pub fn from_csv_str(content: &str) -> NetResult<Self> {
        let mut v4_overrides = Vec::new();
        let mut v6_overrides = Vec::new();
        let mut seen_non_comment_row = false;
        for (line_no, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts = parse_csv_fields(line)
                .map_err(|err| NetError::ParseError(format!("GeoIP CSV line {}: {err}", line_no + 1)))?;
            if parts.len() < 5 {
                return Err(NetError::ParseError(format!(
                    "GeoIP CSV line {} expected 5 columns (cidr,country_code,country_name,asn,org): {line}",
                    line_no + 1
                )));
            }
            let is_first_row = !seen_non_comment_row;
            seen_non_comment_row = true;
            if is_first_row && parts[0].eq_ignore_ascii_case("cidr") {
                continue;
            }
            let info = GeoIpInfo {
                country_code: parts[1].clone(),
                country_name: parts[2].clone(),
                asn: parts[3].clone(),
                as_org: parts[4].clone(),
            };
            if let Ok(cidr4) = CidrV4::parse(&parts[0]) {
                v4_overrides.push(CustomV4Rule { cidr: cidr4, info });
            } else if let Ok(cidr6) = CidrV6::parse(&parts[0]) {
                v6_overrides.push(CustomV6Rule { cidr: cidr6, info });
            } else {
                return Err(NetError::ParseError(format!(
                    "GeoIP CSV line {} invalid CIDR: {}",
                    line_no + 1,
                    parts[0]
                )));
            }
        }
        // Most-specific prefix length wins.
        v4_overrides.sort_by_key(|a| std::cmp::Reverse(a.cidr.prefix_len()));
        v6_overrides.sort_by_key(|a| std::cmp::Reverse(a.cidr.prefix_len()));
        Ok(Self {
            v4_overrides,
            v6_overrides,
        })
    }

    pub fn from_file(path: &Path) -> NetResult<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_csv_str(&content)
    }

    pub fn for_context(ctx: &NetContext) -> NetResult<Self> {
        if let Some(path) = ctx.offline_config().and_then(|c| c.geoip_db_path.as_ref()) {
            Self::from_file(path)
        } else {
            Ok(Self::embedded())
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> GeoIpInfo {
        match ip {
            IpAddr::V4(v4) => {
                for rule in &self.v4_overrides {
                    if rule.cidr.contains(v4) {
                        return rule.info.clone();
                    }
                }
                lookup_v4_embedded(v4).unwrap_or_default()
            }
            IpAddr::V6(v6) => {
                for rule in &self.v6_overrides {
                    if rule.cidr.contains(v6) {
                        return rule.info.clone();
                    }
                }
                lookup_v6_embedded(v6).unwrap_or_default()
            }
        }
    }
}

pub fn lookup_v4_embedded(ip: Ipv4Addr) -> Option<GeoIpInfo> {
    let val = u32::from(ip);
    GEOIP_V4
        .binary_search_by(|entry| {
            if val < entry.start {
                Ordering::Greater
            } else if val > entry.end {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        })
        .ok()
        .map(|idx| {
            let e = &GEOIP_V4[idx];
            GeoIpInfo {
                country_code: e.country_code.to_string(),
                country_name: e.country_name.to_string(),
                asn: e.asn.to_string(),
                as_org: e.as_org.to_string(),
            }
        })
}

pub fn lookup_v6_embedded(ip: Ipv6Addr) -> Option<GeoIpInfo> {
    let val = u128::from(ip);
    GEOIP_V6
        .binary_search_by(|entry| {
            if val < entry.start {
                Ordering::Greater
            } else if val > entry.end {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        })
        .ok()
        .map(|idx| {
            let e = &GEOIP_V6[idx];
            GeoIpInfo {
                country_code: e.country_code.to_string(),
                country_name: e.country_name.to_string(),
                asn: e.asn.to_string(),
                as_org: e.as_org.to_string(),
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geoip_tables_sorted_and_non_overlapping() {
        assert!(!GEOIP_V4.is_empty());
        for entry in GEOIP_V4 {
            assert!(entry.start <= entry.end);
        }
        for pair in GEOIP_V4.windows(2) {
            assert!(
                pair[0].end < pair[1].start,
                "GEOIP_V4 overlap or unsorted: {:#x}..={:#x} vs {:#x}..={:#x}",
                pair[0].start,
                pair[0].end,
                pair[1].start,
                pair[1].end
            );
        }

        assert!(!GEOIP_V6.is_empty());
        for entry in GEOIP_V6 {
            assert!(entry.start <= entry.end);
        }
        for pair in GEOIP_V6.windows(2) {
            assert!(
                pair[0].end < pair[1].start,
                "GEOIP_V6 overlap or unsorted: {:#x}..={:#x} vs {:#x}..={:#x}",
                pair[0].start,
                pair[0].end,
                pair[1].start,
                pair[1].end
            );
        }
    }

    #[test]
    fn test_geoip_lookup_and_csv_override() {
        let db = GeoIpDatabase::embedded();
        let lan = db.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(lan.country_code, "--");
        assert_eq!(lan.country_name, "Private/LAN");

        let dns = db.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(dns.country_code, "US");
        assert_eq!(dns.asn, "AS15169");

        let v6_doc = db.lookup(IpAddr::V6("2001:db8::42".parse().unwrap()));
        assert_eq!(v6_doc.country_name, "Documentation");

        let csv = "cidr,country_code,country_name,asn,org\n198.51.100.0/24,CA,Canada,AS64512,Lab Transit\n";
        let custom = GeoIpDatabase::from_csv_str(csv).unwrap();
        let hit = custom.lookup(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
        assert_eq!(hit.country_code, "CA");
        assert_eq!(hit.asn, "AS64512");
        assert_eq!(hit.as_org, "Lab Transit");
    }

    #[test]
    fn test_geoip_csv_comments_blank_lines_and_quoted_fields() {
        let csv = "\n# Generated 2026-11-23\n   \n# Second comment\ncidr,country_code,country_name,asn,org\n1.1.1.0/24,KR,\"Korea, Republic of\",AS13335,\"Cloudflare, Inc.\"\n198.51.100.0/24,US,United States,AS64513,\"Acme \"\"Edge\"\", LLC\"\n";
        let db = GeoIpDatabase::from_csv_str(csv).unwrap();

        let kr = db.lookup(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(kr.country_code, "KR");
        assert_eq!(kr.country_name, "Korea, Republic of");
        assert_eq!(kr.asn, "AS13335");
        assert_eq!(kr.as_org, "Cloudflare, Inc.");

        let acme = db.lookup(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
        assert_eq!(acme.as_org, r#"Acme "Edge", LLC"#);

        // Header after data rows must still error cleanly.
        let late_header =
            "1.1.1.0/24,AU,Australia,AS13335,\"Cloudflare, Inc.\"\ncidr,country_code,country_name,asn,org\n";
        assert!(matches!(
            GeoIpDatabase::from_csv_str(late_header),
            Err(NetError::ParseError(_))
        ));

        // Unclosed quote must error cleanly.
        let bad_quote = "cidr,country_code,country_name,asn,org\n1.1.1.0/24,AU,Australia,AS13335,\"Cloudflare\n";
        assert!(matches!(
            GeoIpDatabase::from_csv_str(bad_quote),
            Err(NetError::ParseError(_))
        ));
    }
}
