use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::OnceLock;

use net2rust_core::{CidrV4, CidrV6, NetError, NetResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpOfflineRecord {
    pub ip_address: String,
    pub country_code: String,
    pub country_name: String,
    pub continent: String,
    pub asn: Option<u32>,
    pub as_name: String,
    pub matched_cidr: Option<String>,
}

#[derive(Debug, Clone)]
struct GeoAsnMeta {
    country_code: String,
    country_name: String,
    continent: String,
    asn: Option<u32>,
    as_name: String,
}

#[derive(Debug, Clone, Copy)]
struct V4Entry {
    net: u32,
    meta_idx: usize,
}

#[derive(Debug, Clone, Copy)]
struct V6Entry {
    net: u128,
    meta_idx: usize,
}

#[derive(Debug, Clone)]
struct V4Bucket {
    prefix_len: u8,
    mask: u32,
    entries: Vec<V4Entry>,
}

#[derive(Debug, Clone)]
struct V6Bucket {
    prefix_len: u8,
    mask: u128,
    entries: Vec<V6Entry>,
}

/// Embedded + extensible Longest-Prefix Match (LPM) IPv4/IPv6 GeoIP + ASN database.
#[derive(Debug, Clone)]
pub struct OfflineIpDb {
    metas: Vec<GeoAsnMeta>,
    v4_buckets: Vec<V4Bucket>,
    v6_buckets: Vec<V6Bucket>,
}

impl Default for OfflineIpDb {
    fn default() -> Self {
        Self::embedded()
    }
}

static EMBEDDED_DB: OnceLock<OfflineIpDb> = OnceLock::new();

impl OfflineIpDb {
    /// Returns a cloned copy of the cached embedded IPv4/IPv6 LPM database.
    pub fn embedded() -> Self {
        EMBEDDED_DB.get_or_init(Self::build_embedded).clone()
    }

    /// Creates an empty LPM database (useful for testing custom CSV overrides in isolation).
    pub fn empty() -> Self {
        Self {
            metas: Vec::new(),
            v4_buckets: Vec::new(),
            v6_buckets: Vec::new(),
        }
    }

    fn build_embedded() -> Self {
        let mut builder = DbBuilder::default();
        for &(cidr, cc, cname, cont, asn, as_name) in EMBEDDED_V4_ENTRIES {
            if let Ok(parsed) = CidrV4::parse(cidr) {
                builder.insert_v4(
                    parsed,
                    GeoAsnMeta {
                        country_code: cc.to_string(),
                        country_name: cname.to_string(),
                        continent: cont.to_string(),
                        asn,
                        as_name: as_name.to_string(),
                    },
                );
            }
        }
        for &(cidr, cc, cname, cont, asn, as_name) in EMBEDDED_V6_ENTRIES {
            if let Ok(parsed) = CidrV6::parse(cidr) {
                builder.insert_v6(
                    parsed,
                    GeoAsnMeta {
                        country_code: cc.to_string(),
                        country_name: cname.to_string(),
                        continent: cont.to_string(),
                        asn,
                        as_name: as_name.to_string(),
                    },
                );
            }
        }
        builder.build()
    }

    /// Loads additional CSV rows (`cidr,country_code,country_name,continent,asn,as_name`)
    /// and merges them into this database (more-specific or newly inserted prefixes win).
    pub fn merge_csv_file(&mut self, path: &Path) -> NetResult<usize> {
        let content = fs::read_to_string(path)
            .map_err(|e| NetError::InvalidInput(format!("failed to read GeoIP CSV '{}': {e}", path.display())))?;
        self.merge_csv_str(&content)
    }

    /// Parses and merges CSV lines (`cidr,country_code,country_name,continent,asn,as_name`).
    pub fn merge_csv_str(&mut self, csv_text: &str) -> NetResult<usize> {
        let mut builder = DbBuilder::from_existing(self);
        let mut count = 0usize;
        let mut seen_non_comment = false;
        for (line_no, raw_line) in csv_text.lines().enumerate() {
            let line = raw_line.trim_start_matches('\u{FEFF}').trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if !seen_non_comment {
                seen_non_comment = true;
                if line.to_ascii_lowercase().starts_with("cidr,") {
                    continue;
                }
            }
            let parts = parse_csv_line(line);
            if parts.len() < 6 {
                return Err(NetError::ParseError(format!(
                    "GeoIP CSV line {} expected 6 columns, got {}",
                    line_no + 1,
                    parts.len()
                )));
            }
            let cidr_str = parts[0].trim();
            let asn =
                if parts[4].trim().is_empty() {
                    None
                } else {
                    Some(parts[4].trim().parse::<u32>().map_err(|_| {
                        NetError::ParseError(format!("invalid ASN '{}' on line {}", parts[4], line_no + 1))
                    })?)
                };
            let meta = GeoAsnMeta {
                country_code: parts[1].trim().to_string(),
                country_name: parts[2].trim().to_string(),
                continent: parts[3].trim().to_string(),
                asn,
                as_name: parts[5].trim().to_string(),
            };
            if let Ok(v4) = CidrV4::parse(cidr_str) {
                builder.insert_v4(v4, meta);
            } else if let Ok(v6) = CidrV6::parse(cidr_str) {
                builder.insert_v6(v6, meta);
            } else {
                return Err(NetError::ParseError(format!(
                    "invalid CIDR '{cidr_str}' on line {}",
                    line_no + 1
                )));
            }
            count += 1;
        }
        *self = builder.build();
        Ok(count)
    }

    /// Performs deterministic longest-prefix match lookup for an IPv4 or IPv6 address.
    pub fn lookup(&self, ip: IpAddr) -> IpOfflineRecord {
        match ip {
            IpAddr::V4(v4) => self.lookup_v4(v4, &ip.to_string()),
            IpAddr::V6(v6) => {
                if let Some((prefix_len, net, meta)) = self.match_v6(v6) {
                    // If the only IPv6 hit is ::ffff:0:0/96 or broader and v4-mapped, prefer inner IPv4 when more specific
                    if let Some(mapped) = v6.to_ipv4_mapped()
                        && prefix_len <= 96
                    {
                        let v4_rec = self.lookup_v4(mapped, &ip.to_string());
                        if v4_rec.matched_cidr.is_some() {
                            return v4_rec;
                        }
                    }
                    let matched = format!("{}/{}", Ipv6Addr::from(net), prefix_len);
                    return IpOfflineRecord {
                        ip_address: ip.to_string(),
                        country_code: meta.country_code.clone(),
                        country_name: meta.country_name.clone(),
                        continent: meta.continent.clone(),
                        asn: meta.asn,
                        as_name: meta.as_name.clone(),
                        matched_cidr: Some(matched),
                    };
                }
                if let Some(mapped) = v6.to_ipv4_mapped() {
                    let v4_rec = self.lookup_v4(mapped, &ip.to_string());
                    if v4_rec.matched_cidr.is_some() {
                        return v4_rec;
                    }
                }
                unknown_record(&ip.to_string())
            }
        }
    }

    fn lookup_v4(&self, ip: Ipv4Addr, display_ip: &str) -> IpOfflineRecord {
        let bits = u32::from(ip);
        for bucket in &self.v4_buckets {
            let masked = bits & bucket.mask;
            if let Ok(idx) = bucket.entries.binary_search_by_key(&masked, |e| e.net) {
                let meta = &self.metas[bucket.entries[idx].meta_idx];
                return IpOfflineRecord {
                    ip_address: display_ip.to_string(),
                    country_code: meta.country_code.clone(),
                    country_name: meta.country_name.clone(),
                    continent: meta.continent.clone(),
                    asn: meta.asn,
                    as_name: meta.as_name.clone(),
                    matched_cidr: Some(format!("{}/{}", Ipv4Addr::from(masked), bucket.prefix_len)),
                };
            }
        }
        unknown_record(display_ip)
    }

    fn match_v6(&self, ip: Ipv6Addr) -> Option<(u8, u128, &GeoAsnMeta)> {
        let bits = u128::from(ip);
        for bucket in &self.v6_buckets {
            let masked = bits & bucket.mask;
            if let Ok(idx) = bucket.entries.binary_search_by_key(&masked, |e| e.net) {
                let meta = &self.metas[bucket.entries[idx].meta_idx];
                return Some((bucket.prefix_len, masked, meta));
            }
        }
        None
    }

    /// Default seed IPs returned when `osint.ipoffline` is queried without a target filter.
    pub fn default_seed_ips() -> &'static [&'static str] {
        &[
            "1.1.1.1",
            "8.8.8.8",
            "9.9.9.9",
            "93.184.216.34",
            "193.0.0.1",
            "202.12.27.33",
            "192.168.1.1",
            "127.0.0.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ]
    }
}

fn unknown_record(ip: &str) -> IpOfflineRecord {
    IpOfflineRecord {
        ip_address: ip.to_string(),
        country_code: "ZZ".to_string(),
        country_name: "Unallocated / Unknown".to_string(),
        continent: "Unknown".to_string(),
        asn: None,
        as_name: "UNKNOWN".to_string(),
        matched_cidr: None,
    }
}

#[derive(Default)]
struct DbBuilder {
    metas: Vec<GeoAsnMeta>,
    v4_map: BTreeMap<u8, BTreeMap<u32, usize>>,
    v6_map: BTreeMap<u8, BTreeMap<u128, usize>>,
}

impl DbBuilder {
    fn from_existing(db: &OfflineIpDb) -> Self {
        let mut builder = Self {
            metas: db.metas.clone(),
            v4_map: BTreeMap::new(),
            v6_map: BTreeMap::new(),
        };
        for bucket in &db.v4_buckets {
            let map = builder.v4_map.entry(bucket.prefix_len).or_default();
            for entry in &bucket.entries {
                map.insert(entry.net, entry.meta_idx);
            }
        }
        for bucket in &db.v6_buckets {
            let map = builder.v6_map.entry(bucket.prefix_len).or_default();
            for entry in &bucket.entries {
                map.insert(entry.net, entry.meta_idx);
            }
        }
        builder
    }

    fn insert_v4(&mut self, cidr: CidrV4, meta: GeoAsnMeta) {
        let meta_idx = self.metas.len();
        self.metas.push(meta);
        self.v4_map
            .entry(cidr.prefix_len())
            .or_default()
            .insert(u32::from(cidr.network()), meta_idx);
    }

    fn insert_v6(&mut self, cidr: CidrV6, meta: GeoAsnMeta) {
        let meta_idx = self.metas.len();
        self.metas.push(meta);
        self.v6_map
            .entry(cidr.prefix_len())
            .or_default()
            .insert(u128::from(cidr.network()), meta_idx);
    }

    fn build(self) -> OfflineIpDb {
        let v4_buckets = self
            .v4_map
            .into_iter()
            .rev()
            .map(|(prefix_len, map)| V4Bucket {
                prefix_len,
                mask: if prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix_len)
                },
                entries: map
                    .into_iter()
                    .map(|(net, meta_idx)| V4Entry { net, meta_idx })
                    .collect(),
            })
            .collect();

        let v6_buckets = self
            .v6_map
            .into_iter()
            .rev()
            .map(|(prefix_len, map)| V6Bucket {
                prefix_len,
                mask: if prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix_len)
                },
                entries: map
                    .into_iter()
                    .map(|(net, meta_idx)| V6Entry { net, meta_idx })
                    .collect(),
            })
            .collect();

        OfflineIpDb {
            metas: self.metas,
            v4_buckets,
            v6_buckets,
        }
    }
}

pub(crate) fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                current.push(c);
            }
        } else if c == '"' {
            in_quotes = true;
        } else if c == ',' {
            fields.push(current.clone());
            current.clear();
        } else {
            current.push(c);
        }
    }
    fields.push(current);
    fields
}

type StaticCidrRow = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Option<u32>,
    &'static str,
);

const EMBEDDED_V4_ENTRIES: &[StaticCidrRow] = &[
    // IANA Special-Use / Reserved IPv4
    (
        "0.0.0.0/8",
        "ZZ",
        "This Host on This Network",
        "Reserved",
        None,
        "IANA-SPECIAL-USE",
    ),
    (
        "10.0.0.0/8",
        "ZZ",
        "Private-Use (RFC 1918)",
        "Private",
        None,
        "RFC1918-PRIVATE",
    ),
    (
        "100.64.0.0/10",
        "ZZ",
        "Shared Address Space (CGNAT)",
        "Reserved",
        None,
        "RFC6598-CGNAT",
    ),
    (
        "127.0.0.0/8",
        "ZZ",
        "Loopback (RFC 1122)",
        "Reserved",
        None,
        "IANA-LOOPBACK",
    ),
    (
        "169.254.0.0/16",
        "ZZ",
        "Link-Local (RFC 3927)",
        "Reserved",
        None,
        "IANA-LINK-LOCAL",
    ),
    (
        "172.16.0.0/12",
        "ZZ",
        "Private-Use (RFC 1918)",
        "Private",
        None,
        "RFC1918-PRIVATE",
    ),
    (
        "192.0.0.0/24",
        "ZZ",
        "IETF Protocol Assignments",
        "Reserved",
        None,
        "IANA-PROTOCOL",
    ),
    (
        "192.0.2.0/24",
        "ZZ",
        "TEST-NET-1 (RFC 5737)",
        "Reserved",
        None,
        "IANA-DOC-NET1",
    ),
    (
        "192.88.99.0/24",
        "ZZ",
        "6to4 Relay Anycast (Deprecated)",
        "Reserved",
        None,
        "IANA-6TO4",
    ),
    (
        "192.168.0.0/16",
        "ZZ",
        "Private-Use (RFC 1918)",
        "Private",
        None,
        "RFC1918-PRIVATE",
    ),
    (
        "198.18.0.0/15",
        "ZZ",
        "Benchmarking (RFC 2544)",
        "Reserved",
        None,
        "IANA-BENCHMARK",
    ),
    (
        "198.51.100.0/24",
        "ZZ",
        "TEST-NET-2 (RFC 5737)",
        "Reserved",
        None,
        "IANA-DOC-NET2",
    ),
    (
        "203.0.113.0/24",
        "ZZ",
        "TEST-NET-3 (RFC 5737)",
        "Reserved",
        None,
        "IANA-DOC-NET3",
    ),
    (
        "224.0.0.0/4",
        "ZZ",
        "Multicast (RFC 5771)",
        "Reserved",
        None,
        "IANA-MULTICAST",
    ),
    (
        "240.0.0.0/4",
        "ZZ",
        "Reserved for Future Use",
        "Reserved",
        None,
        "IANA-FUTURE-USE",
    ),
    // Overlapping /8 + specific /24 pairs to exercise Longest-Prefix Match
    ("1.0.0.0/8", "AU", "Australia", "OC", Some(1221), "TELSTRA-NET"),
    ("1.0.0.0/24", "AU", "Australia", "OC", Some(13335), "CLOUDFLARENET"),
    ("1.1.1.0/24", "AU", "Australia", "OC", Some(13335), "CLOUDFLARENET"),
    ("4.0.0.0/8", "US", "United States", "NA", Some(3356), "LEVEL3"),
    ("8.0.0.0/8", "US", "United States", "NA", Some(3356), "LEVEL3"),
    ("8.8.4.0/24", "US", "United States", "NA", Some(15169), "GOOGLE"),
    ("8.8.8.0/24", "US", "United States", "NA", Some(15169), "GOOGLE"),
    ("9.0.0.0/8", "US", "United States", "NA", Some(1239), "IBM-NET"),
    ("9.9.9.0/24", "US", "United States", "NA", Some(19281), "QUAD9-AS"),
    // Major Anycast, DNS, Cloud & CDN
    ("3.0.0.0/8", "US", "United States", "NA", Some(16509), "AMAZON-02"),
    (
        "13.64.0.0/11",
        "US",
        "United States",
        "NA",
        Some(8075),
        "MICROSOFT-CORP-MSN-AS-BLOCK",
    ),
    (
        "17.0.0.0/8",
        "US",
        "United States",
        "NA",
        Some(714),
        "APPLE-ENGINEERING",
    ),
    (
        "20.0.0.0/11",
        "US",
        "United States",
        "NA",
        Some(8075),
        "MICROSOFT-CORP-MSN-AS-BLOCK",
    ),
    ("23.0.0.0/12", "US", "United States", "NA", Some(20940), "AKAMAI-ASN1"),
    (
        "34.64.0.0/10",
        "US",
        "United States",
        "NA",
        Some(396982),
        "GOOGLE-CLOUD-PLATFORM",
    ),
    (
        "35.184.0.0/13",
        "US",
        "United States",
        "NA",
        Some(15169),
        "GOOGLE-CLOUD",
    ),
    ("44.0.0.0/8", "US", "United States", "NA", Some(7377), "AMPRNET"),
    ("52.0.0.0/10", "US", "United States", "NA", Some(16509), "AMAZON-AES"),
    ("54.144.0.0/12", "US", "United States", "NA", Some(14618), "AMAZON-AES"),
    ("64.233.160.0/19", "US", "United States", "NA", Some(15169), "GOOGLE"),
    ("74.125.0.0/16", "US", "United States", "NA", Some(15169), "GOOGLE"),
    ("93.184.216.0/24", "US", "United States", "NA", Some(15133), "EDGECAST"),
    (
        "104.16.0.0/12",
        "US",
        "United States",
        "NA",
        Some(13335),
        "CLOUDFLARENET",
    ),
    ("140.82.112.0/20", "US", "United States", "NA", Some(36459), "GITHUB"),
    ("142.250.0.0/15", "US", "United States", "NA", Some(15169), "GOOGLE"),
    ("151.101.0.0/16", "US", "United States", "NA", Some(54113), "FASTLY"),
    ("157.240.0.0/16", "US", "United States", "NA", Some(32934), "FACEBOOK"),
    ("172.217.0.0/16", "US", "United States", "NA", Some(15169), "GOOGLE"),
    (
        "185.199.108.0/22",
        "US",
        "United States",
        "NA",
        Some(54113),
        "FASTLY-GITHUB-PAGES",
    ),
    ("192.30.252.0/22", "US", "United States", "NA", Some(36459), "GITHUB"),
    ("199.232.0.0/16", "US", "United States", "NA", Some(54113), "FASTLY"),
    (
        "208.67.220.0/24",
        "US",
        "United States",
        "NA",
        Some(36692),
        "CISCO-UMBRELLA-OPENDNS",
    ),
    (
        "208.67.222.0/24",
        "US",
        "United States",
        "NA",
        Some(36692),
        "CISCO-UMBRELLA-OPENDNS",
    ),
    // North America (CA, MX)
    ("24.48.0.0/12", "CA", "Canada", "NA", Some(577), "BELL-CANADA"),
    ("99.224.0.0/11", "CA", "Canada", "NA", Some(812), "ROGERS-CABLE"),
    ("142.0.0.0/8", "CA", "Canada", "NA", Some(852), "TELUS-NET"),
    ("187.128.0.0/10", "MX", "Mexico", "NA", Some(8151), "UNINET-MX"),
    ("201.144.0.0/12", "MX", "Mexico", "NA", Some(8151), "UNINET-MX"),
    // Europe (RIPE NCC: NL, GB, DE, FR, CH, SE, RU)
    ("80.0.0.0/8", "DE", "Germany", "EU", Some(3320), "DTAG-DEUTSCHE-TELEKOM"),
    ("81.0.0.0/8", "GB", "United Kingdom", "EU", Some(2856), "BT-UK-AS"),
    (
        "82.0.0.0/8",
        "GB",
        "United Kingdom",
        "EU",
        Some(5089),
        "NTL-VIRGIN-MEDIA",
    ),
    ("85.0.0.0/8", "DE", "Germany", "EU", Some(3320), "DTAG"),
    ("88.0.0.0/8", "FR", "France", "EU", Some(3215), "ORANGE-FR"),
    ("90.0.0.0/8", "FR", "France", "EU", Some(3215), "ORANGE-FR"),
    ("130.237.0.0/16", "SE", "Sweden", "EU", Some(1653), "SUNET"),
    ("145.0.0.0/8", "NL", "Netherlands", "EU", Some(1103), "SURFNET-NL"),
    ("176.0.0.0/8", "DE", "Germany", "EU", Some(24940), "HETZNER-AS"),
    ("193.0.0.0/21", "NL", "Netherlands", "EU", Some(3333), "RIPE-NCC-AS"),
    ("193.0.14.0/24", "NL", "Netherlands", "EU", Some(25152), "RIPE-K-ROOT"),
    ("194.0.0.0/8", "GB", "United Kingdom", "EU", Some(786), "JANET"),
    ("195.0.0.0/8", "CH", "Switzerland", "EU", Some(3303), "SWISSCOM"),
    ("212.0.0.0/8", "DE", "Germany", "EU", Some(6805), "TELEFONICA-DE"),
    ("213.0.0.0/8", "NL", "Netherlands", "EU", Some(1136), "KPN"),
    // Asia-Pacific (APNIC: JP, SG, KR, IN, CN, AU)
    ("101.0.0.0/8", "CN", "China", "AS", Some(4134), "CHINANET-BACKBONE"),
    ("103.0.0.0/8", "SG", "Singapore", "AS", Some(4657), "STARHUB-INTERNET"),
    ("114.0.0.0/8", "CN", "China", "AS", Some(4837), "CHINA169-BACKBONE"),
    ("118.0.0.0/8", "KR", "South Korea", "AS", Some(4766), "KIXS-AS-KR"),
    ("119.0.0.0/8", "JP", "Japan", "AS", Some(2516), "KDDI"),
    ("122.0.0.0/8", "IN", "India", "AS", Some(9829), "BSNL-NIB"),
    ("126.0.0.0/8", "JP", "Japan", "AS", Some(17676), "SOFTBANK-CORP"),
    ("202.0.0.0/8", "JP", "Japan", "AS", Some(2497), "IIJ"),
    ("202.12.27.0/24", "JP", "Japan", "AS", Some(25152), "WIDE-M-ROOT"),
    ("203.0.0.0/8", "AU", "Australia", "OC", Some(1221), "TELSTRA"),
    ("210.0.0.0/8", "JP", "Japan", "AS", Some(4713), "OCN-NTT"),
    // Latin America & Caribbean (LACNIC: BR, AR, CL)
    ("177.0.0.0/8", "BR", "Brazil", "SA", Some(28573), "CLARO-BR"),
    ("179.0.0.0/8", "BR", "Brazil", "SA", Some(27699), "TELEFONICA-BR"),
    ("181.0.0.0/8", "AR", "Argentina", "SA", Some(7303), "TELECOM-ARGENTINA"),
    ("190.0.0.0/8", "AR", "Argentina", "SA", Some(22927), "TELEFONICA-AR"),
    ("200.0.0.0/8", "BR", "Brazil", "SA", Some(4230), "EMBRATEL-BR"),
    // Africa (AFRINIC: ZA, KE, NG, EG)
    ("41.0.0.0/8", "ZA", "South Africa", "AF", Some(37100), "SEACOM-AS"),
    ("102.0.0.0/8", "KE", "Kenya", "AF", Some(33771), "SAFARICOM-LIMITED"),
    ("105.0.0.0/8", "NG", "Nigeria", "AF", Some(29465), "MTN-NIGERIA"),
    ("196.0.0.0/8", "ZA", "South Africa", "AF", Some(3741), "IS-ZA"),
    ("197.0.0.0/8", "EG", "Egypt", "AF", Some(8452), "TE-AS-EG"),
];

const EMBEDDED_V6_ENTRIES: &[StaticCidrRow] = &[
    // IANA Special-Use IPv6
    ("::1/128", "ZZ", "IPv6 Loopback", "Reserved", None, "IANA-LOOPBACK-V6"),
    (
        "::ffff:0:0/96",
        "ZZ",
        "IPv4-Mapped IPv6",
        "Reserved",
        None,
        "IANA-V4-MAPPED",
    ),
    (
        "fc00::/7",
        "ZZ",
        "Unique Local Address (RFC 4193)",
        "Private",
        None,
        "RFC4193-ULA",
    ),
    (
        "fe80::/10",
        "ZZ",
        "Link-Local Unicast (RFC 4291)",
        "Reserved",
        None,
        "IANA-LINK-LOCAL-V6",
    ),
    (
        "ff00::/8",
        "ZZ",
        "Multicast (RFC 4291)",
        "Reserved",
        None,
        "IANA-MULTICAST-V6",
    ),
    (
        "2001:db8::/32",
        "ZZ",
        "Documentation (RFC 3849)",
        "Reserved",
        None,
        "IANA-DOC-V6",
    ),
    // Overlapping /32 + specific /48 pairs for LPM verification
    ("2001:4860::/32", "US", "United States", "NA", Some(15169), "GOOGLE"),
    (
        "2001:4860:4860::/48",
        "US",
        "United States",
        "NA",
        Some(15169),
        "GOOGLE-PUBLIC-DNS",
    ),
    (
        "2606:4700::/32",
        "US",
        "United States",
        "NA",
        Some(13335),
        "CLOUDFLARENET",
    ),
    (
        "2606:4700:4700::/48",
        "US",
        "United States",
        "NA",
        Some(13335),
        "CLOUDFLARE-DNS",
    ),
    ("2620:fe::/48", "US", "United States", "NA", Some(19281), "QUAD9-AS"),
    (
        "2606:2800:220::/48",
        "US",
        "United States",
        "NA",
        Some(15133),
        "EDGECAST",
    ),
    (
        "2603:1000::/24",
        "US",
        "United States",
        "NA",
        Some(8075),
        "MICROSOFT-CORP",
    ),
    ("2a00:1450::/32", "IE", "Ireland", "EU", Some(15169), "GOOGLE-EU"),
    (
        "2001:67c:2e8::/48",
        "NL",
        "Netherlands",
        "EU",
        Some(3333),
        "RIPE-NCC-AS",
    ),
    ("2001:dc0::/32", "JP", "Japan", "AS", Some(2515), "APNIC-JP"),
    ("2800::/12", "BR", "Brazil", "SA", Some(28573), "LACNIC-BR"),
    ("2c0f:f000::/20", "ZA", "South Africa", "AF", Some(3741), "AFRINIC-ZA"),
];
