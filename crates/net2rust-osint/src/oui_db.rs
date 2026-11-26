use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use net2rust_core::{MacAddr, NetError, NetResult};
use serde::{Deserialize, Serialize};

use crate::geoip_db::parse_csv_line;

const MASK_MAL: u64 = 0xFFFF_FF00_0000_0000;
const MASK_MAM: u64 = 0xFFFF_FFF0_0000_0000;
const MASK_MAS: u64 = 0xFFFF_FFFF_F000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RegistryBlock {
    #[serde(rename = "MA-L")]
    MaL,
    #[serde(rename = "MA-M")]
    MaM,
    #[serde(rename = "MA-S")]
    MaS,
}

impl RegistryBlock {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MaL => "MA-L",
            Self::MaM => "MA-M",
            Self::MaS => "MA-S",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OuiRecord {
    pub mac_prefix: String,
    pub vendor_name: String,
    pub address: String,
    pub country: String,
    pub registry_block: RegistryBlock,
}

#[derive(Debug, Clone)]
struct OuiMeta {
    prefix_display: String,
    vendor_name: String,
    address: String,
    country: String,
    registry_block: RegistryBlock,
}

#[derive(Debug, Clone, Copy)]
struct PrefixEntry {
    masked_key: u64,
    meta_idx: usize,
}

/// Embedded + extensible IEEE MA-L (24-bit), MA-M (28-bit), MA-S (36-bit) OUI database.
#[derive(Debug, Clone)]
pub struct OfflineOuiDb {
    metas: Vec<OuiMeta>,
    mas: Vec<PrefixEntry>,
    mam: Vec<PrefixEntry>,
    mal: Vec<PrefixEntry>,
}

impl Default for OfflineOuiDb {
    fn default() -> Self {
        Self::embedded()
    }
}

static EMBEDDED_OUI: OnceLock<OfflineOuiDb> = OnceLock::new();

impl OfflineOuiDb {
    pub fn embedded() -> Self {
        EMBEDDED_OUI.get_or_init(Self::build_embedded).clone()
    }

    pub fn empty() -> Self {
        Self {
            metas: Vec::new(),
            mas: Vec::new(),
            mam: Vec::new(),
            mal: Vec::new(),
        }
    }

    fn build_embedded() -> Self {
        let mut builder = OuiBuilder::default();
        for &(prefix, vendor, addr, country, block) in EMBEDDED_OUI_ENTRIES {
            if let Ok((key, parsed_block, display)) = parse_prefix_key(prefix, Some(block)) {
                builder.insert(
                    parsed_block,
                    key,
                    OuiMeta {
                        prefix_display: display,
                        vendor_name: vendor.to_string(),
                        address: addr.to_string(),
                        country: country.to_string(),
                        registry_block: parsed_block,
                    },
                );
            }
        }
        builder.build()
    }

    /// Merges IEEE OUI CSV rows. Supports both:
    /// - 5-col format: `prefix,vendor_name,address,country,block`
    /// - IEEE official 4-col format: `Registry,Assignment,Organization Name,Organization Address`
    pub fn merge_csv_file(&mut self, path: &Path) -> NetResult<usize> {
        let content = fs::read_to_string(path)
            .map_err(|e| NetError::InvalidInput(format!("failed to read OUI CSV '{}': {e}", path.display())))?;
        self.merge_csv_str(&content)
    }

    pub fn merge_csv_str(&mut self, csv_text: &str) -> NetResult<usize> {
        let mut builder = OuiBuilder::from_existing(self);
        let mut count = 0usize;
        let mut seen_non_comment = false;

        for (line_no, raw_line) in csv_text.lines().enumerate() {
            let line = raw_line.trim_start_matches('\u{FEFF}').trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts = parse_csv_line(line);
            if !seen_non_comment {
                seen_non_comment = true;
                if parts.first().is_some_and(|h| {
                    let h = h.trim();
                    h.eq_ignore_ascii_case("registry")
                        || h.eq_ignore_ascii_case("prefix")
                        || h.eq_ignore_ascii_case("macprefix")
                        || h.eq_ignore_ascii_case("mac_prefix")
                }) {
                    continue;
                }
            }

            if parts.len() >= 4
                && matches!(
                    parts[0].trim().to_ascii_uppercase().as_str(),
                    "MA-L" | "MA-M" | "MA-S" | "OUI" | "OUI36"
                )
            {
                let block_hint = match parts[0].trim().to_ascii_uppercase().as_str() {
                    "MA-L" | "OUI" => RegistryBlock::MaL,
                    "MA-M" => RegistryBlock::MaM,
                    "MA-S" | "OUI36" => RegistryBlock::MaS,
                    _ => unreachable!(),
                };
                let (key, block, display) = parse_prefix_key(parts[1].trim(), Some(block_hint))?;
                let vendor = parts[2].trim().to_string();
                let addr = parts[3].trim().to_string();
                let country = infer_country_from_address(&addr);
                builder.insert(
                    block,
                    key,
                    OuiMeta {
                        prefix_display: display,
                        vendor_name: vendor,
                        address: addr,
                        country,
                        registry_block: block,
                    },
                );
                count += 1;
            } else if parts.len() >= 5 {
                let block_hint = match parts[4].trim().to_ascii_uppercase().as_str() {
                    "MA-L" => Some(RegistryBlock::MaL),
                    "MA-M" => Some(RegistryBlock::MaM),
                    "MA-S" => Some(RegistryBlock::MaS),
                    _ => None,
                };
                let (key, block, display) = parse_prefix_key(parts[0].trim(), block_hint)?;
                builder.insert(
                    block,
                    key,
                    OuiMeta {
                        prefix_display: display,
                        vendor_name: parts[1].trim().to_string(),
                        address: parts[2].trim().to_string(),
                        country: parts[3].trim().to_string(),
                        registry_block: block,
                    },
                );
                count += 1;
            } else {
                return Err(NetError::ParseError(format!(
                    "OUI CSV line {} has unrecognized format ({} columns)",
                    line_no + 1,
                    parts.len()
                )));
            }
        }

        *self = builder.build();
        Ok(count)
    }

    /// Looks up a full `MacAddr` with strict longest-prefix precedence:
    /// `MA-S` (36-bit) > `MA-M` (28-bit) > `MA-L` (24-bit).
    pub fn lookup_mac(&self, mac: MacAddr) -> Option<OuiRecord> {
        let key = mac_to_u64(mac);
        if let Ok(idx) = self.mas.binary_search_by_key(&(key & MASK_MAS), |e| e.masked_key) {
            return Some(self.metas[self.mas[idx].meta_idx].to_record());
        }
        if let Ok(idx) = self.mam.binary_search_by_key(&(key & MASK_MAM), |e| e.masked_key) {
            return Some(self.metas[self.mam[idx].meta_idx].to_record());
        }
        if let Ok(idx) = self.mal.binary_search_by_key(&(key & MASK_MAL), |e| e.masked_key) {
            return Some(self.metas[self.mal[idx].meta_idx].to_record());
        }
        None
    }

    /// Looks up either a full MAC address (`00:50:56:aa:bb:cc`, `00 50 56 aa bb cc`, `0050.56aa.bbcc`, etc.)
    /// or a partial prefix (6, 7, or 9 hex digits with optional `:` / `-` / `.` / ` `).
    pub fn lookup_str(&self, input: &str) -> NetResult<OuiRecord> {
        let trimmed = input.trim();
        if let Some(mac) = parse_full_mac(trimmed) {
            if let Some(hit) = self.lookup_mac(mac) {
                return Ok(hit);
            }
            return Ok(OuiRecord {
                mac_prefix: format!(
                    "{:02X}:{:02X}:{:02X}",
                    mac.octets()[0],
                    mac.octets()[1],
                    mac.octets()[2]
                ),
                vendor_name: "Unknown Vendor".to_string(),
                address: String::new(),
                country: "ZZ".to_string(),
                registry_block: RegistryBlock::MaL,
            });
        }

        let (key, block, display) = parse_prefix_key(trimmed, None)?;
        let hit = match block {
            RegistryBlock::MaS => self
                .mas
                .binary_search_by_key(&(key & MASK_MAS), |e| e.masked_key)
                .ok()
                .map(|i| &self.metas[self.mas[i].meta_idx]),
            RegistryBlock::MaM => self
                .mam
                .binary_search_by_key(&(key & MASK_MAM), |e| e.masked_key)
                .ok()
                .map(|i| &self.metas[self.mam[i].meta_idx]),
            RegistryBlock::MaL => self
                .mal
                .binary_search_by_key(&(key & MASK_MAL), |e| e.masked_key)
                .ok()
                .map(|i| &self.metas[self.mal[i].meta_idx]),
        };

        if let Some(meta) = hit {
            return Ok(meta.to_record());
        }
        // Preserve MA-S > MA-M > MA-L longest-prefix precedence on fallback:
        // if a 36-bit MA-S prefix misses `self.mas`, check `self.mam` before `self.mal`.
        if block == RegistryBlock::MaS
            && let Ok(idx) = self.mam.binary_search_by_key(&(key & MASK_MAM), |e| e.masked_key)
        {
            return Ok(self.metas[self.mam[idx].meta_idx].to_record());
        }
        // If partial 36-bit or 28-bit prefix wasn't in MA-S/MA-M, still fall back to MA-L parent if present
        if matches!(block, RegistryBlock::MaS | RegistryBlock::MaM)
            && let Ok(idx) = self.mal.binary_search_by_key(&(key & MASK_MAL), |e| e.masked_key)
        {
            return Ok(self.metas[self.mal[idx].meta_idx].to_record());
        }

        Ok(OuiRecord {
            mac_prefix: display,
            vendor_name: "Unknown Vendor".to_string(),
            address: String::new(),
            country: "ZZ".to_string(),
            registry_block: block,
        })
    }

    pub fn all_records(&self) -> Vec<OuiRecord> {
        self.metas.iter().map(OuiMeta::to_record).collect()
    }

    /// Returns `true` iff `input` is syntactically a full MAC address or a valid 6/7/9/12-nibble OUI prefix.
    pub fn is_valid_lookup_input(input: &str) -> bool {
        let trimmed = input.trim();
        parse_full_mac(trimmed).is_some() || parse_prefix_key(trimmed, None).is_ok()
    }
}

fn parse_full_mac(trimmed: &str) -> Option<MacAddr> {
    if let Ok(mac) = MacAddr::parse(trimmed) {
        return Some(mac);
    }
    if trimmed.contains(' ') {
        let parts: Vec<&str> = trimmed.split(' ').collect();
        if parts.len() == 6
            && parts
                .iter()
                .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            let mut octets = [0u8; 6];
            for (i, part) in parts.iter().enumerate() {
                octets[i] = u8::from_str_radix(part, 16).ok()?;
            }
            return Some(MacAddr::new(octets));
        }
    }
    None
}

impl OuiMeta {
    fn to_record(&self) -> OuiRecord {
        OuiRecord {
            mac_prefix: self.prefix_display.clone(),
            vendor_name: self.vendor_name.clone(),
            address: self.address.clone(),
            country: self.country.clone(),
            registry_block: self.registry_block,
        }
    }
}

fn mac_to_u64(mac: MacAddr) -> u64 {
    let o = mac.octets();
    ((o[0] as u64) << 56)
        | ((o[1] as u64) << 48)
        | ((o[2] as u64) << 40)
        | ((o[3] as u64) << 32)
        | ((o[4] as u64) << 24)
        | ((o[5] as u64) << 16)
}

fn parse_prefix_key(input: &str, block_hint: Option<RegistryBlock>) -> NetResult<(u64, RegistryBlock, String)> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(NetError::ParseError("empty MAC or OUI prefix".into()));
    }

    let mut seps = BTreeSet::new();
    for ch in trimmed.chars() {
        if ch.is_ascii_hexdigit() {
            continue;
        }
        if matches!(ch, ':' | '-' | '.' | ' ') {
            seps.insert(ch);
        } else {
            return Err(NetError::ParseError(format!(
                "invalid character '{ch}' in MAC or OUI prefix '{input}'"
            )));
        }
    }

    if seps.len() > 1 {
        return Err(NetError::ParseError(format!(
            "mixed separators in MAC or OUI prefix '{input}'"
        )));
    }

    if let Some(&sep) = seps.iter().next() {
        let groups: Vec<&str> = trimmed.split(sep).collect();
        if groups.iter().any(|g| g.is_empty()) {
            return Err(NetError::ParseError(format!(
                "malformed separator placement in MAC or OUI prefix '{input}'"
            )));
        }
        let last_idx = groups.len() - 1;
        if sep == '.' {
            if !groups[..last_idx].iter().all(|g| g.len() == 4) || !(1..=4).contains(&groups[last_idx].len()) {
                return Err(NetError::ParseError(format!(
                    "malformed dot-separated MAC or OUI prefix '{input}'"
                )));
            }
        } else if !groups[..last_idx].iter().all(|g| g.len() == 2) || !(1..=2).contains(&groups[last_idx].len()) {
            return Err(NetError::ParseError(format!(
                "malformed separator group length in MAC or OUI prefix '{input}'"
            )));
        }
    }

    let hex_only: String = trimmed
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_uppercase())
        .collect();

    let (block, nibble_count) = match block_hint {
        Some(b) => {
            let needed = match b {
                RegistryBlock::MaL => 6,
                RegistryBlock::MaM => 7,
                RegistryBlock::MaS => 9,
            };
            if hex_only.len() != needed && hex_only.len() != 12 {
                return Err(NetError::ParseError(format!(
                    "MAC prefix '{input}' has invalid hex length {} for {} (expected {needed} or 12 hex chars)",
                    hex_only.len(),
                    b.as_str()
                )));
            }
            (b, needed)
        }
        None => match hex_only.len() {
            6 => (RegistryBlock::MaL, 6),
            7 => (RegistryBlock::MaM, 7),
            9 => (RegistryBlock::MaS, 9),
            12 => (RegistryBlock::MaL, 6),
            _ => {
                return Err(NetError::ParseError(format!(
                    "invalid MAC or OUI prefix '{input}' (expected 6, 7, 9, or 12 hex digits)"
                )));
            }
        },
    };

    let mut nibbles = [0u8; 9];
    for (i, ch) in hex_only.chars().take(nibble_count).enumerate() {
        nibbles[i] = ch
            .to_digit(16)
            .ok_or_else(|| NetError::ParseError(format!("invalid hex digit in '{input}'")))? as u8;
    }

    let mut key = 0u64;
    for (i, &nib) in nibbles.iter().take(nibble_count).enumerate() {
        key |= (nib as u64) << (60 - i * 4);
    }

    let display = match block {
        RegistryBlock::MaL => format!(
            "{:X}{:X}:{:X}{:X}:{:X}{:X}",
            nibbles[0], nibbles[1], nibbles[2], nibbles[3], nibbles[4], nibbles[5]
        ),
        RegistryBlock::MaM => format!(
            "{:X}{:X}:{:X}{:X}:{:X}{:X}:{:X}",
            nibbles[0], nibbles[1], nibbles[2], nibbles[3], nibbles[4], nibbles[5], nibbles[6]
        ),
        RegistryBlock::MaS => format!(
            "{:X}{:X}:{:X}{:X}:{:X}{:X}:{:X}{:X}:{:X}",
            nibbles[0], nibbles[1], nibbles[2], nibbles[3], nibbles[4], nibbles[5], nibbles[6], nibbles[7], nibbles[8]
        ),
    };

    Ok((key, block, display))
}

fn infer_country_from_address(addr: &str) -> String {
    let trimmed = addr.trim();
    if let Some(last) = trimmed.split_whitespace().last()
        && last.len() == 2
        && last.bytes().all(|b| b.is_ascii_alphabetic())
    {
        return last.to_ascii_uppercase();
    }
    "ZZ".to_string()
}

#[derive(Default)]
struct OuiBuilder {
    metas: Vec<OuiMeta>,
    mas: BTreeMap<u64, usize>,
    mam: BTreeMap<u64, usize>,
    mal: BTreeMap<u64, usize>,
}

impl OuiBuilder {
    fn from_existing(db: &OfflineOuiDb) -> Self {
        let mut builder = Self {
            metas: db.metas.clone(),
            mas: BTreeMap::new(),
            mam: BTreeMap::new(),
            mal: BTreeMap::new(),
        };
        for e in &db.mas {
            builder.mas.insert(e.masked_key, e.meta_idx);
        }
        for e in &db.mam {
            builder.mam.insert(e.masked_key, e.meta_idx);
        }
        for e in &db.mal {
            builder.mal.insert(e.masked_key, e.meta_idx);
        }
        builder
    }

    fn insert(&mut self, block: RegistryBlock, key: u64, meta: OuiMeta) {
        let idx = self.metas.len();
        self.metas.push(meta);
        match block {
            RegistryBlock::MaS => {
                self.mas.insert(key & MASK_MAS, idx);
            }
            RegistryBlock::MaM => {
                self.mam.insert(key & MASK_MAM, idx);
            }
            RegistryBlock::MaL => {
                self.mal.insert(key & MASK_MAL, idx);
            }
        }
    }

    fn build(self) -> OfflineOuiDb {
        OfflineOuiDb {
            metas: self.metas,
            mas: self
                .mas
                .into_iter()
                .map(|(masked_key, meta_idx)| PrefixEntry { masked_key, meta_idx })
                .collect(),
            mam: self
                .mam
                .into_iter()
                .map(|(masked_key, meta_idx)| PrefixEntry { masked_key, meta_idx })
                .collect(),
            mal: self
                .mal
                .into_iter()
                .map(|(masked_key, meta_idx)| PrefixEntry { masked_key, meta_idx })
                .collect(),
        }
    }
}

type StaticOuiRow = (&'static str, &'static str, &'static str, &'static str, RegistryBlock);

const EMBEDDED_OUI_ENTRIES: &[StaticOuiRow] = &[
    // MA-L (24-bit) — Major Networking, Hypervisors, NICs, Endpoint & Cloud Vendors
    (
        "00:00:0C",
        "Cisco Systems, Inc",
        "San Jose CA",
        "US",
        RegistryBlock::MaL,
    ),
    (
        "00:00:5E",
        "ICANN, IANA Department",
        "Los Angeles CA",
        "US",
        RegistryBlock::MaL,
    ),
    (
        "00:01:42",
        "Cisco Systems, Inc",
        "San Jose CA",
        "US",
        RegistryBlock::MaL,
    ),
    (
        "00:03:FF",
        "Microsoft Corporation",
        "Redmond WA",
        "US",
        RegistryBlock::MaL,
    ),
    (
        "00:04:20",
        "Slim Devices, Inc.",
        "Mountain View CA",
        "US",
        RegistryBlock::MaL,
    ),
    ("00:05:69", "VMware, Inc.", "Palo Alto CA", "US", RegistryBlock::MaL),
    (
        "00:07:E9",
        "Intel Corporation",
        "Santa Clara CA",
        "US",
        RegistryBlock::MaL,
    ),
    ("00:0C:29", "VMware, Inc.", "Palo Alto CA", "US", RegistryBlock::MaL),
    (
        "00:0D:3A",
        "Microsoft Corporation",
        "Redmond WA",
        "US",
        RegistryBlock::MaL,
    ),
    (
        "00:0E:C6",
        "ASIX Electronics Corp.",
        "Hsinchu",
        "TW",
        RegistryBlock::MaL,
    ),
    ("00:10:18", "Broadcom", "San Jose CA", "US", RegistryBlock::MaL),
    ("00:11:22", "Cimsys Inc", "Tokyo", "JP", RegistryBlock::MaL),
    ("00:12:3F", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    ("00:13:72", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    ("00:14:22", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    (
        "00:15:5D",
        "Microsoft Corporation",
        "Redmond WA",
        "US",
        RegistryBlock::MaL,
    ),
    ("00:16:3E", "Xensource, Inc.", "Palo Alto CA", "US", RegistryBlock::MaL),
    ("00:17:F2", "Apple, Inc.", "Cupertino CA", "US", RegistryBlock::MaL),
    (
        "00:19:99",
        "Fujitsu Technology Solutions GmbH",
        "Augsburg",
        "DE",
        RegistryBlock::MaL,
    ),
    ("00:1A:A0", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    (
        "00:1B:21",
        "Intel Corporate",
        "Santa Clara CA",
        "US",
        RegistryBlock::MaL,
    ),
    ("00:1C:14", "VMware, Inc.", "Palo Alto CA", "US", RegistryBlock::MaL),
    ("00:1C:42", "Parallels, Inc.", "Renton WA", "US", RegistryBlock::MaL),
    ("00:1D:09", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    (
        "00:1E:67",
        "Intel Corporate",
        "Santa Clara CA",
        "US",
        RegistryBlock::MaL,
    ),
    ("00:1F:5B", "Apple, Inc.", "Cupertino CA", "US", RegistryBlock::MaL),
    ("00:21:5A", "Hewlett Packard", "Palo Alto CA", "US", RegistryBlock::MaL),
    (
        "00:22:48",
        "Microsoft Corporation",
        "Redmond WA",
        "US",
        RegistryBlock::MaL,
    ),
    ("00:23:AE", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    ("00:24:E8", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    (
        "00:25:90",
        "Super Micro Computer, Inc.",
        "San Jose CA",
        "US",
        RegistryBlock::MaL,
    ),
    ("00:26:B9", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    ("00:50:56", "VMware, Inc.", "Palo Alto CA", "US", RegistryBlock::MaL),
    (
        "00:50:C2",
        "IEEE Registration Authority",
        "Piscataway NJ",
        "US",
        RegistryBlock::MaL,
    ),
    (
        "00:55:DA",
        "IEEE Registration Authority (MA-M Parent)",
        "Piscataway NJ",
        "US",
        RegistryBlock::MaL,
    ),
    (
        "00:E0:4C",
        "Realtek Semiconductor Corp.",
        "Hsinchu",
        "TW",
        RegistryBlock::MaL,
    ),
    ("04:42:1A", "ASUSTek COMPUTER INC.", "Taipei", "TW", RegistryBlock::MaL),
    (
        "08:00:27",
        "Oracle Corporation (VirtualBox)",
        "Austin TX",
        "US",
        RegistryBlock::MaL,
    ),
    (
        "0C:C4:7A",
        "Super Micro Computer, Inc.",
        "San Jose CA",
        "US",
        RegistryBlock::MaL,
    ),
    ("10:7B:44", "ASUSTek COMPUTER INC.", "Taipei", "TW", RegistryBlock::MaL),
    ("14:18:77", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    ("18:66:DA", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    (
        "1C:1B:0D",
        "GIGA-BYTE TECHNOLOGY CO.,LTD.",
        "New Taipei",
        "TW",
        RegistryBlock::MaL,
    ),
    ("20:47:47", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    ("24:5E:BE", "QNAP Systems, Inc.", "New Taipei", "TW", RegistryBlock::MaL),
    ("28:CF:E9", "Apple, Inc.", "Cupertino CA", "US", RegistryBlock::MaL),
    (
        "2C:F0:5D",
        "Micro-Star INTL CO., LTD.",
        "New Taipei",
        "TW",
        RegistryBlock::MaL,
    ),
    (
        "30:9C:23",
        "Micro-Star INTL CO., LTD.",
        "New Taipei",
        "TW",
        RegistryBlock::MaL,
    ),
    ("34:97:F6", "ASUSTek COMPUTER INC.", "Taipei", "TW", RegistryBlock::MaL),
    ("38:F9:D3", "Apple, Inc.", "Cupertino CA", "US", RegistryBlock::MaL),
    (
        "3C:FD:FE",
        "Intel Corporate",
        "Santa Clara CA",
        "US",
        RegistryBlock::MaL,
    ),
    (
        "40:8D:5C",
        "GIGA-BYTE TECHNOLOGY CO.,LTD.",
        "New Taipei",
        "TW",
        RegistryBlock::MaL,
    ),
    (
        "44:37:E6",
        "Hon Hai Precision Ind. Co.,Ltd.",
        "New Taipei",
        "TW",
        RegistryBlock::MaL,
    ),
    (
        "48:2A:E3",
        "Wistron InfoComm (Kunshan) Co.,Ltd.",
        "Kunshan",
        "CN",
        RegistryBlock::MaL,
    ),
    ("4C:52:62", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    ("50:EB:F6", "ASUSTek COMPUTER INC.", "Taipei", "TW", RegistryBlock::MaL),
    ("52:54:00", "QEMU / KVM Virtual NIC", "Zurich", "CH", RegistryBlock::MaL),
    ("54:BF:64", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    (
        "58:47:CA",
        "Intel Corporate",
        "Santa Clara CA",
        "US",
        RegistryBlock::MaL,
    ),
    ("5C:F9:DD", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    (
        "60:45:BD",
        "Microsoft Corporation",
        "Redmond WA",
        "US",
        RegistryBlock::MaL,
    ),
    ("64:00:6A", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    (
        "68:05:CA",
        "Intel Corporate",
        "Santa Clara CA",
        "US",
        RegistryBlock::MaL,
    ),
    (
        "6C:4B:90",
        "Liteon Technology Corporation",
        "Taipei",
        "TW",
        RegistryBlock::MaL,
    ),
    (
        "70:B3:D5",
        "IEEE Registration Authority",
        "Piscataway NJ",
        "US",
        RegistryBlock::MaL,
    ),
    (
        "74:1A:E0",
        "IEEE Registration Authority (MA-M Parent)",
        "Piscataway NJ",
        "US",
        RegistryBlock::MaL,
    ),
    ("74:86:7A", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    ("78:2B:CB", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    ("7C:10:C9", "ASUSTek COMPUTER INC.", "Taipei", "TW", RegistryBlock::MaL),
    ("80:EE:73", "Shuttle Inc.", "Taipei", "TW", RegistryBlock::MaL),
    ("84:2B:2B", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    (
        "88:AE:DD",
        "Intel Corporate",
        "Santa Clara CA",
        "US",
        RegistryBlock::MaL,
    ),
    (
        "8C:1F:64",
        "IEEE Registration Authority",
        "Piscataway NJ",
        "US",
        RegistryBlock::MaL,
    ),
    ("90:B1:1C", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    (
        "94:C6:91",
        "Elitegroup Computer Systems Co.,Ltd.",
        "Taipei",
        "TW",
        RegistryBlock::MaL,
    ),
    ("98:90:96", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    (
        "9C:B6:D0",
        "Rivet Networks (Killer)",
        "Austin TX",
        "US",
        RegistryBlock::MaL,
    ),
    (
        "A0:36:9F",
        "Intel Corporate",
        "Santa Clara CA",
        "US",
        RegistryBlock::MaL,
    ),
    ("A4:BA:DB", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    ("A8:A1:59", "ASRock Incorporation", "Taipei", "TW", RegistryBlock::MaL),
    (
        "AC:1F:6B",
        "Super Micro Computer, Inc.",
        "San Jose CA",
        "US",
        RegistryBlock::MaL,
    ),
    ("B0:83:FE", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    (
        "B4:2E:99",
        "GIGA-BYTE TECHNOLOGY CO.,LTD.",
        "New Taipei",
        "TW",
        RegistryBlock::MaL,
    ),
    (
        "B8:27:EB",
        "Raspberry Pi Foundation",
        "Cambridge",
        "GB",
        RegistryBlock::MaL,
    ),
    (
        "BC:24:11",
        "Proxmox Server Solutions GmbH",
        "Vienna",
        "AT",
        RegistryBlock::MaL,
    ),
    ("C0:25:A5", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    ("C4:34:6B", "Hewlett Packard", "Palo Alto CA", "US", RegistryBlock::MaL),
    ("C8:F7:50", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    (
        "CC:46:D6",
        "Cisco Systems, Inc",
        "San Jose CA",
        "US",
        RegistryBlock::MaL,
    ),
    ("D0:50:99", "ASRock Incorporation", "Taipei", "TW", RegistryBlock::MaL),
    ("D4:AE:52", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    (
        "D8:3A:DD",
        "Raspberry Pi Trading Ltd",
        "Cambridge",
        "GB",
        RegistryBlock::MaL,
    ),
    (
        "DC:A6:32",
        "Raspberry Pi Trading Ltd",
        "Cambridge",
        "GB",
        RegistryBlock::MaL,
    ),
    (
        "E0:D5:5E",
        "GIGA-BYTE TECHNOLOGY CO.,LTD.",
        "New Taipei",
        "TW",
        RegistryBlock::MaL,
    ),
    (
        "E4:5F:01",
        "Raspberry Pi Trading Ltd",
        "Cambridge",
        "GB",
        RegistryBlock::MaL,
    ),
    (
        "E8:6A:64",
        "LCFC(HeFei) Electronics Technology co., ltd",
        "Hefei",
        "CN",
        RegistryBlock::MaL,
    ),
    ("EC:B1:D7", "Hewlett Packard", "Palo Alto CA", "US", RegistryBlock::MaL),
    ("F0:1F:AF", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    (
        "F4:4D:30",
        "Elitegroup Computer Systems Co.,Ltd.",
        "Taipei",
        "TW",
        RegistryBlock::MaL,
    ),
    ("F8:BC:12", "Dell Inc.", "Round Rock TX", "US", RegistryBlock::MaL),
    (
        "FC:AA:14",
        "GIGA-BYTE TECHNOLOGY CO.,LTD.",
        "New Taipei",
        "TW",
        RegistryBlock::MaL,
    ),
    // MA-M (28-bit) — Shares 24-bit parents to prove MA-M > MA-L precedence
    (
        "00:55:DA:0",
        "Nordic Semiconductor ASA",
        "Trondheim",
        "NO",
        RegistryBlock::MaM,
    ),
    ("00:55:DA:5", "Ubiquiti Inc", "New York NY", "US", RegistryBlock::MaM),
    (
        "74:1A:E0:1",
        "Synology Incorporated",
        "Taipei",
        "TW",
        RegistryBlock::MaM,
    ),
    (
        "74:1A:E0:A",
        "TP-Link Systems Inc.",
        "Irvine CA",
        "US",
        RegistryBlock::MaM,
    ),
    // MA-S (36-bit) — Shares 24-bit parents to prove MA-S > MA-M > MA-L precedence
    (
        "70:B3:D5:00:1",
        "Schweitzer Engineering Laboratories",
        "Pullman WA",
        "US",
        RegistryBlock::MaS,
    ),
    (
        "70:B3:D5:1A:2",
        "Acme Embedded Systems GmbH",
        "Munich",
        "DE",
        RegistryBlock::MaS,
    ),
    (
        "8C:1F:64:12:3",
        "Industrial Telemetry Controls Ltd",
        "Bristol",
        "GB",
        RegistryBlock::MaS,
    ),
    (
        "00:50:C2:AA:B",
        "Precision Instruments Corp",
        "Boston MA",
        "US",
        RegistryBlock::MaS,
    ),
];
