use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;

use net2rust_core::{MacAddr, NetContext, NetError, NetResult};

use crate::common::parse_csv_fields;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OuiEntry {
    pub prefix: [u8; 3],
    pub vendor: &'static str,
}

/// Compile-time sorted IEEE OUI prefix table (strictly ascending by `prefix`).
pub const OUI_TABLE: &[OuiEntry] = &[
    OuiEntry {
        prefix: [0x00, 0x03, 0xFF],
        vendor: "Microsoft Corporation",
    },
    OuiEntry {
        prefix: [0x00, 0x05, 0x69],
        vendor: "VMware, Inc.",
    },
    OuiEntry {
        prefix: [0x00, 0x0C, 0x29],
        vendor: "VMware, Inc.",
    },
    OuiEntry {
        prefix: [0x00, 0x0D, 0x3A],
        vendor: "Microsoft Corporation",
    },
    OuiEntry {
        prefix: [0x00, 0x0F, 0x66],
        vendor: "Cisco-Linksys, LLC",
    },
    OuiEntry {
        prefix: [0x00, 0x10, 0x18],
        vendor: "Broadcom",
    },
    OuiEntry {
        prefix: [0x00, 0x11, 0x32],
        vendor: "Synology Incorporated",
    },
    OuiEntry {
        prefix: [0x00, 0x14, 0x22],
        vendor: "Dell Inc.",
    },
    OuiEntry {
        prefix: [0x00, 0x15, 0x5D],
        vendor: "Microsoft Corporation (Hyper-V)",
    },
    OuiEntry {
        prefix: [0x00, 0x16, 0x3E],
        vendor: "Xensource, Inc.",
    },
    OuiEntry {
        prefix: [0x00, 0x17, 0x88],
        vendor: "Signify B.V.",
    },
    OuiEntry {
        prefix: [0x00, 0x1A, 0xA0],
        vendor: "Dell Inc.",
    },
    OuiEntry {
        prefix: [0x00, 0x1B, 0x21],
        vendor: "Intel Corporate",
    },
    OuiEntry {
        prefix: [0x00, 0x1C, 0x42],
        vendor: "Parallels, Inc.",
    },
    OuiEntry {
        prefix: [0x00, 0x1E, 0x67],
        vendor: "Intel Corporate",
    },
    OuiEntry {
        prefix: [0x00, 0x21, 0x9B],
        vendor: "Dell Inc.",
    },
    OuiEntry {
        prefix: [0x00, 0x22, 0x48],
        vendor: "Microsoft Corporation",
    },
    OuiEntry {
        prefix: [0x00, 0x24, 0xE8],
        vendor: "Dell Inc.",
    },
    OuiEntry {
        prefix: [0x00, 0x25, 0x90],
        vendor: "Super Micro Computer, Inc.",
    },
    OuiEntry {
        prefix: [0x00, 0x26, 0xB9],
        vendor: "Dell Inc.",
    },
    OuiEntry {
        prefix: [0x00, 0x50, 0x56],
        vendor: "VMware, Inc.",
    },
    OuiEntry {
        prefix: [0x00, 0xE0, 0x4C],
        vendor: "Realtek Semiconductor Corp.",
    },
    OuiEntry {
        prefix: [0x04, 0x18, 0xD6],
        vendor: "Ubiquiti Inc.",
    },
    OuiEntry {
        prefix: [0x08, 0x00, 0x27],
        vendor: "PCS Systemtechnik GmbH (VirtualBox)",
    },
    OuiEntry {
        prefix: [0x0C, 0x9D, 0x92],
        vendor: "ASUSTek COMPUTER INC.",
    },
    OuiEntry {
        prefix: [0x14, 0xCC, 0x20],
        vendor: "TP-Link Corporation Limited",
    },
    OuiEntry {
        prefix: [0x18, 0xE8, 0x29],
        vendor: "Ubiquiti Inc.",
    },
    OuiEntry {
        prefix: [0x24, 0x5E, 0xBE],
        vendor: "QNAP Systems, Inc.",
    },
    OuiEntry {
        prefix: [0x28, 0xCF, 0xE9],
        vendor: "Apple, Inc.",
    },
    OuiEntry {
        prefix: [0x3C, 0x22, 0xFB],
        vendor: "Apple, Inc.",
    },
    OuiEntry {
        prefix: [0x3C, 0xFD, 0xFE],
        vendor: "Intel Corporate",
    },
    OuiEntry {
        prefix: [0x48, 0x2C, 0xA0],
        vendor: "Xiaomi Communications Co Ltd",
    },
    OuiEntry {
        prefix: [0x4C, 0x5E, 0x0C],
        vendor: "Routerboard.com (MikroTik)",
    },
    OuiEntry {
        prefix: [0x50, 0xC7, 0xBF],
        vendor: "TP-Link Corporation Limited",
    },
    OuiEntry {
        prefix: [0x52, 0x54, 0x00],
        vendor: "Realtek / QEMU KVM",
    },
    OuiEntry {
        prefix: [0x60, 0xA4, 0x4C],
        vendor: "ASUSTek COMPUTER INC.",
    },
    OuiEntry {
        prefix: [0x64, 0xD1, 0x54],
        vendor: "Routerboard.com (MikroTik)",
    },
    OuiEntry {
        prefix: [0x70, 0x85, 0xC2],
        vendor: "ASRock Incorporation",
    },
    OuiEntry {
        prefix: [0x74, 0x83, 0xC2],
        vendor: "Ubiquiti Inc.",
    },
    OuiEntry {
        prefix: [0x7C, 0xDF, 0xA1],
        vendor: "Espressif Inc.",
    },
    OuiEntry {
        prefix: [0x80, 0x2A, 0xA8],
        vendor: "Ubiquiti Inc.",
    },
    OuiEntry {
        prefix: [0x94, 0x83, 0xC4],
        vendor: "GL Technologies (Hong Kong) Limited",
    },
    OuiEntry {
        prefix: [0xA4, 0xC3, 0xF0],
        vendor: "Intel Corporate",
    },
    OuiEntry {
        prefix: [0xB8, 0x27, 0xEB],
        vendor: "Raspberry Pi Foundation",
    },
    OuiEntry {
        prefix: [0xBC, 0x5F, 0xF4],
        vendor: "ASRock Incorporation",
    },
    OuiEntry {
        prefix: [0xC0, 0x3F, 0xD5],
        vendor: "Elitegroup Computer Systems Co.,Ltd.",
    },
    OuiEntry {
        prefix: [0xD8, 0x3A, 0xDD],
        vendor: "Raspberry Pi Trading Ltd",
    },
    OuiEntry {
        prefix: [0xDC, 0xA6, 0x32],
        vendor: "Raspberry Pi Trading Ltd",
    },
    OuiEntry {
        prefix: [0xE4, 0x5F, 0x01],
        vendor: "Raspberry Pi Trading Ltd",
    },
    OuiEntry {
        prefix: [0xF0, 0x9F, 0xC2],
        vendor: "Ubiquiti Inc.",
    },
    OuiEntry {
        prefix: [0xFC, 0xEC, 0xDA],
        vendor: "Ubiquiti Inc.",
    },
];

static EMBEDDED_INDEX: OnceLock<BTreeMap<[u8; 3], &'static str>> = OnceLock::new();

pub fn lookup_oui_embedded(mac: MacAddr) -> Option<&'static str> {
    let prefix = mac.oui_prefix();
    if let Ok(idx) = OUI_TABLE.binary_search_by_key(&prefix, |e| e.prefix) {
        return Some(OUI_TABLE[idx].vendor);
    }
    let map = EMBEDDED_INDEX.get_or_init(|| OUI_TABLE.iter().map(|e| (e.prefix, e.vendor)).collect());
    map.get(&prefix).copied()
}

#[derive(Debug, Clone, Default)]
pub struct OuiDatabase {
    overrides: BTreeMap<[u8; 3], String>,
}

impl OuiDatabase {
    pub fn embedded() -> Self {
        Self::default()
    }

    pub fn from_csv_str(content: &str) -> NetResult<Self> {
        let mut overrides = BTreeMap::new();
        let mut seen_non_comment_row = false;
        for (line_no, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (prefix_clean, vendor_clean) = if let Some((raw_prefix, raw_vendor)) = line.split_once('\t')
                && !raw_prefix.contains(',')
                && !raw_prefix.contains('"')
                && !raw_vendor.trim_start().starts_with(',')
            {
                let vendor_trimmed = raw_vendor.trim();
                let vendor_parsed = if vendor_trimmed.starts_with('"') {
                    let v_parts = parse_csv_fields(vendor_trimmed)
                        .map_err(|err| NetError::ParseError(format!("OUI CSV line {}: {err}", line_no + 1)))?;
                    v_parts.into_iter().next().unwrap_or_default().trim().to_string()
                } else {
                    vendor_trimmed.to_string()
                };
                (raw_prefix.trim().to_string(), vendor_parsed)
            } else {
                let parts = parse_csv_fields(line)
                    .map_err(|err| NetError::ParseError(format!("OUI CSV line {}: {err}", line_no + 1)))?;
                if parts.len() >= 2 {
                    (parts[0].trim().to_string(), parts[1].trim().to_string())
                } else {
                    return Err(NetError::ParseError(format!(
                        "OUI CSV line {} missing delimiter: {line}",
                        line_no + 1
                    )));
                }
            };

            let is_first_row = !seen_non_comment_row;
            seen_non_comment_row = true;
            if is_first_row && prefix_clean.eq_ignore_ascii_case("prefix") {
                continue;
            }
            let prefix = parse_oui_prefix(&prefix_clean)?;
            overrides.insert(prefix, vendor_clean);
        }
        Ok(Self { overrides })
    }

    pub fn from_file(path: &Path) -> NetResult<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_csv_str(&content)
    }

    pub fn for_context(ctx: &NetContext) -> NetResult<Self> {
        if let Some(path) = ctx.offline_config().and_then(|c| c.oui_db_path.as_ref()) {
            Self::from_file(path)
        } else {
            Ok(Self::embedded())
        }
    }

    pub fn lookup(&self, mac: MacAddr) -> Option<&str> {
        if let Some(v) = self.overrides.get(&mac.oui_prefix()) {
            return Some(v.as_str());
        }
        lookup_oui_embedded(mac)
    }

    pub fn lookup_or_unknown(&self, mac: MacAddr) -> String {
        if let Some(vendor) = self.lookup(mac) {
            vendor.to_string()
        } else if mac.is_locally_administered() {
            "Locally Administered".to_string()
        } else {
            "Unknown".to_string()
        }
    }
}

fn parse_oui_prefix(input: &str) -> NetResult<[u8; 3]> {
    let hex_only: String = input.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex_only.len() != 6 {
        return Err(NetError::ParseError(format!("invalid OUI prefix: {input}")));
    }
    let b0 = u8::from_str_radix(&hex_only[0..2], 16)
        .map_err(|_| NetError::ParseError(format!("invalid OUI prefix: {input}")))?;
    let b1 = u8::from_str_radix(&hex_only[2..4], 16)
        .map_err(|_| NetError::ParseError(format!("invalid OUI prefix: {input}")))?;
    let b2 = u8::from_str_radix(&hex_only[4..6], 16)
        .map_err(|_| NetError::ParseError(format!("invalid OUI prefix: {input}")))?;
    Ok([b0, b1, b2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oui_table_strictly_sorted() {
        assert!(!OUI_TABLE.is_empty());
        for pair in OUI_TABLE.windows(2) {
            assert!(
                pair[0].prefix < pair[1].prefix,
                "OUI_TABLE out of order: {:?} >= {:?}",
                pair[0].prefix,
                pair[1].prefix
            );
        }
    }

    #[test]
    fn test_oui_lookup_embedded_and_override() {
        let vmware = MacAddr::parse("00:50:56:ab:cd:ef").unwrap();
        assert_eq!(lookup_oui_embedded(vmware), Some("VMware, Inc."));

        let rpi = MacAddr::parse("B8-27-EB-11-22-33").unwrap();
        assert_eq!(lookup_oui_embedded(rpi), Some("Raspberry Pi Foundation"));

        let csv = "prefix,vendor\n00:50:56,Custom VMware Lab\nAA-BB-CC,Acme NIC\n";
        let db = OuiDatabase::from_csv_str(csv).unwrap();
        assert_eq!(db.lookup(vmware), Some("Custom VMware Lab"));
        assert_eq!(
            db.lookup(MacAddr::parse("aa:bb:cc:01:02:03").unwrap()),
            Some("Acme NIC")
        );
        assert_eq!(db.lookup(rpi), Some("Raspberry Pi Foundation"));
    }

    #[test]
    fn test_oui_csv_comments_blank_lines_and_quoted_fields() {
        let csv = "\n# OUI DB\n\nprefix,vendor\n00:50:56,\"Acme, LLC\"\nAA:BB:CC,\"Acme \"\"Lab\"\", Inc.\"\n11:22:33\t\"Tab Vendor, Inc.\"\n";
        let db = OuiDatabase::from_csv_str(csv).unwrap();

        assert_eq!(
            db.lookup(MacAddr::parse("00:50:56:01:02:03").unwrap()),
            Some("Acme, LLC")
        );
        assert_eq!(
            db.lookup(MacAddr::parse("aa:bb:cc:01:02:03").unwrap()),
            Some(r#"Acme "Lab", Inc."#)
        );
        assert_eq!(
            db.lookup(MacAddr::parse("11:22:33:01:02:03").unwrap()),
            Some("Tab Vendor, Inc.")
        );

        let late_header = "00:50:56,Custom VMware\nprefix,vendor\n";
        assert!(matches!(
            OuiDatabase::from_csv_str(late_header),
            Err(NetError::ParseError(_))
        ));

        let bad_quote = "prefix,vendor\n00:50:56,\"Unclosed\n";
        assert!(matches!(
            OuiDatabase::from_csv_str(bad_quote),
            Err(NetError::ParseError(_))
        ));
    }
}
