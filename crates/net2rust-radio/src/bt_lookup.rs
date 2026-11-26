use net2rust_core::MacAddr;

/// Sorted ascending by 3-byte OUI prefix for binary search.
pub static OUI_TABLE: &[([u8; 3], &str)] = &[
    ([0x00, 0x03, 0x93], "Apple, Inc."),
    ([0x00, 0x0A, 0x95], "Apple, Inc."),
    ([0x00, 0x0C, 0x29], "VMware, Inc."),
    ([0x00, 0x11, 0x22], "CIMSYS Inc"),
    ([0x00, 0x15, 0x5D], "Microsoft Corporation"),
    ([0x00, 0x16, 0x3E], "Xensource, Inc."),
    ([0x00, 0x17, 0xF2], "Apple, Inc."),
    ([0x00, 0x1A, 0x11], "Google, Inc."),
    ([0x00, 0x1B, 0x63], "Apple, Inc."),
    ([0x00, 0x1E, 0xC2], "Apple, Inc."),
    ([0x00, 0x23, 0xDF], "Apple, Inc."),
    ([0x00, 0x25, 0x00], "Apple, Inc."),
    ([0x00, 0x50, 0xF2], "Microsoft Corp."),
    ([0x00, 0x90, 0x4C], "Broadcom"),
    ([0x00, 0xE0, 0x4C], "Realtek Semiconductor Corp."),
    ([0x04, 0xD9, 0xF5], "ASUSTek COMPUTER INC."),
    ([0x08, 0x00, 0x27], "Oracle VirtualBox"),
    ([0x14, 0xAB, 0xF0], "Intel Corporate"),
    ([0x18, 0x66, 0xDA], "Dell Inc."),
    ([0x24, 0x0A, 0xC4], "Espressif Inc."),
    ([0x28, 0xCD, 0xC1], "Raspberry Pi Trading Ltd"),
    ([0x30, 0xAE, 0xA4], "Espressif Inc."),
    ([0x34, 0xAB, 0x95], "Espressif Inc."),
    ([0x3C, 0x5A, 0xB4], "Google, Inc."),
    ([0x3C, 0x84, 0x6A], "TP-Link Systems Inc."),
    ([0x40, 0xB0, 0x76], "ASUSTek COMPUTER INC."),
    ([0x44, 0x65, 0x0D], "Amazon Technologies Inc."),
    ([0x50, 0xC7, 0xBF], "TP-Link Systems Inc."),
    ([0x54, 0xB7, 0xE5], "Sony Corporation"),
    ([0x58, 0xCB, 0x52], "Google, Inc."),
    ([0x60, 0xA4, 0x4C], "ASUSTek COMPUTER INC."),
    ([0x70, 0x88, 0x6B], "Logitech"),
    ([0x74, 0xDA, 0x38], "Edimax Technology Co. Ltd."),
    ([0x78, 0x4F, 0x43], "Apple, Inc."),
    ([0x7C, 0xD1, 0xC3], "Apple, Inc."),
    ([0x80, 0x7D, 0x3A], "Espressif Inc."),
    ([0x84, 0xD8, 0x1B], "TP-Link Systems Inc."),
    ([0x8C, 0x85, 0x90], "Apple, Inc."),
    ([0x90, 0x78, 0x41], "Intel Corporate"),
    ([0x98, 0xDA, 0xC4], "TP-Link Systems Inc."),
    ([0xA4, 0x83, 0xE7], "Apple, Inc."),
    ([0xAC, 0xBC, 0x32], "Apple, Inc."),
    ([0xB0, 0xBE, 0x76], "TP-Link Systems Inc."),
    ([0xB4, 0x2E, 0x99], "GIGA-BYTE TECHNOLOGY CO.,LTD."),
    ([0xB8, 0x27, 0xEB], "Raspberry Pi Foundation"),
    ([0xBC, 0xD0, 0x74], "Apple, Inc."),
    ([0xC0, 0x25, 0xE9], "TP-Link Systems Inc."),
    ([0xC8, 0x69, 0xCD], "Apple, Inc."),
    ([0xCC, 0x46, 0xD6], "Cisco Systems, Inc"),
    ([0xD4, 0x6E, 0x0E], "TP-Link Systems Inc."),
    ([0xD8, 0x3A, 0xDD], "Raspberry Pi Trading Ltd"),
    ([0xDC, 0xA6, 0x32], "Raspberry Pi Trading Ltd"),
    ([0xE4, 0x5F, 0x01], "Raspberry Pi Trading Ltd"),
    ([0xEC, 0x08, 0x6B], "TP-Link Systems Inc."),
    ([0xF0, 0x18, 0x98], "Apple, Inc."),
    ([0xF4, 0xF5, 0xD8], "Google, Inc."),
    ([0xF8, 0x4D, 0x89], "Apple, Inc."),
];

/// Sorted ascending by Bluetooth SIG 16-bit Company Identifier.
pub static COMPANY_ID_TABLE: &[(u16, &str)] = &[
    (0x0001, "Nokia Mobile Phones"),
    (0x0002, "Intel Corp."),
    (0x0003, "IBM Corp."),
    (0x0004, "Toshiba Corp."),
    (0x0006, "Microsoft"),
    (0x000A, "Qualcomm Technologies International, Ltd. (CSR)"),
    (0x000D, "Texas Instruments Inc."),
    (0x000F, "Broadcom Corporation"),
    (0x001D, "Qualcomm"),
    (0x004C, "Apple, Inc."),
    (0x0059, "Nordic Semiconductor ASA"),
    (0x0075, "Samsung Electronics Co. Ltd."),
    (0x0087, "Garmin International, Inc."),
    (0x009E, "Bose Corporation"),
    (0x00D2, "Dialog Semiconductor B.V."),
    (0x00E0, "Google"),
    (0x010F, "Broadcom Corporation"),
    (0x012D, "Sony Corporation"),
    (0x0131, "Cypress Semiconductor"),
    (0x0157, "Anhui Huami Information Technology Co., Ltd."),
    (0x0171, "Amazon.com Services, Inc."),
    (0x02E5, "Espressif Incorporated"),
    (0x038F, "Xiaomi Inc."),
    (0x0499, "Ruuvi Innovations Ltd."),
    (0x05A7, "Sonos Inc"),
    (0x060F, "Signify Netherlands B.V."),
    (0x08A9, "Tile, Inc."),
];

pub fn lookup_oui(mac: &MacAddr) -> String {
    if mac.is_broadcast() {
        return "Broadcast".to_string();
    }
    if mac.is_locally_administered() {
        return "Locally Administered (Random)".to_string();
    }
    if mac.is_multicast() {
        return "Multicast".to_string();
    }
    let prefix = mac.oui_prefix();
    match OUI_TABLE.binary_search_by_key(&prefix, |&(k, _)| k) {
        Ok(idx) => OUI_TABLE[idx].1.to_string(),
        Err(_) => "Unknown".to_string(),
    }
}

pub fn lookup_company_id(company_id: u16) -> Option<&'static str> {
    COMPANY_ID_TABLE
        .binary_search_by_key(&company_id, |&(id, _)| id)
        .ok()
        .map(|idx| COMPANY_ID_TABLE[idx].1)
}

/// Decodes a 48-bit Bluetooth address stored in a `u64` (`ullLong` / WinRT `BluetoothAddress`) MSB-first.
pub const fn mac_from_bt_u64(addr: u64) -> MacAddr {
    MacAddr::new([
        ((addr >> 40) & 0xFF) as u8,
        ((addr >> 32) & 0xFF) as u8,
        ((addr >> 24) & 0xFF) as u8,
        ((addr >> 16) & 0xFF) as u8,
        ((addr >> 8) & 0xFF) as u8,
        (addr & 0xFF) as u8,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tables_are_strictly_sorted() {
        assert!(OUI_TABLE.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(COMPANY_ID_TABLE.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn test_oui_lookup_respects_locally_administered_bit() {
        // 00:1A:11 -> Google, Inc. (globally administered)
        let google = MacAddr::new([0x00, 0x1A, 0x11, 0x01, 0x02, 0x03]);
        assert_eq!(lookup_oui(&google), "Google, Inc.");

        // 02:1A:11 -> bit 1 of first octet set (locally administered random MAC)
        let random_ble = MacAddr::new([0x02, 0x1A, 0x11, 0xAA, 0xBB, 0xCC]);
        assert!(random_ble.is_locally_administered());
        assert_eq!(lookup_oui(&random_ble), "Locally Administered (Random)");
    }

    #[test]
    fn test_company_id_and_bt_u64_decoding() {
        assert_eq!(lookup_company_id(0x004C), Some("Apple, Inc."));
        assert_eq!(lookup_company_id(0x0059), Some("Nordic Semiconductor ASA"));
        assert_eq!(lookup_company_id(0x00E0), Some("Google"));
        assert_eq!(lookup_company_id(0xFFFF), None);

        let mac = mac_from_bt_u64(0x0000_AABB_CCDD_EEFF);
        assert_eq!(mac, MacAddr::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
    }
}
