use net2rust_core::MacAddr;

static OUI_TABLE: &[(&str, &str)] = &[
    ("00005E", "IANA (VRRP/Reserved)"),
    ("000C29", "VMware, Inc."),
    ("00155D", "Microsoft Corporation (Hyper-V)"),
    ("001A11", "Google, Inc."),
    ("001B63", "Apple, Inc."),
    ("001C42", "Parallels, Inc."),
    ("002590", "Super Micro Computer, Inc."),
    ("005056", "VMware, Inc."),
    ("00E04C", "Realtek Semiconductor Corp."),
    ("04D9F5", "ASUSTek COMPUTER INC."),
    ("080027", "Oracle VirtualBox"),
    ("0C9D92", "ASUSTek COMPUTER INC."),
    ("107B44", "ASUSTek COMPUTER INC."),
    ("14DDA9", "ASUSTek COMPUTER INC."),
    ("1866DA", "Dell Inc."),
    ("1C1B0D", "GIGA-BYTE TECHNOLOGY CO., LTD."),
    ("244BFE", "ASUSTek COMPUTER INC."),
    ("28CDC1", "Raspberry Pi Trading Ltd"),
    ("3497F6", "ASUSTek COMPUTER INC."),
    ("38D547", "ASUSTek COMPUTER INC."),
    ("3C5282", "Hewlett Packard"),
    ("3CD92B", "Hewlett Packard"),
    ("40B076", "ASUSTek COMPUTER INC."),
    ("482AE3", "Lenovo"),
    ("50EBF6", "ASUSTek COMPUTER INC."),
    ("525400", "QEMU / KVM Virtual NIC"),
    ("54BF64", "Dell Inc."),
    ("6045CB", "ASUSTek COMPUTER INC."),
    ("6C4B90", "Liteon Technology Corporation"),
    ("7085C2", "ASRock Incorporation"),
    ("74D435", "GIGA-BYTE TECHNOLOGY CO., LTD."),
    ("80FA5B", "CLEVO CO."),
    ("88AE07", "Apple, Inc."),
    ("90B11C", "Dell Inc."),
    ("94C691", "Elitegroup Computer Systems"),
    ("98E7F4", "Hewlett Packard"),
    ("A0369F", "Intel Corporate"),
    ("A4BB6D", "Dell Inc."),
    ("AC1F6B", "Super Micro Computer, Inc."),
    ("B06EBF", "ASUSTek COMPUTER INC."),
    ("B42E99", "GIGA-BYTE TECHNOLOGY CO., LTD."),
    ("B827EB", "Raspberry Pi Foundation"),
    ("C85B76", "Lenovo"),
    ("D43D7E", "Micro-Star International Co., Ltd."),
    ("D85ED3", "GIGA-BYTE TECHNOLOGY CO., LTD."),
    ("DCA632", "Raspberry Pi Trading Ltd"),
    ("E45F01", "Raspberry Pi Trading Ltd"),
    ("F07959", "ASUSTek COMPUTER INC."),
    ("F8B156", "Dell Inc."),
    ("FCF8AE", "Intel Corporate"),
];

/// Look up an IEEE OUI vendor name from a `MacAddr`.
pub fn lookup_oui(mac: &MacAddr) -> Option<&'static str> {
    let oui = mac.oui_hex();
    OUI_TABLE
        .iter()
        .find(|(prefix, _)| *prefix == oui)
        .map(|(_, vendor)| *vendor)
}

/// Format the `VendorOUI` column value consistently for `IPNeighborsView`.
pub fn format_vendor_oui(mac: &MacAddr) -> String {
    let oui = mac.oui_hex();
    if let Some(vendor) = lookup_oui(mac) {
        format!("{vendor} ({oui})")
    } else if mac.is_broadcast() {
        format!("Broadcast ({oui})")
    } else if mac.is_multicast() {
        format!("Multicast ({oui})")
    } else if mac.is_locally_administered() {
        format!("Locally Administered ({oui})")
    } else {
        format!("Unknown ({oui})")
    }
}
