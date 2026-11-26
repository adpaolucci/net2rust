use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use net2rust_core::{MacAddr, sanitize_wlan_profile_xml};

use crate::backend::{
    BleAdvertisementRecord, BluetoothClassicDevice, BluetoothRadioInfo, HostedNetworkStatus, OfflineRadioFixtures,
    WlanAvailableNetwork, WlanBssRecord, WlanConnectionRecord, WlanInterfaceInfo, WlanProfileRecord,
};
use crate::ble_ad::encode_ad_sections;

fn ie(id: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(id);
    out.push(payload.len() as u8);
    out.extend_from_slice(payload);
    out
}

fn fixed_time(secs_offset: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 20, 14, 0, 0).unwrap() + ChronoDuration::seconds(secs_offset)
}

pub fn build_default_radio_fixtures() -> OfflineRadioFixtures {
    let iface1_guid = "{11111111-2222-3333-4444-555555555555}".to_string();
    let iface1_name = "Wi-Fi (Intel AX211)".to_string();

    let interfaces = vec![WlanInterfaceInfo {
        guid: iface1_guid.clone(),
        description: iface1_name.clone(),
        state: "connected".to_string(),
        mac_address: Some(MacAddr::new([0x14, 0xAB, 0xF0, 0x10, 0x20, 0x30])),
    }];

    // AP 1: Wi-Fi 6 (802.11ax), 5 GHz Ch 36, WPA3-SAE, Country US, WPS Configured
    let mut ies_ap1 = Vec::new();
    ies_ap1.extend(ie(0, b"CorpNet-5G"));
    ies_ap1.extend(ie(1, &[0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C, 0xFA]));
    ies_ap1.extend(ie(7, b"US \x24\x04\x1E"));
    let mut ht_cap1 = vec![0u8; 26];
    ht_cap1[0] = 0x6E;
    ht_cap1[3] = 0xFF;
    ht_cap1[4] = 0xFF;
    ies_ap1.extend(ie(45, &ht_cap1));
    ies_ap1.extend(ie(
        48,
        &[
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x08,
            0xC0, 0x00,
        ],
    ));
    let mut vht_cap1 = vec![0u8; 12];
    vht_cap1[0] = 0x64;
    vht_cap1[4] = 0xFA;
    vht_cap1[5] = 0xFF;
    ies_ap1.extend(ie(191, &vht_cap1));
    ies_ap1.extend(ie(192, &[0x01, 42, 0, 0, 0]));
    let mut wps1 = vec![0x00, 0x50, 0xF2, 0x04];
    wps1.extend_from_slice(&[0x10, 0x44, 0x00, 0x01, 0x02]);
    wps1.extend_from_slice(&[0x10, 0x21, 0x00, 0x07, b'T', b'P', b'-', b'L', b'i', b'n', b'k']);
    wps1.extend_from_slice(&[
        0x10, 0x23, 0x00, 0x0B, b'A', b'r', b'c', b'h', b'e', b'r', b' ', b'A', b'X', b'7', b'3',
    ]);
    ies_ap1.extend(ie(221, &wps1));
    let mut he_cap1 = vec![0u8; 22];
    he_cap1[0] = 35;
    he_cap1[1 + 6] = 0x0C; // 80+160 MHz
    he_cap1[1 + 17] = 0xFA; // 2SS MCS0-11
    he_cap1[1 + 18] = 0xFF;
    ies_ap1.extend(ie(255, &he_cap1));

    // AP 2: Wi-Fi 7 (802.11be), 6 GHz Ch 33, WPA3-SAE-EXT-KEY, 320 MHz
    let mut ies_ap2 = Vec::new();
    ies_ap2.extend(ie(0, b"NextGen-6E"));
    ies_ap2.extend(ie(1, &[0x8C, 0x98, 0xB0, 0x60, 0xF9]));
    ies_ap2.extend(ie(7, b"US \x01\x04\x18"));
    ies_ap2.extend(ie(
        48,
        &[
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x08, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x08, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x18,
            0xC0, 0x00,
        ],
    ));
    let mut he_op2 = vec![0u8; 12];
    he_op2[0] = 36;
    he_op2[1 + 2] = 0x02; // 6GHz op info present (bit 17 -> byte 2 bit 1)
    he_op2[1 + 3] = 17; // BSS color 17
    he_op2[1 + 6] = 33; // primary ch 33
    he_op2[1 + 7] = 0x03; // 160 MHz in HE
    he_op2[1 + 8] = 31;
    ies_ap2.extend(ie(255, &he_op2));
    let mut eht_cap2 = vec![0u8; 15];
    eht_cap2[0] = 108;
    eht_cap2[1 + 2] = 0x02; // 320 MHz
    eht_cap2[1 + 11] = 0x02; // 2SS
    ies_ap2.extend(ie(255, &eht_cap2));
    ies_ap2.extend(ie(255, &[106, 0x01, 0, 0, 0, 0, 0x04, 31, 0]));

    // AP 3: Wi-Fi 4 (802.11n), 2.4 GHz Ch 6, Hidden SSID, WPA2-PSK
    let mut ies_ap3 = Vec::new();
    ies_ap3.extend(ie(0, b""));
    ies_ap3.extend(ie(1, &[0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C]));
    ies_ap3.extend(ie(3, &[6]));
    let mut ht_cap3 = vec![0u8; 26];
    ht_cap3[0] = 0x20;
    ht_cap3[3] = 0xFF;
    ht_cap3[4] = 0xFF;
    ies_ap3.extend(ie(45, &ht_cap3));
    ies_ap3.extend(ie(
        48,
        &[
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02,
            0x80, 0x00,
        ],
    ));

    // AP 4: Open Guest Wi-Fi on 2.4 GHz Ch 11
    let mut ies_ap4 = Vec::new();
    ies_ap4.extend(ie(0, b"Guest-Open"));
    ies_ap4.extend(ie(
        1,
        &[0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6C],
    ));
    ies_ap4.extend(ie(3, &[11]));
    ies_ap4.extend(ie(7, b"CA \x01\x0B\x14"));

    let bss_list = vec![
        WlanBssRecord {
            interface_guid: iface1_guid.clone(),
            interface_name: iface1_name.clone(),
            ssid: "CorpNet-5G".to_string(),
            bssid: MacAddr::new([0x3C, 0x84, 0x6A, 0xAA, 0xBB, 0x01]),
            bss_type: "Infrastructure".to_string(),
            phy_type: "HE (802.11ax)".to_string(),
            rssi_dbm: -52,
            signal_pct: 88,
            in_reg_domain: true,
            beacon_period_tu: 100,
            capability_info: 0x1511,
            center_freq_khz: 5_180_000,
            rate_set_kbps: vec![6000, 12000, 24000, 54000],
            raw_ies: ies_ap1,
        },
        WlanBssRecord {
            interface_guid: iface1_guid.clone(),
            interface_name: iface1_name.clone(),
            ssid: "NextGen-6E".to_string(),
            bssid: MacAddr::new([0x60, 0xA4, 0x4C, 0x11, 0x22, 0x02]),
            bss_type: "Infrastructure".to_string(),
            phy_type: "EHT (802.11be)".to_string(),
            rssi_dbm: -61,
            signal_pct: 74,
            in_reg_domain: true,
            beacon_period_tu: 100,
            capability_info: 0x1511,
            center_freq_khz: 6_115_000,
            rate_set_kbps: vec![6000, 24000, 54000],
            raw_ies: ies_ap2,
        },
        WlanBssRecord {
            interface_guid: iface1_guid.clone(),
            interface_name: iface1_name.clone(),
            ssid: String::new(),
            bssid: MacAddr::new([0xCC, 0x46, 0xD6, 0x55, 0x66, 0x03]),
            bss_type: "Infrastructure".to_string(),
            phy_type: "HT (802.11n)".to_string(),
            rssi_dbm: -74,
            signal_pct: 48,
            in_reg_domain: true,
            beacon_period_tu: 100,
            capability_info: 0x0411,
            center_freq_khz: 2_437_000,
            rate_set_kbps: vec![1000, 2000, 11000, 54000],
            raw_ies: ies_ap3,
        },
        WlanBssRecord {
            interface_guid: iface1_guid.clone(),
            interface_name: iface1_name.clone(),
            ssid: "Guest-Open".to_string(),
            bssid: MacAddr::new([0x98, 0xDA, 0xC4, 0x77, 0x88, 0x04]),
            bss_type: "Infrastructure".to_string(),
            phy_type: "ERP (802.11g)".to_string(),
            rssi_dbm: -68,
            signal_pct: 62,
            in_reg_domain: true,
            beacon_period_tu: 100,
            capability_info: 0x0401,
            center_freq_khz: 2_462_000,
            rate_set_kbps: vec![1000, 11000, 54000],
            raw_ies: ies_ap4,
        },
    ];

    let available_networks = vec![
        WlanAvailableNetwork {
            interface_guid: iface1_guid.clone(),
            interface_name: iface1_name.clone(),
            profile_name: "CorpNet-5G".to_string(),
            ssid: "CorpNet-5G".to_string(),
            bss_type: "Infrastructure".to_string(),
            number_of_bssids: 1,
            connectable: true,
            not_connectable_reason: 0,
            phy_types: vec!["HE (802.11ax)".to_string()],
            signal_quality_pct: 88,
            security_enabled: true,
            default_auth_algo: "WPA3-SAE".to_string(),
            default_cipher_algo: "CCMP".to_string(),
            connected: true,
            has_profile: true,
            detected_at: fixed_time(0),
        },
        WlanAvailableNetwork {
            interface_guid: iface1_guid.clone(),
            interface_name: iface1_name.clone(),
            profile_name: "NextGen-6E".to_string(),
            ssid: "NextGen-6E".to_string(),
            bss_type: "Infrastructure".to_string(),
            number_of_bssids: 1,
            connectable: true,
            not_connectable_reason: 0,
            phy_types: vec!["EHT (802.11be)".to_string()],
            signal_quality_pct: 74,
            security_enabled: true,
            default_auth_algo: "WPA3-SAE".to_string(),
            default_cipher_algo: "CCMP".to_string(),
            connected: false,
            has_profile: true,
            detected_at: fixed_time(0),
        },
        WlanAvailableNetwork {
            interface_guid: iface1_guid.clone(),
            interface_name: iface1_name.clone(),
            profile_name: String::new(),
            ssid: "Guest-Open".to_string(),
            bss_type: "Infrastructure".to_string(),
            number_of_bssids: 1,
            connectable: true,
            not_connectable_reason: 0,
            phy_types: vec!["ERP (802.11g)".to_string()],
            signal_quality_pct: 62,
            security_enabled: false,
            default_auth_algo: "Open".to_string(),
            default_cipher_algo: "None".to_string(),
            connected: false,
            has_profile: false,
            detected_at: fixed_time(0),
        },
    ];

    let connections = vec![WlanConnectionRecord {
        interface_guid: iface1_guid.clone(),
        interface_name: iface1_name.clone(),
        state: "Connected".to_string(),
        connection_mode: "Profile".to_string(),
        profile_name: "CorpNet-5G".to_string(),
        ssid: "CorpNet-5G".to_string(),
        bssid: MacAddr::new([0x3C, 0x84, 0x6A, 0xAA, 0xBB, 0x01]),
        bss_type: "Infrastructure".to_string(),
        phy_type: "HE (802.11ax)".to_string(),
        channel: 36,
        center_freq_mhz: 5180,
        rx_rate_kbps: 1_201_000,
        tx_rate_kbps: 1_201_000,
        signal_quality_pct: 88,
        rssi_dbm: Some(-52),
        security_enabled: true,
        one_x_enabled: false,
        auth_algo: "WPA3-SAE".to_string(),
        cipher_algo: "CCMP".to_string(),
        tx_packets: Some(128_450),
        rx_packets: Some(392_110),
    }];

    let xml_profile_1 = sanitize_wlan_profile_xml(
        r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"
             xmlns:v3="http://www.microsoft.com/networking/WLAN/profile/v3">
    <name>CorpNet-5G</name>
    <SSIDConfig>
        <SSID>
            <hex>436F72704E65742D3547</hex>
            <name>CorpNet-5G</name>
        </SSID>
        <nonBroadcast>false</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA3SAE</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>true</protected>
                <keyMaterial>SYNTHETIC-PROTECTED-BLOB</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
    <v3:MacRandomization>
        <v3:enableRandomization>true</v3:enableRandomization>
    </v3:MacRandomization>
</WLANProfile>"#,
    );

    let xml_profile_2 = sanitize_wlan_profile_xml(
        r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>NextGen-6E</name>
    <SSIDConfig>
        <SSID>
            <name>NextGen-6E</name>
        </SSID>
        <nonBroadcast>false</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA3SAE</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>"#,
    );

    let xml_profile_3 = sanitize_wlan_profile_xml(
        r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>LabHidden</name>
    <SSIDConfig>
        <SSID>
            <hex>4C616248696464656E</hex>
        </SSID>
        <nonBroadcast>true</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>"#,
    );

    let profiles = vec![
        WlanProfileRecord {
            interface_guid: iface1_guid.clone(),
            interface_name: iface1_name.clone(),
            profile_name: "CorpNet-5G".to_string(),
            flags: 2, // User profile
            position: 0,
            sanitized_xml: xml_profile_1,
        },
        WlanProfileRecord {
            interface_guid: iface1_guid.clone(),
            interface_name: iface1_name.clone(),
            profile_name: "NextGen-6E".to_string(),
            flags: 2,
            position: 1,
            sanitized_xml: xml_profile_2,
        },
        WlanProfileRecord {
            interface_guid: iface1_guid,
            interface_name: iface1_name,
            profile_name: "LabHidden".to_string(),
            flags: 0,
            position: 2,
            sanitized_xml: xml_profile_3,
        },
    ];

    let hosted_network = HostedNetworkStatus {
        state: "Idle".to_string(),
        adapter_guid: Some("{33333333-4444-5555-6666-777777777777}".to_string()),
        bssid: None,
        ssid: Some("GUAP-Hotspot".to_string()),
        max_peers: 8,
        active_peers: 0,
        phy_type: None,
        channel_freq_khz: None,
        peers: Vec::new(),
    };

    let bt_radios = vec![BluetoothRadioInfo {
        name: "Intel(R) Wireless Bluetooth(R)".to_string(),
        address: MacAddr::new([0x14, 0xAB, 0xF0, 0x99, 0x88, 0x77]),
        class_of_device: 0x0A010C,
        lmp_subversion: 12,
        manufacturer_id: 0x0002,
    }];

    let bt_headphones = BluetoothClassicDevice {
        name: "WH-1000XM5".to_string(),
        address: MacAddr::new([0x54, 0xB7, 0xE5, 0x11, 0x22, 0x33]), // Sony OUI
        class_of_device: 0x240418,                                   // Audio/Video: Headphones
        connected: true,
        remembered: true,
        authenticated: true,
        last_seen: Some(fixed_time(10)),
        last_used: Some(fixed_time(10)),
    };

    let bt_keyboard = BluetoothClassicDevice {
        name: "MX Keys".to_string(),
        address: MacAddr::new([0x70, 0x88, 0x6B, 0x44, 0x55, 0x66]), // Logitech OUI
        class_of_device: 0x002540,                                   // Peripheral: Keyboard
        connected: true,
        remembered: true,
        authenticated: true,
        last_seen: Some(fixed_time(15)),
        last_used: Some(fixed_time(12)),
    };

    let bt_phone = BluetoothClassicDevice {
        name: "Pixel 9".to_string(),
        address: MacAddr::new([0x3C, 0x5A, 0xB4, 0x77, 0x88, 0x99]), // Google OUI
        class_of_device: 0x5A020C,                                   // Phone: Smartphone
        connected: false,
        remembered: true,
        authenticated: true,
        last_seen: Some(fixed_time(5)),
        last_used: Some(fixed_time(-300)),
    };

    let bt_devices = vec![bt_headphones.clone(), bt_keyboard.clone(), bt_phone.clone()];

    // Multi-step snapshot timeline so offline bt-log emits both Arrived and Departed events.
    let bt_log_snapshots = vec![
        (fixed_time(0), vec![bt_headphones.clone(), bt_phone.clone()]),
        (fixed_time(30), vec![bt_headphones.clone(), bt_keyboard.clone()]),
        (fixed_time(60), vec![bt_headphones, bt_keyboard, bt_phone]),
    ];

    let ble_sections_polar = vec![
        (0x01, vec![0x06]),
        (0x09, b"Polar H10".to_vec()),
        (0x03, vec![0x0D, 0x18, 0x0F, 0x18]),
        (0x0A, vec![(-4i8) as u8]),
        (0x19, vec![0x41, 0x03]), // Heart Rate Belt
        (0xFF, vec![0x59, 0x00, 0x01, 0x02, 0x03, 0x04]),
    ];

    let ble_sections_apple = vec![
        (0x01, vec![0x1A]),
        (0xFF, vec![0x4C, 0x00, 0x10, 0x05, 0x03, 0x1C, 0xAA, 0xBB]),
    ];

    let ble_sections_google = vec![
        (0x01, vec![0x06]),
        (0x09, b"FastPair-Tag".to_vec()),
        (0x03, vec![0x9F, 0xFE]), // 0xFE9F Google Fast Pair
        (0xFF, vec![0xE0, 0x00, 0x11, 0x22]),
    ];

    let ble_advertisements = vec![
        BleAdvertisementRecord {
            address: MacAddr::new([0xD8, 0x3A, 0xDD, 0x01, 0x02, 0x03]),
            address_type: "Public".to_string(),
            advertisement_type: "ConnectableUndirected".to_string(),
            rssi_dbm: -58,
            tx_power_dbm: Some(-4),
            local_name: "Polar H10".to_string(),
            flags: Some(0x06),
            service_uuids: vec![
                "0x180D (Heart Rate)".to_string(),
                "0x180F (Battery Service)".to_string(),
            ],
            manufacturer_data: vec![(0x0059, vec![0x01, 0x02, 0x03, 0x04])],
            data_sections: ble_sections_polar,
            last_seen: fixed_time(20),
        },
        BleAdvertisementRecord {
            address: MacAddr::new([0x4E, 0x12, 0x34, 0x56, 0x78, 0x9A]), // Locally administered random MAC
            address_type: "Random".to_string(),
            advertisement_type: "NonConnectableUndirected".to_string(),
            rssi_dbm: -66,
            tx_power_dbm: Some(12),
            local_name: String::new(),
            flags: Some(0x1A),
            service_uuids: Vec::new(),
            manufacturer_data: vec![(0x004C, vec![0x10, 0x05, 0x03, 0x1C, 0xAA, 0xBB])],
            data_sections: ble_sections_apple,
            last_seen: fixed_time(22),
        },
        BleAdvertisementRecord {
            address: MacAddr::new([0x3C, 0x5A, 0xB4, 0xCC, 0xDD, 0xEE]),
            address_type: "Public".to_string(),
            advertisement_type: "ScannableUndirected".to_string(),
            rssi_dbm: -71,
            tx_power_dbm: None,
            local_name: "FastPair-Tag".to_string(),
            flags: Some(0x06),
            service_uuids: vec!["0xFE9F (Google Fast Pair)".to_string()],
            manufacturer_data: vec![(0x00E0, vec![0x11, 0x22])],
            data_sections: ble_sections_google,
            last_seen: fixed_time(25),
        },
    ];

    let _ = encode_ad_sections(&[]);

    OfflineRadioFixtures {
        interfaces,
        bss_list,
        available_networks,
        connections,
        profiles,
        hosted_network,
        bt_radios,
        bt_devices,
        bt_log_snapshots,
        ble_advertisements,
    }
}
