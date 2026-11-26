use net2rust_core::{NetError, NetResult};
use serde::{Deserialize, Serialize};

use crate::bt_lookup::lookup_company_id;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleServiceData {
    pub uuid16: u16,
    pub uuid_label: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleManufacturerData {
    pub company_id: u16,
    pub company_name: Option<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BleAdSection {
    pub ad_type: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ParsedBleAd {
    pub flags: Option<u8>,
    pub flag_labels: Vec<String>,
    pub local_name: Option<String>,
    pub local_name_complete: bool,
    pub service_uuids: Vec<String>,
    pub tx_power_dbm: Option<i8>,
    pub appearance: Option<u16>,
    pub appearance_label: Option<String>,
    pub service_data: Vec<BleServiceData>,
    pub manufacturer_data: Vec<BleManufacturerData>,
    pub raw_sections: Vec<BleAdSection>,
}

pub fn encode_ad_sections(sections: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (ad_type, data) in sections {
        let total_len = 1usize.saturating_add(data.len());
        if total_len > u8::MAX as usize {
            continue;
        }
        out.push(total_len as u8);
        out.push(*ad_type);
        out.extend_from_slice(data);
    }
    out
}

pub fn parse_ble_ad(payload: &[u8]) -> NetResult<ParsedBleAd> {
    let mut parsed = ParsedBleAd::default();
    let mut offset = 0usize;

    while offset < payload.len() {
        let len = payload[offset] as usize;
        if len == 0 {
            // Zero-length AD structure acts as padding/terminator in BLE advertising packets.
            break;
        }

        let end = offset
            .checked_add(1)
            .and_then(|v| v.checked_add(len))
            .ok_or_else(|| NetError::ParseError("BLE AD length overflow".to_string()))?;

        if end > payload.len() {
            return Err(NetError::ParseError(format!(
                "truncated BLE AD structure at offset {offset}: declared len {len}, remaining {}",
                payload.len() - offset - 1
            )));
        }

        let ad_type = payload[offset + 1];
        let data = &payload[offset + 2..end];
        parsed.raw_sections.push(BleAdSection {
            ad_type,
            data: data.to_vec(),
        });

        match ad_type {
            0x01 => {
                if data.is_empty() {
                    return Err(NetError::ParseError(
                        "BLE Flags AD (0x01) has empty payload".to_string(),
                    ));
                }
                let f = data[0];
                parsed.flags = Some(f);
                parsed.flag_labels = decode_flags(f);
            }
            0x02 | 0x03 => {
                if !data.len().is_multiple_of(2) {
                    return Err(NetError::ParseError(format!(
                        "BLE 16-bit Service UUIDs AD (0x{ad_type:02X}) length {} not divisible by 2",
                        data.len()
                    )));
                }
                for chunk in data.as_chunks::<2>().0 {
                    let uuid = u16::from_le_bytes(*chunk);
                    let formatted = format_uuid16(uuid);
                    if !parsed.service_uuids.contains(&formatted) {
                        parsed.service_uuids.push(formatted);
                    }
                }
            }
            0x04 | 0x05 => {
                if !data.len().is_multiple_of(4) {
                    return Err(NetError::ParseError(format!(
                        "BLE 32-bit Service UUIDs AD (0x{ad_type:02X}) length {} not divisible by 4",
                        data.len()
                    )));
                }
                for chunk in data.as_chunks::<4>().0 {
                    let uuid = u32::from_le_bytes(*chunk);
                    let formatted = format!("0x{uuid:08X}");
                    if !parsed.service_uuids.contains(&formatted) {
                        parsed.service_uuids.push(formatted);
                    }
                }
            }
            0x06 | 0x07 => {
                if !data.len().is_multiple_of(16) {
                    return Err(NetError::ParseError(format!(
                        "BLE 128-bit Service UUIDs AD (0x{ad_type:02X}) length {} not divisible by 16",
                        data.len()
                    )));
                }
                for chunk in data.as_chunks::<16>().0 {
                    let mut be = *chunk;
                    be.reverse();
                    let formatted = format_uuid128_be(&be);
                    if !parsed.service_uuids.contains(&formatted) {
                        parsed.service_uuids.push(formatted);
                    }
                }
            }
            0x08 => {
                if !parsed.local_name_complete {
                    parsed.local_name = Some(String::from_utf8_lossy(data).into_owned());
                }
            }
            0x09 => {
                parsed.local_name = Some(String::from_utf8_lossy(data).into_owned());
                parsed.local_name_complete = true;
            }
            0x0A => {
                if data.len() != 1 {
                    return Err(NetError::ParseError(format!(
                        "BLE Tx Power Level AD (0x0A) expected 1 byte, got {}",
                        data.len()
                    )));
                }
                parsed.tx_power_dbm = Some(data[0] as i8);
            }
            0x16 => {
                if data.len() < 2 {
                    return Err(NetError::ParseError(
                        "BLE 16-bit Service Data AD (0x16) shorter than 2 bytes".to_string(),
                    ));
                }
                let uuid16 = u16::from_le_bytes([data[0], data[1]]);
                parsed.service_data.push(BleServiceData {
                    uuid16,
                    uuid_label: format_uuid16(uuid16),
                    data: data[2..].to_vec(),
                });
            }
            0x19 => {
                if data.len() != 2 {
                    return Err(NetError::ParseError(format!(
                        "BLE Appearance AD (0x19) expected 2 bytes, got {}",
                        data.len()
                    )));
                }
                let code = u16::from_le_bytes([data[0], data[1]]);
                parsed.appearance = Some(code);
                parsed.appearance_label = Some(decode_appearance(code).to_string());
            }
            0xFF => {
                if data.len() < 2 {
                    return Err(NetError::ParseError(
                        "BLE Manufacturer Specific Data AD (0xFF) shorter than 2 bytes".to_string(),
                    ));
                }
                let company_id = u16::from_le_bytes([data[0], data[1]]);
                let company_name = lookup_company_id(company_id).map(str::to_string);
                parsed.manufacturer_data.push(BleManufacturerData {
                    company_id,
                    company_name,
                    data: data[2..].to_vec(),
                });
            }
            _ => {}
        }

        offset = end;
    }

    Ok(parsed)
}

pub fn decode_flags(flags: u8) -> Vec<String> {
    let mut out = Vec::new();
    if (flags & 0x01) != 0 {
        out.push("LE Limited Discoverable".to_string());
    }
    if (flags & 0x02) != 0 {
        out.push("LE General Discoverable".to_string());
    }
    if (flags & 0x04) != 0 {
        out.push("BR/EDR Not Supported".to_string());
    }
    if (flags & 0x08) != 0 {
        out.push("Dual-Mode Controller".to_string());
    }
    if (flags & 0x10) != 0 {
        out.push("Dual-Mode Host".to_string());
    }
    out
}

pub fn format_uuid16(uuid: u16) -> String {
    if let Some(name) = well_known_uuid16_name(uuid) {
        format!("0x{uuid:04X} ({name})")
    } else {
        format!("0x{uuid:04X}")
    }
}

pub fn well_known_uuid16_name(uuid: u16) -> Option<&'static str> {
    match uuid {
        0x1800 => Some("Generic Access"),
        0x1801 => Some("Generic Attribute"),
        0x180A => Some("Device Information"),
        0x180D => Some("Heart Rate"),
        0x180F => Some("Battery Service"),
        0x1812 => Some("Human Interface Device"),
        0x181C => Some("User Data"),
        0x1844 => Some("Volume Control"),
        0xFD6F => Some("Exposure Notification"),
        0xFE9F => Some("Google Fast Pair"),
        0xFEAA => Some("Eddystone"),
        0xFEED => Some("Tile"),
        _ => None,
    }
}

pub fn format_uuid128_be(be: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        be[0],
        be[1],
        be[2],
        be[3],
        be[4],
        be[5],
        be[6],
        be[7],
        be[8],
        be[9],
        be[10],
        be[11],
        be[12],
        be[13],
        be[14],
        be[15]
    )
}

pub fn decode_appearance(code: u16) -> &'static str {
    match code {
        0 => "Unknown",
        64 => "Phone",
        128 => "Computer",
        192 => "Watch",
        193 => "Sports Watch",
        256 => "Clock",
        320 => "Display",
        384 => "Remote Control",
        448 => "Eye-glasses",
        512 => "Tag",
        576 => "Keyring",
        640 => "Media Player",
        704 => "Barcode Scanner",
        768 => "Thermometer",
        832 => "Heart Rate Sensor",
        833 => "Heart Rate Belt",
        960 => "HID Generic",
        961 => "Keyboard",
        962 => "Mouse",
        963 => "Joystick",
        964 => "Gamepad",
        1024 => "Glucose Meter",
        1088 => "Running Walking Sensor",
        1152 => "Cycling",
        2113 => "Audio Sink",
        2114 => "Audio Source",
        _ => match code >> 6 {
            1 => "Phone",
            2 => "Computer",
            3 => "Watch",
            13 => "Heart Rate Sensor",
            15 => "HID",
            33 => "Audio",
            _ => "Generic BLE Device",
        },
    }
}

pub fn format_hex_upper(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02X}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ble_ad_full_roundtrip() {
        // 128-bit UUID: 6e400001-b5a3-f393-e0a9-e50e24dcca9e (Nordic UART) in LE wire order
        let mut nus_le = [
            0x6e, 0x40, 0x00, 0x01, 0xb5, 0xa3, 0xf3, 0x93, 0xe0, 0xa9, 0xe5, 0x0e, 0x24, 0xdc, 0xca, 0x9e,
        ];
        nus_le.reverse();

        let sections = vec![
            (0x01, vec![0x06]),
            (0x08, b"Short".to_vec()),
            (0x09, b"Polar H10".to_vec()),
            (0x03, vec![0x0D, 0x18, 0x0F, 0x18]),
            (0x07, nus_le.to_vec()),
            (0x0A, vec![(-4i8) as u8]),
            (0x16, vec![0x0F, 0x18, 0x64]),
            (0x19, vec![0x41, 0x03]), // 0x0341 = 833 Heart Rate Belt
            (0xFF, vec![0x59, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]),
        ];

        let mut wire = encode_ad_sections(&sections);
        wire.extend_from_slice(&[0x00, 0x00, 0x00]); // trailing zero-padding

        let parsed = parse_ble_ad(&wire).unwrap();
        assert_eq!(parsed.flags, Some(0x06));
        assert!(parsed.flag_labels.contains(&"LE General Discoverable".to_string()));
        assert!(parsed.flag_labels.contains(&"BR/EDR Not Supported".to_string()));
        assert_eq!(parsed.local_name.as_deref(), Some("Polar H10"));
        assert!(parsed.local_name_complete);
        assert!(parsed.service_uuids.contains(&"0x180D (Heart Rate)".to_string()));
        assert!(parsed.service_uuids.contains(&"0x180F (Battery Service)".to_string()));
        assert!(
            parsed
                .service_uuids
                .contains(&"6e400001-b5a3-f393-e0a9-e50e24dcca9e".to_string())
        );
        assert_eq!(parsed.tx_power_dbm, Some(-4));
        assert_eq!(parsed.appearance, Some(833));
        assert_eq!(parsed.appearance_label.as_deref(), Some("Heart Rate Belt"));
        assert_eq!(parsed.service_data.len(), 1);
        assert_eq!(parsed.service_data[0].data, vec![0x64]);
        assert_eq!(parsed.manufacturer_data.len(), 1);
        assert_eq!(parsed.manufacturer_data[0].company_id, 0x0059);
        assert_eq!(
            parsed.manufacturer_data[0].company_name.as_deref(),
            Some("Nordic Semiconductor ASA")
        );
        assert_eq!(parsed.manufacturer_data[0].data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_parse_ble_ad_rejects_truncated_and_malformed() {
        // Declared length 5, only 3 bytes remaining
        let truncated = [0x05, 0x09, b'A', b'B'];
        assert!(matches!(parse_ble_ad(&truncated), Err(NetError::ParseError(_))));

        // Invalid 16-bit UUID length (3 bytes)
        let bad_uuid16 = [0x04, 0x03, 0x0D, 0x18, 0xFF];
        assert!(matches!(parse_ble_ad(&bad_uuid16), Err(NetError::ParseError(_))));

        // Invalid 128-bit UUID length (4 bytes)
        let bad_uuid128 = [0x05, 0x07, 1, 2, 3, 4];
        assert!(matches!(parse_ble_ad(&bad_uuid128), Err(NetError::ParseError(_))));

        // Manufacturer data shorter than 2 bytes
        let short_mfg = [0x02, 0xFF, 0x4C];
        assert!(matches!(parse_ble_ad(&short_mfg), Err(NetError::ParseError(_))));
    }
}
