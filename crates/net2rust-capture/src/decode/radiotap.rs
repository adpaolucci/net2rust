//! 802.11 RadioTap header & Management frame (Beacon / Probe Request / Probe Response) parser.

use net2rust_core::{MacAddr, NetError, NetResult};

use crate::capture::{CapturedPacket, LinkType};
use crate::decode::lan_discovery::lookup_oui;

#[derive(Debug, Clone)]
pub struct WifiBeaconInfo {
    pub ssid: String,
    pub bssid: MacAddr,
    pub channel: Option<u16>,
    pub frequency_mhz: Option<u16>,
    pub rssi_dbm: Option<i8>,
    pub phy_type: String,
    pub security_mode: String,
    pub beacon_interval: Option<u16>,
    pub vendor_oui: Option<String>,
    pub frame_subtype: String,
}

pub fn freq_to_channel(freq_mhz: u16) -> Option<u16> {
    match freq_mhz {
        2412..=2472 => Some((freq_mhz - 2412) / 5 + 1),
        2484 => Some(14),
        5180..=5885 => Some((freq_mhz - 5000) / 5),
        5955..=7115 => Some((freq_mhz - 5950) / 5),
        _ => None,
    }
}

fn align_up(offset: usize, align: usize) -> usize {
    if align <= 1 {
        offset
    } else {
        (offset + align - 1) & !(align - 1)
    }
}

#[derive(Default)]
struct RadioTapFields {
    has_fcs: bool,
    frequency_mhz: Option<u16>,
    rssi_dbm: Option<i8>,
}

fn parse_radiotap_header(frame: &[u8]) -> NetResult<(RadioTapFields, &[u8])> {
    if frame.len() < 8 {
        return Err(NetError::ParseError(format!(
            "truncated RadioTap header: expected >= 8 bytes, got {}",
            frame.len()
        )));
    }
    let version = frame[0];
    if version != 0 {
        return Err(NetError::ParseError(format!("unsupported RadioTap version {version}")));
    }
    let it_len = usize::from(u16::from_le_bytes([frame[2], frame[3]]));
    if it_len < 8 || it_len > frame.len() {
        return Err(NetError::ParseError(format!(
            "invalid RadioTap it_len {it_len} for frame len {}",
            frame.len()
        )));
    }

    let first_present = u32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]);
    let mut cursor = 8usize;
    let mut present_word = first_present;
    let mut ext_words = 0usize;
    while (present_word & 0x8000_0000) != 0 {
        if ext_words >= 8 || cursor + 4 > it_len {
            break;
        }
        present_word = u32::from_le_bytes([frame[cursor], frame[cursor + 1], frame[cursor + 2], frame[cursor + 3]]);
        cursor += 4;
        ext_words += 1;
    }

    let mut fields = RadioTapFields::default();

    // Parse aligned RadioTap fields in bit 0..=5 of the primary it_present word.
    for bit in 0..=5u32 {
        if (first_present & (1 << bit)) == 0 {
            continue;
        }
        let (align, size) = match bit {
            0 => (8usize, 8usize), // TSFT
            1 => (1, 1),           // Flags
            2 => (1, 1),           // Rate
            3 => (2, 4),           // Channel (freq u16 + flags u16)
            4 => (2, 2),           // FHSS
            5 => (1, 1),           // dBm Antenna Signal
            _ => break,
        };
        cursor = align_up(cursor, align);
        if cursor + size > it_len {
            break;
        }
        match bit {
            1 => {
                fields.has_fcs = (frame[cursor] & 0x10) != 0;
            }
            3 => {
                let freq = u16::from_le_bytes([frame[cursor], frame[cursor + 1]]);
                if freq > 0 {
                    fields.frequency_mhz = Some(freq);
                }
            }
            5 => {
                fields.rssi_dbm = Some(frame[cursor] as i8);
            }
            _ => {}
        }
        cursor += size;
    }

    let mut mac_end = frame.len();
    if fields.has_fcs && mac_end >= it_len + 4 {
        mac_end -= 4;
    }

    Ok((fields, &frame[it_len..mac_end]))
}

fn decode_rsn_ie(data: &[u8]) -> Option<String> {
    // Version (2B) + Group cipher (4B) + Pairwise count (2B) + Pairwise list (4B*N) + AKM count (2B) + AKM list (4B*M)
    if data.len() < 8 {
        return None;
    }
    let version = u16::from_le_bytes([data[0], data[1]]);
    if version != 1 {
        return None;
    }
    let pairwise_count = usize::from(u16::from_le_bytes([data[6], data[7]]));
    let akm_count_off = 8usize.checked_add(pairwise_count.checked_mul(4)?)?;
    if akm_count_off + 2 > data.len() {
        return Some("WPA2-PSK".to_string());
    }
    let akm_count = usize::from(u16::from_le_bytes([data[akm_count_off], data[akm_count_off + 1]]));
    let mut pos = akm_count_off + 2;

    let mut has_eap = false;
    let mut has_psk = false;
    let mut has_sae = false;

    for _ in 0..akm_count {
        if pos + 4 > data.len() {
            break;
        }
        let oui = &data[pos..pos + 3];
        let suite_type = data[pos + 3];
        if oui == [0x00, 0x0F, 0xAC] {
            match suite_type {
                1 | 3 | 5 => has_eap = true,
                2 | 4 | 6 => has_psk = true,
                8 | 9 => has_sae = true,
                _ => {}
            }
        }
        pos += 4;
    }

    if has_sae && has_psk {
        Some("WPA2/WPA3".to_string())
    } else if has_sae {
        Some("WPA3-SAE".to_string())
    } else if has_eap {
        Some("WPA2-Enterprise".to_string())
    } else if has_psk {
        Some("WPA2-PSK".to_string())
    } else {
        Some("WPA2".to_string())
    }
}

pub fn parse_wifi_management_packet(pkt: &CapturedPacket) -> NetResult<Option<WifiBeaconInfo>> {
    let (rt_fields, mac) = match pkt.link_type {
        LinkType::Ieee80211Radiotap => parse_radiotap_header(&pkt.data)?,
        LinkType::Ieee80211 => (RadioTapFields::default(), pkt.data.as_slice()),
        _ => return Ok(None),
    };

    if mac.len() < 24 {
        return Ok(None);
    }
    let fc = u16::from_le_bytes([mac[0], mac[1]]);
    let frame_type = (fc >> 2) & 0x03;
    let subtype = (fc >> 4) & 0x0F;
    if frame_type != 0 || !matches!(subtype, 4 | 5 | 8) {
        return Ok(None);
    }

    let addr2 = MacAddr::new([mac[10], mac[11], mac[12], mac[13], mac[14], mac[15]]);
    let addr3 = MacAddr::new([mac[16], mac[17], mac[18], mac[19], mac[20], mac[21]]);

    let (beacon_interval, capability_info, ie_start, bssid, frame_subtype) = match subtype {
        8 | 5 => {
            // Beacon or Probe Response: 24B MAC + 12B fixed params
            if mac.len() < 36 {
                return Ok(None);
            }
            let bi = u16::from_le_bytes([mac[32], mac[33]]);
            let cap = u16::from_le_bytes([mac[34], mac[35]]);
            let label = if subtype == 8 { "Beacon" } else { "ProbeResponse" };
            (Some(bi), cap, 36usize, addr3, label.to_string())
        }
        4 => {
            // Probe Request: 24B MAC -> IEs directly
            let bssid = if addr3.is_broadcast() { addr2 } else { addr3 };
            (None, 0u16, 24usize, bssid, "ProbeRequest".to_string())
        }
        _ => return Ok(None),
    };

    let mut ssid: Option<String> = None;
    let mut ds_channel: Option<u16> = None;
    let mut has_ht = false;
    let mut has_vht = false;
    let mut has_he = false;
    let mut rsn_sec: Option<String> = None;
    let mut has_wpa1 = false;

    let mut pos = ie_start;
    while pos + 2 <= mac.len() {
        let tag_id = mac[pos];
        let len = usize::from(mac[pos + 1]);
        pos += 2;
        if pos + len > mac.len() {
            break;
        }
        let ie_data = &mac[pos..pos + len];
        pos += len;

        match tag_id {
            0 => {
                if ie_data.is_empty() || ie_data.iter().all(|&b| b == 0) {
                    ssid = Some("<Hidden>".to_string());
                } else {
                    ssid = Some(String::from_utf8_lossy(ie_data).into_owned());
                }
            }
            3 if !ie_data.is_empty() => {
                ds_channel = Some(u16::from(ie_data[0]));
            }
            45 => has_ht = true,
            61 if !ie_data.is_empty() => {
                has_ht = true;
                if ds_channel.is_none() {
                    ds_channel = Some(u16::from(ie_data[0]));
                }
            }
            191 => has_vht = true,
            255 if !ie_data.is_empty() && ie_data[0] == 35 => {
                has_he = true;
            }
            48 => {
                if let Some(sec) = decode_rsn_ie(ie_data) {
                    rsn_sec = Some(sec);
                }
            }
            221 if ie_data.len() >= 4 && ie_data[0..3] == [0x00, 0x50, 0xF2] && ie_data[3] == 0x01 => {
                has_wpa1 = true;
            }
            _ => {}
        }
    }

    let phy_type = if has_he {
        "802.11ax (HE)".to_string()
    } else if has_vht {
        "802.11ac (VHT)".to_string()
    } else if has_ht {
        "802.11n (HT)".to_string()
    } else {
        "802.11b/g".to_string()
    };

    let security_mode = if let Some(rsn) = rsn_sec {
        rsn
    } else if has_wpa1 {
        "WPA".to_string()
    } else if (capability_info & 0x0010) != 0 {
        "WEP".to_string()
    } else {
        "Open".to_string()
    };

    let channel = ds_channel.or_else(|| rt_fields.frequency_mhz.and_then(freq_to_channel));
    let vendor_oui = lookup_oui(bssid, None);

    Ok(Some(WifiBeaconInfo {
        ssid: ssid.unwrap_or_else(|| "<Hidden>".to_string()),
        bssid,
        channel,
        frequency_mhz: rt_fields.frequency_mhz,
        rssi_dbm: rt_fields.rssi_dbm,
        phy_type,
        security_mode,
        beacon_interval,
        vendor_oui,
        frame_subtype,
    }))
}
