use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtCapabilities {
    pub supports_40mhz: bool,
    pub sgi_20: bool,
    pub sgi_40: bool,
    pub nss: u8,
    pub max_mcs: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtOperation {
    pub primary_channel: u8,
    pub secondary_offset: u8,
    pub sta_40mhz: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsnInfo {
    pub version: u16,
    pub group_cipher: Option<String>,
    pub pairwise_ciphers: Vec<String>,
    pub akm_suites: Vec<String>,
    pub mfpr: bool,
    pub mfpc: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wpa1Info {
    pub multicast_cipher: Option<String>,
    pub unicast_ciphers: Vec<String>,
    pub akm_suites: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ExtCapabilities {
    pub bss_transition_11v: bool,
    pub interworking_hs20: bool,
    pub ftm_responder: bool,
    pub ftm_initiator: bool,
    pub twt_responder: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VhtCapabilities {
    pub max_width_mhz: u32,
    pub sgi_80: bool,
    pub sgi_160: bool,
    pub nss: u8,
    pub max_mcs: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VhtOperation {
    pub channel_width_mhz: u32,
    pub ccfs0: u8,
    pub ccfs1: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeCapabilities {
    pub channel_width_mhz: u32,
    pub nss: u8,
    pub max_mcs: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeOperation {
    pub bss_color: u8,
    pub bss_color_disabled: bool,
    pub six_ghz_primary_channel: Option<u8>,
    pub six_ghz_width_mhz: Option<u32>,
    pub ccfs0: Option<u8>,
    pub ccfs1: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EhtCapabilities {
    pub supports_320mhz: bool,
    pub nss: u8,
    pub max_mcs: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EhtOperation {
    pub channel_width_mhz: Option<u32>,
    pub ccfs0: Option<u8>,
    pub ccfs1: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WpsInfo {
    pub state: Option<String>,
    pub ap_locked: Option<bool>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_number: Option<String>,
    pub device_name: Option<String>,
    pub serial_number: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ParsedIes {
    pub ssid: Option<String>,
    pub hidden_ssid: bool,
    pub supported_rates_mbps: Vec<f64>,
    pub bss_membership_selectors: Vec<u8>,
    pub ds_channel: Option<u8>,
    pub country_code: Option<String>,
    pub country_environment: Option<char>,
    pub ht_cap: Option<HtCapabilities>,
    pub ht_op: Option<HtOperation>,
    pub rsn: Option<RsnInfo>,
    pub wpa1: Option<Wpa1Info>,
    pub ext_cap: Option<ExtCapabilities>,
    pub vht_cap: Option<VhtCapabilities>,
    pub vht_op: Option<VhtOperation>,
    pub he_cap: Option<HeCapabilities>,
    pub he_op: Option<HeOperation>,
    pub eht_cap: Option<EhtCapabilities>,
    pub eht_op: Option<EhtOperation>,
    pub wps: Option<WpsInfo>,
    pub wmm_present: bool,
    pub element_count: usize,
    pub truncated: bool,
}

pub fn channel_from_freq_khz(freq_khz: u32) -> Option<u32> {
    let mhz = freq_khz / 1000;
    if mhz == 2484 {
        return Some(14);
    }
    if (2412..=2472).contains(&mhz) && (mhz - 2407).is_multiple_of(5) {
        return Some((mhz - 2407) / 5);
    }
    if (5005..=5895).contains(&mhz) && (mhz - 5000).is_multiple_of(5) {
        return Some((mhz - 5000) / 5);
    }
    if mhz == 5935 {
        return Some(2);
    }
    if (5955..=7115).contains(&mhz) && (mhz - 5950).is_multiple_of(5) {
        return Some((mhz - 5950) / 5);
    }
    None
}

pub fn freq_mhz_from_channel(channel: u32, band_6ghz: bool) -> Option<u32> {
    if band_6ghz {
        if channel == 2 {
            return Some(5935);
        }
        if (1..=233).contains(&channel) {
            return Some(5950 + channel * 5);
        }
        return None;
    }

    if channel == 14 {
        return Some(2484);
    }
    if (1..=13).contains(&channel) {
        return Some(2407 + channel * 5);
    }
    if (32..=177).contains(&channel) {
        return Some(5000 + channel * 5);
    }
    None
}

pub fn parse_ie_stream(bytes: &[u8]) -> ParsedIes {
    let mut parsed = ParsedIes::default();
    let mut offset = 0usize;

    while offset < bytes.len() {
        if offset + 2 > bytes.len() {
            parsed.truncated = true;
            break;
        }
        let id = bytes[offset];
        let len = bytes[offset + 1] as usize;
        let payload_start = offset + 2;
        let Some(payload_end) = payload_start.checked_add(len) else {
            parsed.truncated = true;
            break;
        };
        if payload_end > bytes.len() {
            parsed.truncated = true;
            break;
        }

        let payload = &bytes[payload_start..payload_end];
        parsed.element_count += 1;

        match id {
            0 => parse_ssid(payload, &mut parsed),
            1 | 50 => parse_rates(payload, &mut parsed),
            3 => {
                if !payload.is_empty() {
                    parsed.ds_channel = Some(payload[0]);
                }
            }
            7 => parse_country(payload, &mut parsed),
            45 => parse_ht_cap(payload, &mut parsed),
            48 => parse_rsn(payload, &mut parsed),
            61 => parse_ht_op(payload, &mut parsed),
            127 => parse_ext_cap(payload, &mut parsed),
            191 => parse_vht_cap(payload, &mut parsed),
            192 => parse_vht_op(payload, &mut parsed),
            221 => parse_vendor_specific(payload, &mut parsed),
            255 => parse_extension_ie(payload, &mut parsed),
            _ => {}
        }

        offset = payload_end;
    }

    parsed
}

fn parse_ssid(payload: &[u8], out: &mut ParsedIes) {
    let trimmed_len = payload.len().min(32);
    let slice = &payload[..trimmed_len];
    if slice.is_empty() || slice.iter().all(|&b| b == 0) {
        out.hidden_ssid = true;
        out.ssid = Some(String::new());
    } else {
        out.hidden_ssid = false;
        out.ssid = Some(String::from_utf8_lossy(slice).into_owned());
    }
}

fn parse_rates(payload: &[u8], out: &mut ParsedIes) {
    for &b in payload {
        let code = b & 0x7F;
        if code >= 121 {
            if !out.bss_membership_selectors.contains(&code) {
                out.bss_membership_selectors.push(code);
            }
            continue;
        }
        let mbps = (code as f64) * 0.5;
        if !out.supported_rates_mbps.contains(&mbps) {
            out.supported_rates_mbps.push(mbps);
        }
    }
}

fn parse_country(payload: &[u8], out: &mut ParsedIes) {
    if payload.len() >= 3 {
        let code = String::from_utf8_lossy(&payload[0..2]).trim().to_string();
        if !code.is_empty() {
            out.country_code = Some(code);
        }
        let env = payload[2] as char;
        out.country_environment = Some(env);
    }
}

fn parse_ht_cap(payload: &[u8], out: &mut ParsedIes) {
    if payload.len() < 26 {
        return;
    }
    let info = u16::from_le_bytes([payload[0], payload[1]]);
    let supports_40mhz = (info & 0x0002) != 0;
    let sgi_20 = (info & 0x0020) != 0;
    let sgi_40 = (info & 0x0040) != 0;

    let mut nss = 0u8;
    let mut max_mcs = 0u8;
    for ss in 0..4usize {
        let mask = payload[3 + ss];
        if mask != 0 {
            nss = (ss + 1) as u8;
            let highest_bit = 7 - mask.leading_zeros() as u8;
            max_mcs = (ss as u8) * 8 + highest_bit;
        }
    }
    let nss = nss.max(1);

    out.ht_cap = Some(HtCapabilities {
        supports_40mhz,
        sgi_20,
        sgi_40,
        nss,
        max_mcs,
    });
}

fn parse_ht_op(payload: &[u8], out: &mut ParsedIes) {
    if payload.len() < 22 {
        return;
    }
    out.ht_op = Some(HtOperation {
        primary_channel: payload[0],
        secondary_offset: payload[1] & 0x03,
        sta_40mhz: (payload[1] & 0x04) != 0,
    });
}

fn decode_cipher_suite(suite: &[u8]) -> String {
    if suite.len() != 4 {
        return "Unknown".to_string();
    }
    let oui = &suite[0..3];
    let stype = suite[3];
    if oui == [0x00, 0x0F, 0xAC] {
        match stype {
            0 => "Use-Group".to_string(),
            1 => "WEP-40".to_string(),
            2 => "TKIP".to_string(),
            4 => "CCMP-128".to_string(),
            5 => "WEP-104".to_string(),
            6 => "BIP-CMAC-128".to_string(),
            8 => "GCMP-128".to_string(),
            9 => "GCMP-256".to_string(),
            10 => "CCMP-256".to_string(),
            11 => "BIP-GMAC-128".to_string(),
            12 => "BIP-GMAC-256".to_string(),
            13 => "BIP-CMAC-256".to_string(),
            other => format!("RSN-Cipher-{other}"),
        }
    } else if oui == [0x00, 0x50, 0xF2] {
        match stype {
            1 => "WEP-40".to_string(),
            2 => "TKIP".to_string(),
            4 => "CCMP-128".to_string(),
            5 => "WEP-104".to_string(),
            other => format!("WPA-Cipher-{other}"),
        }
    } else {
        format!("{:02X}:{:02X}:{:02X}:{stype}", oui[0], oui[1], oui[2])
    }
}

fn decode_akm_suite(suite: &[u8]) -> String {
    if suite.len() != 4 {
        return "Unknown".to_string();
    }
    let oui = &suite[0..3];
    let stype = suite[3];
    if oui == [0x00, 0x0F, 0xAC] {
        match stype {
            1 => "802.1X".to_string(),
            2 => "PSK".to_string(),
            3 => "FT-802.1X".to_string(),
            4 => "FT-PSK".to_string(),
            5 => "802.1X-SHA256".to_string(),
            6 => "PSK-SHA256".to_string(),
            8 => "SAE".to_string(),
            9 => "FT-SAE".to_string(),
            11 => "Suite-B-802.1X".to_string(),
            12 => "Suite-B-192".to_string(),
            18 => "OWE".to_string(),
            24 => "SAE-EXT-KEY".to_string(),
            other => format!("RSN-AKM-{other}"),
        }
    } else if oui == [0x00, 0x50, 0xF2] {
        match stype {
            1 => "WPA-802.1X".to_string(),
            2 => "WPA-PSK".to_string(),
            other => format!("WPA-AKM-{other}"),
        }
    } else {
        format!("{:02X}:{:02X}:{:02X}:{stype}", oui[0], oui[1], oui[2])
    }
}

fn parse_rsn(payload: &[u8], out: &mut ParsedIes) {
    if payload.len() < 2 {
        return;
    }
    let version = u16::from_le_bytes([payload[0], payload[1]]);
    let mut pos = 2usize;

    let group_cipher = if pos + 4 <= payload.len() {
        let c = decode_cipher_suite(&payload[pos..pos + 4]);
        pos += 4;
        Some(c)
    } else {
        None
    };

    let mut pairwise_ciphers = Vec::new();
    if pos + 2 <= payload.len() {
        let count = u16::from_le_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;
        for _ in 0..count {
            if pos + 4 > payload.len() {
                out.truncated = true;
                break;
            }
            pairwise_ciphers.push(decode_cipher_suite(&payload[pos..pos + 4]));
            pos += 4;
        }
    }

    let mut akm_suites = Vec::new();
    if pos + 2 <= payload.len() {
        let count = u16::from_le_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;
        for _ in 0..count {
            if pos + 4 > payload.len() {
                out.truncated = true;
                break;
            }
            akm_suites.push(decode_akm_suite(&payload[pos..pos + 4]));
            pos += 4;
        }
    }

    let (mfpr, mfpc) = if pos + 2 <= payload.len() {
        let caps = u16::from_le_bytes([payload[pos], payload[pos + 1]]);
        ((caps & 0x0040) != 0, (caps & 0x0080) != 0)
    } else {
        (false, false)
    };

    out.rsn = Some(RsnInfo {
        version,
        group_cipher,
        pairwise_ciphers,
        akm_suites,
        mfpr,
        mfpc,
    });
}

fn parse_ext_cap(payload: &[u8], out: &mut ParsedIes) {
    let bit = |b: usize| -> bool {
        let byte_idx = b / 8;
        let bit_idx = b % 8;
        payload.get(byte_idx).is_some_and(|v| (v & (1 << bit_idx)) != 0)
    };

    out.ext_cap = Some(ExtCapabilities {
        bss_transition_11v: bit(19),
        interworking_hs20: bit(31),
        ftm_responder: bit(70),
        ftm_initiator: bit(71),
        twt_responder: bit(77),
    });
}

fn parse_vht_cap(payload: &[u8], out: &mut ParsedIes) {
    if payload.len() < 12 {
        return;
    }
    let cap = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let width_sup = (cap >> 2) & 0x03;
    let max_width_mhz = match width_sup {
        1 | 2 => 160,
        _ => 80,
    };
    let sgi_80 = (cap & 0x0020) != 0;
    let sgi_160 = (cap & 0x0040) != 0;

    let rx_mcs_map = u16::from_le_bytes([payload[4], payload[5]]);
    let mut nss = 0u8;
    let mut max_mcs = 7u8;
    for ss in 0..8u8 {
        let code = (rx_mcs_map >> (ss * 2)) & 0x03;
        if code != 3 {
            nss = ss + 1;
            max_mcs = match code {
                0 => 7,
                1 => 8,
                2 => 9,
                _ => 7,
            };
        }
    }

    out.vht_cap = Some(VhtCapabilities {
        max_width_mhz,
        sgi_80,
        sgi_160,
        nss: nss.max(1),
        max_mcs,
    });
}

fn parse_vht_op(payload: &[u8], out: &mut ParsedIes) {
    if payload.len() < 5 {
        return;
    }
    let width = match payload[0] {
        0 => 40, // 20 or 40 MHz
        1 => 80,
        2 | 3 => 160,
        _ => 80,
    };
    out.vht_op = Some(VhtOperation {
        channel_width_mhz: width,
        ccfs0: payload[1],
        ccfs1: payload[2],
    });
}

fn parse_vendor_specific(payload: &[u8], out: &mut ParsedIes) {
    if payload.len() < 4 {
        return;
    }
    let oui = &payload[0..3];
    let vtype = payload[3];
    let body = &payload[4..];

    if oui == [0x00, 0x50, 0xF2] {
        match vtype {
            0x01 => parse_wpa1(body, out),
            0x02 => out.wmm_present = true,
            0x04 => parse_wps(body, out),
            _ => {}
        }
    }
}

fn parse_wpa1(body: &[u8], out: &mut ParsedIes) {
    if body.len() < 2 {
        return;
    }
    let mut pos = 2usize; // skip version
    let multicast_cipher = if pos + 4 <= body.len() {
        let c = decode_cipher_suite(&body[pos..pos + 4]);
        pos += 4;
        Some(c)
    } else {
        None
    };

    let mut unicast_ciphers = Vec::new();
    if pos + 2 <= body.len() {
        let count = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        for _ in 0..count {
            if pos + 4 > body.len() {
                break;
            }
            unicast_ciphers.push(decode_cipher_suite(&body[pos..pos + 4]));
            pos += 4;
        }
    }

    let mut akm_suites = Vec::new();
    if pos + 2 <= body.len() {
        let count = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        for _ in 0..count {
            if pos + 4 > body.len() {
                break;
            }
            akm_suites.push(decode_akm_suite(&body[pos..pos + 4]));
            pos += 4;
        }
    }

    out.wpa1 = Some(Wpa1Info {
        multicast_cipher,
        unicast_ciphers,
        akm_suites,
    });
}

fn parse_wps(body: &[u8], out: &mut ParsedIes) {
    let mut wps = out.wps.take().unwrap_or_default();
    let mut pos = 0usize;
    while pos + 4 <= body.len() {
        let tag = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let tlen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + tlen > body.len() {
            out.truncated = true;
            break;
        }
        let val = &body[pos..pos + tlen];
        match tag {
            0x1044 if !val.is_empty() => {
                wps.state = Some(match val[0] {
                    1 => "Unconfigured".to_string(),
                    2 => "Configured".to_string(),
                    other => format!("State-{other}"),
                });
            }
            0x1057 if !val.is_empty() => {
                wps.ap_locked = Some(val[0] != 0);
            }
            0x1021 => wps.manufacturer = Some(String::from_utf8_lossy(val).trim_end_matches('\0').to_string()),
            0x1023 => wps.model_name = Some(String::from_utf8_lossy(val).trim_end_matches('\0').to_string()),
            0x1024 => wps.model_number = Some(String::from_utf8_lossy(val).trim_end_matches('\0').to_string()),
            0x1011 => wps.device_name = Some(String::from_utf8_lossy(val).trim_end_matches('\0').to_string()),
            0x1042 => wps.serial_number = Some(String::from_utf8_lossy(val).trim_end_matches('\0').to_string()),
            _ => {}
        }
        pos += tlen;
    }
    out.wps = Some(wps);
}

fn parse_extension_ie(payload: &[u8], out: &mut ParsedIes) {
    if payload.is_empty() {
        return;
    }
    let ext_id = payload[0];
    let ext = &payload[1..];
    match ext_id {
        35 => parse_he_cap(ext, out),
        36 => parse_he_op(ext, out),
        106 => parse_eht_op(ext, out),
        108 => parse_eht_cap(ext, out),
        _ => {}
    }
}

fn parse_he_cap(ext: &[u8], out: &mut ParsedIes) {
    if ext.len() < 21 {
        return;
    }
    // ext[0..6] = HE MAC Cap, ext[6..17] = HE PHY Cap (first byte ext[6] holds channel width set)
    let cw_set = ext[6];
    let channel_width_mhz = if (cw_set & 0x08) != 0 || (cw_set & 0x10) != 0 {
        160
    } else if (cw_set & 0x04) != 0 {
        80
    } else if (cw_set & 0x02) != 0 {
        40
    } else {
        20
    };

    let rx_he_mcs_80 = u16::from_le_bytes([ext[17], ext[18]]);
    let mut nss = 0u8;
    let mut max_mcs = 7u8;
    for ss in 0..8u8 {
        let code = (rx_he_mcs_80 >> (ss * 2)) & 0x03;
        if code != 3 {
            nss = ss + 1;
            max_mcs = match code {
                0 => 7,
                1 => 9,
                2 => 11,
                _ => 7,
            };
        }
    }

    out.he_cap = Some(HeCapabilities {
        channel_width_mhz,
        nss: nss.max(1),
        max_mcs,
    });
}

fn parse_he_op(ext: &[u8], out: &mut ParsedIes) {
    if ext.len() < 6 {
        return;
    }
    let he_op_params = u32::from_le_bytes([ext[0], ext[1], ext[2], 0]);
    let bss_color = ext[3] & 0x3F;
    let bss_color_disabled = (ext[3] & 0x80) != 0;

    let vht_op_present = (he_op_params & (1 << 14)) != 0;
    let co_hosted_present = (he_op_params & (1 << 15)) != 0;
    let six_ghz_present = (he_op_params & (1 << 17)) != 0;

    let mut pos = 6usize;
    if vht_op_present {
        pos += 3;
    }
    if co_hosted_present {
        pos += 1;
    }

    let (six_ghz_primary_channel, six_ghz_width_mhz, ccfs0, ccfs1) = if six_ghz_present && pos + 5 <= ext.len() {
        let primary = ext[pos];
        let control = ext[pos + 1];
        let width_mhz = match control & 0x03 {
            0 => 20,
            1 => 40,
            2 => 80,
            _ => 160,
        };
        (Some(primary), Some(width_mhz), Some(ext[pos + 2]), Some(ext[pos + 3]))
    } else if six_ghz_present && ext.len() >= 11 && pos == 6 {
        // Fallback standard layout when no optional VHT/Co-hosted fields precede 6 GHz op info
        let primary = ext[6];
        let width_mhz = match ext[7] & 0x03 {
            0 => 20,
            1 => 40,
            2 => 80,
            _ => 160,
        };
        (Some(primary), Some(width_mhz), Some(ext[8]), Some(ext[9]))
    } else {
        (None, None, None, None)
    };

    out.he_op = Some(HeOperation {
        bss_color,
        bss_color_disabled,
        six_ghz_primary_channel,
        six_ghz_width_mhz,
        ccfs0,
        ccfs1,
    });
}

fn parse_eht_op(ext: &[u8], out: &mut ParsedIes) {
    if ext.len() < 5 {
        return;
    }
    let eht_op_params = ext[0];
    let op_info_present = (eht_op_params & 0x01) != 0;
    let (channel_width_mhz, ccfs0, ccfs1) = if op_info_present && ext.len() >= 8 {
        let width = match ext[5] & 0x07 {
            0 => 20,
            1 => 40,
            2 => 80,
            3 => 160,
            4 => 320,
            _ => 160,
        };
        (Some(width), Some(ext[6]), Some(ext[7]))
    } else {
        (None, None, None)
    };

    out.eht_op = Some(EhtOperation {
        channel_width_mhz,
        ccfs0,
        ccfs1,
    });
}

fn parse_eht_cap(ext: &[u8], out: &mut ParsedIes) {
    if ext.len() < 11 {
        return;
    }
    // ext[0..2] = EHT MAC Cap, ext[2..11] = EHT PHY Cap
    let supports_320mhz = (ext[2] & 0x02) != 0;
    let mut nss = 2u8;
    let mut max_mcs = 13u8;
    if ext.len() >= 14 {
        // Basic EHT-MCS map probe (non-zero nibbles indicate supported SS)
        let b = ext[11];
        let rx_ss = b & 0x0F;
        if (1..=8).contains(&rx_ss) {
            nss = rx_ss;
        }
        max_mcs = 13;
    }
    out.eht_cap = Some(EhtCapabilities {
        supports_320mhz,
        nss,
        max_mcs,
    });
}

impl ParsedIes {
    pub fn channel_width_mhz(&self) -> u32 {
        if let Some(eht_op) = &self.eht_op
            && let Some(w) = eht_op.channel_width_mhz
        {
            return w;
        }
        if let Some(eht_cap) = &self.eht_cap
            && eht_cap.supports_320mhz
        {
            return 320;
        }
        if let Some(he_op) = &self.he_op
            && let Some(w) = he_op.six_ghz_width_mhz
        {
            return w;
        }
        if let Some(vht_op) = &self.vht_op
            && vht_op.channel_width_mhz >= 80
        {
            return vht_op.channel_width_mhz;
        }
        if let Some(he_cap) = &self.he_cap {
            return he_cap.channel_width_mhz;
        }
        if let Some(vht_cap) = &self.vht_cap {
            return vht_cap.max_width_mhz;
        }
        if let Some(ht_op) = &self.ht_op
            && (ht_op.sta_40mhz || ht_op.secondary_offset != 0)
        {
            return 40;
        }
        if let Some(ht_cap) = &self.ht_cap
            && ht_cap.supports_40mhz
        {
            return 40;
        }
        20
    }

    pub fn effective_channel(&self, center_freq_khz: u32) -> Option<u32> {
        if let Some(he_op) = &self.he_op
            && let Some(ch) = he_op.six_ghz_primary_channel
        {
            return Some(ch as u32);
        }
        if let Some(ch) = channel_from_freq_khz(center_freq_khz) {
            return Some(ch);
        }
        if let Some(ht_op) = &self.ht_op
            && ht_op.primary_channel > 0
        {
            return Some(ht_op.primary_channel as u32);
        }
        self.ds_channel.map(u32::from)
    }

    pub fn phy_generation(&self) -> &'static str {
        if self.eht_cap.is_some() || self.eht_op.is_some() {
            "EHT (802.11be)"
        } else if self.he_cap.is_some() || self.he_op.is_some() {
            "HE (802.11ax)"
        } else if self.vht_cap.is_some() || self.vht_op.is_some() {
            "VHT (802.11ac)"
        } else if self.ht_cap.is_some() || self.ht_op.is_some() {
            "HT (802.11n)"
        } else if self.supported_rates_mbps.iter().any(|&r| r > 11.0) {
            "ERP/OFDM (802.11a/g)"
        } else {
            "HRDSSS (802.11b)"
        }
    }

    pub fn max_speed_mbps(&self, rate_set_kbps: &[u32]) -> f64 {
        let width = self.channel_width_mhz();
        if let Some(eht_cap) = &self.eht_cap {
            // Wi-Fi 7 EHT MCS13 (4096-QAM 5/6) single-stream baseline
            let per_ss = match width {
                320 => 1441.2,
                160 => 720.6,
                80 => 360.3,
                40 => 172.1,
                _ => 86.0,
            };
            return round1(per_ss * f64::from(eht_cap.nss.max(1)));
        }
        if let Some(he_cap) = &self.he_cap {
            // Wi-Fi 6/6E HE single-stream rate at 0.8us GI
            let per_ss = match (width, he_cap.max_mcs) {
                (160, 11) => 1201.0,
                (160, 9) => 960.8,
                (160, _) => 800.6,
                (80, 11) => 600.5,
                (80, 9) => 480.4,
                (80, _) => 400.3,
                (40, 11) => 286.8,
                (40, 9) => 229.4,
                (40, _) => 191.2,
                (_, 11) => 143.4,
                (_, 9) => 114.7,
                _ => 95.6,
            };
            return round1(per_ss * f64::from(he_cap.nss.max(1)));
        }
        if let Some(vht_cap) = &self.vht_cap {
            let per_ss = match (width, vht_cap.max_mcs) {
                (160, 9) => 866.7,
                (160, _) => 780.0,
                (80, 9) => 433.3,
                (80, 8) => 390.0,
                (80, _) => 325.0,
                (40, 9) => 200.0,
                (40, _) => 150.0,
                _ => 86.7,
            };
            return round1(per_ss * f64::from(vht_cap.nss.max(1)));
        }
        if let Some(ht_cap) = &self.ht_cap {
            let w40 = self
                .ht_op
                .as_ref()
                .map(|o| o.sta_40mhz)
                .unwrap_or(ht_cap.supports_40mhz);
            let sgi = if w40 { ht_cap.sgi_40 } else { ht_cap.sgi_20 };
            let per_ss = match (w40, sgi) {
                (true, true) => 150.0,
                (true, false) => 135.0,
                (false, true) => 72.2,
                (false, false) => 65.0,
            };
            return round1(per_ss * f64::from(ht_cap.nss.max(1)));
        }

        let max_ie = self.supported_rates_mbps.iter().copied().fold(0.0_f64, f64::max);
        let max_win = rate_set_kbps
            .iter()
            .map(|&k| f64::from(k) / 1000.0)
            .fold(0.0_f64, f64::max);
        round1(max_ie.max(max_win))
    }

    pub fn security_summary(&self, capability_info: u16) -> String {
        let privacy_bit = (capability_info & 0x0010) != 0;

        if let Some(rsn) = &self.rsn {
            let has_sae = rsn.akm_suites.iter().any(|a| a.contains("SAE"));
            let has_psk = rsn.akm_suites.iter().any(|a| a.contains("PSK"));
            let has_1x = rsn
                .akm_suites
                .iter()
                .any(|a| a.contains("802.1X") || a.contains("Suite-B"));
            let has_owe = rsn.akm_suites.iter().any(|a| a == "OWE");

            let cipher = rsn
                .pairwise_ciphers
                .first()
                .cloned()
                .or_else(|| rsn.group_cipher.clone())
                .unwrap_or_else(|| "CCMP-128".to_string());

            let proto = if has_sae && has_psk {
                "WPA2/WPA3-Transition"
            } else if has_sae {
                "WPA3-SAE"
            } else if has_owe {
                "OWE"
            } else if has_1x && rsn.akm_suites.iter().any(|a| a.contains("Suite-B")) {
                "WPA3-Enterprise"
            } else if has_1x {
                "WPA2-Enterprise"
            } else if has_psk {
                "WPA2-PSK"
            } else {
                "RSN"
            };

            return if self.wpa1.is_some() && !has_sae {
                format!("WPA/{proto} ({cipher})")
            } else {
                format!("{proto} ({cipher})")
            };
        }

        if let Some(wpa1) = &self.wpa1 {
            let cipher = wpa1
                .unicast_ciphers
                .first()
                .cloned()
                .unwrap_or_else(|| "TKIP".to_string());
            let is_1x = wpa1.akm_suites.iter().any(|a| a.contains("802.1X"));
            return if is_1x {
                format!("WPA-Enterprise ({cipher})")
            } else {
                format!("WPA-PSK ({cipher})")
            };
        }

        if privacy_bit {
            "WEP".to_string()
        } else {
            "Open".to_string()
        }
    }
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ie(id: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + payload.len());
        out.push(id);
        out.push(payload.len() as u8);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn test_channel_frequency_conversions() {
        assert_eq!(channel_from_freq_khz(2_412_000), Some(1));
        assert_eq!(channel_from_freq_khz(2_437_000), Some(6));
        assert_eq!(channel_from_freq_khz(2_484_000), Some(14));
        assert_eq!(channel_from_freq_khz(5_180_000), Some(36));
        assert_eq!(channel_from_freq_khz(5_745_000), Some(149));
        assert_eq!(channel_from_freq_khz(5_955_000), Some(1));
        assert_eq!(channel_from_freq_khz(6_115_000), Some(33));

        assert_eq!(freq_mhz_from_channel(6, false), Some(2437));
        assert_eq!(freq_mhz_from_channel(36, false), Some(5180));
        assert_eq!(freq_mhz_from_channel(33, true), Some(6115));
    }

    #[test]
    fn test_parse_ie_stream_wifi6_rsn_country_wps_and_selectors() {
        let mut stream = Vec::new();
        // SSID: "LabNet-6"
        stream.extend(ie(0, b"LabNet-6"));
        // Supported rates: 6, 12, 24 Mbps + BSS membership selector 122 (0x7A = HE)
        stream.extend(ie(1, &[0x8C, 0x18, 0x30, 0xFA]));
        // DS channel 36
        stream.extend(ie(3, &[36]));
        // Country US Indoor
        stream.extend(ie(7, b"USI\x24\x04\x1e"));
        // HT Cap (40MHz + SGI20 + SGI40 + 2SS)
        let mut ht_cap = vec![0u8; 26];
        ht_cap[0] = 0x62;
        ht_cap[3] = 0xFF;
        ht_cap[4] = 0xFF;
        stream.extend(ie(45, &ht_cap));
        // RSN: WPA3-SAE + CCMP-128 + MFPR/MFPC
        stream.extend(ie(
            48,
            &[
                0x01, 0x00, // version 1
                0x00, 0x0F, 0xAC, 0x04, // group CCMP-128
                0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, // 1 pairwise CCMP-128
                0x01, 0x00, 0x00, 0x0F, 0xAC, 0x08, // 1 AKM SAE
                0xC0, 0x00, // MFPR + MFPC
            ],
        ));
        // VHT Cap (80/160 + 2SS MCS0-9)
        let mut vht_cap = vec![0u8; 12];
        vht_cap[0] = 0x64;
        vht_cap[4] = 0xFA; // SS1=2(MCS9), SS2=2(MCS9), SS3=3, SS4=3 -> 0b1111_1010 = 0xFA
        vht_cap[5] = 0xFF;
        stream.extend(ie(191, &vht_cap));
        // WPS Vendor IE (00:50:F2:04)
        let mut wps = vec![0x00, 0x50, 0xF2, 0x04];
        wps.extend_from_slice(&[0x10, 0x44, 0x00, 0x01, 0x02]); // Configured
        wps.extend_from_slice(&[0x10, 0x21, 0x00, 0x04, b'A', b'C', b'M', b'E']);
        stream.extend(ie(221, &wps));
        // HE Cap (Ext 35, 160 MHz + 2SS MCS0-11)
        let mut he_cap = vec![0u8; 22];
        he_cap[0] = 35;
        he_cap[1 + 6] = 0x0C; // 80 + 160 MHz
        he_cap[1 + 17] = 0xFA; // 2SS MCS0-11 (2, 2, 3, 3 -> 0xFA)
        he_cap[1 + 18] = 0xFF;
        stream.extend(ie(255, &he_cap));

        let parsed = parse_ie_stream(&stream);
        assert!(!parsed.truncated);
        assert_eq!(parsed.ssid.as_deref(), Some("LabNet-6"));
        assert_eq!(parsed.bss_membership_selectors, vec![122]);
        assert_eq!(parsed.supported_rates_mbps, vec![6.0, 12.0, 24.0]);
        assert_eq!(parsed.country_code.as_deref(), Some("US"));
        assert_eq!(parsed.country_environment, Some('I'));
        assert_eq!(parsed.security_summary(0x0011), "WPA3-SAE (CCMP-128)");
        assert!(parsed.rsn.as_ref().unwrap().mfpr);
        assert!(parsed.rsn.as_ref().unwrap().mfpc);
        assert_eq!(parsed.wps.as_ref().unwrap().state.as_deref(), Some("Configured"));
        assert_eq!(parsed.wps.as_ref().unwrap().manufacturer.as_deref(), Some("ACME"));
        assert_eq!(parsed.phy_generation(), "HE (802.11ax)");
        assert_eq!(parsed.channel_width_mhz(), 160);
        assert_eq!(parsed.max_speed_mbps(&[]), 2402.0);
    }

    #[test]
    fn test_parse_ie_stream_wifi7_and_truncation_safety() {
        let mut stream = Vec::new();
        stream.extend(ie(0, b"")); // Hidden SSID
        // EHT Cap (Ext 108, 320 MHz)
        let mut eht_cap = vec![0u8; 15];
        eht_cap[0] = 108;
        eht_cap[1 + 2] = 0x02; // 320 MHz
        eht_cap[1 + 11] = 0x04; // 4 SS
        stream.extend(ie(255, &eht_cap));
        // EHT Op (Ext 106, 320 MHz)
        stream.extend(ie(255, &[106, 0x01, 0, 0, 0, 0, 0x04, 31, 0]));
        // Truncated IE at tail
        stream.extend_from_slice(&[221, 20, 0x00, 0x50]);

        let parsed = parse_ie_stream(&stream);
        assert!(parsed.truncated);
        assert!(parsed.hidden_ssid);
        assert_eq!(parsed.phy_generation(), "EHT (802.11be)");
        assert_eq!(parsed.channel_width_mhz(), 320);
        assert!(parsed.max_speed_mbps(&[]) > 5000.0);
    }
}
