use net2rust_core::{NetError, NetResult, sanitize_wlan_profile_xml};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WlanProfileMetadata {
    pub name: String,
    pub ssid: String,
    pub connection_type: String,
    pub connection_mode: String,
    pub non_broadcast: bool,
    pub authentication: String,
    pub encryption: String,
    pub use_one_x: bool,
    pub mac_randomization: Option<bool>,
    pub sanitized_xml: String,
}

pub fn parse_wlan_profile_xml(raw_xml: &str) -> NetResult<WlanProfileMetadata> {
    // STRICT R4: Always sanitize XML before parsing or returning.
    let sanitized = sanitize_wlan_profile_xml(raw_xml);
    let doc = roxmltree::Document::parse(&sanitized)
        .map_err(|e| NetError::ParseError(format!("invalid WLANProfile XML: {e}")))?;
    let root = doc.root_element();
    if root.tag_name().name() != "WLANProfile" {
        return Err(NetError::ParseError(format!(
            "expected root element WLANProfile, found {}",
            root.tag_name().name()
        )));
    }

    let name = direct_child_text(root, "name").unwrap_or_default();
    let connection_type = direct_child_text(root, "connectionType").unwrap_or_else(|| "ESS".to_string());
    let connection_mode = direct_child_text(root, "connectionMode").unwrap_or_else(|| "manual".to_string());

    let ssid_cfg = direct_child(root, "SSIDConfig");
    let non_broadcast = ssid_cfg
        .and_then(|n| direct_child_text(n, "nonBroadcast"))
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));

    let ssid_node = ssid_cfg.and_then(|n| direct_child(n, "SSID"));
    let ssid = ssid_node
        .and_then(|n| {
            direct_child_text(n, "name")
                .or_else(|| direct_child_text(n, "hex").and_then(|hex_str| decode_hex_utf8(&hex_str)))
        })
        .unwrap_or_else(|| name.clone());

    let auth_enc = direct_child(root, "MSM")
        .and_then(|n| direct_child(n, "security"))
        .and_then(|n| direct_child(n, "authEncryption"));

    let authentication = auth_enc
        .and_then(|n| direct_child_text(n, "authentication"))
        .unwrap_or_else(|| "open".to_string());
    let encryption = auth_enc
        .and_then(|n| direct_child_text(n, "encryption"))
        .unwrap_or_else(|| "none".to_string());
    let use_one_x = auth_enc
        .and_then(|n| direct_child_text(n, "useOneX"))
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));

    // v3 MacRandomization element
    let mac_randomization = root
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "MacRandomization")
        .and_then(|n| direct_child_text(n, "enableRandomization"))
        .map(|v| v.eq_ignore_ascii_case("true"));

    Ok(WlanProfileMetadata {
        name,
        ssid,
        connection_type,
        connection_mode,
        non_broadcast,
        authentication,
        encryption,
        use_one_x,
        mac_randomization,
        sanitized_xml: sanitized,
    })
}

/// Surgically updates `<connectionMode>` using `roxmltree::Node::range()` on sanitized XML.
pub fn set_connection_mode_xml(raw_xml: &str, auto_connect: bool) -> NetResult<String> {
    let sanitized = sanitize_wlan_profile_xml(raw_xml);
    patch_connection_mode_range(&sanitized, auto_connect)
}

#[cfg(windows)]
pub(crate) fn patch_connection_mode_transient_for_set_profile(
    transient_xml: &str,
    auto_connect: bool,
) -> NetResult<String> {
    patch_connection_mode_range(transient_xml, auto_connect)
}

fn patch_connection_mode_range(xml: &str, auto_connect: bool) -> NetResult<String> {
    let doc =
        roxmltree::Document::parse(xml).map_err(|e| NetError::ParseError(format!("invalid WLANProfile XML: {e}")))?;
    let root = doc.root_element();
    if root.tag_name().name() != "WLANProfile" {
        return Err(NetError::ParseError(format!(
            "expected root element WLANProfile, found {}",
            root.tag_name().name()
        )));
    }

    let mode_value = if auto_connect { "auto" } else { "manual" };

    if let Some(mode_node) = direct_child(root, "connectionMode") {
        let range = mode_node.range();
        let mut out = String::with_capacity(xml.len() + 8);
        out.push_str(&xml[..range.start]);
        out.push_str(&format!("<connectionMode>{mode_value}</connectionMode>"));
        out.push_str(&xml[range.end..]);
        return Ok(out);
    }

    let anchor = direct_child(root, "connectionType")
        .or_else(|| direct_child(root, "SSIDConfig"))
        .or_else(|| direct_child(root, "name"));

    if let Some(node) = anchor {
        let pos = node.range().end;
        let mut out = String::with_capacity(xml.len() + 48);
        out.push_str(&xml[..pos]);
        out.push_str(&format!("\n\t<connectionMode>{mode_value}</connectionMode>"));
        out.push_str(&xml[pos..]);
        return Ok(out);
    }

    Err(NetError::ParseError(
        "WLANProfile XML missing anchor element for connectionMode".to_string(),
    ))
}

fn direct_child<'a, 'input>(
    parent: roxmltree::Node<'a, 'input>,
    local_name: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    parent
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == local_name)
}

fn direct_child_text(parent: roxmltree::Node<'_, '_>, local_name: &str) -> Option<String> {
    direct_child(parent, local_name)
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn decode_hex_utf8(hex: &str) -> Option<String> {
    let clean: String = hex.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(2) || clean.is_empty() {
        return None;
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for pair in clean.as_bytes().as_chunks::<2>().0 {
        let s = std::str::from_utf8(pair).ok()?;
        let byte = u8::from_str_radix(s, 16).ok()?;
        bytes.push(byte);
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1_XML: &str = r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>HomeNet</name>
    <SSIDConfig>
        <SSID>
            <hex>486F6D654E6574</hex>
            <name>HomeNet</name>
        </SSID>
        <nonBroadcast>false</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>SuperSecretPassphrase123</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"#;

    const V3_V4_XML: &str = r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"
             xmlns:v3="http://www.microsoft.com/networking/WLAN/profile/v3"
             xmlns:v4="http://www.microsoft.com/networking/WLAN/profile/v4">
    <name>CorpWiFi</name>
    <SSIDConfig>
        <SSID>
            <hex>436F727057694669</hex>
        </SSID>
        <nonBroadcast>true</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA3SAE</authentication>
                <encryption>AES</encryption>
                <useOneX>true</useOneX>
            </authEncryption>
        </security>
    </MSM>
    <v3:MacRandomization>
        <v3:enableRandomization>true</v3:enableRandomization>
    </v3:MacRandomization>
</WLANProfile>"#;

    #[test]
    fn test_parse_wlan_profile_redacts_key_material_and_extracts_metadata() {
        let meta = parse_wlan_profile_xml(V1_XML).unwrap();
        assert_eq!(meta.name, "HomeNet");
        assert_eq!(meta.ssid, "HomeNet");
        assert_eq!(meta.connection_type, "ESS");
        assert_eq!(meta.connection_mode, "auto");
        assert!(!meta.non_broadcast);
        assert_eq!(meta.authentication, "WPA2PSK");
        assert_eq!(meta.encryption, "AES");
        assert!(!meta.use_one_x);
        assert_eq!(meta.mac_randomization, None);
        assert!(!meta.sanitized_xml.contains("SuperSecretPassphrase123"));
        assert!(meta.sanitized_xml.contains("<keyMaterial>[REDACTED]</keyMaterial>"));
    }

    #[test]
    fn test_parse_v3_v4_hex_ssid_and_toggle_connection_mode() {
        let meta = parse_wlan_profile_xml(V3_V4_XML).unwrap();
        assert_eq!(meta.ssid, "CorpWiFi");
        assert!(meta.non_broadcast);
        assert_eq!(meta.connection_mode, "manual");
        assert_eq!(meta.authentication, "WPA3SAE");
        assert!(meta.use_one_x);
        assert_eq!(meta.mac_randomization, Some(true));

        let inserted = set_connection_mode_xml(V3_V4_XML, true).unwrap();
        let meta2 = parse_wlan_profile_xml(&inserted).unwrap();
        assert_eq!(meta2.connection_mode, "auto");

        let flipped = set_connection_mode_xml(V1_XML, false).unwrap();
        assert!(!flipped.contains("SuperSecretPassphrase123"));
        assert!(flipped.contains("<keyMaterial>[REDACTED]</keyMaterial>"));
        let meta3 = parse_wlan_profile_xml(&flipped).unwrap();
        assert_eq!(meta3.connection_mode, "manual");
    }
}
