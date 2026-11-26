use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use net2rust_core::{NetError, NetResult};
use serde::{Deserialize, Serialize};

use crate::transport::RdapHttpResponse;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpNetRecord {
    pub ip_address: String,
    pub net_range: String,
    pub cidr: String,
    pub org_name: String,
    pub country: String,
    pub abuse_email: String,
    pub rir: String,
    pub updated: String,
    pub asn: Option<String>,
    pub referral_whois: Option<String>,
    pub referral_rdap: Option<String>,
    pub rwhois_server: Option<String>,
    pub created: Option<String>,
    pub raw_record: String,
    pub is_referral_stub: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainWhoisRecord {
    pub domain: String,
    pub registrar: String,
    pub created_date: String,
    pub updated_date: String,
    pub expiry_date: String,
    pub name_servers: String,
    pub status: String,
    pub whois_server: String,
    pub referral_server: Option<String>,
    pub raw_text: String,
}

#[derive(Debug, Clone, Copy)]
pub struct RirEndpoint {
    pub rir: &'static str,
    pub whois_host: &'static str,
    pub whois_prefix: &'static str,
    pub rdap_base: &'static str,
}

pub fn select_rir_for_ip(ip: IpAddr) -> RirEndpoint {
    match ip {
        IpAddr::V4(v4) => {
            let first = v4.octets()[0];
            match first {
                // RIPE NCC /8 blocks (representative IANA allocations)
                2
                | 5
                | 31
                | 37
                | 46
                | 51
                | 57
                | 62
                | 77..=95
                | 109
                | 141
                | 145
                | 151
                | 176
                | 178
                | 185
                | 188
                | 193..=195
                | 212
                | 213
                | 217 => RirEndpoint {
                    rir: "RIPE",
                    whois_host: "whois.ripe.net",
                    whois_prefix: "-B ",
                    rdap_base: "https://rdap.db.ripe.net/ip/",
                },
                // APNIC /8 blocks
                1
                | 14
                | 27
                | 36
                | 39
                | 42
                | 43
                | 49
                | 58..=61
                | 101
                | 103
                | 106
                | 110..=126
                | 133
                | 150
                | 153
                | 163
                | 171
                | 175
                | 180
                | 182
                | 183
                | 202
                | 203
                | 210
                | 211
                | 218..=223 => RirEndpoint {
                    rir: "APNIC",
                    whois_host: "whois.apnic.net",
                    whois_prefix: "",
                    rdap_base: "https://rdap.apnic.net/ip/",
                },
                // LACNIC /8 blocks
                131 | 132 | 177 | 179 | 181 | 186 | 187 | 189..=191 | 200 | 201 => RirEndpoint {
                    rir: "LACNIC",
                    whois_host: "whois.lacnic.net",
                    whois_prefix: "",
                    rdap_base: "https://rdap.lacnic.net/rdap/ip/",
                },
                // AFRINIC /8 blocks
                41 | 102 | 105 | 154 | 160 | 164 | 196 | 197 => RirEndpoint {
                    rir: "AFRINIC",
                    whois_host: "whois.afrinic.net",
                    whois_prefix: "",
                    rdap_base: "https://rdap.afrinic.net/rdap/ip/",
                },
                // ARIN / default
                _ => RirEndpoint {
                    rir: "ARIN",
                    whois_host: "whois.arin.net",
                    whois_prefix: "n + ",
                    rdap_base: "https://rdap.arin.net/registry/ip/",
                },
            }
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            if (0x2a00..=0x2a0f).contains(&seg0) || seg0 == 0x2001 && (0x0600..=0x0bff).contains(&v6.segments()[1]) {
                RirEndpoint {
                    rir: "RIPE",
                    whois_host: "whois.ripe.net",
                    whois_prefix: "-B ",
                    rdap_base: "https://rdap.db.ripe.net/ip/",
                }
            } else if (0x2400..=0x240f).contains(&seg0)
                || (seg0 == 0x2001 && (0x0c00..=0x0fff).contains(&v6.segments()[1]))
            {
                RirEndpoint {
                    rir: "APNIC",
                    whois_host: "whois.apnic.net",
                    whois_prefix: "",
                    rdap_base: "https://rdap.apnic.net/ip/",
                }
            } else if (0x2800..=0x280f).contains(&seg0) {
                RirEndpoint {
                    rir: "LACNIC",
                    whois_host: "whois.lacnic.net",
                    whois_prefix: "",
                    rdap_base: "https://rdap.lacnic.net/rdap/ip/",
                }
            } else if (0x2c00..=0x2c0f).contains(&seg0) {
                RirEndpoint {
                    rir: "AFRINIC",
                    whois_host: "whois.afrinic.net",
                    whois_prefix: "",
                    rdap_base: "https://rdap.afrinic.net/rdap/ip/",
                }
            } else {
                RirEndpoint {
                    rir: "ARIN",
                    whois_host: "whois.arin.net",
                    whois_prefix: "n + ",
                    rdap_base: "https://rdap.arin.net/registry/ip/",
                }
            }
        }
    }
}

pub fn rir_whois_query_string(server: &str, ip: IpAddr) -> String {
    let lower = server.to_ascii_lowercase();
    if lower.contains("arin") {
        format!("n + {ip}")
    } else if lower.contains("ripe") {
        format!("-B {ip}")
    } else {
        ip.to_string()
    }
}

pub fn infer_rir_from_host(host: &str) -> String {
    let lower = host.to_ascii_lowercase();
    if lower.contains("arin") {
        "ARIN".to_string()
    } else if lower.contains("ripe") {
        "RIPE".to_string()
    } else if lower.contains("apnic") {
        "APNIC".to_string()
    } else if lower.contains("lacnic") {
        "LACNIC".to_string()
    } else if lower.contains("afrinic") {
        "AFRINIC".to_string()
    } else if lower.contains("jpnic") {
        "JPNIC".to_string()
    } else if lower.contains("iana") {
        "IANA".to_string()
    } else {
        host.to_string()
    }
}

/// Converts an inclusive IP range `[start, end]` into the minimal list of aligned CIDR blocks.
pub fn ip_range_to_cidrs(start: IpAddr, end: IpAddr) -> Vec<String> {
    match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) => {
            let mut cur = u32::from(s);
            let end_u = u32::from(e);
            if cur > end_u {
                return Vec::new();
            }
            let mut out = Vec::new();
            while cur <= end_u {
                let max_align = if cur == 0 { 32 } else { cur.trailing_zeros() };
                let remaining = (end_u - cur) as u64 + 1;
                let max_size = 63 - remaining.leading_zeros();
                let block_bits = max_align.min(max_size).min(32);
                let prefix = 32 - block_bits as u8;
                out.push(format!("{}/{}", Ipv4Addr::from(cur), prefix));
                let step = 1u64 << block_bits;
                if cur as u64 + step > u32::MAX as u64 {
                    break;
                }
                cur = (cur as u64 + step) as u32;
            }
            out
        }
        (IpAddr::V6(s), IpAddr::V6(e)) => {
            let mut cur = u128::from(s);
            let end_u = u128::from(e);
            if cur > end_u {
                return Vec::new();
            }
            let mut out = Vec::new();
            while cur <= end_u {
                let max_align = if cur == 0 { 128 } else { cur.trailing_zeros() };
                let remaining = end_u - cur;
                // largest power of 2 <= (remaining + 1)
                let max_size = if remaining == u128::MAX {
                    128
                } else {
                    127 - (remaining + 1).leading_zeros()
                };
                let block_bits = max_align.min(max_size).min(128);
                let prefix = 128 - block_bits as u8;
                out.push(format!("{}/{}", Ipv6Addr::from(cur), prefix));
                if block_bits == 128 {
                    break;
                }
                let step = 1u128 << block_bits;
                if let Some(next) = cur.checked_add(step) {
                    cur = next;
                } else {
                    break;
                }
            }
            out
        }
        _ => Vec::new(),
    }
}

/// Parses an RDAP IP network JSON response into `IpNetRecord`.
pub fn parse_rdap_ip(ip: IpAddr, rir_hint: &str, resp: &RdapHttpResponse) -> NetResult<IpNetRecord> {
    let obj = resp
        .body
        .as_object()
        .ok_or_else(|| NetError::ParseError("RDAP IP response is not a JSON object".into()))?;

    let start_addr = obj.get("startAddress").and_then(|v| v.as_str()).unwrap_or("");
    let end_addr = obj.get("endAddress").and_then(|v| v.as_str()).unwrap_or("");
    let net_range = if !start_addr.is_empty() && !end_addr.is_empty() {
        format!("{start_addr} - {end_addr}")
    } else {
        obj.get("handle").and_then(|v| v.as_str()).unwrap_or("").to_string()
    };

    let mut cidrs = Vec::new();
    if let Some(arr) = obj.get("cidr0_cidrs").and_then(|v| v.as_array()) {
        for item in arr {
            if let (Some(p), Some(l)) = (
                item.get("v4prefix")
                    .or_else(|| item.get("v6prefix"))
                    .and_then(|v| v.as_str()),
                item.get("length").and_then(|v| v.as_u64()),
            ) {
                cidrs.push(format!("{p}/{l}"));
            }
        }
    }
    if cidrs.is_empty()
        && let (Ok(s_ip), Ok(e_ip)) = (start_addr.parse::<IpAddr>(), end_addr.parse::<IpAddr>())
    {
        cidrs = ip_range_to_cidrs(s_ip, e_ip);
    }

    let (created, updated) = extract_rdap_events(obj.get("events"));

    let mut org_name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let mut abuse_email = String::new();
    let mut country = obj.get("country").and_then(|v| v.as_str()).unwrap_or("").to_string();

    if let Some(entities) = obj.get("entities").and_then(|v| v.as_array()) {
        let mut info = RdapEntityScan::default();
        scan_rdap_entities(entities, 0, &mut info);
        if let Some(o) = info.org_name {
            org_name = o;
        }
        if let Some(e) = info.abuse_email.or(info.fallback_email) {
            abuse_email = e;
        }
        if country.is_empty()
            && let Some(c) = info.country
        {
            country = c;
        }
    }

    if abuse_email.is_empty()
        && let Some(remarks) = obj.get("remarks").and_then(|v| v.as_array())
    {
        for remark in remarks {
            if let Some(desc) = remark.get("description").and_then(|v| v.as_array()) {
                for line in desc.iter().filter_map(|v| v.as_str()) {
                    if line.to_ascii_lowercase().contains("abuse")
                        && let Some(found) = extract_first_email(line)
                    {
                        abuse_email = found;
                        break;
                    }
                }
            }
            if !abuse_email.is_empty() {
                break;
            }
        }
    }

    let port43 = obj.get("port43").and_then(|v| v.as_str()).map(str::to_string);
    let mut referral_rdap: Option<String> = None;
    if let Some(links) = obj.get("links").and_then(|v| v.as_array()) {
        for link in links {
            let rel = link.get("rel").and_then(|v| v.as_str()).unwrap_or("");
            let link_type = link.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let href = link.get("href").and_then(|v| v.as_str()).unwrap_or("");
            if rel.eq_ignore_ascii_case("related")
                && (link_type.contains("rdap+json") || link_type.contains("json") || link_type.is_empty())
                && !href.is_empty()
                && href != resp.final_url
            {
                referral_rdap = Some(href.to_string());
                break;
            }
        }
    }

    let asn = obj
        .get("arin_originas0_originautnums")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_u64())
        .map(|n| format!("AS{n}"));

    let rir = port43
        .as_deref()
        .map(infer_rir_from_host)
        .filter(|s| !s.is_empty() && !s.contains('.'))
        .unwrap_or_else(|| rir_hint.to_string());

    let no_entities = obj
        .get("entities")
        .and_then(|v| v.as_array())
        .is_none_or(|a| a.is_empty());
    let is_referral_stub = referral_rdap.is_some()
        && (no_entities
            || port43
                .as_deref()
                .is_some_and(|p| has_authority_mismatch(&resp.final_url, p)));

    let raw_record = serde_json::to_string_pretty(&resp.body).unwrap_or_else(|_| resp.body.to_string());

    Ok(IpNetRecord {
        ip_address: ip.to_string(),
        net_range,
        cidr: cidrs.join(", "),
        org_name,
        country,
        abuse_email,
        rir,
        updated,
        asn,
        referral_whois: port43,
        referral_rdap,
        rwhois_server: None,
        created,
        raw_record,
        is_referral_stub,
    })
}

fn extract_url_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split('/').next()?;
    let host = authority.split('@').next_back()?;
    let host = host.split(':').next()?;
    (!host.is_empty()).then_some(host)
}

fn host_base_domain(host: &str) -> String {
    let lower = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        lower
    }
}

fn has_authority_mismatch(final_url: &str, port43_host: &str) -> bool {
    let Some(url_host) = extract_url_host(final_url) else {
        return false;
    };
    let port43_clean = port43_host.trim().split(':').next().unwrap_or(port43_host).trim();
    if port43_clean.is_empty() {
        return false;
    }
    let url_rir = infer_rir_from_host(url_host);
    let p43_rir = infer_rir_from_host(port43_clean);
    if !url_rir.contains('.') && !p43_rir.contains('.') {
        return !url_rir.eq_ignore_ascii_case(&p43_rir);
    }
    host_base_domain(url_host) != host_base_domain(port43_clean)
}

#[derive(Default)]
struct RdapEntityScan {
    org_name: Option<String>,
    abuse_email: Option<String>,
    fallback_email: Option<String>,
    country: Option<String>,
}

fn scan_rdap_entities(entities: &[serde_json::Value], depth: usize, acc: &mut RdapEntityScan) {
    if depth > 8 {
        return;
    }
    for ent in entities {
        let roles: Vec<String> = ent
            .get("roles")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|r| r.as_str().map(str::to_ascii_lowercase))
                    .collect()
            })
            .unwrap_or_default();
        let is_abuse = roles.iter().any(|r| r == "abuse");
        let is_registrant = roles.iter().any(|r| r == "registrant" || r == "administrative");

        if let Some(vcard_items) = ent
            .get("vcardArray")
            .and_then(|v| v.as_array())
            .and_then(|a| a.get(1))
            .and_then(|v| v.as_array())
        {
            for prop in vcard_items {
                let Some(arr) = prop.as_array() else {
                    continue;
                };
                let prop_name = arr.first().and_then(|v| v.as_str()).unwrap_or("");
                let prop_val = arr.get(3);
                match prop_name {
                    "fn" => {
                        if let Some(s) = prop_val.and_then(|v| v.as_str())
                            && !s.trim().is_empty()
                            && (is_registrant || acc.org_name.is_none())
                        {
                            acc.org_name = Some(s.trim().to_string());
                        }
                    }
                    "email" => {
                        if let Some(s) = prop_val.and_then(|v| v.as_str())
                            && !s.trim().is_empty()
                        {
                            if is_abuse && acc.abuse_email.is_none() {
                                acc.abuse_email = Some(s.trim().to_string());
                            } else if acc.fallback_email.is_none() {
                                acc.fallback_email = Some(s.trim().to_string());
                            }
                        }
                    }
                    "adr" => {
                        if acc.country.is_none()
                            && let Some(adr_arr) = prop_val.and_then(|v| v.as_array())
                            && let Some(c) = adr_arr.last().and_then(|v| v.as_str())
                            && c.trim().len() == 2
                        {
                            acc.country = Some(c.trim().to_ascii_uppercase());
                        }
                    }
                    _ => {}
                }
            }
        }

        if let Some(nested) = ent.get("entities").and_then(|v| v.as_array()) {
            scan_rdap_entities(nested, depth + 1, acc);
        }
    }
}

fn extract_rdap_events(events: Option<&serde_json::Value>) -> (Option<String>, String) {
    let mut created = None;
    let mut updated = String::new();
    if let Some(arr) = events.and_then(|v| v.as_array()) {
        for ev in arr {
            let action = ev.get("eventAction").and_then(|v| v.as_str()).unwrap_or("");
            let date = ev.get("eventDate").and_then(|v| v.as_str()).unwrap_or("");
            if date.is_empty() {
                continue;
            }
            if action.eq_ignore_ascii_case("last changed")
                || action.eq_ignore_ascii_case("last update of rdap database")
            {
                if updated.is_empty() {
                    updated = date.to_string();
                }
            } else if action.eq_ignore_ascii_case("registration") && created.is_none() {
                created = Some(date.to_string());
            }
        }
    }
    (created, updated)
}

/// Parses ARIN, RIPE/APNIC/AFRINIC RPSL, IANA, and LACNIC TCP:43 WHOIS text into `IpNetRecord`.
pub fn parse_whois_ip(ip: IpAddr, rir_hint: &str, raw: &str) -> IpNetRecord {
    let mut net_range = String::new();
    let mut cidr = String::new();
    let mut org_name = String::new();
    let mut net_name = String::new();
    let mut country = String::new();
    let mut abuse_email = String::new();
    let mut updated = String::new();
    let mut created = None;
    let mut rir = rir_hint.to_string();
    let mut asn = None;
    let mut referral_whois = None;
    let mut rwhois_server = None;

    // Resolve RIPE/APNIC org IDs -> org-name from organisation: stanzas
    let mut org_id_target = String::new();
    let mut current_org_id = String::new();
    let mut org_names_by_id = std::collections::HashMap::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            current_org_id.clear();
            continue;
        }
        if trimmed.starts_with('%') || trimmed.starts_with('#') {
            if trimmed.to_ascii_lowercase().contains("abuse contact")
                && abuse_email.is_empty()
                && let Some(email) = extract_first_email(trimmed)
            {
                abuse_email = email;
            }
            continue;
        }
        let Some((k, v)) = trimmed.split_once(':') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        if val.is_empty() {
            continue;
        }

        match key.as_str() {
            "netrange" | "inetnum" | "inet6num" => {
                if net_range.is_empty() {
                    net_range = val.to_string();
                    if val.contains('/') && cidr.is_empty() {
                        cidr = val.to_string();
                    }
                }
            }
            "cidr" | "route" | "route6" => {
                if cidr.is_empty() {
                    cidr = val.to_string();
                }
            }
            "orgname" | "organization" | "owner" | "descr" => {
                if org_name.is_empty() {
                    org_name = val.to_string();
                }
            }
            "netname" => {
                if net_name.is_empty() {
                    net_name = val.to_string();
                }
            }
            "org" => {
                if org_id_target.is_empty() {
                    org_id_target = val.to_ascii_uppercase();
                }
            }
            "organisation" => {
                current_org_id = val.to_ascii_uppercase();
            }
            "org-name" => {
                if !current_org_id.is_empty() {
                    org_names_by_id.insert(current_org_id.clone(), val.to_string());
                } else if org_name.is_empty() {
                    org_name = val.to_string();
                }
            }
            "country" => {
                if country.is_empty() {
                    country = val.to_ascii_uppercase();
                }
            }
            "orgabuseemail" | "abuse-mailbox" | "e-mail" => {
                if abuse_email.is_empty() || key == "orgabuseemail" || key == "abuse-mailbox" {
                    abuse_email = val.to_string();
                }
            }
            "updated" | "last-modified" | "changed" => {
                if updated.is_empty() {
                    updated = val.to_string();
                }
            }
            "regdate" | "created" => {
                if created.is_none() {
                    created = Some(val.to_string());
                }
            }
            "source" => {
                rir = val.to_ascii_uppercase();
            }
            "originas" | "origin" => {
                if asn.is_none() {
                    let norm = val.split(',').next().unwrap_or(val).trim().to_ascii_uppercase();
                    if norm.starts_with("AS") {
                        asn = Some(norm);
                    } else if norm.chars().all(|c| c.is_ascii_digit()) {
                        asn = Some(format!("AS{norm}"));
                    }
                }
            }
            "referralserver" => {
                if let Some(rest) = val.strip_prefix("whois://") {
                    referral_whois = Some(rest.trim_end_matches('/').to_string());
                } else if val.starts_with("rwhois://") {
                    rwhois_server = Some(val.to_string());
                }
            }
            "refer" if referral_whois.is_none() => {
                referral_whois = Some(val.to_string());
            }
            _ => {}
        }
    }

    if !org_id_target.is_empty()
        && let Some(resolved_org) = org_names_by_id.get(&org_id_target)
    {
        org_name = resolved_org.clone();
    }
    if org_name.is_empty() {
        org_name = net_name;
    }

    if cidr.is_empty()
        && let Some((s, e)) = net_range.split_once('-')
        && let (Ok(s_ip), Ok(e_ip)) = (s.trim().parse::<IpAddr>(), e.trim().parse::<IpAddr>())
    {
        cidr = ip_range_to_cidrs(s_ip, e_ip).join(", ");
    }

    let is_referral_stub = referral_whois.is_some() && org_name.is_empty() && abuse_email.is_empty();

    IpNetRecord {
        ip_address: ip.to_string(),
        net_range,
        cidr,
        org_name,
        country,
        abuse_email,
        rir,
        updated,
        asn,
        referral_whois,
        referral_rdap: None,
        rwhois_server,
        created,
        raw_record: raw.to_string(),
        is_referral_stub,
    }
}

pub fn extract_first_email(text: &str) -> Option<String> {
    for token in text.split(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | ',' | ';' | '"' | '\'' | '(' | ')'))
    {
        let t = token.trim_matches(|c: char| c == '.' || c == ':');
        if let Some((local, domain)) = t.split_once('@')
            && !local.is_empty()
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
        {
            return Some(t.to_string());
        }
    }
    None
}

/// Validates and normalizes a DNS domain name (strips scheme/path/trailing dot, lowercases ASCII).
pub fn normalize_domain(input: &str) -> NetResult<String> {
    let mut s = input.trim();
    if let Some((_, rest)) = s.split_once("://") {
        s = rest;
    }
    if let Some((host, _)) = s.split_once('/') {
        s = host;
    }
    if let Some((host, _)) = s.split_once(':') {
        s = host;
    }
    let norm = s.trim_end_matches('.').to_ascii_lowercase();
    if norm.is_empty() || norm.len() > 253 {
        return Err(NetError::InvalidInput(format!("invalid domain name: '{input}'")));
    }
    for label in norm.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(NetError::InvalidInput(format!("invalid domain label in '{input}'")));
        }
    }
    Ok(norm)
}

pub fn select_tld_whois_server(domain: &str) -> Option<(&'static str, String)> {
    let lower = domain.to_ascii_lowercase();
    if lower.ends_with(".co.uk") || lower.ends_with(".org.uk") || lower.ends_with(".uk") {
        return Some(("whois.nic.uk", lower));
    }
    let tld = lower.rsplit('.').next()?;
    match tld {
        "com" | "net" => Some(("whois.verisign-grs.com", format!("={lower}"))),
        "org" => Some(("whois.pir.org", lower)),
        "io" => Some(("whois.nic.io", lower)),
        "de" => Some(("whois.denic.de", format!("-T dn,ace {lower}"))),
        "jp" => Some(("whois.jprs.jp", format!("{lower}/e"))),
        "ca" => Some(("whois.cira.ca", lower)),
        "au" => Some(("whois.auda.org.au", lower)),
        "dev" | "app" => Some(("whois.nic.google", lower)),
        "info" => Some(("whois.nic.info", lower)),
        "biz" => Some(("whois.nic.biz", lower)),
        _ => None,
    }
}

pub fn rdap_domain_url(domain: &str) -> String {
    let tld = domain.rsplit('.').next().unwrap_or("");
    match tld {
        "com" => format!("https://rdap.verisign.com/com/v1/domain/{domain}"),
        "net" => format!("https://rdap.verisign.com/net/v1/domain/{domain}"),
        "org" => format!("https://rdap.publicinterestregistry.org/rdap/domain/{domain}"),
        "dev" | "app" => format!("https://pubapi.registry.google/rdap/domain/{domain}"),
        _ => format!("https://rdap.org/domain/{domain}"),
    }
}

/// Parses ICANN/EPP, Nominet (`.uk`), DENIC (`.de`), and JPRS (`.jp`) domain WHOIS output.
pub fn parse_whois_domain(domain: &str, whois_server: &str, raw: &str) -> DomainWhoisRecord {
    if domain.ends_with(".uk") || whois_server.contains("nic.uk") {
        return parse_nominet_uk(domain, whois_server, raw);
    }
    if domain.ends_with(".de") || whois_server.contains("denic") {
        return parse_denic_de(domain, whois_server, raw);
    }
    if domain.ends_with(".jp") || whois_server.contains("jprs") {
        return parse_jprs_jp(domain, whois_server, raw);
    }

    let mut registrar = String::new();
    let mut created = String::new();
    let mut updated = String::new();
    let mut expiry = String::new();
    let mut referral_server = None;
    let mut name_servers = Vec::new();
    let mut ns_seen = HashSet::new();
    let mut statuses = Vec::new();
    let mut status_seen = HashSet::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('%') || trimmed.starts_with('#') || trimmed.starts_with(">>>") {
            continue;
        }
        let Some((k, v)) = trimmed.split_once(':') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        if val.is_empty() {
            continue;
        }
        match key.as_str() {
            "registrar" | "registrar name" | "sponsoring registrar" => {
                if registrar.is_empty() {
                    registrar = val.to_string();
                }
            }
            "creation date" | "created" | "created on" | "registered on" => {
                if created.is_empty() {
                    created = val.to_string();
                }
            }
            "updated date" | "last updated" | "last-modified" | "updated" => {
                if updated.is_empty() {
                    updated = val.to_string();
                }
            }
            "registry expiry date" | "registrar registration expiration date" | "expiry date" | "paid-till" => {
                if expiry.is_empty() {
                    expiry = val.to_string();
                }
            }
            "registrar whois server" | "whois server" | "refer" => {
                let cleaned = val.trim_start_matches("whois://").trim_end_matches('/').to_string();
                if !cleaned.is_empty() && referral_server.is_none() {
                    referral_server = Some(cleaned);
                }
            }
            "name server" | "nserver" => {
                let ns = val
                    .split_whitespace()
                    .next()
                    .unwrap_or(val)
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if !ns.is_empty() && ns_seen.insert(ns.clone()) {
                    name_servers.push(ns);
                }
            }
            "domain status" | "status" => {
                let token = val.split_whitespace().next().unwrap_or(val).to_string();
                if !token.is_empty() && status_seen.insert(token.clone()) {
                    statuses.push(token);
                }
            }
            _ => {}
        }
    }

    DomainWhoisRecord {
        domain: domain.to_string(),
        registrar,
        created_date: created,
        updated_date: updated,
        expiry_date: expiry,
        name_servers: name_servers.join(", "),
        status: statuses.join(", "),
        whois_server: whois_server.to_string(),
        referral_server,
        raw_text: raw.to_string(),
    }
}

fn parse_nominet_uk(domain: &str, whois_server: &str, raw: &str) -> DomainWhoisRecord {
    let mut section = "";
    let mut registrar = String::new();
    let mut created = String::new();
    let mut updated = String::new();
    let mut expiry = String::new();
    let mut status = String::new();
    let mut name_servers = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            section = "";
            continue;
        }
        if trimmed.ends_with(':') && !line.starts_with(' ') {
            section = match trimmed.to_ascii_lowercase().as_str() {
                "registrar:" => "registrar",
                "relevant dates:" => "dates",
                "registration status:" => "status",
                "name servers:" => "ns",
                _ => "",
            };
            continue;
        }
        match section {
            "registrar" if registrar.is_empty() => registrar = trimmed.to_string(),
            "dates" => {
                if let Some((k, v)) = trimmed.split_once(':') {
                    match k.trim().to_ascii_lowercase().as_str() {
                        "registered on" => created = v.trim().to_string(),
                        "expiry date" => expiry = v.trim().to_string(),
                        "last updated" => updated = v.trim().to_string(),
                        _ => {}
                    }
                }
            }
            "status" if status.is_empty() => status = trimmed.to_string(),
            "ns" => {
                if let Some(ns) = trimmed.split_whitespace().next() {
                    let lc = ns.trim_end_matches('.').to_ascii_lowercase();
                    if !lc.is_empty() && !name_servers.contains(&lc) {
                        name_servers.push(lc);
                    }
                }
            }
            _ => {}
        }
    }

    DomainWhoisRecord {
        domain: domain.to_string(),
        registrar,
        created_date: created,
        updated_date: updated,
        expiry_date: expiry,
        name_servers: name_servers.join(", "),
        status,
        whois_server: whois_server.to_string(),
        referral_server: None,
        raw_text: raw.to_string(),
    }
}

fn parse_denic_de(domain: &str, whois_server: &str, raw: &str) -> DomainWhoisRecord {
    let mut updated = String::new();
    let mut status = String::new();
    let mut name_servers = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('%') || trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let val = v.trim();
            match k.trim().to_ascii_lowercase().as_str() {
                "status" if status.is_empty() => status = val.to_string(),
                "changed" if updated.is_empty() => updated = val.to_string(),
                "nserver" => {
                    if let Some(ns) = val.split_whitespace().next() {
                        let lc = ns.trim_end_matches('.').to_ascii_lowercase();
                        if !lc.is_empty() && !name_servers.contains(&lc) {
                            name_servers.push(lc);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    DomainWhoisRecord {
        domain: domain.to_string(),
        registrar: "DENIC eG".to_string(),
        created_date: String::new(),
        updated_date: updated,
        expiry_date: String::new(),
        name_servers: name_servers.join(", "),
        status,
        whois_server: whois_server.to_string(),
        referral_server: None,
        raw_text: raw.to_string(),
    }
}

fn parse_jprs_jp(domain: &str, whois_server: &str, raw: &str) -> DomainWhoisRecord {
    let mut registrar = String::new();
    let mut created = String::new();
    let mut updated = String::new();
    let mut expiry = String::new();
    let mut status = String::new();
    let mut name_servers = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('[') {
            continue;
        }
        if let Some((bracket_key, val)) = trimmed.split_once(']') {
            let key = bracket_key.trim_start_matches('[').trim().to_ascii_lowercase();
            let v = val.trim();
            if v.is_empty() {
                continue;
            }
            match key.as_str() {
                "registrar" | "organization" if registrar.is_empty() => registrar = v.to_string(),
                "created on" | "registered date" if created.is_empty() => created = v.to_string(),
                "last updated" | "last update" if updated.is_empty() => updated = v.to_string(),
                "expires on" if expiry.is_empty() => expiry = v.to_string(),
                "state" | "status" if status.is_empty() => status = v.to_string(),
                "name server" => {
                    let ns = v.trim_end_matches('.').to_ascii_lowercase();
                    if !ns.is_empty() && !name_servers.contains(&ns) {
                        name_servers.push(ns);
                    }
                }
                _ => {}
            }
        }
    }

    DomainWhoisRecord {
        domain: domain.to_string(),
        registrar,
        created_date: created,
        updated_date: updated,
        expiry_date: expiry,
        name_servers: name_servers.join(", "),
        status,
        whois_server: whois_server.to_string(),
        referral_server: None,
        raw_text: raw.to_string(),
    }
}

pub fn parse_rdap_domain(domain: &str, resp: &RdapHttpResponse) -> NetResult<DomainWhoisRecord> {
    let obj = resp
        .body
        .as_object()
        .ok_or_else(|| NetError::ParseError("RDAP domain response is not a JSON object".into()))?;

    let ldh = obj
        .get("ldhName")
        .and_then(|v| v.as_str())
        .unwrap_or(domain)
        .to_ascii_lowercase();

    let status: Vec<String> = obj
        .get("status")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();

    let mut created = String::new();
    let mut updated = String::new();
    let mut expiry = String::new();
    if let Some(events) = obj.get("events").and_then(|v| v.as_array()) {
        for ev in events {
            let action = ev.get("eventAction").and_then(|v| v.as_str()).unwrap_or("");
            let date = ev.get("eventDate").and_then(|v| v.as_str()).unwrap_or("");
            if date.is_empty() {
                continue;
            }
            if action.eq_ignore_ascii_case("registration") && created.is_empty() {
                created = date.to_string();
            } else if action.eq_ignore_ascii_case("last changed") && updated.is_empty() {
                updated = date.to_string();
            } else if action.eq_ignore_ascii_case("expiration") && expiry.is_empty() {
                expiry = date.to_string();
            }
        }
    }

    let name_servers: Vec<String> = obj
        .get("nameservers")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|ns| {
                    ns.get("ldhName")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
                })
                .collect()
        })
        .unwrap_or_default();

    let mut registrar = String::new();
    if let Some(entities) = obj.get("entities").and_then(|v| v.as_array()) {
        for ent in entities {
            let is_reg = ent
                .get("roles")
                .and_then(|v| v.as_array())
                .is_some_and(|r| r.iter().any(|x| x.as_str() == Some("registrar")));
            if is_reg
                && let Some(vcard) = ent
                    .get("vcardArray")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.get(1))
                    .and_then(|v| v.as_array())
            {
                for item in vcard {
                    if let Some(arr) = item.as_array()
                        && arr.first().and_then(|v| v.as_str()) == Some("fn")
                        && let Some(name) = arr.get(3).and_then(|v| v.as_str())
                    {
                        registrar = name.to_string();
                        break;
                    }
                }
            }
            if !registrar.is_empty() {
                break;
            }
        }
    }

    Ok(DomainWhoisRecord {
        domain: ldh,
        registrar,
        created_date: created,
        updated_date: updated,
        expiry_date: expiry,
        name_servers: name_servers.join(", "),
        status: status.join(", "),
        whois_server: resp.final_url.clone(),
        referral_server: None,
        raw_text: serde_json::to_string_pretty(&resp.body).unwrap_or_else(|_| resp.body.to_string()),
    })
}

pub fn merge_domain_records(registry: DomainWhoisRecord, registrar_rec: DomainWhoisRecord) -> DomainWhoisRecord {
    DomainWhoisRecord {
        domain: registry.domain,
        registrar: if registrar_rec.registrar.is_empty() {
            registry.registrar
        } else {
            registrar_rec.registrar
        },
        created_date: if registrar_rec.created_date.is_empty() {
            registry.created_date
        } else {
            registrar_rec.created_date
        },
        updated_date: if registrar_rec.updated_date.is_empty() {
            registry.updated_date
        } else {
            registrar_rec.updated_date
        },
        expiry_date: if registry.expiry_date.is_empty() {
            registrar_rec.expiry_date
        } else {
            registry.expiry_date
        },
        name_servers: if registry.name_servers.is_empty() {
            registrar_rec.name_servers
        } else {
            registry.name_servers
        },
        status: if registrar_rec.status.is_empty() {
            registry.status
        } else {
            registrar_rec.status
        },
        whois_server: registrar_rec.whois_server,
        referral_server: registrar_rec.referral_server.or(registry.referral_server),
        raw_text: format!(
            "{}\n\n--- Registrar WHOIS ---\n{}",
            registry.raw_text, registrar_rec.raw_text
        ),
    }
}
