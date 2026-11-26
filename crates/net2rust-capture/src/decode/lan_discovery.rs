//! Passive LAN discovery decoders: NetBIOS NBNS (UDP 137, RFC 1001/1002 + NBSTAT),
//! SSDP (UDP 1900), and embedded OUI vendor lookup table (plus optional OUI DB override).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::Path;

use chrono::{DateTime, Utc};
use net2rust_core::MacAddr;

use crate::capture::CapturedPacket;
use crate::decode::dhcp::parse_dhcp;
use crate::decode::dns_wire::{DnsRdata, parse_dns_message, read_dns_name};
use crate::decode::l2_l4::{L4Header, decode_packet};

// Sorted by 3-byte OUI prefix for O(log N) binary_search.
const EMBEDDED_OUIS: &[([u8; 3], &str)] = &[
    ([0x00, 0x05, 0x69], "VMware, Inc."),
    ([0x00, 0x0C, 0x29], "VMware, Inc."),
    ([0x00, 0x15, 0x5D], "Microsoft Corporation (Hyper-V)"),
    ([0x00, 0x1A, 0x11], "Google, Inc."),
    ([0x00, 0x1B, 0x21], "Intel Corporate"),
    ([0x00, 0x50, 0x56], "VMware, Inc."),
    ([0x08, 0x00, 0x27], "Oracle VirtualBox"),
    ([0x3C, 0x22, 0xFB], "Apple, Inc."),
    ([0x52, 0x54, 0x00], "QEMU/KVM Virtual NIC"),
    ([0x78, 0x8A, 0x20], "Ubiquiti Inc."),
    ([0xAC, 0xBC, 0x32], "Apple, Inc."),
    ([0xB8, 0x27, 0xEB], "Raspberry Pi Foundation"),
    ([0xD8, 0x3A, 0xDD], "Raspberry Pi Trading Ltd"),
    ([0xDC, 0xA6, 0x32], "Raspberry Pi Trading Ltd"),
    ([0xF0, 0x9F, 0xC2], "Ubiquiti Inc."),
];

pub fn load_oui_overrides(path: Option<&Path>) -> HashMap<[u8; 3], String> {
    let mut map = HashMap::new();
    let Some(p) = path else {
        return map;
    };
    let Ok(content) = std::fs::read_to_string(p) else {
        return map;
    };
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let sep = if trimmed.contains('\t') { '\t' } else { ',' };
        if let Some((prefix_raw, vendor_raw)) = trimmed.split_once(sep) {
            let clean_hex: String = prefix_raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if clean_hex.len() == 6
                && let (Ok(b0), Ok(b1), Ok(b2)) = (
                    u8::from_str_radix(&clean_hex[0..2], 16),
                    u8::from_str_radix(&clean_hex[2..4], 16),
                    u8::from_str_radix(&clean_hex[4..6], 16),
                )
            {
                let vendor = vendor_raw.trim().trim_matches('"').to_string();
                if !vendor.is_empty() {
                    map.insert([b0, b1, b2], vendor);
                }
            }
        }
    }
    map
}

pub fn lookup_oui(mac: MacAddr, overrides: Option<&HashMap<[u8; 3], String>>) -> Option<String> {
    let prefix = mac.oui_prefix();
    if let Some(ov) = overrides
        && let Some(v) = ov.get(&prefix)
    {
        return Some(v.clone());
    }
    if let Ok(idx) = EMBEDDED_OUIS.binary_search_by_key(&prefix, |&(p, _)| p) {
        return Some(EMBEDDED_OUIS[idx].1.to_string());
    }
    if mac.is_locally_administered() {
        return Some("Locally Administered".to_string());
    }
    None
}

/// Decode RFC 1001/1002 first-level NetBIOS encoded 32-char name into `(trimmed_name, suffix)`.
pub fn decode_netbios_first_level(encoded: &[u8]) -> Option<(String, u8)> {
    if encoded.len() != 32 {
        return None;
    }
    let mut raw = [0u8; 16];
    for i in 0..16 {
        let c0 = encoded[i * 2];
        let c1 = encoded[i * 2 + 1];
        if !(b'A'..=b'P').contains(&c0) || !(b'A'..=b'P').contains(&c1) {
            return None;
        }
        raw[i] = ((c0 - b'A') << 4) | (c1 - b'A');
    }
    let suffix = raw[15];
    let name = String::from_utf8_lossy(&raw[..15]).trim().to_string();
    if name.is_empty() || name == "*" {
        return None;
    }
    Some((name, suffix))
}

#[derive(Debug, Clone, Default)]
pub struct NbnsDecoded {
    pub names: Vec<String>,
    pub unit_mac: Option<MacAddr>,
}

pub fn parse_nbns_packet(data: &[u8]) -> Option<NbnsDecoded> {
    if data.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let nscount = u16::from_be_bytes([data[8], data[9]]);
    let arcount = u16::from_be_bytes([data[10], data[11]]);

    let mut out = NbnsDecoded::default();
    let mut offset = 12usize;

    for _ in 0..qdcount {
        if offset >= data.len() {
            return Some(out);
        }
        if data[offset] == 32 && offset + 33 <= data.len() {
            if let Some((name, _)) = decode_netbios_first_level(&data[offset + 1..offset + 33]) {
                out.names.push(name);
            }
            offset += 33;
            if offset < data.len() && data[offset] == 0 {
                offset += 1;
            }
        } else if let Ok((_, next_off)) = read_dns_name(data, offset) {
            offset = next_off;
        } else {
            return Some(out);
        }
        if offset + 4 > data.len() {
            return Some(out);
        }
        offset += 4;
    }

    let total_rrs = usize::from(ancount) + usize::from(nscount) + usize::from(arcount);
    for _ in 0..total_rrs {
        if offset >= data.len() {
            break;
        }
        if data[offset] == 32 && offset + 33 <= data.len() {
            if let Some((name, _)) = decode_netbios_first_level(&data[offset + 1..offset + 33])
                && !out.names.contains(&name)
            {
                out.names.push(name);
            }
            offset += 33;
            if offset < data.len() && data[offset] == 0 {
                offset += 1;
            }
        } else if let Ok((_, next_off)) = read_dns_name(data, offset) {
            offset = next_off;
        } else {
            break;
        }

        if offset + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlength = usize::from(u16::from_be_bytes([data[offset + 8], data[offset + 9]]));
        offset += 10;
        if offset + rdlength > data.len() {
            break;
        }
        let rdata = &data[offset..offset + rdlength];
        offset += rdlength;

        // NBSTAT (0x0021) response
        if rtype == 0x0021 && !rdata.is_empty() {
            let num_names = usize::from(rdata[0]);
            let entries_end = 1 + num_names * 18;
            if entries_end <= rdata.len() {
                for i in 0..num_names {
                    let base = 1 + i * 18;
                    let n = String::from_utf8_lossy(&rdata[base..base + 15]).trim().to_string();
                    if !n.is_empty() && !out.names.contains(&n) {
                        out.names.push(n);
                    }
                }
                if entries_end + 6 <= rdata.len() {
                    let mac = MacAddr::new([
                        rdata[entries_end],
                        rdata[entries_end + 1],
                        rdata[entries_end + 2],
                        rdata[entries_end + 3],
                        rdata[entries_end + 4],
                        rdata[entries_end + 5],
                    ]);
                    if !mac.is_zero() {
                        out.unit_mac = Some(mac);
                    }
                }
            }
        }
    }

    Some(out)
}

#[derive(Debug, Clone, Default)]
pub struct SsdpInfo {
    pub server: Option<String>,
    pub usn: Option<String>,
    pub location: Option<String>,
}

pub fn parse_ssdp_packet(data: &[u8]) -> Option<SsdpInfo> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.lines();
    let first = lines.next()?.trim();
    if !(first.starts_with("NOTIFY ") || first.starts_with("M-SEARCH ") || first.starts_with("HTTP/1.")) {
        return None;
    }
    let mut info = SsdpInfo::default();
    for line in lines {
        let trimmed = line.trim();
        if let Some((k, v)) = trimmed.split_once(':') {
            let val = v.trim().to_string();
            if val.is_empty() {
                continue;
            }
            if k.eq_ignore_ascii_case("server") {
                info.server = Some(val);
            } else if k.eq_ignore_ascii_case("usn") {
                info.usn = Some(val);
            } else if k.eq_ignore_ascii_case("location") {
                info.location = Some(val);
            }
        }
    }
    Some(info)
}

#[derive(Debug, Clone)]
pub struct DiscoveredHost {
    pub ip_address: Option<IpAddr>,
    pub mac_address: Option<MacAddr>,
    pub host_name: Option<String>,
    pub vendor_oui: Option<String>,
    pub protocols: BTreeSet<String>,
    pub os_hint: Option<String>,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum HostKey {
    Mac(String),
    Ip(String),
}

fn update_timestamps(host: &mut DiscoveredHost, ts: Option<DateTime<Utc>>) {
    let Some(t) = ts else {
        return;
    };
    host.first_seen = Some(match host.first_seen {
        Some(prev) => prev.min(t),
        None => t,
    });
    host.last_seen = Some(match host.last_seen {
        Some(prev) => prev.max(t),
        None => t,
    });
}

fn is_valid_unicast_mac(mac: MacAddr) -> bool {
    !mac.is_zero() && !mac.is_broadcast() && !mac.is_multicast()
}

pub fn discover_lan_hosts(packets: &[CapturedPacket], oui_db_path: Option<&Path>) -> Vec<DiscoveredHost> {
    let overrides = load_oui_overrides(oui_db_path);
    let override_ref = if overrides.is_empty() { None } else { Some(&overrides) };

    let mut hosts: BTreeMap<HostKey, DiscoveredHost> = BTreeMap::new();

    let mut record = |ip: Option<IpAddr>,
                      mac: Option<MacAddr>,
                      hostname: Option<String>,
                      proto: &str,
                      os_hint: Option<String>,
                      ts: Option<DateTime<Utc>>| {
        let valid_mac = mac.filter(|m| is_valid_unicast_mac(*m));
        let key = if let Some(m) = valid_mac {
            HostKey::Mac(m.to_colon_string())
        } else if let Some(i) = ip {
            HostKey::Ip(i.to_string())
        } else {
            return;
        };

        let entry = hosts.entry(key).or_insert_with(|| DiscoveredHost {
            ip_address: ip,
            mac_address: valid_mac,
            host_name: None,
            vendor_oui: valid_mac.and_then(|m| lookup_oui(m, override_ref)),
            protocols: BTreeSet::new(),
            os_hint: None,
            first_seen: ts,
            last_seen: ts,
        });

        if entry.ip_address.is_none() {
            entry.ip_address = ip;
        }
        if entry.mac_address.is_none() && valid_mac.is_some() {
            entry.mac_address = valid_mac;
            entry.vendor_oui = valid_mac.and_then(|m| lookup_oui(m, override_ref));
        }
        if entry.host_name.is_none() && hostname.is_some() {
            entry.host_name = hostname;
        }
        if entry.os_hint.is_none() && os_hint.is_some() {
            entry.os_hint = os_hint;
        }
        entry.protocols.insert(proto.to_string());
        update_timestamps(entry, ts);
    };

    for pkt in packets {
        let Ok(dec) = decode_packet(pkt) else {
            continue;
        };

        if let Some(arp) = dec.arp {
            let spa = if arp.spa.is_unspecified() {
                None
            } else {
                Some(IpAddr::V4(arp.spa))
            };
            record(spa, Some(arp.sha), None, "ARP", None, dec.timestamp);
            continue;
        }

        let Some(L4Header::Udp(udp)) = dec.l4 else {
            continue;
        };

        // DHCP (67/68)
        if matches!(udp.src_port, 67 | 68) || matches!(udp.dst_port, 67 | 68) {
            if let Ok(dhcp) = parse_dhcp(
                dec.payload,
                dec.src_ip.and_then(|ip| match ip {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(_) => None,
                }),
            ) {
                let ip = dhcp.assigned_ip.or(dhcp.requested_ip).map(IpAddr::V4);
                let mac = dhcp.client_mac.or(dec.src_mac);
                let os_hint = dhcp.vendor_class.map(|vc| {
                    if vc.contains("MSFT") {
                        format!("Windows ({vc})")
                    } else {
                        vc
                    }
                });
                record(ip, mac, dhcp.hostname, "DHCP", os_hint, dec.timestamp);
            }
            continue;
        }

        // mDNS (5353)
        if udp.src_port == 5353 || udp.dst_port == 5353 {
            if let Ok(msg) = parse_dns_message(dec.payload, true) {
                for rr in msg.answers.iter().chain(msg.additionals.iter()) {
                    match &rr.rdata {
                        DnsRdata::A(ip) if rr.name.ends_with(".local") => {
                            record(
                                Some(IpAddr::V4(*ip)),
                                dec.src_mac,
                                Some(rr.name.clone()),
                                "mDNS",
                                None,
                                dec.timestamp,
                            );
                        }
                        DnsRdata::Aaaa(ip) if rr.name.ends_with(".local") => {
                            record(
                                Some(IpAddr::V6(*ip)),
                                dec.src_mac,
                                Some(rr.name.clone()),
                                "mDNS",
                                None,
                                dec.timestamp,
                            );
                        }
                        _ => {}
                    }
                }
            }
            continue;
        }

        // NetBIOS NBNS (137)
        if udp.src_port == 137 || udp.dst_port == 137 {
            if let Some(nb) = parse_nbns_packet(dec.payload) {
                let mac = nb.unit_mac.or(dec.src_mac);
                let hname = nb.names.into_iter().next();
                record(dec.src_ip, mac, hname, "NBNS", None, dec.timestamp);
            }
            continue;
        }

        // SSDP (1900)
        if (udp.src_port == 1900 || udp.dst_port == 1900)
            && let Some(ssdp) = parse_ssdp_packet(dec.payload)
        {
            record(dec.src_ip, dec.src_mac, None, "SSDP", ssdp.server, dec.timestamp);
        }
    }

    hosts.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netbios_first_level_decoding() {
        // "WORKSTATION1" padded with spaces + 0x00
        let mut enc = Vec::new();
        let mut padded = [b' '; 16];
        padded[..12].copy_from_slice(b"WORKSTATION1");
        padded[15] = 0x00;
        for b in padded {
            enc.push(b'A' + (b >> 4));
            enc.push(b'A' + (b & 0x0F));
        }
        let (name, suffix) = decode_netbios_first_level(&enc).unwrap();
        assert_eq!(name, "WORKSTATION1");
        assert_eq!(suffix, 0x00);
        assert!(decode_netbios_first_level(b"INVALID").is_none());
    }
}
