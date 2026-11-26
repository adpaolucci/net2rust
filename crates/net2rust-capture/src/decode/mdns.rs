//! mDNS (UDP 5353, RFC 6762) and DNS-SD service discovery correlation (PTR/SRV/TXT/A/AAAA).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::capture::CapturedPacket;
use crate::decode::dns_wire::{DnsRdata, DnsResourceRecord, parse_dns_message, qtype_name};
use crate::decode::l2_l4::{L4Header, decode_packet};

#[derive(Debug, Clone)]
pub struct MdnsServiceEntry {
    pub timestamp: Option<DateTime<Utc>>,
    pub service_name: String,
    pub service_type: Option<String>,
    pub host_name: Option<String>,
    pub ip_addresses: Vec<IpAddr>,
    pub port: Option<u16>,
    pub txt_records: Vec<String>,
    pub ttl: Option<u32>,
    pub cache_flush: bool,
}

fn infer_service_type(instance_name: &str) -> Option<String> {
    let parts: Vec<&str> = instance_name.split('.').collect();
    if parts.len() >= 3 {
        for i in 0..parts.len() {
            if (parts[i] == "_tcp" || parts[i] == "_udp") && i > 0 {
                return Some(parts[i - 1..].join("."));
            }
        }
    }
    None
}

pub fn extract_mdns_services(packets: &[CapturedPacket]) -> Vec<MdnsServiceEntry> {
    let mut host_ips: BTreeMap<String, BTreeSet<IpAddr>> = BTreeMap::new();
    let mut services: BTreeMap<String, MdnsServiceEntry> = BTreeMap::new();
    let mut query_only: Vec<MdnsServiceEntry> = Vec::new();
    let mut seen_response_names: BTreeSet<String> = BTreeSet::new();

    for pkt in packets {
        let Ok(dec) = decode_packet(pkt) else {
            continue;
        };
        let Some(L4Header::Udp(udp)) = dec.l4 else {
            continue;
        };
        if udp.src_port != 5353 && udp.dst_port != 5353 {
            continue;
        }
        let Ok(msg) = parse_dns_message(dec.payload, true) else {
            continue;
        };

        let all_rrs: Vec<&DnsResourceRecord> = msg
            .answers
            .iter()
            .chain(msg.authorities.iter())
            .chain(msg.additionals.iter())
            .collect();

        // First collect A/AAAA host -> IP mappings
        for rr in &all_rrs {
            let key = rr.name.to_ascii_lowercase();
            match &rr.rdata {
                DnsRdata::A(ip) => {
                    host_ips.entry(key).or_default().insert(IpAddr::V4(*ip));
                }
                DnsRdata::Aaaa(ip) => {
                    host_ips.entry(key).or_default().insert(IpAddr::V6(*ip));
                }
                _ => {}
            }
        }

        // Correlate PTR -> SRV -> TXT
        for rr in &all_rrs {
            match &rr.rdata {
                DnsRdata::Name(instance) if rr.rtype == 12 => {
                    seen_response_names.insert(instance.to_ascii_lowercase());
                    let entry = services
                        .entry(instance.to_ascii_lowercase())
                        .or_insert_with(|| MdnsServiceEntry {
                            timestamp: dec.timestamp,
                            service_name: instance.clone(),
                            service_type: Some(rr.name.clone()),
                            host_name: None,
                            ip_addresses: Vec::new(),
                            port: None,
                            txt_records: Vec::new(),
                            ttl: Some(rr.ttl),
                            cache_flush: rr.cache_flush,
                        });
                    if entry.service_type.is_none() {
                        entry.service_type = Some(rr.name.clone());
                    }
                    if entry.timestamp.is_none() {
                        entry.timestamp = dec.timestamp;
                    }
                }
                DnsRdata::Srv { port, target, .. } if rr.rtype == 33 => {
                    seen_response_names.insert(rr.name.to_ascii_lowercase());
                    let entry = services
                        .entry(rr.name.to_ascii_lowercase())
                        .or_insert_with(|| MdnsServiceEntry {
                            timestamp: dec.timestamp,
                            service_name: rr.name.clone(),
                            service_type: infer_service_type(&rr.name),
                            host_name: None,
                            ip_addresses: Vec::new(),
                            port: None,
                            txt_records: Vec::new(),
                            ttl: Some(rr.ttl),
                            cache_flush: rr.cache_flush,
                        });
                    entry.host_name = Some(target.clone());
                    entry.port = Some(*port);
                    entry.ttl = Some(rr.ttl);
                    entry.cache_flush |= rr.cache_flush;
                    if let Some(ips) = host_ips.get(&target.to_ascii_lowercase()) {
                        for ip in ips {
                            if !entry.ip_addresses.contains(ip) {
                                entry.ip_addresses.push(*ip);
                            }
                        }
                    } else if let Some(sender) = dec.src_ip
                        && !entry.ip_addresses.contains(&sender)
                    {
                        entry.ip_addresses.push(sender);
                    }
                }
                DnsRdata::Txt(txts) if rr.rtype == 16 => {
                    seen_response_names.insert(rr.name.to_ascii_lowercase());
                    let entry = services
                        .entry(rr.name.to_ascii_lowercase())
                        .or_insert_with(|| MdnsServiceEntry {
                            timestamp: dec.timestamp,
                            service_name: rr.name.clone(),
                            service_type: infer_service_type(&rr.name),
                            host_name: None,
                            ip_addresses: Vec::new(),
                            port: None,
                            txt_records: Vec::new(),
                            ttl: Some(rr.ttl),
                            cache_flush: rr.cache_flush,
                        });
                    for t in txts {
                        if !entry.txt_records.contains(t) {
                            entry.txt_records.push(t.clone());
                        }
                    }
                }
                DnsRdata::A(ip) if rr.rtype == 1 => {
                    if !seen_response_names.contains(&rr.name.to_ascii_lowercase()) && msg.answers.contains(rr) {
                        let entry = services
                            .entry(rr.name.to_ascii_lowercase())
                            .or_insert_with(|| MdnsServiceEntry {
                                timestamp: dec.timestamp,
                                service_name: rr.name.clone(),
                                service_type: Some("A".to_string()),
                                host_name: Some(rr.name.clone()),
                                ip_addresses: Vec::new(),
                                port: None,
                                txt_records: Vec::new(),
                                ttl: Some(rr.ttl),
                                cache_flush: rr.cache_flush,
                            });
                        if !entry.ip_addresses.contains(&IpAddr::V4(*ip)) {
                            entry.ip_addresses.push(IpAddr::V4(*ip));
                        }
                    }
                }
                DnsRdata::Aaaa(ip)
                    if rr.rtype == 28
                        && !seen_response_names.contains(&rr.name.to_ascii_lowercase())
                        && msg.answers.contains(rr) =>
                {
                    let entry = services
                        .entry(rr.name.to_ascii_lowercase())
                        .or_insert_with(|| MdnsServiceEntry {
                            timestamp: dec.timestamp,
                            service_name: rr.name.clone(),
                            service_type: Some("AAAA".to_string()),
                            host_name: Some(rr.name.clone()),
                            ip_addresses: Vec::new(),
                            port: None,
                            txt_records: Vec::new(),
                            ttl: Some(rr.ttl),
                            cache_flush: rr.cache_flush,
                        });
                    if !entry.ip_addresses.contains(&IpAddr::V6(*ip)) {
                        entry.ip_addresses.push(IpAddr::V6(*ip));
                    }
                }
                _ => {}
            }
        }

        if !msg.is_response && all_rrs.is_empty() {
            for q in &msg.questions {
                query_only.push(MdnsServiceEntry {
                    timestamp: dec.timestamp,
                    service_name: q.name.clone(),
                    service_type: Some(format!("Query({})", qtype_name(q.qtype))),
                    host_name: None,
                    ip_addresses: dec.src_ip.into_iter().collect(),
                    port: None,
                    txt_records: Vec::new(),
                    ttl: None,
                    cache_flush: false,
                });
            }
        }
    }

    // Second pass: resolve any host_ips discovered later in the capture
    for entry in services.values_mut() {
        if let Some(ref host) = entry.host_name
            && let Some(ips) = host_ips.get(&host.to_ascii_lowercase())
        {
            for ip in ips {
                if !entry.ip_addresses.contains(ip) {
                    entry.ip_addresses.push(*ip);
                }
            }
        }
    }

    let mut result: Vec<MdnsServiceEntry> = services.into_values().collect();
    for q in query_only {
        if !seen_response_names.contains(&q.service_name.to_ascii_lowercase()) {
            result.push(q);
        }
    }
    result
}
