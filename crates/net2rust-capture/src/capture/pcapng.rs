//! Pure-Rust `.pcapng` block parser and encoder (SHB, IDB, EPB, SPB, obsolete PB, unknown block skip).

use byteorder::{BigEndian, ByteOrder, LittleEndian};
use chrono::{DateTime, Utc};
use net2rust_core::{NetError, NetResult};

use super::pcap::Endianness;
use super::{CapturedPacket, LinkType, MAX_CAPTURE_PACKET_BYTES};

pub const BLOCK_SHB: u32 = 0x0A0D_0D0A;
pub const BLOCK_IDB: u32 = 0x0000_0001;
pub const BLOCK_PB: u32 = 0x0000_0002;
pub const BLOCK_SPB: u32 = 0x0000_0003;
pub const BLOCK_EPB: u32 = 0x0000_0006;

const SHB_BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

#[derive(Debug, Clone)]
struct PcapngInterface {
    link_type: LinkType,
    snaplen: u32,
    name: Option<String>,
    ts_resol: u8,
    ts_offset_secs: i64,
}

pub fn is_pcapng_magic(magic: [u8; 4]) -> bool {
    magic == [0x0A, 0x0D, 0x0D, 0x0A]
}

fn read_u16(bytes: &[u8], endian: Endianness) -> u16 {
    match endian {
        Endianness::Little => LittleEndian::read_u16(bytes),
        Endianness::Big => BigEndian::read_u16(bytes),
    }
}

fn read_u32(bytes: &[u8], endian: Endianness) -> u32 {
    match endian {
        Endianness::Little => LittleEndian::read_u32(bytes),
        Endianness::Big => BigEndian::read_u32(bytes),
    }
}

fn read_i64(bytes: &[u8], endian: Endianness) -> i64 {
    match endian {
        Endianness::Little => LittleEndian::read_i64(bytes),
        Endianness::Big => BigEndian::read_i64(bytes),
    }
}

fn convert_pcapng_timestamp(ts_high: u32, ts_low: u32, ts_resol: u8, ts_offset_secs: i64) -> Option<DateTime<Utc>> {
    let raw_ts = (u64::from(ts_high) << 32) | u64::from(ts_low);
    let total_ns: u128 = if (ts_resol & 0x80) == 0 {
        let exp = u32::from(ts_resol);
        if exp <= 9 {
            let scale = 10u128.checked_pow(9 - exp)?;
            u128::from(raw_ts).checked_mul(scale)?
        } else if exp <= 19 {
            let div = 10u128.checked_pow(exp - 9)?;
            u128::from(raw_ts) / div
        } else {
            return None;
        }
    } else {
        let exp = u32::from(ts_resol & 0x7F);
        if exp > 63 {
            return None;
        }
        (u128::from(raw_ts).checked_mul(1_000_000_000u128)?) >> exp
    };

    let secs_part = i64::try_from(total_ns / 1_000_000_000u128).ok()?;
    let subsec_ns = (total_ns % 1_000_000_000u128) as u32;
    let adjusted_secs = secs_part.checked_add(ts_offset_secs)?;
    DateTime::from_timestamp(adjusted_secs, subsec_ns)
}

fn parse_idb_options(opts: &[u8], endian: Endianness, iface: &mut PcapngInterface) -> NetResult<()> {
    let mut pos = 0usize;
    while pos + 4 <= opts.len() {
        let code = read_u16(&opts[pos..pos + 2], endian);
        let len = usize::from(read_u16(&opts[pos + 2..pos + 4], endian));
        pos += 4;
        if code == 0 {
            break;
        }
        let end = pos
            .checked_add(len)
            .ok_or_else(|| NetError::ParseError("pcapng IDB option length overflow".to_string()))?;
        if end > opts.len() {
            return Err(NetError::ParseError(format!(
                "truncated pcapng IDB option {code}: len {len}, remaining {}",
                opts.len() - pos
            )));
        }
        let val = &opts[pos..end];
        match code {
            2 => {
                // if_name
                let s = String::from_utf8_lossy(val).trim_end_matches('\0').to_string();
                if !s.is_empty() {
                    iface.name = Some(s);
                }
            }
            9 => {
                // if_tsresol
                if !val.is_empty() {
                    iface.ts_resol = val[0];
                }
            }
            14 if val.len() == 8 => {
                // if_tsoffset
                iface.ts_offset_secs = read_i64(val, endian);
            }
            _ => {}
        }
        let padded = (len + 3) & !3;
        pos = pos
            .checked_add(padded)
            .ok_or_else(|| NetError::ParseError("pcapng IDB option padding overflow".to_string()))?;
        if pos > opts.len() {
            break;
        }
    }
    Ok(())
}

pub fn parse_pcapng(data: &[u8]) -> NetResult<Vec<CapturedPacket>> {
    if data.len() < 28 {
        return Err(NetError::ParseError(format!(
            "truncated pcapng stream: expected at least 28 bytes, got {}",
            data.len()
        )));
    }

    let mut offset = 0usize;
    let mut endian: Option<Endianness> = None;
    let mut interfaces: Vec<PcapngInterface> = Vec::new();
    let mut packets: Vec<CapturedPacket> = Vec::new();
    let mut packet_no = 1u64;

    while offset < data.len() {
        let remaining = data.len() - offset;
        if remaining < 12 {
            return Err(NetError::ParseError(format!(
                "truncated pcapng block header at offset {offset}: {remaining} bytes remaining"
            )));
        }

        let is_shb_magic = data[offset..offset + 4] == [0x0A, 0x0D, 0x0D, 0x0A];
        if is_shb_magic {
            if remaining < 28 {
                return Err(NetError::ParseError(format!(
                    "truncated pcapng SHB at offset {offset}: {remaining} bytes remaining"
                )));
            }
            let bom = &data[offset + 8..offset + 12];
            if LittleEndian::read_u32(bom) == SHB_BYTE_ORDER_MAGIC {
                endian = Some(Endianness::Little);
            } else if BigEndian::read_u32(bom) == SHB_BYTE_ORDER_MAGIC {
                endian = Some(Endianness::Big);
            } else {
                return Err(NetError::ParseError(format!(
                    "invalid pcapng SHB byte-order magic at offset {offset}"
                )));
            }
        }

        let active_endian = endian.ok_or_else(|| {
            NetError::ParseError("pcapng stream does not start with a valid Section Header Block".to_string())
        })?;

        let block_type = read_u32(&data[offset..offset + 4], active_endian);
        let total_len = read_u32(&data[offset + 4..offset + 8], active_endian);

        if total_len < 12 || !total_len.is_multiple_of(4) {
            return Err(NetError::ParseError(format!(
                "invalid pcapng block length {total_len} at offset {offset}"
            )));
        }
        let total_usize = total_len as usize;
        let block_end = offset
            .checked_add(total_usize)
            .ok_or_else(|| NetError::ParseError("pcapng block offset overflow".to_string()))?;
        if block_end > data.len() {
            return Err(NetError::ParseError(format!(
                "truncated pcapng block at offset {offset}: expected {total_usize} bytes, available {remaining}"
            )));
        }

        let trailing_len = read_u32(&data[block_end - 4..block_end], active_endian);
        if trailing_len != total_len {
            return Err(NetError::ParseError(format!(
                "pcapng block trailing length mismatch at offset {offset}: leading {total_len} != trailing {trailing_len}"
            )));
        }

        let body = &data[offset + 8..block_end - 4];

        match block_type {
            BLOCK_SHB => {
                if body.len() < 16 {
                    return Err(NetError::ParseError("truncated pcapng SHB body".to_string()));
                }
                let major = read_u16(&body[4..6], active_endian);
                if major != 1 {
                    return Err(NetError::ParseError(format!(
                        "unsupported pcapng SHB major version {major}"
                    )));
                }
                interfaces.clear();
            }
            BLOCK_IDB => {
                if body.len() < 8 {
                    return Err(NetError::ParseError("truncated pcapng IDB body".to_string()));
                }
                let raw_link = u32::from(read_u16(&body[0..2], active_endian));
                let snaplen = read_u32(&body[4..8], active_endian);
                let mut iface = PcapngInterface {
                    link_type: LinkType::from(raw_link),
                    snaplen,
                    name: None,
                    ts_resol: 6, // Default 10^-6 seconds per PCAPNG spec
                    ts_offset_secs: 0,
                };
                if body.len() > 8 {
                    parse_idb_options(&body[8..], active_endian, &mut iface)?;
                }
                interfaces.push(iface);
            }
            BLOCK_EPB => {
                if body.len() < 20 {
                    return Err(NetError::ParseError("truncated pcapng EPB body".to_string()));
                }
                let iface_id = read_u32(&body[0..4], active_endian);
                let ts_high = read_u32(&body[4..8], active_endian);
                let ts_low = read_u32(&body[8..12], active_endian);
                let captured_len = read_u32(&body[12..16], active_endian);
                let original_len = read_u32(&body[16..20], active_endian);

                let iface = interfaces.get(iface_id as usize).ok_or_else(|| {
                    NetError::ParseError(format!("pcapng EPB references unknown interface_id {iface_id}"))
                })?;
                let cap_usize = captured_len as usize;
                if cap_usize > MAX_CAPTURE_PACKET_BYTES {
                    return Err(NetError::ParseError(format!(
                        "pcapng EPB captured_len {captured_len} exceeds MAX_CAPTURE_PACKET_BYTES"
                    )));
                }
                let padded_cap = (cap_usize + 3) & !3;
                let data_end = 20usize
                    .checked_add(padded_cap)
                    .ok_or_else(|| NetError::ParseError("pcapng EPB payload overflow".to_string()))?;
                if data_end > body.len() {
                    return Err(NetError::ParseError(format!(
                        "truncated pcapng EPB packet payload: needed {padded_cap}, body len {}",
                        body.len()
                    )));
                }

                packets.push(CapturedPacket {
                    packet_no,
                    timestamp: convert_pcapng_timestamp(ts_high, ts_low, iface.ts_resol, iface.ts_offset_secs),
                    link_type: iface.link_type,
                    original_len,
                    interface_id: Some(iface_id),
                    interface_name: iface.name.clone(),
                    data: body[20..20 + cap_usize].to_vec(),
                });
                packet_no += 1;
            }
            BLOCK_SPB => {
                if body.len() < 4 {
                    return Err(NetError::ParseError("truncated pcapng SPB body".to_string()));
                }
                let iface = interfaces
                    .first()
                    .ok_or_else(|| NetError::ParseError("pcapng SPB encountered before any IDB".to_string()))?;
                let original_len = read_u32(&body[0..4], active_endian);
                let snap_cap = if iface.snaplen > 0 {
                    iface.snaplen as usize
                } else {
                    usize::MAX
                };
                let cap_usize = (original_len as usize)
                    .min(snap_cap)
                    .min(body.len() - 4)
                    .min(MAX_CAPTURE_PACKET_BYTES);
                packets.push(CapturedPacket {
                    packet_no,
                    timestamp: None,
                    link_type: iface.link_type,
                    original_len,
                    interface_id: Some(0),
                    interface_name: iface.name.clone(),
                    data: body[4..4 + cap_usize].to_vec(),
                });
                packet_no += 1;
            }
            BLOCK_PB => {
                if body.len() < 20 {
                    return Err(NetError::ParseError("truncated pcapng PB body".to_string()));
                }
                let iface_id = u32::from(read_u16(&body[0..2], active_endian));
                let ts_high = read_u32(&body[4..8], active_endian);
                let ts_low = read_u32(&body[8..12], active_endian);
                let captured_len = read_u32(&body[12..16], active_endian);
                let original_len = read_u32(&body[16..20], active_endian);

                let iface = interfaces.get(iface_id as usize).ok_or_else(|| {
                    NetError::ParseError(format!("pcapng PB references unknown interface_id {iface_id}"))
                })?;
                let cap_usize = captured_len as usize;
                if cap_usize > MAX_CAPTURE_PACKET_BYTES {
                    return Err(NetError::ParseError(format!(
                        "pcapng PB captured_len {captured_len} exceeds MAX_CAPTURE_PACKET_BYTES"
                    )));
                }
                let padded_cap = (cap_usize + 3) & !3;
                let data_end = 20usize
                    .checked_add(padded_cap)
                    .ok_or_else(|| NetError::ParseError("pcapng PB payload overflow".to_string()))?;
                if data_end > body.len() {
                    return Err(NetError::ParseError("truncated pcapng PB payload".to_string()));
                }
                packets.push(CapturedPacket {
                    packet_no,
                    timestamp: convert_pcapng_timestamp(ts_high, ts_low, iface.ts_resol, iface.ts_offset_secs),
                    link_type: iface.link_type,
                    original_len,
                    interface_id: Some(iface_id),
                    interface_name: iface.name.clone(),
                    data: body[20..20 + cap_usize].to_vec(),
                });
                packet_no += 1;
            }
            _ => {
                // Unknown block: skipped cleanly because leading == trailing block_total_length was verified.
            }
        }

        offset = block_end;
    }

    Ok(packets)
}

fn push_block(out: &mut Vec<u8>, block_type: u32, body: &[u8], endian: Endianness) {
    let total_len = (12 + body.len()) as u32;
    let write_u32 = |buf: &mut Vec<u8>, v: u32| match endian {
        Endianness::Little => buf.extend_from_slice(&v.to_le_bytes()),
        Endianness::Big => buf.extend_from_slice(&v.to_be_bytes()),
    };
    write_u32(out, block_type);
    write_u32(out, total_len);
    out.extend_from_slice(body);
    write_u32(out, total_len);
}

fn timestamp_to_ts_units(ts: Option<DateTime<Utc>>, ts_resol: u8) -> (u32, u32) {
    let Some(dt) = ts else {
        return (0, 0);
    };
    let ns = u128::try_from(dt.timestamp_nanos_opt().unwrap_or(0)).unwrap_or(0);
    let raw: u64 = if (ts_resol & 0x80) == 0 {
        let exp = u32::from(ts_resol);
        if exp <= 9 {
            let div = 10u128.checked_pow(9 - exp).unwrap_or(1);
            u64::try_from(ns / div).unwrap_or(u64::MAX)
        } else {
            10u128
                .checked_pow(exp - 9)
                .and_then(|mul| ns.checked_mul(mul))
                .and_then(|units| u64::try_from(units).ok())
                .unwrap_or(u64::MAX)
        }
    } else {
        let exp = u32::from(ts_resol & 0x7F);
        if exp > 63 {
            u64::MAX
        } else {
            1u128
                .checked_shl(exp)
                .and_then(|mul| ns.checked_mul(mul))
                .map(|v| v / 1_000_000_000u128)
                .and_then(|units| u64::try_from(units).ok())
                .unwrap_or(u64::MAX)
        }
    };
    ((raw >> 32) as u32, (raw & 0xFFFF_FFFF) as u32)
}

pub fn encode_pcapng(interfaces: &[(LinkType, &str, u8)], packets: &[CapturedPacket], endian: Endianness) -> Vec<u8> {
    let mut out = Vec::new();
    let push_u16 = |buf: &mut Vec<u8>, v: u16| match endian {
        Endianness::Little => buf.extend_from_slice(&v.to_le_bytes()),
        Endianness::Big => buf.extend_from_slice(&v.to_be_bytes()),
    };
    let push_u32 = |buf: &mut Vec<u8>, v: u32| match endian {
        Endianness::Little => buf.extend_from_slice(&v.to_le_bytes()),
        Endianness::Big => buf.extend_from_slice(&v.to_be_bytes()),
    };

    // SHB
    let mut shb = Vec::with_capacity(16);
    push_u32(&mut shb, SHB_BYTE_ORDER_MAGIC);
    push_u16(&mut shb, 1);
    push_u16(&mut shb, 0);
    shb.extend_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
    push_block(&mut out, BLOCK_SHB, &shb, endian);

    // IDBs
    for &(link_type, name, ts_resol) in interfaces {
        let mut idb = Vec::new();
        push_u16(&mut idb, link_type.to_u32() as u16);
        push_u16(&mut idb, 0);
        push_u32(&mut idb, 65535);

        // Option 2: if_name
        if !name.is_empty() {
            let nb = name.as_bytes();
            push_u16(&mut idb, 2);
            push_u16(&mut idb, nb.len() as u16);
            idb.extend_from_slice(nb);
            let pad = (4 - (nb.len() % 4)) % 4;
            idb.extend(std::iter::repeat_n(0u8, pad));
        }

        // Option 9: if_tsresol
        push_u16(&mut idb, 9);
        push_u16(&mut idb, 1);
        idb.push(ts_resol);
        idb.extend_from_slice(&[0, 0, 0]);

        // Option 0: end of options
        push_u16(&mut idb, 0);
        push_u16(&mut idb, 0);

        push_block(&mut out, BLOCK_IDB, &idb, endian);
    }

    // EPBs
    for pkt in packets {
        let iface_id = pkt.interface_id.unwrap_or(0);
        let ts_resol = interfaces.get(iface_id as usize).map(|i| i.2).unwrap_or(6);
        let (ts_high, ts_low) = timestamp_to_ts_units(pkt.timestamp, ts_resol);

        let mut epb = Vec::with_capacity(20 + pkt.data.len() + 4);
        push_u32(&mut epb, iface_id);
        push_u32(&mut epb, ts_high);
        push_u32(&mut epb, ts_low);
        push_u32(&mut epb, pkt.data.len() as u32);
        push_u32(&mut epb, pkt.original_len.max(pkt.data.len() as u32));
        epb.extend_from_slice(&pkt.data);
        let pad = (4 - (pkt.data.len() % 4)) % 4;
        epb.extend(std::iter::repeat_n(0u8, pad));
        push_block(&mut out, BLOCK_EPB, &epb, endian);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::fixtures::base_timestamp;

    #[test]
    fn test_encode_pcapng_high_ts_resol_no_panic_or_wrap() {
        let pkt = CapturedPacket {
            packet_no: 1,
            timestamp: Some(base_timestamp()),
            link_type: LinkType::Ethernet,
            original_len: 4,
            interface_id: Some(0),
            interface_name: Some("eth0".to_string()),
            data: vec![1, 2, 3, 4],
        };

        // ts_resol = 12 (exceeds u64 for 2026 epoch): clamps cleanly to u64::MAX without wrapping
        let ng_12 = encode_pcapng(
            &[(LinkType::Ethernet, "eth0", 12)],
            std::slice::from_ref(&pkt),
            Endianness::Little,
        );
        let parsed_12 = parse_pcapng(&ng_12).unwrap();
        assert_eq!(parsed_12.len(), 1);
        let (hi12, lo12) = timestamp_to_ts_units(pkt.timestamp, 12);
        assert_eq!((hi12, lo12), (u32::MAX, u32::MAX));

        // ts_resol = 50 (previously panicked at 10u128.pow(50 - 9)): no panic
        let ng_50 = encode_pcapng(
            &[(LinkType::Ethernet, "eth0", 50)],
            std::slice::from_ref(&pkt),
            Endianness::Little,
        );
        let parsed_50 = parse_pcapng(&ng_50).unwrap();
        assert_eq!(parsed_50.len(), 1);
        assert_eq!(timestamp_to_ts_units(pkt.timestamp, 50), (u32::MAX, u32::MAX));

        // Binary high exponent (0x80 | 63 and 0x80 | 127): no panic or shift wrap
        assert_eq!(timestamp_to_ts_units(pkt.timestamp, 0x80 | 63), (u32::MAX, u32::MAX));
        assert_eq!(timestamp_to_ts_units(pkt.timestamp, 0x80 | 127), (u32::MAX, u32::MAX));
    }
}
