//! Pure-Rust classic `.pcap` parser and encoder (LE/BE, microsecond & nanosecond magics).

use std::io::Cursor;

use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};
use chrono::{DateTime, Utc};
use net2rust_core::{NetError, NetResult};

use super::{CapturedPacket, LinkType, MAX_CAPTURE_PACKET_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampScale {
    Microseconds,
    Nanoseconds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcapGlobalHeader {
    pub endianness: Endianness,
    pub timestamp_scale: TimestampScale,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub link_type: LinkType,
}

pub fn is_pcap_magic(magic: [u8; 4]) -> bool {
    detect_magic(magic).is_some()
}

fn detect_magic(magic: [u8; 4]) -> Option<(Endianness, TimestampScale)> {
    match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => Some((Endianness::Little, TimestampScale::Microseconds)),
        [0xa1, 0xb2, 0xc3, 0xd4] => Some((Endianness::Big, TimestampScale::Microseconds)),
        [0x4d, 0x3c, 0xb2, 0xa1] => Some((Endianness::Little, TimestampScale::Nanoseconds)),
        [0xa1, 0xb2, 0x3c, 0x4d] => Some((Endianness::Big, TimestampScale::Nanoseconds)),
        _ => None,
    }
}

fn read_u16(cur: &mut Cursor<&[u8]>, endian: Endianness) -> NetResult<u16> {
    match endian {
        Endianness::Little => cur.read_u16::<LittleEndian>(),
        Endianness::Big => cur.read_u16::<BigEndian>(),
    }
    .map_err(|e| NetError::ParseError(format!("pcap truncated u16: {e}")))
}

fn read_u32(cur: &mut Cursor<&[u8]>, endian: Endianness) -> NetResult<u32> {
    match endian {
        Endianness::Little => cur.read_u32::<LittleEndian>(),
        Endianness::Big => cur.read_u32::<BigEndian>(),
    }
    .map_err(|e| NetError::ParseError(format!("pcap truncated u32: {e}")))
}

fn read_i32(cur: &mut Cursor<&[u8]>, endian: Endianness) -> NetResult<i32> {
    match endian {
        Endianness::Little => cur.read_i32::<LittleEndian>(),
        Endianness::Big => cur.read_i32::<BigEndian>(),
    }
    .map_err(|e| NetError::ParseError(format!("pcap truncated i32: {e}")))
}

fn convert_pcap_timestamp(ts_sec: u32, ts_subsec: u32, scale: TimestampScale) -> Option<DateTime<Utc>> {
    match scale {
        TimestampScale::Microseconds => {
            let extra_secs = i64::from(ts_subsec / 1_000_000);
            let sub_ns = (ts_subsec % 1_000_000) * 1_000;
            DateTime::from_timestamp(i64::from(ts_sec) + extra_secs, sub_ns)
        }
        TimestampScale::Nanoseconds => {
            let extra_secs = i64::from(ts_subsec / 1_000_000_000);
            let sub_ns = ts_subsec % 1_000_000_000;
            DateTime::from_timestamp(i64::from(ts_sec) + extra_secs, sub_ns)
        }
    }
}

pub fn parse_pcap(data: &[u8]) -> NetResult<(PcapGlobalHeader, Vec<CapturedPacket>)> {
    if data.len() < 24 {
        return Err(NetError::ParseError(format!(
            "truncated pcap global header: expected 24 bytes, got {}",
            data.len()
        )));
    }

    let magic = [data[0], data[1], data[2], data[3]];
    let (endianness, timestamp_scale) = detect_magic(magic).ok_or_else(|| {
        NetError::ParseError(format!(
            "invalid pcap magic {:02x}{:02x}{:02x}{:02x}",
            magic[0], magic[1], magic[2], magic[3]
        ))
    })?;

    let mut cur = Cursor::new(data);
    cur.set_position(4);

    let version_major = read_u16(&mut cur, endianness)?;
    let version_minor = read_u16(&mut cur, endianness)?;
    if version_major != 2 {
        return Err(NetError::ParseError(format!(
            "unsupported pcap major version {version_major} (expected 2)"
        )));
    }
    let thiszone = read_i32(&mut cur, endianness)?;
    let sigfigs = read_u32(&mut cur, endianness)?;
    let snaplen = read_u32(&mut cur, endianness)?;
    if snaplen == 0 {
        return Err(NetError::ParseError("invalid pcap snaplen 0".to_string()));
    }
    let network = read_u32(&mut cur, endianness)?;
    let link_type = LinkType::from(network);

    let global = PcapGlobalHeader {
        endianness,
        timestamp_scale,
        version_major,
        version_minor,
        thiszone,
        sigfigs,
        snaplen,
        link_type,
    };

    let mut packets = Vec::new();
    let mut packet_no = 1u64;

    while (cur.position() as usize) < data.len() {
        let pos = cur.position() as usize;
        if data.len() - pos < 16 {
            return Err(NetError::ParseError(format!(
                "truncated pcap packet header at offset {pos}: {} bytes remaining",
                data.len() - pos
            )));
        }

        let ts_sec = read_u32(&mut cur, endianness)?;
        let ts_subsec = read_u32(&mut cur, endianness)?;
        let incl_len = read_u32(&mut cur, endianness)?;
        let orig_len = read_u32(&mut cur, endianness)?;

        let incl_usize = incl_len as usize;
        if incl_usize > MAX_CAPTURE_PACKET_BYTES {
            return Err(NetError::ParseError(format!(
                "pcap packet {packet_no} incl_len {incl_len} exceeds MAX_CAPTURE_PACKET_BYTES ({MAX_CAPTURE_PACKET_BYTES})"
            )));
        }
        if incl_len > snaplen {
            return Err(NetError::ParseError(format!(
                "pcap packet {packet_no} incl_len {incl_len} exceeds snaplen {snaplen}"
            )));
        }

        let payload_start = cur.position() as usize;
        let payload_end = payload_start
            .checked_add(incl_usize)
            .ok_or_else(|| NetError::ParseError("pcap payload offset overflow".to_string()))?;
        if payload_end > data.len() {
            return Err(NetError::ParseError(format!(
                "truncated pcap packet {packet_no} payload: needed {incl_usize} bytes at {payload_start}, available {}",
                data.len() - payload_start
            )));
        }

        let payload = data[payload_start..payload_end].to_vec();
        cur.set_position(payload_end as u64);

        packets.push(CapturedPacket {
            packet_no,
            timestamp: convert_pcap_timestamp(ts_sec, ts_subsec, timestamp_scale),
            link_type,
            original_len: orig_len,
            interface_id: Some(0),
            interface_name: None,
            data: payload,
        });
        packet_no += 1;
    }

    Ok((global, packets))
}

pub fn encode_pcap<B: ByteOrder>(link_type: LinkType, scale: TimestampScale, packets: &[CapturedPacket]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + packets.len() * 80);
    // Write magic in B's byte order for 0xa1b2c3d4 / 0xa1b23c4d
    let magic = match scale {
        TimestampScale::Microseconds => 0xa1b2_c3d4u32,
        TimestampScale::Nanoseconds => 0xa1b2_3c4du32,
    };
    let _ = out.write_u32::<B>(magic);
    let _ = out.write_u16::<B>(2); // version_major
    let _ = out.write_u16::<B>(4); // version_minor
    let _ = out.write_i32::<B>(0); // thiszone
    let _ = out.write_u32::<B>(0); // sigfigs
    let _ = out.write_u32::<B>(65535); // snaplen
    let _ = out.write_u32::<B>(link_type.to_u32());

    for pkt in packets {
        let (ts_sec, ts_subsec) = match pkt.timestamp {
            Some(ts) => {
                let secs = ts.timestamp().max(0) as u32;
                let nanos = ts.timestamp_subsec_nanos();
                let subsec = match scale {
                    TimestampScale::Microseconds => nanos / 1_000,
                    TimestampScale::Nanoseconds => nanos,
                };
                (secs, subsec)
            }
            None => (0, 0),
        };
        let incl_len = pkt.data.len() as u32;
        let orig_len = pkt.original_len.max(incl_len);
        let _ = out.write_u32::<B>(ts_sec);
        let _ = out.write_u32::<B>(ts_subsec);
        let _ = out.write_u32::<B>(incl_len);
        let _ = out.write_u32::<B>(orig_len);
        out.extend_from_slice(&pkt.data);
    }

    out
}

pub fn encode_pcap_le_us(link_type: LinkType, packets: &[CapturedPacket]) -> Vec<u8> {
    encode_pcap::<LittleEndian>(link_type, TimestampScale::Microseconds, packets)
}

pub fn encode_pcap_be_ns(link_type: LinkType, packets: &[CapturedPacket]) -> Vec<u8> {
    encode_pcap::<BigEndian>(link_type, TimestampScale::Nanoseconds, packets)
}
