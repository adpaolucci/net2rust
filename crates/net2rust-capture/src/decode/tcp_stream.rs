//! Bounded directional TCP stream reassembler with 32-bit sequence ordering and overlap handling.

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::capture::CapturedPacket;
use crate::decode::l2_l4::{L4Header, decode_packet};

pub const MAX_STREAMS: usize = 4096;
pub const MAX_STREAM_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl StreamKey {
    pub fn reverse(self) -> Self {
        Self {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        }
    }
}

#[derive(Debug, Clone)]
struct SegmentChunk {
    seq: u32,
    timestamp: Option<DateTime<Utc>>,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct StreamState {
    base_seq: Option<u32>,
    segments: Vec<SegmentChunk>,
    total_buffered: usize,
    first_ts: Option<DateTime<Utc>>,
    last_ts: Option<DateTime<Utc>>,
    closed: bool,
}

#[derive(Debug, Clone)]
pub struct ReassembledStream {
    pub key: StreamKey,
    pub data: Vec<u8>,
    /// `(byte_offset, timestamp)` marks for locating segment arrival times.
    pub timestamp_marks: Vec<(usize, DateTime<Utc>)>,
    pub first_ts: Option<DateTime<Utc>>,
    pub last_ts: Option<DateTime<Utc>>,
    pub closed: bool,
}

impl ReassembledStream {
    pub fn timestamp_at(&self, offset: usize) -> Option<DateTime<Utc>> {
        let mut best = self.first_ts;
        for &(mark_off, ts) in &self.timestamp_marks {
            if mark_off <= offset {
                best = Some(ts);
            } else {
                break;
            }
        }
        best
    }
}

pub struct TcpStreamReassembler {
    streams: HashMap<StreamKey, StreamState>,
    order: Vec<StreamKey>,
}

impl Default for TcpStreamReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpStreamReassembler {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            order: Vec::new(),
        }
    }

    pub fn ingest_packets(&mut self, packets: &[CapturedPacket]) {
        for pkt in packets {
            let Ok(dec) = decode_packet(pkt) else {
                continue;
            };
            let (Some(src_ip), Some(dst_ip)) = (dec.src_ip, dec.dst_ip) else {
                continue;
            };
            let Some(L4Header::Tcp(tcp)) = dec.l4 else {
                continue;
            };

            let key = StreamKey {
                src_ip,
                src_port: tcp.src_port,
                dst_ip,
                dst_port: tcp.dst_port,
            };
            self.ingest_segment(key, tcp.seq, tcp.flags, dec.timestamp, dec.payload);
        }
    }

    pub fn ingest_segment(
        &mut self,
        key: StreamKey,
        seq: u32,
        flags: u16,
        timestamp: Option<DateTime<Utc>>,
        payload: &[u8],
    ) {
        let is_syn = (flags & 0x0002) != 0;
        let is_fin_or_rst = (flags & 0x0005) != 0;

        if !self.streams.contains_key(&key) {
            if self.streams.len() >= MAX_STREAMS {
                return;
            }
            self.order.push(key);
            self.streams.insert(
                key,
                StreamState {
                    base_seq: None,
                    segments: Vec::new(),
                    total_buffered: 0,
                    first_ts: timestamp,
                    last_ts: timestamp,
                    closed: false,
                },
            );
        }

        let Some(state) = self.streams.get_mut(&key) else {
            return;
        };

        if let Some(ts) = timestamp {
            if state.first_ts.is_none() {
                state.first_ts = Some(ts);
            }
            state.last_ts = Some(ts);
        }

        if is_syn {
            let data_start_seq = seq.wrapping_add(1);
            if state.base_seq.is_none() {
                state.base_seq = Some(data_start_seq);
            }
        }

        if is_fin_or_rst {
            state.closed = true;
        }

        if payload.is_empty() {
            return;
        }

        if state.base_seq.is_none() {
            state.base_seq = Some(seq);
        }

        let remaining_cap = MAX_STREAM_BYTES.saturating_sub(state.total_buffered);
        if remaining_cap == 0 {
            return;
        }
        let take_len = payload.len().min(remaining_cap);
        state.total_buffered += take_len;
        state.segments.push(SegmentChunk {
            seq,
            timestamp,
            data: payload[..take_len].to_vec(),
        });
    }

    pub fn finalize(mut self) -> Vec<ReassembledStream> {
        let mut out = Vec::new();
        for key in self.order {
            let Some(mut state) = self.streams.remove(&key) else {
                continue;
            };
            if state.segments.is_empty() {
                continue;
            }
            let Some(base_seq) = state.base_seq else {
                continue;
            };

            // Compute relative offset using wrapping subtraction; guard against pre-base wraparound
            // by treating offsets > 0x8000_0000 as pre-base and shifting base if needed.
            state.segments.sort_by_key(|seg| {
                let rel = seg.seq.wrapping_sub(base_seq);
                if rel >= 0x8000_0000 { 0u32 } else { rel }
            });

            let mut data = Vec::with_capacity(state.total_buffered);
            let mut timestamp_marks = Vec::new();
            let mut cursor_rel = 0u32;

            for seg in state.segments {
                let rel = seg.seq.wrapping_sub(base_seq);
                if rel >= 0x8000_0000 {
                    // Segment entirely or partially before base_seq
                    let behind = base_seq.wrapping_sub(seg.seq) as usize;
                    if behind >= seg.data.len() {
                        continue;
                    }
                    let slice = &seg.data[behind..];
                    let already = cursor_rel as usize;
                    if slice.len() > already {
                        let start_off = data.len();
                        if let Some(ts) = seg.timestamp {
                            timestamp_marks.push((start_off, ts));
                        }
                        data.extend_from_slice(&slice[already..]);
                        cursor_rel = data.len() as u32;
                    }
                    continue;
                }

                if rel > cursor_rel {
                    // Gap in sequence space: fill with zeros up to bounded cap.
                    let gap = (rel - cursor_rel) as usize;
                    if data.len().saturating_add(gap) > MAX_STREAM_BYTES {
                        break;
                    }
                    data.resize(data.len() + gap, 0);
                    cursor_rel = rel;
                }

                let overlap = (cursor_rel - rel) as usize;
                if overlap >= seg.data.len() {
                    continue;
                }
                let slice = &seg.data[overlap..];
                let avail = MAX_STREAM_BYTES.saturating_sub(data.len());
                if avail == 0 {
                    break;
                }
                let take = slice.len().min(avail);
                let start_off = data.len();
                if let Some(ts) = seg.timestamp {
                    timestamp_marks.push((start_off, ts));
                }
                data.extend_from_slice(&slice[..take]);
                cursor_rel = cursor_rel.saturating_add(take as u32);
            }

            if !data.is_empty() {
                out.push(ReassembledStream {
                    key,
                    data,
                    timestamp_marks,
                    first_ts: state.first_ts,
                    last_ts: state.last_ts,
                    closed: state.closed,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn test_tcp_stream_out_of_order_overlap_and_wraparound() {
        let mut r = TcpStreamReassembler::new();
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 12345,
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: 80,
        };
        let syn_seq = u32::MAX - 2; // wraps right after SYN
        r.ingest_segment(key, syn_seq, 0x0002, None, b"");
        // Second segment arrives first (wraparound past u32::MAX)
        r.ingest_segment(key, syn_seq.wrapping_add(1 + 5), 0x0018, None, b"World!");
        // First segment arrives second, overlapping 1 byte
        r.ingest_segment(key, syn_seq.wrapping_add(1), 0x0018, None, b"HelloW");

        let streams = r.finalize();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].data, b"HelloWorld!");
    }
}
