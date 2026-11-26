//! Capture & file-parsing layer (`pcap`, `pcapng`, Windows NDIS ETW + `.etl`, optional `wpcap.dll`,
//! and embedded deterministic synthetic fixtures).

pub mod etw_ndis;
pub mod fixtures;
pub mod pcap;
pub mod pcapng;
pub mod wpcap;

use std::path::Path;

use chrono::{DateTime, Utc};
use net2rust_core::{ExecutionMode, NetContext, NetError, NetResult, OfflineConfig};

pub const MAX_CAPTURE_PACKET_BYTES: usize = 16 * 1024 * 1024; // 16 MiB OOM guard

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkType {
    Null,              // DLT_NULL = 0
    Ethernet,          // DLT_EN10MB = 1
    RawIp,             // DLT_RAW = 101
    Ieee80211,         // DLT_IEEE802_11 = 105
    LinuxSll,          // DLT_LINUX_SLL = 113
    Ieee80211Radiotap, // DLT_IEEE802_11_RADIO = 127
    Ipv4,              // DLT_IPV4 = 228
    Ipv6,              // DLT_IPV6 = 229
    Other(u32),
}

impl LinkType {
    pub const fn to_u32(self) -> u32 {
        match self {
            Self::Null => 0,
            Self::Ethernet => 1,
            Self::RawIp => 101,
            Self::Ieee80211 => 105,
            Self::LinuxSll => 113,
            Self::Ieee80211Radiotap => 127,
            Self::Ipv4 => 228,
            Self::Ipv6 => 229,
            Self::Other(v) => v,
        }
    }
}

impl From<u32> for LinkType {
    fn from(raw: u32) -> Self {
        match raw {
            0 => Self::Null,
            1 => Self::Ethernet,
            101 => Self::RawIp,
            105 => Self::Ieee80211,
            113 => Self::LinuxSll,
            127 => Self::Ieee80211Radiotap,
            228 => Self::Ipv4,
            229 => Self::Ipv6,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureBackend {
    PcapFile,
    PcapngFile,
    EtlFile,
    SyntheticEtl,
    SyntheticFixture,
    NdisEtwLive,
    NpcapLive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedPacket {
    pub packet_no: u64,
    pub timestamp: Option<DateTime<Utc>>,
    pub link_type: LinkType,
    pub original_len: u32,
    pub interface_id: Option<u32>,
    pub interface_name: Option<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureRequest {
    pub interface: Option<String>,
    pub max_packets: Option<usize>,
    pub snaplen: u32,
    pub promiscuous: bool,
    pub monitor_mode: bool,
    pub prefer_npcap: bool,
}

impl Default for CaptureRequest {
    fn default() -> Self {
        Self {
            interface: None,
            max_packets: None,
            snaplen: 65535,
            promiscuous: true,
            monitor_mode: false,
            prefer_npcap: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureResult {
    pub backend: CaptureBackend,
    pub packets: Vec<CapturedPacket>,
}

pub trait PacketSource {
    fn backend(&self) -> CaptureBackend;
    fn read_packets(&mut self, max_packets: Option<usize>) -> NetResult<Vec<CapturedPacket>>;
}

fn load_pcap_or_pcapng_file(path: &Path) -> NetResult<CaptureResult> {
    let bytes = std::fs::read(path)?;
    if bytes.len() < 4 {
        return Err(NetError::ParseError(format!(
            "capture file '{}' is too short ({} bytes)",
            path.display(),
            bytes.len()
        )));
    }
    let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if pcapng::is_pcapng_magic(magic) {
        let packets = pcapng::parse_pcapng(&bytes)?;
        Ok(CaptureResult {
            backend: CaptureBackend::PcapngFile,
            packets,
        })
    } else if pcap::is_pcap_magic(magic) {
        let (_hdr, packets) = pcap::parse_pcap(&bytes)?;
        Ok(CaptureResult {
            backend: CaptureBackend::PcapFile,
            packets,
        })
    } else {
        Err(NetError::ParseError(format!(
            "unrecognized capture file magic {:02x}{:02x}{:02x}{:02x} in '{}'",
            magic[0],
            magic[1],
            magic[2],
            magic[3],
            path.display()
        )))
    }
}

fn load_etl_file(path: &Path, max_packets: Option<usize>) -> NetResult<CaptureResult> {
    let bytes = std::fs::read(path)?;
    if etw_ndis::is_synthetic_etl(&bytes) {
        let mut packets = etw_ndis::parse_synthetic_etl(&bytes)?;
        if let Some(cap) = max_packets {
            packets.truncate(cap);
        }
        Ok(CaptureResult {
            backend: CaptureBackend::SyntheticEtl,
            packets,
        })
    } else {
        let packets = etw_ndis::read_native_etl_file(path, max_packets)?;
        Ok(CaptureResult {
            backend: CaptureBackend::EtlFile,
            packets,
        })
    }
}

fn load_from_fixture_dir(dir: &Path, cfg: &OfflineConfig, max_packets: Option<usize>) -> NetResult<CaptureResult> {
    if !dir.exists() {
        return Err(NetError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("fixture_dir '{}' does not exist", dir.display()),
        )));
    }

    let mut candidates: Vec<String> = Vec::new();
    if let Some(ref scenario) = cfg.scenario {
        candidates.push(format!("{scenario}.pcapng"));
        candidates.push(format!("{scenario}.pcap"));
        candidates.push(format!("{scenario}.etl"));
    }
    candidates.extend([
        "capture.pcapng".to_string(),
        "capture.pcap".to_string(),
        "capture.etl".to_string(),
    ]);

    for name in candidates {
        let candidate = dir.join(&name);
        if candidate.is_file() {
            if name.ends_with(".etl") {
                return load_etl_file(&candidate, max_packets);
            }
            return load_pcap_or_pcapng_file(&candidate);
        }
    }

    Ok(CaptureResult {
        backend: CaptureBackend::SyntheticFixture,
        packets: fixtures::build_default_fixture_packets(cfg.scenario.as_deref()),
    })
}

fn acquire_offline(cfg: &OfflineConfig, req: &CaptureRequest) -> NetResult<CaptureResult> {
    let mut res = if let Some(ref pcap_path) = cfg.pcap_path {
        load_pcap_or_pcapng_file(pcap_path)?
    } else if let Some(ref etl_path) = cfg.etl_path {
        load_etl_file(etl_path, req.max_packets)?
    } else if let Some(ref fixture_dir) = cfg.fixture_dir {
        load_from_fixture_dir(fixture_dir, cfg, req.max_packets)?
    } else {
        CaptureResult {
            backend: CaptureBackend::SyntheticFixture,
            packets: fixtures::build_default_fixture_packets(cfg.scenario.as_deref()),
        }
    };

    if let Some(cap) = req.max_packets {
        res.packets.truncate(cap);
    }
    Ok(res)
}

fn acquire_live(ctx: &NetContext, req: &CaptureRequest) -> NetResult<CaptureResult> {
    if req.monitor_mode {
        if !ctx.allow_npcap {
            return Err(NetError::DriverUnavailable(
                "Npcap is disabled (allow_npcap = false); 802.11 monitor mode requires Npcap (wpcap.dll)".to_string(),
            ));
        }
        let mut packets = wpcap::capture_live(req, ctx.timeout)?;
        if let Some(cap) = req.max_packets {
            packets.truncate(cap);
        }
        return Ok(CaptureResult {
            backend: CaptureBackend::NpcapLive,
            packets,
        });
    }

    if req.prefer_npcap && ctx.allow_npcap {
        match wpcap::capture_live(req, ctx.timeout) {
            Ok(mut packets) => {
                if let Some(cap) = req.max_packets {
                    packets.truncate(cap);
                }
                return Ok(CaptureResult {
                    backend: CaptureBackend::NpcapLive,
                    packets,
                });
            }
            Err(NetError::DriverUnavailable(_)) => {}
            Err(err) => return Err(err),
        }
    }

    match etw_ndis::capture_live(req, ctx.timeout) {
        Ok(mut packets) => {
            if let Some(cap) = req.max_packets {
                packets.truncate(cap);
            }
            Ok(CaptureResult {
                backend: CaptureBackend::NdisEtwLive,
                packets,
            })
        }
        Err(etw_err) => {
            if ctx.allow_npcap
                && matches!(
                    etw_err,
                    NetError::PermissionDenied(_) | NetError::DriverUnavailable(_) | NetError::NotSupported(_)
                )
                && let Ok(mut packets) = wpcap::capture_live(req, ctx.timeout)
            {
                if let Some(cap) = req.max_packets {
                    packets.truncate(cap);
                }
                return Ok(CaptureResult {
                    backend: CaptureBackend::NpcapLive,
                    packets,
                });
            }
            Err(etw_err)
        }
    }
}

pub fn capture_with_backend(ctx: &NetContext, req: &CaptureRequest) -> NetResult<CaptureResult> {
    match &ctx.mode {
        ExecutionMode::Offline(cfg) => acquire_offline(cfg, req),
        ExecutionMode::Live => acquire_live(ctx, req),
    }
}

pub fn capture_packets(ctx: &NetContext, req: &CaptureRequest) -> NetResult<Vec<CapturedPacket>> {
    Ok(capture_with_backend(ctx, req)?.packets)
}
