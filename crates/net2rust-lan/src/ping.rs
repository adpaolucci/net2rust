use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use net2rust_core::{NetContext, NetError, NetResult};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::common::run_bounded;
use crate::fixtures;
use crate::resolve::{DnsBackend, LiveWinSockDnsBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PingStatus {
    Succeeded,
    TimedOut,
    TtlExpired,
    Failed,
}

impl PingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "Succeeded",
            Self::TimedOut => "Timed Out",
            Self::TtlExpired => "TTL Expired",
            Self::Failed => "Failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PingProbeResult {
    pub responder: Option<IpAddr>,
    pub status: PingStatus,
    pub rtt_ms: Option<f64>,
    pub ttl: Option<u8>,
    pub error_detail: Option<String>,
}

pub trait PingBackend: Send + Sync {
    fn ping_icmp(
        &self,
        target: IpAddr,
        timeout: Duration,
        ttl: Option<u8>,
        payload: &[u8],
    ) -> NetResult<PingProbeResult>;

    fn ping_tcp(&self, target: IpAddr, port: u16, timeout: Duration) -> NetResult<PingProbeResult>;
}

#[derive(Debug, Default)]
pub struct LivePingBackend;

impl PingBackend for LivePingBackend {
    fn ping_icmp(
        &self,
        target: IpAddr,
        timeout: Duration,
        ttl: Option<u8>,
        payload: &[u8],
    ) -> NetResult<PingProbeResult> {
        #[cfg(windows)]
        {
            match target {
                IpAddr::V4(v4) => win32_icmp::ping_icmp_v4(v4, timeout, ttl, payload),
                IpAddr::V6(v6) => win32_icmp::ping_icmp_v6(v6, timeout, ttl, payload),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = (target, timeout, ttl, payload);
            Err(NetError::NotSupported(
                "Win32 ICMP Echo requires Windows; use TCP connect fallback".into(),
            ))
        }
    }

    fn ping_tcp(&self, target: IpAddr, port: u16, timeout: Duration) -> NetResult<PingProbeResult> {
        let addr = SocketAddr::new(target, port);
        let started = Instant::now();
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(_stream) => {
                let rtt_ms = started.elapsed().as_secs_f64() * 1000.0;
                Ok(PingProbeResult {
                    responder: Some(target),
                    status: PingStatus::Succeeded,
                    rtt_ms: Some(rtt_ms),
                    ttl: None,
                    error_detail: None,
                })
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                Ok(PingProbeResult {
                    responder: None,
                    status: PingStatus::TimedOut,
                    rtt_ms: None,
                    ttl: None,
                    error_detail: Some(err.to_string()),
                })
            }
            Err(err) => Ok(PingProbeResult {
                responder: None,
                status: PingStatus::Failed,
                rtt_ms: None,
                ttl: None,
                error_detail: Some(err.to_string()),
            }),
        }
    }
}

#[cfg(windows)]
mod win32_icmp {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::ptr;
    use std::time::Duration;

    use net2rust_core::{NetError, NetResult};
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, GetLastError, HANDLE};
    use windows::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, IP_DEST_HOST_UNREACHABLE, IP_DEST_NET_UNREACHABLE,
        IP_OPTION_INFORMATION, IP_REQ_TIMED_OUT, IP_SUCCESS, IP_TTL_EXPIRED_REASSEM, IP_TTL_EXPIRED_TRANSIT,
        Icmp6CreateFile, Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2,
    };
    use windows::Win32::Networking::WinSock::{AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6};

    use super::{PingProbeResult, PingStatus};
    use crate::common::{ipv4_to_win32_u32, win32_u32_to_ipv4};

    struct IcmpHandle(HANDLE);
    impl Drop for IcmpHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: `self.0` was opened by `IcmpCreateFile` or `Icmp6CreateFile`.
                let _ = unsafe { IcmpCloseHandle(self.0) };
            }
        }
    }

    pub fn ping_icmp_v4(
        target: Ipv4Addr,
        timeout: Duration,
        ttl: Option<u8>,
        payload: &[u8],
    ) -> NetResult<PingProbeResult> {
        // SAFETY: Opens a standard Win32 ICMPv4 handle.
        let handle = unsafe { IcmpCreateFile() }.map_err(|e| {
            if e.code() == ERROR_ACCESS_DENIED.to_hresult() {
                NetError::PermissionDenied(format!("IcmpCreateFile denied: {e}"))
            } else {
                NetError::NetworkError(format!("IcmpCreateFile failed: {e}"))
            }
        })?;
        let handle = IcmpHandle(handle);

        let opt = ttl.map(|t| IP_OPTION_INFORMATION {
            Ttl: t,
            ..Default::default()
        });
        let opt_ptr = opt.as_ref().map(|o| o as *const IP_OPTION_INFORMATION);

        let reply_bytes = size_of::<ICMP_ECHO_REPLY>() + payload.len().max(32) + 64;
        let mut reply_buf = vec![0u64; reply_bytes.div_ceil(8)];
        let timeout_ms = timeout.as_millis().clamp(1, u32::MAX as u128) as u32;
        let req_ptr = if payload.is_empty() {
            ptr::null()
        } else {
            payload.as_ptr().cast::<c_void>()
        };
        let req_len = u16::try_from(payload.len()).unwrap_or(u16::MAX);

        // SAFETY: Synchronous `IcmpSendEcho2` with 8-byte aligned `reply_buf` and valid `handle`.
        let count = unsafe {
            IcmpSendEcho2(
                handle.0,
                None,
                None,
                None,
                ipv4_to_win32_u32(target),
                req_ptr,
                req_len,
                opt_ptr,
                reply_buf.as_mut_ptr().cast::<c_void>(),
                (reply_buf.len() * 8) as u32,
                timeout_ms,
            )
        };

        if count == 0 {
            // SAFETY: Reads thread-local Win32 error set by `IcmpSendEcho2`.
            let err = unsafe { GetLastError() };
            if err.0 == IP_REQ_TIMED_OUT {
                return Ok(PingProbeResult {
                    responder: None,
                    status: PingStatus::TimedOut,
                    rtt_ms: None,
                    ttl: None,
                    error_detail: Some("IP_REQ_TIMED_OUT".into()),
                });
            }
            if err.0 == ERROR_ACCESS_DENIED.0 {
                return Err(NetError::PermissionDenied(
                    "IcmpSendEcho2 denied by local policy or privileges".into(),
                ));
            }
            return Ok(PingProbeResult {
                responder: None,
                status: PingStatus::Failed,
                rtt_ms: None,
                ttl: None,
                error_detail: Some(format!("IcmpSendEcho2 failed with Win32 error {}", err.0)),
            });
        }

        // SAFETY: `count > 0` guarantees `reply_buf` holds at least one `ICMP_ECHO_REPLY`.
        let reply: ICMP_ECHO_REPLY = unsafe { ptr::read_unaligned(reply_buf.as_ptr().cast::<ICMP_ECHO_REPLY>()) };
        let responder = Some(IpAddr::V4(win32_u32_to_ipv4(reply.Address)));
        let (status, rtt_ms, detail) = map_icmp_status(reply.Status, reply.RoundTripTime);
        Ok(PingProbeResult {
            responder,
            status,
            rtt_ms,
            ttl: Some(reply.Options.Ttl),
            error_detail: detail,
        })
    }

    pub fn ping_icmp_v6(
        target: Ipv6Addr,
        timeout: Duration,
        ttl: Option<u8>,
        payload: &[u8],
    ) -> NetResult<PingProbeResult> {
        // SAFETY: Opens a standard Win32 ICMPv6 handle.
        let handle = unsafe { Icmp6CreateFile() }.map_err(|e| {
            if e.code() == ERROR_ACCESS_DENIED.to_hresult() {
                NetError::PermissionDenied(format!("Icmp6CreateFile denied: {e}"))
            } else {
                NetError::NetworkError(format!("Icmp6CreateFile failed: {e}"))
            }
        })?;
        let handle = IcmpHandle(handle);

        // SAFETY: `SOCKADDR_IN6` is plain C POD bytes.
        let mut src: SOCKADDR_IN6 = unsafe { zeroed() };
        src.sin6_family = AF_INET6;

        // SAFETY: `SOCKADDR_IN6` is plain C POD bytes.
        let mut dst: SOCKADDR_IN6 = unsafe { zeroed() };
        dst.sin6_family = AF_INET6;
        dst.sin6_addr = IN6_ADDR {
            u: IN6_ADDR_0 { Byte: target.octets() },
        };

        let opt = ttl.map(|t| IP_OPTION_INFORMATION {
            Ttl: t,
            ..Default::default()
        });
        let opt_ptr = opt.as_ref().map(|o| o as *const IP_OPTION_INFORMATION);

        let reply_bytes = size_of::<ICMPV6_ECHO_REPLY_LH>() + payload.len().max(32) + 64;
        let mut reply_buf = vec![0u64; reply_bytes.div_ceil(8)];
        let timeout_ms = timeout.as_millis().clamp(1, u32::MAX as u128) as u32;
        let req_ptr = if payload.is_empty() {
            ptr::null()
        } else {
            payload.as_ptr().cast::<c_void>()
        };
        let req_len = u16::try_from(payload.len()).unwrap_or(u16::MAX);

        // SAFETY: Synchronous `Icmp6SendEcho2` with valid source/dest `SOCKADDR_IN6` and 8-byte aligned buffer.
        let count = unsafe {
            Icmp6SendEcho2(
                handle.0,
                None,
                None,
                None,
                &raw const src,
                &raw const dst,
                req_ptr,
                req_len,
                opt_ptr,
                reply_buf.as_mut_ptr().cast::<c_void>(),
                (reply_buf.len() * 8) as u32,
                timeout_ms,
            )
        };

        if count == 0 {
            // SAFETY: Reads thread-local Win32 error set by `Icmp6SendEcho2`.
            let err = unsafe { GetLastError() };
            if err.0 == IP_REQ_TIMED_OUT {
                return Ok(PingProbeResult {
                    responder: None,
                    status: PingStatus::TimedOut,
                    rtt_ms: None,
                    ttl: None,
                    error_detail: Some("IP_REQ_TIMED_OUT".into()),
                });
            }
            if err.0 == ERROR_ACCESS_DENIED.0 {
                return Err(NetError::PermissionDenied(
                    "Icmp6SendEcho2 denied by local policy or privileges".into(),
                ));
            }
            return Ok(PingProbeResult {
                responder: None,
                status: PingStatus::Failed,
                rtt_ms: None,
                ttl: None,
                error_detail: Some(format!("Icmp6SendEcho2 failed with Win32 error {}", err.0)),
            });
        }

        // SAFETY: `count > 0` guarantees `reply_buf` holds at least one `ICMPV6_ECHO_REPLY_LH`.
        let reply: ICMPV6_ECHO_REPLY_LH =
            unsafe { ptr::read_unaligned(reply_buf.as_ptr().cast::<ICMPV6_ECHO_REPLY_LH>()) };
        // Copy packed `sin6_addr` by value to avoid Rust 2024 E0793 unaligned reference error.
        let words: [u16; 8] = reply.Address.sin6_addr;
        let mut octets = [0u8; 16];
        for (i, word) in words.iter().enumerate() {
            let b = word.to_ne_bytes();
            octets[i * 2] = b[0];
            octets[i * 2 + 1] = b[1];
        }
        let responder = Some(IpAddr::V6(Ipv6Addr::from(octets)));
        let (status, rtt_ms, detail) = map_icmp_status(reply.Status, reply.RoundTripTime);
        Ok(PingProbeResult {
            responder,
            status,
            rtt_ms,
            ttl: None,
            error_detail: detail,
        })
    }

    fn map_icmp_status(code: u32, rtt_raw: u32) -> (PingStatus, Option<f64>, Option<String>) {
        if code == IP_SUCCESS {
            (PingStatus::Succeeded, Some(rtt_raw as f64), None)
        } else if code == IP_REQ_TIMED_OUT {
            (PingStatus::TimedOut, None, Some("IP_REQ_TIMED_OUT".into()))
        } else if code == IP_TTL_EXPIRED_TRANSIT || code == IP_TTL_EXPIRED_REASSEM {
            (
                PingStatus::TtlExpired,
                Some(rtt_raw as f64),
                Some(format!("ICMP status {code}")),
            )
        } else if code == IP_DEST_NET_UNREACHABLE || code == IP_DEST_HOST_UNREACHABLE {
            (
                PingStatus::Failed,
                None,
                Some(format!("Destination unreachable ({code})")),
            )
        } else {
            (PingStatus::Failed, None, Some(format!("ICMP status {code}")))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingTargetSpec {
    pub host: String,
    pub tcp_port: Option<u16>,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingSummaryRecord {
    pub host: String,
    pub ip: Option<IpAddr>,
    pub protocol: String,
    pub port: Option<u64>,
    pub status: String,
    pub rtt_ms: Option<f64>,
    pub min_rtt_ms: Option<f64>,
    pub avg_rtt_ms: Option<f64>,
    pub max_rtt_ms: Option<f64>,
    pub sent: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub loss_pct: f64,
    pub ttl: Option<u64>,
    pub last_checked: DateTime<Utc>,
}

/// Pure-Rust ping probe statistics aggregator.
pub fn aggregate_ping_probes(
    host: &str,
    ip: Option<IpAddr>,
    protocol: &str,
    port: Option<u16>,
    probes: &[PingProbeResult],
    checked_at: DateTime<Utc>,
) -> PingSummaryRecord {
    let sent = probes.len() as u64;
    let mut succeeded = 0u64;
    let mut rtts = Vec::new();
    let mut last_status = PingStatus::Failed;
    let mut last_rtt = None;
    let mut last_ttl = None;

    for probe in probes {
        last_status = probe.status;
        if probe.status == PingStatus::Succeeded {
            succeeded += 1;
            if let Some(ms) = probe.rtt_ms {
                rtts.push(ms);
                last_rtt = Some(ms);
            }
            if let Some(t) = probe.ttl {
                last_ttl = Some(t as u64);
            }
        }
    }

    let failed = sent.saturating_sub(succeeded);
    let loss_pct = if sent == 0 {
        0.0
    } else {
        (failed as f64 / sent as f64) * 100.0
    };
    let min_rtt_ms = rtts.iter().copied().reduce(f64::min);
    let max_rtt_ms = rtts.iter().copied().reduce(f64::max);
    let avg_rtt_ms = if rtts.is_empty() {
        None
    } else {
        Some(rtts.iter().sum::<f64>() / rtts.len() as f64)
    };

    PingSummaryRecord {
        host: host.to_string(),
        ip,
        protocol: protocol.to_string(),
        port: port.map(u64::from),
        status: last_status.as_str().to_string(),
        rtt_ms: last_rtt,
        min_rtt_ms,
        avg_rtt_ms,
        max_rtt_ms,
        sent,
        succeeded,
        failed,
        loss_pct,
        ttl: last_ttl,
        last_checked: checked_at,
    }
}

pub struct PingInfoViewProvider {
    ctx: NetContext,
    targets: Vec<PingTargetSpec>,
    custom_targets: bool,
    backend: Arc<dyn PingBackend>,
    dns: Arc<dyn DnsBackend>,
}

impl PingInfoViewProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self {
            ctx,
            targets: vec![
                PingTargetSpec {
                    host: "127.0.0.1".into(),
                    tcp_port: None,
                    count: 2,
                },
                PingTargetSpec {
                    host: "::1".into(),
                    tcp_port: None,
                    count: 2,
                },
            ],
            custom_targets: false,
            backend: Arc::new(LivePingBackend),
            dns: Arc::new(LiveWinSockDnsBackend),
        }
    }

    pub fn with_targets(mut self, targets: Vec<PingTargetSpec>) -> Self {
        self.targets = targets;
        self.custom_targets = true;
        self
    }

    pub fn with_backends(mut self, backend: Arc<dyn PingBackend>, dns: Arc<dyn DnsBackend>) -> Self {
        self.backend = backend;
        self.dns = dns;
        self
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "lan.ping",
            "PingInfoView — Ping Monitor",
            vec![
                ColumnDef::new("host", "Host", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("ip", "IP Address", ColumnType::IpAddr).with_width_hint(130),
                ColumnDef::new("protocol", "Protocol", ColumnType::Text).with_width_hint(80),
                ColumnDef::new("port", "Port", ColumnType::Uint).with_width_hint(70),
                ColumnDef::new("status", "Status", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("rtt_ms", "Last RTT (ms)", ColumnType::Float).with_width_hint(100),
                ColumnDef::new("min_rtt_ms", "Min RTT (ms)", ColumnType::Float).with_width_hint(100),
                ColumnDef::new("avg_rtt_ms", "Avg RTT (ms)", ColumnType::Float).with_width_hint(100),
                ColumnDef::new("max_rtt_ms", "Max RTT (ms)", ColumnType::Float).with_width_hint(100),
                ColumnDef::new("sent", "Sent", ColumnType::Uint).with_width_hint(70),
                ColumnDef::new("succeeded", "Succeeded", ColumnType::Uint).with_width_hint(90),
                ColumnDef::new("failed", "Failed", ColumnType::Uint).with_width_hint(70),
                ColumnDef::new("loss_pct", "Loss %", ColumnType::Float).with_width_hint(80),
                ColumnDef::new("ttl", "TTL", ColumnType::Uint).with_width_hint(60),
                ColumnDef::new("last_checked", "Last Checked", ColumnType::Timestamp).with_width_hint(170),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn probe_target(&self, spec: &PingTargetSpec) -> PingSummaryRecord {
        let now = Utc::now();
        let resolved_ip = if let Ok(ip) = spec.host.trim().parse::<IpAddr>() {
            Some(ip)
        } else {
            self.dns
                .forward_lookup(&spec.host)
                .ok()
                .and_then(|ips| ips.into_iter().next())
        };

        let Some(ip) = resolved_ip else {
            return PingSummaryRecord {
                host: spec.host.clone(),
                ip: None,
                protocol: if spec.tcp_port.is_some() { "TCP" } else { "ICMP" }.to_string(),
                port: spec.tcp_port.map(u64::from),
                status: "Failed".to_string(),
                rtt_ms: None,
                min_rtt_ms: None,
                avg_rtt_ms: None,
                max_rtt_ms: None,
                sent: spec.count.max(1) as u64,
                succeeded: 0,
                failed: spec.count.max(1) as u64,
                loss_pct: 100.0,
                ttl: None,
                last_checked: now,
            };
        };

        let timeout = self.ctx.timeout.min(Duration::from_secs(2));
        let count = spec.count.clamp(1, 16);
        let mut results = Vec::with_capacity(count as usize);
        let mut used_protocol = match (spec.tcp_port, ip) {
            (Some(_), _) => "TCP",
            (None, IpAddr::V4(_)) => "ICMP",
            (None, IpAddr::V6(_)) => "ICMPv6",
        };

        for _ in 0..count {
            if let Some(port) = spec.tcp_port {
                let res = self.backend.ping_tcp(ip, port, timeout).unwrap_or(PingProbeResult {
                    responder: None,
                    status: PingStatus::Failed,
                    rtt_ms: None,
                    ttl: None,
                    error_detail: None,
                });
                results.push(res);
            } else {
                match self.backend.ping_icmp(ip, timeout, None, b"GUAP-PING") {
                    Ok(res) => results.push(res),
                    Err(NetError::PermissionDenied(_)) | Err(NetError::NotSupported(_)) => {
                        used_protocol = "TCP";
                        let res = self.backend.ping_tcp(ip, 80, timeout).unwrap_or(PingProbeResult {
                            responder: None,
                            status: PingStatus::Failed,
                            rtt_ms: None,
                            ttl: None,
                            error_detail: None,
                        });
                        results.push(res);
                    }
                    Err(err) => results.push(PingProbeResult {
                        responder: None,
                        status: PingStatus::Failed,
                        rtt_ms: None,
                        ttl: None,
                        error_detail: Some(err.to_string()),
                    }),
                }
            }
        }

        let effective_port = if used_protocol == "TCP" {
            Some(spec.tcp_port.unwrap_or(80))
        } else {
            None
        };
        aggregate_ping_probes(&spec.host, Some(ip), used_protocol, effective_port, &results, now)
    }

    fn collect_records(&self) -> NetResult<Vec<PingSummaryRecord>> {
        if self.ctx.is_offline() && !self.custom_targets {
            return fixtures::load_ping_records(&self.ctx);
        }
        Ok(run_bounded(&self.targets, 16, |spec| self.probe_target(spec)))
    }
}

impl TableProvider for PingInfoViewProvider {
    fn tool_id(&self) -> &'static str {
        "lan.ping"
    }

    fn description(&self) -> &'static str {
        "Monitor host reachability and RTT statistics via ICMP/ICMPv6 or TCP connect (PingInfoView)"
    }

    fn schema(&self) -> TableSchema {
        Self::schema_def()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let schema = Self::schema_def();
        let mut records = self.collect_records()?;
        self.ctx.apply_row_limit(&mut records);

        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, rec)| {
                let opt_f64 = |v: Option<f64>| v.map(CellValue::Float).unwrap_or(CellValue::Null);
                let detail = json!({
                    "host": rec.host,
                    "ip": rec.ip.map(|ip| ip.to_string()),
                    "protocol": rec.protocol,
                    "port": rec.port,
                    "status": rec.status,
                    "loss_pct": rec.loss_pct,
                });
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.host),
                        rec.ip
                            .map(|ip| CellValue::Text(ip.to_string()))
                            .unwrap_or(CellValue::Null),
                        CellValue::Text(rec.protocol),
                        rec.port.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        CellValue::Text(rec.status),
                        opt_f64(rec.rtt_ms),
                        opt_f64(rec.min_rtt_ms),
                        opt_f64(rec.avg_rtt_ms),
                        opt_f64(rec.max_rtt_ms),
                        CellValue::Uint(rec.sent),
                        CellValue::Uint(rec.succeeded),
                        CellValue::Uint(rec.failed),
                        CellValue::Float(rec.loss_pct),
                        rec.ttl.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        CellValue::Timestamp(rec.last_checked),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        apply_query(&schema, &rows, req)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    struct MockPingBackend;
    impl PingBackend for MockPingBackend {
        fn ping_icmp(
            &self,
            target: IpAddr,
            _timeout: Duration,
            _ttl: Option<u8>,
            _payload: &[u8],
        ) -> NetResult<PingProbeResult> {
            match target {
                IpAddr::V4(ip) if ip == Ipv4Addr::new(192, 0, 2, 1) => Ok(PingProbeResult {
                    responder: Some(target),
                    status: PingStatus::Succeeded,
                    rtt_ms: Some(2.5),
                    ttl: Some(64),
                    error_detail: None,
                }),
                IpAddr::V4(ip) if ip == Ipv4Addr::new(192, 0, 2, 2) => {
                    Err(NetError::PermissionDenied("icmp blocked".into()))
                }
                _ => Ok(PingProbeResult {
                    responder: None,
                    status: PingStatus::TimedOut,
                    rtt_ms: None,
                    ttl: None,
                    error_detail: Some("timeout".into()),
                }),
            }
        }

        fn ping_tcp(&self, target: IpAddr, _port: u16, _timeout: Duration) -> NetResult<PingProbeResult> {
            Ok(PingProbeResult {
                responder: Some(target),
                status: PingStatus::Succeeded,
                rtt_ms: Some(4.0),
                ttl: None,
                error_detail: None,
            })
        }
    }

    struct MockDns;
    impl DnsBackend for MockDns {
        fn forward_lookup(&self, _host: &str) -> NetResult<Vec<IpAddr>> {
            Ok(Vec::new())
        }
        fn reverse_lookup(&self, _ip: IpAddr) -> NetResult<Option<String>> {
            Ok(None)
        }
    }

    #[test]
    fn test_ping_stats_and_tcp_fallback() {
        let probes = vec![
            PingProbeResult {
                responder: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                status: PingStatus::Succeeded,
                rtt_ms: Some(1.0),
                ttl: Some(64),
                error_detail: None,
            },
            PingProbeResult {
                responder: None,
                status: PingStatus::TimedOut,
                rtt_ms: None,
                ttl: None,
                error_detail: None,
            },
            PingProbeResult {
                responder: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                status: PingStatus::Succeeded,
                rtt_ms: Some(3.0),
                ttl: Some(64),
                error_detail: None,
            },
        ];
        let summary = aggregate_ping_probes(
            "localhost",
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "ICMP",
            None,
            &probes,
            Utc::now(),
        );
        assert_eq!(summary.sent, 3);
        assert_eq!(summary.succeeded, 2);
        assert_eq!(summary.failed, 1);
        assert!((summary.min_rtt_ms.unwrap() - 1.0).abs() < 1e-6);
        assert!((summary.avg_rtt_ms.unwrap() - 2.0).abs() < 1e-6);
        assert!((summary.max_rtt_ms.unwrap() - 3.0).abs() < 1e-6);
        assert!((summary.loss_pct - 33.333333).abs() < 0.01);

        // Provider with MockPingBackend tests ICMP success + PermissionDenied->TCP fallback + timeout
        let provider = PingInfoViewProvider::new(NetContext::live())
            .with_backends(Arc::new(MockPingBackend), Arc::new(MockDns))
            .with_targets(vec![
                PingTargetSpec {
                    host: "192.0.2.1".into(),
                    tcp_port: None,
                    count: 2,
                },
                PingTargetSpec {
                    host: "192.0.2.2".into(),
                    tcp_port: None,
                    count: 1,
                },
                PingTargetSpec {
                    host: "192.0.2.99".into(),
                    tcp_port: None,
                    count: 1,
                },
            ]);
        let data = provider.query(&TableQuery::default()).unwrap();
        assert_eq!(data.total_rows, 3);
        assert_eq!(data.rows[0].cells[2], CellValue::Text("ICMP".into()));
        assert_eq!(data.rows[0].cells[4], CellValue::Text("Succeeded".into()));
        assert_eq!(data.rows[1].cells[2], CellValue::Text("TCP".into()));
        assert_eq!(data.rows[1].cells[4], CellValue::Text("Succeeded".into()));
        assert_eq!(data.rows[2].cells[4], CellValue::Text("Timed Out".into()));

        // Custom targets starting with 127.0.0.1 (len 2) bypass default fixture shortcut.
        let custom_offline = PingInfoViewProvider::new(NetContext::offline(Default::default()))
            .with_backends(Arc::new(MockPingBackend), Arc::new(MockDns))
            .with_targets(vec![
                PingTargetSpec {
                    host: "127.0.0.1".into(),
                    tcp_port: None,
                    count: 1,
                },
                PingTargetSpec {
                    host: "192.0.2.1".into(),
                    tcp_port: None,
                    count: 1,
                },
            ]);
        let custom_data = custom_offline.query(&TableQuery::default()).unwrap();
        assert_eq!(custom_data.total_rows, 2);
        assert!(
            custom_data
                .rows
                .iter()
                .any(|r| r.cells[0] == CellValue::Text("192.0.2.1".into()))
        );
    }
}
