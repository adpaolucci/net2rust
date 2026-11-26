use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use guap_table::{CellValue, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query};
use net2rust_core::{ExecutionMode, NetContext, NetError, NetResult};
use serde_json::json;

use crate::diff::{AdapterSnapshot, CounterSnapshot, TcpDiffEngine, TcpLogEvent, diff_adapters, diff_counters};
use crate::etw_decode::{
    AppNetworkAccumulator, DnsLookupCorrelator, KernelNetDirection, LiveTcpUdpAccumulator, TcpErrorsCorrelator,
    decode_dns_client, decode_kernel_network, decode_tcpip,
};
use crate::model::{
    RawAdapterRow, RawInterfaceConfig, RawNeighborRow, RawPathRow, RawPortsBundle, RawRouteRow, tcp_state_name,
};
use crate::offline;
use crate::oui;
use crate::schema;

/// `Microsoft-Windows-Kernel-Network` (`{7DD42A49-5329-4832-8DFD-43D979153A88}`) keyword for IPv4 events.
pub const KERNEL_NETWORK_KEYWORD_IPV4: u64 = 0x10;
/// `Microsoft-Windows-Kernel-Network` (`{7DD42A49-5329-4832-8DFD-43D979153A88}`) keyword for IPv6 events.
pub const KERNEL_NETWORK_KEYWORD_IPV6: u64 = 0x20;
/// Combined `Microsoft-Windows-Kernel-Network` IPv4 + IPv6 keyword bitmask (`0x30`).
pub const KERNEL_NETWORK_KEYWORDS_ALL: u64 = KERNEL_NETWORK_KEYWORD_IPV4 | KERNEL_NETWORK_KEYWORD_IPV6;

#[cfg(windows)]
fn scaled_etw_raw_cap(max_rows: Option<usize>) -> Option<usize> {
    max_rows.map(|n| if n == 0 { 0 } else { n.saturating_mul(1024).max(25_000) })
}

fn opt_text(s: Option<String>) -> CellValue {
    match s {
        Some(v) if !v.is_empty() => CellValue::Text(v),
        _ => CellValue::Null,
    }
}

fn opt_bytes(v: Option<u64>) -> CellValue {
    v.map(CellValue::Bytes).unwrap_or(CellValue::Null)
}

fn opt_uint(v: Option<u64>) -> CellValue {
    v.map(CellValue::Uint).unwrap_or(CellValue::Null)
}

fn opt_float(v: Option<f64>) -> CellValue {
    v.map(CellValue::Float).unwrap_or(CellValue::Null)
}

pub fn build_all_providers(ctx: &NetContext) -> Vec<Arc<dyn TableProvider>> {
    vec![
        Arc::new(PortsProvider::new(ctx.clone())),
        Arc::new(TcpLogProvider::new(ctx.clone())),
        Arc::new(LiveWatchProvider::new(ctx.clone())),
        Arc::new(AppNetProvider::new(ctx.clone())),
        Arc::new(ProcTcpProvider::new(ctx.clone())),
        Arc::new(TcpErrorsProvider::new(ctx.clone())),
        Arc::new(DnsLogProvider::new(ctx.clone())),
        Arc::new(CountersProvider::new(ctx.clone())),
        Arc::new(AdapterWatchProvider::new(ctx.clone())),
        Arc::new(InterfacesProvider::new(ctx.clone())),
        Arc::new(RoutesProvider::new(ctx.clone())),
        Arc::new(NeighborsProvider::new(ctx.clone())),
        Arc::new(PathsProvider::new(ctx.clone())),
    ]
}

// 1. sockets.ports (CurrPorts)
pub struct PortsProvider {
    ctx: NetContext,
}

impl PortsProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }

    fn collect(&self) -> NetResult<RawPortsBundle> {
        match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => offline::load_ports_bundle(cfg),
            ExecutionMode::Live => {
                #[cfg(windows)]
                {
                    crate::win32_iphelper::query_ports_live(false)
                }
                #[cfg(not(windows))]
                {
                    Err(NetError::NotSupported(
                        "live port enumeration requires Windows".to_string(),
                    ))
                }
            }
        }
    }
}

impl TableProvider for PortsProvider {
    fn tool_id(&self) -> &'static str {
        schema::TOOL_ID_PORTS
    }

    fn description(&self) -> &'static str {
        "List active TCP/UDP listening and connected sockets with process metadata (CurrPorts)"
    }

    fn schema(&self) -> TableSchema {
        schema::schema_ports()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let bundle = self.collect()?;
        let mut rows = Vec::with_capacity(bundle.tcp.len() + bundle.udp.len());
        let mut next_id = 0u64;

        for t in bundle.tcp {
            let state_str = tcp_state_name(t.state_code);
            let detail = json!({
                "protocol": t.protocol,
                "pid": t.pid,
                "local": format!("{}:{}", t.local_addr, t.local_port),
                "remote": format!("{}:{}", t.remote_addr, t.remote_port),
                "state_code": t.state_code,
                "state": state_str,
                "process_path": t.process_path,
                "user_name": t.user_name,
            });
            rows.push(
                Row::new(
                    next_id,
                    vec![
                        opt_text(t.process_name),
                        CellValue::Uint(u64::from(t.pid)),
                        CellValue::Text(t.protocol),
                        CellValue::Text(t.local_addr.to_string()),
                        CellValue::Uint(u64::from(t.local_port)),
                        CellValue::Text(t.remote_addr.to_string()),
                        CellValue::Uint(u64::from(t.remote_port)),
                        CellValue::Text(state_str.to_string()),
                        opt_text(t.process_path),
                        opt_text(t.user_name),
                        t.created_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(detail),
            );
            next_id += 1;
        }

        for u in bundle.udp {
            let detail = json!({
                "protocol": u.protocol,
                "pid": u.pid,
                "local": format!("{}:{}", u.local_addr, u.local_port),
                "process_path": u.process_path,
                "user_name": u.user_name,
            });
            rows.push(
                Row::new(
                    next_id,
                    vec![
                        opt_text(u.process_name),
                        CellValue::Uint(u64::from(u.pid)),
                        CellValue::Text(u.protocol),
                        CellValue::Text(u.local_addr.to_string()),
                        CellValue::Uint(u64::from(u.local_port)),
                        CellValue::Null,
                        CellValue::Null,
                        CellValue::Null,
                        opt_text(u.process_path),
                        opt_text(u.user_name),
                        u.created_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(detail),
            );
            next_id += 1;
        }

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&self.schema(), &rows, req)
    }
}

// 2. sockets.tcplog (TcpLogView)
pub struct TcpLogProvider {
    ctx: NetContext,
    diff_engine: Arc<Mutex<TcpDiffEngine>>,
}

impl TcpLogProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self {
            ctx,
            diff_engine: Arc::new(Mutex::new(TcpDiffEngine::new())),
        }
    }

    fn collect(&self) -> NetResult<Vec<TcpLogEvent>> {
        match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => {
                let snapshots = offline::load_tcp_snapshots(cfg)?;
                Ok(TcpDiffEngine::diff_sequence(&snapshots))
            }
            ExecutionMode::Live => {
                #[cfg(windows)]
                {
                    let mut resolver = crate::win32_proc::ProcessResolver::new();
                    match crate::etw_net::capture_provider_window(
                        "tcplog",
                        crate::etw_net::kernel_network_guid(),
                        KERNEL_NETWORK_KEYWORDS_ALL,
                        self.ctx.timeout,
                        scaled_etw_raw_cap(self.ctx.max_rows),
                    ) {
                        Ok(raw_recs) => {
                            let mut events = Vec::new();
                            for rec in raw_recs {
                                if let Ok(ev) = decode_kernel_network(&rec) {
                                    let event_type = match ev.direction {
                                        KernelNetDirection::Connect | KernelNetDirection::Accept => Some("Open"),
                                        KernelNetDirection::Disconnect => Some("Close"),
                                        _ => None,
                                    };
                                    if let Some(et) = event_type {
                                        let meta = resolver.resolve(ev.pid);
                                        events.push(TcpLogEvent {
                                            event_time: ev.timestamp_utc,
                                            event_type: et.to_string(),
                                            local_addr: ev.local_addr,
                                            local_port: ev.local_port,
                                            remote_addr: ev.remote_addr,
                                            remote_port: ev.remote_port,
                                            state: if et == "Close" {
                                                "CLOSED".to_string()
                                            } else {
                                                "ESTABLISHED".to_string()
                                            },
                                            pid: ev.pid,
                                            process_name: meta.name,
                                        });
                                    }
                                }
                            }
                            Ok(events)
                        }
                        Err(NetError::PermissionDenied(_)) => {
                            // Graceful non-elevated degradation to GetExtendedTcpTable snapshot diffing.
                            let mut engine = self
                                .diff_engine
                                .lock()
                                .map_err(|_| NetError::Internal("tcplog diff mutex poisoned".to_string()))?;
                            let snap0 = crate::win32_iphelper::capture_tcp_snapshot_live(&mut resolver)?;
                            let mut events = engine.step(&snap0);

                            let poll_window = self.ctx.timeout.clamp(
                                std::time::Duration::from_millis(50),
                                std::time::Duration::from_millis(600),
                            );
                            let interval = poll_window / 2;
                            for _ in 0..2 {
                                std::thread::sleep(interval);
                                let snap_next = crate::win32_iphelper::capture_tcp_snapshot_live(&mut resolver)?;
                                events.extend(engine.step(&snap_next));
                            }
                            Ok(events)
                        }
                        Err(e) => Err(e),
                    }
                }
                #[cfg(not(windows))]
                {
                    Err(NetError::NotSupported("live tcplog requires Windows".to_string()))
                }
            }
        }
    }
}

impl TableProvider for TcpLogProvider {
    fn tool_id(&self) -> &'static str {
        schema::TOOL_ID_TCPLOG
    }

    fn description(&self) -> &'static str {
        "Track TCP open, close, and listen state transitions via snapshot diffing and ETW (TcpLogView)"
    }

    fn schema(&self) -> TableSchema {
        schema::schema_tcplog()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let events = self.collect()?;
        let mut rows: Vec<Row> = events
            .into_iter()
            .enumerate()
            .map(|(idx, ev)| {
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Timestamp(ev.event_time),
                        CellValue::Text(ev.event_type),
                        CellValue::Text(ev.local_addr.to_string()),
                        CellValue::Uint(u64::from(ev.local_port)),
                        CellValue::Text(ev.remote_addr.to_string()),
                        CellValue::Uint(u64::from(ev.remote_port)),
                        CellValue::Text(ev.state),
                        CellValue::Uint(u64::from(ev.pid)),
                        opt_text(ev.process_name),
                    ],
                )
            })
            .collect();
        self.ctx.apply_row_limit(&mut rows);
        apply_query(&self.schema(), &rows, req)
    }
}

// 3. sockets.live (LiveTcpUdpWatch)
pub struct LiveWatchProvider {
    ctx: NetContext,
}

impl LiveWatchProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

impl TableProvider for LiveWatchProvider {
    fn tool_id(&self) -> &'static str {
        schema::TOOL_ID_LIVE
    }

    fn description(&self) -> &'static str {
        "Observe live TCP/UDP byte and packet counters per socket tuple via Kernel-Network ETW (LiveTcpUdpWatch)"
    }

    fn schema(&self) -> TableSchema {
        schema::schema_live()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (records, is_offline) = match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => (offline::load_kernel_network_records(cfg)?, true),
            ExecutionMode::Live => {
                #[cfg(windows)]
                {
                    let recs = crate::etw_net::capture_provider_window(
                        "live",
                        crate::etw_net::kernel_network_guid(),
                        KERNEL_NETWORK_KEYWORDS_ALL,
                        self.ctx.timeout,
                        scaled_etw_raw_cap(self.ctx.max_rows),
                    )?;
                    (recs, false)
                }
                #[cfg(not(windows))]
                {
                    return Err(NetError::NotSupported("live Kernel-Network ETW requires Windows".to_string()).into());
                }
            }
        };

        let mut acc = LiveTcpUdpAccumulator::default();
        for rec in &records {
            if let Ok(ev) = decode_kernel_network(rec) {
                acc.ingest(&ev);
            }
        }
        let entries = acc.into_entries();

        #[cfg(windows)]
        let mut resolver = if !is_offline {
            Some(crate::win32_proc::ProcessResolver::new())
        } else {
            None
        };

        let mut rows: Vec<Row> = entries
            .into_iter()
            .enumerate()
            .map(|(idx, e)| {
                let pname = if is_offline {
                    offline::offline_process_name(e.pid)
                } else {
                    #[cfg(windows)]
                    {
                        resolver.as_mut().and_then(|r| r.resolve(e.pid).name)
                    }
                    #[cfg(not(windows))]
                    {
                        None
                    }
                };
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Timestamp(e.timestamp),
                        CellValue::Text(e.protocol),
                        CellValue::Text(e.local_addr.to_string()),
                        CellValue::Uint(u64::from(e.local_port)),
                        CellValue::Text(e.remote_addr.to_string()),
                        CellValue::Uint(u64::from(e.remote_port)),
                        CellValue::Uint(u64::from(e.pid)),
                        opt_text(pname),
                        CellValue::Bytes(e.sent_bytes),
                        CellValue::Bytes(e.recvd_bytes),
                        CellValue::Uint(e.send_packets),
                        CellValue::Uint(e.recv_packets),
                    ],
                )
            })
            .collect();

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&self.schema(), &rows, req)
    }
}

// 4. sockets.app-net (AppNetworkCounter)
pub struct AppNetProvider {
    ctx: NetContext,
}

impl AppNetProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

impl TableProvider for AppNetProvider {
    fn tool_id(&self) -> &'static str {
        schema::TOOL_ID_APP_NET
    }

    fn description(&self) -> &'static str {
        "Aggregate TCP/UDP sent and received traffic and throughput per process (AppNetworkCounter)"
    }

    fn schema(&self) -> TableSchema {
        schema::schema_app_net()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (records, is_offline) = match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => (offline::load_kernel_network_records(cfg)?, true),
            ExecutionMode::Live => {
                #[cfg(windows)]
                {
                    let recs = crate::etw_net::capture_provider_window(
                        "appnet",
                        crate::etw_net::kernel_network_guid(),
                        KERNEL_NETWORK_KEYWORDS_ALL,
                        self.ctx.timeout,
                        scaled_etw_raw_cap(self.ctx.max_rows),
                    )?;
                    (recs, false)
                }
                #[cfg(not(windows))]
                {
                    return Err(
                        NetError::NotSupported("live AppNetworkCounter ETW requires Windows".to_string()).into(),
                    );
                }
            }
        };

        let mut acc = AppNetworkAccumulator::default();
        for rec in &records {
            if let Ok(ev) = decode_kernel_network(rec) {
                acc.ingest(&ev);
            }
        }
        let entries = acc.into_entries();

        #[cfg(windows)]
        let mut resolver = if !is_offline {
            Some(crate::win32_proc::ProcessResolver::new())
        } else {
            None
        };

        let mut rows: Vec<Row> = entries
            .into_iter()
            .enumerate()
            .map(|(idx, e)| {
                let (pname, ppath) = if is_offline {
                    (
                        offline::offline_process_name(e.pid),
                        offline::offline_process_path(e.pid),
                    )
                } else {
                    #[cfg(windows)]
                    {
                        resolver
                            .as_mut()
                            .map(|r| {
                                let m = r.resolve(e.pid);
                                (m.name, m.path)
                            })
                            .unwrap_or((None, None))
                    }
                    #[cfg(not(windows))]
                    {
                        (None, None)
                    }
                };
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Uint(u64::from(e.pid)),
                        opt_text(pname),
                        opt_text(ppath),
                        CellValue::Bytes(e.tcp_sent_bytes),
                        CellValue::Bytes(e.tcp_recvd_bytes),
                        CellValue::Bytes(e.udp_sent_bytes),
                        CellValue::Bytes(e.udp_recvd_bytes),
                        CellValue::Uint(e.send_speed_bps),
                        CellValue::Uint(e.recv_speed_bps),
                    ],
                )
            })
            .collect();

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&self.schema(), &rows, req)
    }
}

// 5. sockets.proc-tcp (ProcessTCPSummary)
pub struct ProcTcpProvider {
    ctx: NetContext,
}

impl ProcTcpProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }

    fn collect(&self) -> NetResult<RawPortsBundle> {
        match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => offline::load_ports_bundle(cfg),
            ExecutionMode::Live => {
                #[cfg(windows)]
                {
                    crate::win32_iphelper::query_ports_live(true)
                }
                #[cfg(not(windows))]
                {
                    Err(NetError::NotSupported(
                        "live ProcessTCPSummary requires Windows".to_string(),
                    ))
                }
            }
        }
    }
}

#[derive(Default)]
struct ProcTcpAgg {
    process_name: Option<String>,
    established: u64,
    listen: u64,
    time_wait: u64,
    udp_endpoints: u64,
    bytes_sent: Option<u64>,
    bytes_recvd: Option<u64>,
}

impl TableProvider for ProcTcpProvider {
    fn tool_id(&self) -> &'static str {
        schema::TOOL_ID_PROC_TCP
    }

    fn description(&self) -> &'static str {
        "Summarize TCP connection states, UDP endpoints, and EStats byte totals per PID (ProcessTCPSummary)"
    }

    fn schema(&self) -> TableSchema {
        schema::schema_proc_tcp()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let bundle = self.collect()?;
        let mut per_pid: BTreeMap<u32, ProcTcpAgg> = BTreeMap::new();

        for t in bundle.tcp {
            let agg = per_pid.entry(t.pid).or_default();
            if agg.process_name.is_none() {
                agg.process_name = t.process_name;
            }
            match t.state_code {
                2 => agg.listen += 1,
                5 => agg.established += 1,
                11 => agg.time_wait += 1,
                _ => {}
            }
            if let Some(sent) = t.estats_bytes_sent {
                agg.bytes_sent = Some(agg.bytes_sent.unwrap_or(0).saturating_add(sent));
            }
            if let Some(recvd) = t.estats_bytes_recvd {
                agg.bytes_recvd = Some(agg.bytes_recvd.unwrap_or(0).saturating_add(recvd));
            }
        }

        for u in bundle.udp {
            let agg = per_pid.entry(u.pid).or_default();
            if agg.process_name.is_none() {
                agg.process_name = u.process_name;
            }
            agg.udp_endpoints += 1;
        }

        let mut rows: Vec<Row> = per_pid
            .into_iter()
            .enumerate()
            .map(|(idx, (pid, agg))| {
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Uint(u64::from(pid)),
                        opt_text(agg.process_name),
                        CellValue::Uint(agg.established),
                        CellValue::Uint(agg.listen),
                        CellValue::Uint(agg.time_wait),
                        CellValue::Uint(agg.udp_endpoints),
                        opt_bytes(agg.bytes_sent),
                        opt_bytes(agg.bytes_recvd),
                    ],
                )
            })
            .collect();

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&self.schema(), &rows, req)
    }
}

// 6. sockets.tcp-errors (TCPConnectProblemView)
pub struct TcpErrorsProvider {
    ctx: NetContext,
}

impl TcpErrorsProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

impl TableProvider for TcpErrorsProvider {
    fn tool_id(&self) -> &'static str {
        schema::TOOL_ID_TCP_ERRORS
    }

    fn description(&self) -> &'static str {
        "Monitor TCP connection failures, timeouts, resets, and retransmissions via TCPIP ETW (TCPConnectProblemView)"
    }

    fn schema(&self) -> TableSchema {
        schema::schema_tcp_errors()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (records, is_offline) = match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => (offline::load_tcpip_records(cfg)?, true),
            ExecutionMode::Live => {
                #[cfg(windows)]
                {
                    let recs = crate::etw_net::capture_provider_window(
                        "tcperr",
                        crate::etw_net::tcpip_guid(),
                        u64::MAX,
                        self.ctx.timeout,
                        scaled_etw_raw_cap(self.ctx.max_rows),
                    )?;
                    (recs, false)
                }
                #[cfg(not(windows))]
                {
                    return Err(NetError::NotSupported("live TCPIP ETW requires Windows".to_string()).into());
                }
            }
        };

        let mut correlator = TcpErrorsCorrelator::default();
        for rec in &records {
            if let Ok(ev) = decode_tcpip(rec) {
                correlator.ingest(&ev);
            }
        }
        let entries = correlator.into_entries();

        #[cfg(windows)]
        let mut resolver = if !is_offline {
            Some(crate::win32_proc::ProcessResolver::new())
        } else {
            None
        };

        let mut rows: Vec<Row> = entries
            .into_iter()
            .enumerate()
            .map(|(idx, e)| {
                let pname = if is_offline {
                    offline::offline_process_name(e.pid)
                } else {
                    #[cfg(windows)]
                    {
                        resolver.as_mut().and_then(|r| r.resolve(e.pid).name)
                    }
                    #[cfg(not(windows))]
                    {
                        None
                    }
                };
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Timestamp(e.timestamp),
                        CellValue::Uint(u64::from(e.pid)),
                        opt_text(pname),
                        CellValue::Uint(u64::from(e.local_port)),
                        CellValue::Text(e.remote_addr.to_string()),
                        CellValue::Uint(u64::from(e.remote_port)),
                        CellValue::Uint(e.attempt_count),
                        CellValue::Text(e.error_status),
                    ],
                )
            })
            .collect();

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&self.schema(), &rows, req)
    }
}

// 7. sockets.dns-log (DNSLookupView)
pub struct DnsLogProvider {
    ctx: NetContext,
}

impl DnsLogProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

impl TableProvider for DnsLogProvider {
    fn tool_id(&self) -> &'static str {
        schema::TOOL_ID_DNS_LOG
    }

    fn description(&self) -> &'static str {
        "Trace DNS client queries, responses, latencies, and local DNS resolver cache (DNSLookupView)"
    }

    fn schema(&self) -> TableSchema {
        schema::schema_dns_log()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (records, cache_entries, is_offline) = match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => {
                let (recs, cache) = offline::load_dns_client_records(cfg)?;
                (recs, cache, true)
            }
            ExecutionMode::Live => {
                #[cfg(windows)]
                {
                    let etw_res = crate::etw_net::capture_provider_window(
                        "dnslog",
                        crate::etw_net::dns_client_guid(),
                        u64::MAX,
                        self.ctx.timeout,
                        scaled_etw_raw_cap(self.ctx.max_rows),
                    );
                    let cache_res = crate::win32_dns::query_dns_cache_table();
                    match (etw_res, cache_res) {
                        (Ok(recs), Ok(cache)) => (recs, cache, false),
                        (Ok(recs), Err(_)) => (recs, Vec::new(), false),
                        (Err(_), Ok(cache)) if !cache.is_empty() => (Vec::new(), cache, false),
                        (Err(e), _) => return Err(e.into()),
                    }
                }
                #[cfg(not(windows))]
                {
                    return Err(NetError::NotSupported("live DNS-Client ETW requires Windows".to_string()).into());
                }
            }
        };

        let mut correlator = DnsLookupCorrelator::default();
        for rec in &records {
            if let Ok(ev) = decode_dns_client(rec) {
                correlator.ingest(&ev);
            }
        }
        let cache_ts = records.last().map(|r| r.timestamp_utc).unwrap_or_else(chrono::Utc::now);
        correlator.merge_cache_entries(&cache_entries, cache_ts);
        let entries = correlator.into_entries();

        #[cfg(windows)]
        let mut resolver = if !is_offline {
            Some(crate::win32_proc::ProcessResolver::new())
        } else {
            None
        };

        let mut rows: Vec<Row> = entries
            .into_iter()
            .enumerate()
            .map(|(idx, e)| {
                let pname = e.pid.and_then(|pid| {
                    if is_offline {
                        offline::offline_process_name(pid)
                    } else {
                        #[cfg(windows)]
                        {
                            resolver.as_mut().and_then(|r| r.resolve(pid).name)
                        }
                        #[cfg(not(windows))]
                        {
                            None
                        }
                    }
                });
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Timestamp(e.timestamp),
                        opt_uint(e.pid.map(u64::from)),
                        opt_text(pname),
                        CellValue::Text(e.query_name),
                        CellValue::Text(e.query_type),
                        CellValue::Text(e.status),
                        opt_text(e.result_records),
                        opt_uint(e.latency_ms),
                    ],
                )
            })
            .collect();

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&self.schema(), &rows, req)
    }
}

// 8. sockets.counters (NetworkCountersWatch)
pub struct CountersProvider {
    ctx: NetContext,
    start: Instant,
    prev: Arc<Mutex<Option<CounterSnapshot>>>,
}

impl CountersProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self {
            ctx,
            start: Instant::now(),
            prev: Arc::new(Mutex::new(None)),
        }
    }
}

impl TableProvider for CountersProvider {
    fn tool_id(&self) -> &'static str {
        schema::TOOL_ID_COUNTERS
    }

    fn description(&self) -> &'static str {
        "Inspect IPv4/IPv6, TCP, UDP, and ICMP protocol stack counters and per-second rates (NetworkCountersWatch)"
    }

    fn schema(&self) -> TableSchema {
        schema::schema_counters()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let counter_rows = match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => {
                let (prev, curr) = offline::load_counter_snapshots(cfg)?;
                diff_counters(prev.as_ref(), &curr)
            }
            ExecutionMode::Live => {
                #[cfg(windows)]
                {
                    let elapsed_ns = self.start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
                    let curr = crate::win32_iphelper::query_counters_snapshot_live(elapsed_ns)?;
                    let mut guard = self
                        .prev
                        .lock()
                        .map_err(|_| NetError::Internal("counters snapshot mutex poisoned".to_string()))?;
                    let res = diff_counters(guard.as_ref(), &curr);
                    *guard = Some(curr);
                    res
                }
                #[cfg(not(windows))]
                {
                    let _ = (&self.start, &self.prev);
                    return Err(NetError::NotSupported("live protocol counters require Windows".to_string()).into());
                }
            }
        };

        let mut rows: Vec<Row> = counter_rows
            .into_iter()
            .enumerate()
            .map(|(idx, r)| {
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Text(r.counter_group),
                        CellValue::Text(r.metric_name),
                        CellValue::Uint(r.value),
                        opt_float(r.delta_per_sec),
                    ],
                )
            })
            .collect();

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&self.schema(), &rows, req)
    }
}

// 9. sockets.adapter-watch (AdapterWatch)
pub struct AdapterWatchProvider {
    ctx: NetContext,
    start: Instant,
    prev: Arc<Mutex<Option<AdapterSnapshot>>>,
}

impl AdapterWatchProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self {
            ctx,
            start: Instant::now(),
            prev: Arc::new(Mutex::new(None)),
        }
    }
}

impl TableProvider for AdapterWatchProvider {
    fn tool_id(&self) -> &'static str {
        schema::TOOL_ID_ADAPTER_WATCH
    }

    fn description(&self) -> &'static str {
        "Monitor per-adapter link speed, byte totals, Rx/Tx throughput, errors, and discards (AdapterWatch)"
    }

    fn schema(&self) -> TableSchema {
        schema::schema_adapter_watch()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let watch_rows = match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => {
                let (prev, curr) = offline::load_adapter_snapshots(cfg)?;
                diff_adapters(prev.as_ref(), &curr)
            }
            ExecutionMode::Live => {
                #[cfg(windows)]
                {
                    let elapsed_ns = self.start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
                    let raw_rows: Vec<RawAdapterRow> = crate::win32_iphelper::query_adapters_if_table_live()?;
                    let curr = AdapterSnapshot {
                        captured_at_ns: elapsed_ns,
                        rows: raw_rows.into_iter().map(|r| (r.luid, r)).collect(),
                    };
                    let mut guard = self
                        .prev
                        .lock()
                        .map_err(|_| NetError::Internal("adapter snapshot mutex poisoned".to_string()))?;
                    let res = diff_adapters(guard.as_ref(), &curr);
                    *guard = Some(curr);
                    res
                }
                #[cfg(not(windows))]
                {
                    let _ = (&self.start, &self.prev, std::mem::size_of::<RawAdapterRow>());
                    return Err(NetError::NotSupported("live AdapterWatch requires Windows".to_string()).into());
                }
            }
        };

        let mut rows: Vec<Row> = watch_rows
            .into_iter()
            .enumerate()
            .map(|(idx, r)| {
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Text(r.adapter_name),
                        CellValue::Text(r.description),
                        CellValue::Text(r.media_state),
                        opt_uint(r.link_speed),
                        CellValue::Bytes(r.bytes_sent),
                        CellValue::Bytes(r.bytes_recvd),
                        opt_float(r.rx_rate_bps),
                        opt_float(r.tx_rate_bps),
                        CellValue::Uint(r.errors),
                        CellValue::Uint(r.discards),
                    ],
                )
            })
            .collect();

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&self.schema(), &rows, req)
    }
}

// 10. sockets.interfaces (NetworkInterfacesView)
pub struct InterfacesProvider {
    ctx: NetContext,
}

impl InterfacesProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }

    fn collect(&self) -> NetResult<Vec<RawInterfaceConfig>> {
        match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => offline::load_interfaces(cfg),
            ExecutionMode::Live => {
                #[cfg(windows)]
                {
                    crate::win32_iphelper::query_interfaces_live()
                }
                #[cfg(not(windows))]
                {
                    Err(NetError::NotSupported(
                        "live interface enumeration requires Windows".to_string(),
                    ))
                }
            }
        }
    }
}

impl TableProvider for InterfacesProvider {
    fn tool_id(&self) -> &'static str {
        schema::TOOL_ID_INTERFACES
    }

    fn description(&self) -> &'static str {
        "Enumerate network interface hardware, IP, gateway, DNS, and DHCP configuration (NetworkInterfacesView)"
    }

    fn schema(&self) -> TableSchema {
        schema::schema_interfaces()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.collect()?;
        let mut rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(idx, it)| {
                let ipv4 = (!it.ipv4.is_empty()).then(|| it.ipv4.join(", "));
                let ipv6 = (!it.ipv6.is_empty()).then(|| it.ipv6.join(", "));
                let gw = (!it.gateway.is_empty()).then(|| it.gateway.join(", "));
                let dns = (!it.dns_servers.is_empty()).then(|| it.dns_servers.join(", "));
                let detail = serde_json::to_value(&it).unwrap_or_default();
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Text(it.interface_name),
                        CellValue::Text(it.description),
                        CellValue::Text(it.guid),
                        it.mac_address
                            .map(|m| CellValue::Text(m.to_colon_string()))
                            .unwrap_or(CellValue::Null),
                        CellValue::Text(it.operational_status),
                        CellValue::Text(it.if_type),
                        opt_uint(it.speed_mbps),
                        opt_text(ipv4),
                        opt_text(ipv6),
                        opt_text(gw),
                        opt_text(dns),
                        CellValue::Bool(it.dhcp_enabled),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&self.schema(), &rows, req)
    }
}

// 11. sockets.routes (NetRouteView)
pub struct RoutesProvider {
    ctx: NetContext,
}

impl RoutesProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }

    fn collect(&self) -> NetResult<Vec<RawRouteRow>> {
        match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => offline::load_routes(cfg),
            ExecutionMode::Live => {
                #[cfg(windows)]
                {
                    crate::win32_iphelper::query_routes_live()
                }
                #[cfg(not(windows))]
                {
                    Err(NetError::NotSupported(
                        "live routing table enumeration requires Windows".to_string(),
                    ))
                }
            }
        }
    }
}

impl TableProvider for RoutesProvider {
    fn tool_id(&self) -> &'static str {
        schema::TOOL_ID_ROUTES
    }

    fn description(&self) -> &'static str {
        "Inspect and manage IPv4/IPv6 kernel routing table entries (NetRouteView)"
    }

    fn schema(&self) -> TableSchema {
        schema::schema_routes()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.collect()?;
        let mut rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(idx, r)| {
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Text(r.destination.to_string()),
                        CellValue::Uint(u64::from(r.prefix_length)),
                        CellValue::Text(r.next_hop.to_string()),
                        CellValue::Uint(u64::from(r.interface_index)),
                        opt_text(r.interface_alias),
                        CellValue::Uint(u64::from(r.metric)),
                        CellValue::Text(r.protocol),
                        // ColumnType::Duration in guap-table expects milliseconds.
                        CellValue::Uint(u64::from(r.age_secs).saturating_mul(1000)),
                    ],
                )
            })
            .collect();

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&self.schema(), &rows, req)
    }
}

// 12. sockets.neighbors (IPNeighborsView)
pub struct NeighborsProvider {
    ctx: NetContext,
}

impl NeighborsProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }

    fn collect(&self) -> NetResult<Vec<RawNeighborRow>> {
        match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => offline::load_neighbors(cfg),
            ExecutionMode::Live => {
                #[cfg(windows)]
                {
                    crate::win32_iphelper::query_neighbors_live()
                }
                #[cfg(not(windows))]
                {
                    Err(NetError::NotSupported(
                        "live IP neighbors enumeration requires Windows".to_string(),
                    ))
                }
            }
        }
    }
}

impl TableProvider for NeighborsProvider {
    fn tool_id(&self) -> &'static str {
        schema::TOOL_ID_NEIGHBORS
    }

    fn description(&self) -> &'static str {
        "Inspect ARP and IPv6 NDP neighbor cache entries with OUI vendor resolution (IPNeighborsView)"
    }

    fn schema(&self) -> TableSchema {
        schema::schema_neighbors()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.collect()?;
        let mut rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(idx, r)| {
                let vendor = r.mac_address.as_ref().map(oui::format_vendor_oui);
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Uint(u64::from(r.interface_index)),
                        CellValue::Text(r.ip_address.to_string()),
                        r.mac_address
                            .map(|m| CellValue::Text(m.to_colon_string()))
                            .unwrap_or(CellValue::Null),
                        CellValue::Text(r.state),
                        CellValue::Bool(r.is_router),
                        opt_text(vendor),
                    ],
                )
            })
            .collect();

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&self.schema(), &rows, req)
    }
}

// 13. sockets.paths (IPPathTableView)
pub struct PathsProvider {
    ctx: NetContext,
}

impl PathsProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }

    fn collect(&self) -> NetResult<Vec<RawPathRow>> {
        match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => offline::load_paths(cfg),
            ExecutionMode::Live => {
                #[cfg(windows)]
                {
                    crate::win32_iphelper::query_paths_live()
                }
                #[cfg(not(windows))]
                {
                    Err(NetError::NotSupported(
                        "live IP path table enumeration requires Windows".to_string(),
                    ))
                }
            }
        }
    }
}

impl TableProvider for PathsProvider {
    fn tool_id(&self) -> &'static str {
        schema::TOOL_ID_PATHS
    }

    fn description(&self) -> &'static str {
        "Inspect IP path MTU, RTT mean/deviation, next-hop, and link speeds (IPPathTableView)"
    }

    fn schema(&self) -> TableSchema {
        schema::schema_paths()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.collect()?;
        let mut rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(idx, r)| {
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Text(r.source_ip.to_string()),
                        CellValue::Text(r.destination_ip.to_string()),
                        CellValue::Text(r.next_hop.to_string()),
                        opt_uint(r.link_speed_tx),
                        opt_uint(r.link_speed_rx),
                        opt_uint(r.rtt_mean_ms.map(u64::from)),
                        opt_uint(r.rtt_deviation_ms.map(u64::from)),
                        CellValue::Uint(u64::from(r.mtu)),
                    ],
                )
            })
            .collect();

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&self.schema(), &rows, req)
    }
}
