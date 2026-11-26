use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use chrono::{DateTime, Duration, TimeZone, Utc};
use net2rust_core::{MacAddr, NetError, NetResult, OfflineConfig};
use serde::de::DeserializeOwned;

use crate::diff::{
    AdapterSnapshot, CounterKind, CounterSample, CounterSnapshot, TcpEndpointKey, TcpEndpointState, TcpSnapshot,
};
use crate::etw_decode::{DNS_CLIENT_GUID_STR, KERNEL_NETWORK_GUID_STR, RawEtwRecord, TCPIP_GUID_STR};
use crate::model::{
    RawAdapterRow, RawDnsCacheEntry, RawInterfaceConfig, RawNeighborRow, RawPathRow, RawPortsBundle, RawRouteRow,
    RawTcpipRegConfig, decode_tcp4_owner_module_table, decode_tcp6_owner_module_table, decode_udp4_owner_module_table,
    decode_udp6_owner_module_table, encode_mib_port, parse_reg_dns_list, utc_to_filetime_i64,
};

#[derive(Debug, Clone)]
pub struct OfflineMutationState {
    pub ports: RawPortsBundle,
    pub routes: Vec<RawRouteRow>,
}

impl OfflineMutationState {
    fn from_config(cfg: &OfflineConfig) -> NetResult<Self> {
        let ports = load_ports_bundle_inner(cfg)?;
        let routes = load_routes_inner(cfg)?;
        Ok(Self { ports, routes })
    }
}

static OFFLINE_STORES: OnceLock<Mutex<HashMap<String, Arc<Mutex<OfflineMutationState>>>>> = OnceLock::new();

fn config_cache_key(cfg: &OfflineConfig) -> String {
    format!(
        "sc={}|fd={}|etl={}",
        cfg.scenario.as_deref().unwrap_or(""),
        cfg.fixture_dir
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        cfg.etl_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
    )
}

fn get_or_init_store(cfg: &OfflineConfig) -> NetResult<Arc<Mutex<OfflineMutationState>>> {
    check_scenario_guard(cfg)?;
    let map_lock = OFFLINE_STORES.get_or_init(|| Mutex::new(HashMap::new()));
    let key = config_cache_key(cfg);
    let mut map = map_lock
        .lock()
        .map_err(|_| NetError::Internal("offline store map mutex poisoned".to_string()))?;
    if let Some(existing) = map.get(&key) {
        return Ok(Arc::clone(existing));
    }
    let created = Arc::new(Mutex::new(OfflineMutationState::from_config(cfg)?));
    map.insert(key, Arc::clone(&created));
    Ok(created)
}

pub fn check_scenario_guard(cfg: &OfflineConfig) -> NetResult<()> {
    if cfg.scenario.as_deref() == Some("access_denied") {
        return Err(NetError::PermissionDenied(
            "simulated non-elevated error (offline scenario=access_denied)".to_string(),
        ));
    }
    Ok(())
}

fn is_empty_scenario(cfg: &OfflineConfig) -> bool {
    cfg.scenario.as_deref() == Some("empty")
}

fn find_fixture_file(cfg: &OfflineConfig, filename: &str) -> Option<PathBuf> {
    let dir = cfg.fixture_dir.as_ref()?;
    let nested = dir.join("sockets").join(filename);
    if nested.exists() {
        return Some(nested);
    }
    let flat = dir.join(filename);
    if flat.exists() {
        return Some(flat);
    }
    None
}

fn read_json_fixture<T: DeserializeOwned>(path: &Path) -> NetResult<T> {
    let text = fs::read_to_string(path)?;
    serde_json::from_str(&text)
        .map_err(|e| NetError::ParseError(format!("invalid JSON fixture {}: {e}", path.display())))
}

fn read_etl_or_json_records(path: &Path, expected_provider: &str) -> NetResult<Vec<RawEtwRecord>> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext == "etl" {
        #[cfg(windows)]
        {
            return crate::etw_net::replay_etl_file(path, Some(expected_provider));
        }
        #[cfg(not(windows))]
        {
            return Err(NetError::NotSupported(format!(
                "binary .etl replay is only supported on Windows: {}",
                path.display()
            )));
        }
    }

    let text = fs::read_to_string(path)?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut records: Vec<RawEtwRecord> = if trimmed.starts_with('[') {
        serde_json::from_str(trimmed)
            .map_err(|e| NetError::ParseError(format!("invalid JSON ETW fixture {}: {e}", path.display())))?
    } else {
        let mut out = Vec::new();
        for (idx, line) in trimmed.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let rec: RawEtwRecord = serde_json::from_str(line).map_err(|e| {
                NetError::ParseError(format!("invalid JSONL ETW line {} in {}: {e}", idx + 1, path.display()))
            })?;
            out.push(rec);
        }
        out
    };
    records.retain(|r| r.provider_guid.eq_ignore_ascii_case(expected_provider));
    Ok(records)
}

fn base_ts() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 20, 14, 30, 0)
        .single()
        .expect("valid static timestamp")
}

fn build_synthetic_tcp4_table_bytes() -> Vec<u8> {
    let ft1 = utc_to_filetime_i64(base_ts() - Duration::minutes(15));
    let ft2 = utc_to_filetime_i64(base_ts() - Duration::minutes(4));
    let ft3 = utc_to_filetime_i64(base_ts() - Duration::seconds(45));
    let rows = [
        (
            2u32, // LISTEN
            Ipv4Addr::UNSPECIFIED,
            445u16,
            Ipv4Addr::UNSPECIFIED,
            0u16,
            4u32,
            ft1,
        ),
        (
            5u32, // ESTABLISHED
            Ipv4Addr::new(192, 168, 1, 50),
            54321u16,
            Ipv4Addr::new(93, 184, 216, 34),
            443u16,
            4120u32,
            ft2,
        ),
        (
            11u32, // TIME_WAIT
            Ipv4Addr::new(192, 168, 1, 50),
            54322u16,
            Ipv4Addr::new(151, 101, 1, 69),
            80u16,
            4120u32,
            ft3,
        ),
    ];

    let mut buf = vec![0u8; 8 + rows.len() * 160];
    buf[0..4].copy_from_slice(&(rows.len() as u32).to_le_bytes());
    for (idx, (state, laddr, lport, raddr, rport, pid, ft)) in rows.iter().enumerate() {
        let base = 8 + idx * 160;
        buf[base..base + 4].copy_from_slice(&state.to_le_bytes());
        buf[base + 4..base + 8].copy_from_slice(&laddr.octets());
        buf[base + 8..base + 12].copy_from_slice(&encode_mib_port(*lport).to_le_bytes());
        buf[base + 12..base + 16].copy_from_slice(&raddr.octets());
        buf[base + 16..base + 20].copy_from_slice(&encode_mib_port(*rport).to_le_bytes());
        buf[base + 20..base + 24].copy_from_slice(&pid.to_le_bytes());
        buf[base + 24..base + 32].copy_from_slice(&ft.to_le_bytes());
    }
    buf
}

fn build_synthetic_tcp6_table_bytes() -> Vec<u8> {
    let ft = utc_to_filetime_i64(base_ts() - Duration::minutes(2));
    let mut buf = vec![0u8; 8 + 192];
    buf[0..4].copy_from_slice(&1u32.to_le_bytes());
    let base = 8;
    let laddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0x10);
    let raddr = Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946);
    buf[base..base + 16].copy_from_slice(&laddr.octets());
    buf[base + 20..base + 24].copy_from_slice(&encode_mib_port(55100).to_le_bytes());
    buf[base + 24..base + 40].copy_from_slice(&raddr.octets());
    buf[base + 44..base + 48].copy_from_slice(&encode_mib_port(443).to_le_bytes());
    buf[base + 48..base + 52].copy_from_slice(&5u32.to_le_bytes()); // ESTABLISHED
    buf[base + 52..base + 56].copy_from_slice(&7840u32.to_le_bytes());
    buf[base + 56..base + 64].copy_from_slice(&ft.to_le_bytes());
    buf
}

fn build_synthetic_udp4_table_bytes() -> Vec<u8> {
    let ft = utc_to_filetime_i64(base_ts() - Duration::minutes(10));
    let rows = [
        (Ipv4Addr::UNSPECIFIED, 5353u16, 2048u32),
        (Ipv4Addr::LOCALHOST, 68u16, 1100u32),
    ];
    let mut buf = vec![0u8; 8 + rows.len() * 160];
    buf[0..4].copy_from_slice(&(rows.len() as u32).to_le_bytes());
    for (idx, (laddr, lport, pid)) in rows.iter().enumerate() {
        let base = 8 + idx * 160;
        buf[base..base + 4].copy_from_slice(&laddr.octets());
        buf[base + 4..base + 8].copy_from_slice(&encode_mib_port(*lport).to_le_bytes());
        buf[base + 8..base + 12].copy_from_slice(&pid.to_le_bytes());
        buf[base + 16..base + 24].copy_from_slice(&ft.to_le_bytes());
    }
    buf
}

fn build_synthetic_udp6_table_bytes() -> Vec<u8> {
    let ft = utc_to_filetime_i64(base_ts() - Duration::minutes(8));
    let mut buf = vec![0u8; 8 + 176];
    buf[0..4].copy_from_slice(&1u32.to_le_bytes());
    let base = 8;
    buf[base..base + 16].copy_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
    buf[base + 20..base + 24].copy_from_slice(&encode_mib_port(5353).to_le_bytes());
    buf[base + 24..base + 28].copy_from_slice(&2048u32.to_le_bytes());
    buf[base + 32..base + 40].copy_from_slice(&ft.to_le_bytes());
    buf
}

fn annotate_pid_meta(pid: u32) -> (Option<String>, Option<String>, Option<String>) {
    match pid {
        0 => (
            Some("System Idle Process".to_string()),
            None,
            Some("NT AUTHORITY\\SYSTEM".to_string()),
        ),
        4 => (
            Some("System".to_string()),
            None,
            Some("NT AUTHORITY\\SYSTEM".to_string()),
        ),
        1100 => (
            Some("svchost.exe".to_string()),
            Some("C:\\Windows\\System32\\svchost.exe".to_string()),
            Some("NT AUTHORITY\\LOCAL SERVICE".to_string()),
        ),
        2048 => (
            Some("dnscache.exe".to_string()),
            Some("C:\\Windows\\System32\\svchost.exe".to_string()),
            Some("NT AUTHORITY\\NETWORK SERVICE".to_string()),
        ),
        4120 => (
            Some("firefox.exe".to_string()),
            Some("C:\\Program Files\\Mozilla Firefox\\firefox.exe".to_string()),
            Some("WORKSTATION\\alice".to_string()),
        ),
        7840 => (
            Some("cargo.exe".to_string()),
            Some("C:\\Users\\alice\\.cargo\\bin\\cargo.exe".to_string()),
            Some("WORKSTATION\\alice".to_string()),
        ),
        _ => (None, None, None),
    }
}

fn load_ports_bundle_inner(cfg: &OfflineConfig) -> NetResult<RawPortsBundle> {
    check_scenario_guard(cfg)?;
    if is_empty_scenario(cfg) {
        return Ok(RawPortsBundle {
            tcp: Vec::new(),
            udp: Vec::new(),
        });
    }
    if let Some(path) = find_fixture_file(cfg, "ports.json") {
        return read_json_fixture(&path);
    }

    // Exercise genuine binary MIB decoders in offline mode.
    let mut tcp = decode_tcp4_owner_module_table(&build_synthetic_tcp4_table_bytes())?;
    tcp.extend(decode_tcp6_owner_module_table(&build_synthetic_tcp6_table_bytes())?);
    let mut udp = decode_udp4_owner_module_table(&build_synthetic_udp4_table_bytes())?;
    udp.extend(decode_udp6_owner_module_table(&build_synthetic_udp6_table_bytes())?);

    for row in &mut tcp {
        let (name, path, user) = annotate_pid_meta(row.pid);
        row.process_name = name;
        row.process_path = path;
        row.user_name = user;
        if row.state_code == 5 && row.pid == 4120 {
            row.estats_bytes_sent = Some(48_200);
            row.estats_bytes_recvd = Some(512_900);
        } else if row.state_code == 5 && row.pid == 7840 {
            row.estats_bytes_sent = Some(12_400);
            row.estats_bytes_recvd = Some(198_400);
        }
    }
    for row in &mut udp {
        let (name, path, user) = annotate_pid_meta(row.pid);
        row.process_name = name;
        row.process_path = path;
        row.user_name = user;
    }

    Ok(RawPortsBundle { tcp, udp })
}

pub fn load_ports_bundle(cfg: &OfflineConfig) -> NetResult<RawPortsBundle> {
    let store = get_or_init_store(cfg)?;
    let guard = store
        .lock()
        .map_err(|_| NetError::Internal("offline mutation state mutex poisoned".to_string()))?;
    Ok(guard.ports.clone())
}

pub fn close_offline_socket(
    cfg: &OfflineConfig,
    local_addr: Ipv4Addr,
    local_port: u16,
    remote_addr: Ipv4Addr,
    remote_port: u16,
) -> NetResult<()> {
    let store = get_or_init_store(cfg)?;
    let mut guard = store
        .lock()
        .map_err(|_| NetError::Internal("offline mutation state mutex poisoned".to_string()))?;

    let pos = guard
        .ports
        .tcp
        .iter()
        .position(|r| {
            r.local_addr == IpAddr::V4(local_addr)
                && r.local_port == local_port
                && r.remote_addr == IpAddr::V4(remote_addr)
                && r.remote_port == remote_port
        })
        .ok_or_else(|| {
            NetError::HardwareNotFound(format!(
                "TCP socket {local_addr}:{local_port} -> {remote_addr}:{remote_port} not found"
            ))
        })?;
    guard.ports.tcp.remove(pos);
    Ok(())
}

pub fn load_tcp_snapshots(cfg: &OfflineConfig) -> NetResult<Vec<TcpSnapshot>> {
    check_scenario_guard(cfg)?;
    if is_empty_scenario(cfg) {
        return Ok(Vec::new());
    }
    if let Some(path) = find_fixture_file(cfg, "tcp_snapshots.json") {
        return read_json_fixture(&path);
    }

    let t0 = base_ts();
    let k_listen = TcpEndpointKey {
        ip_version: 4,
        local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        local_port: 8080,
        remote_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        remote_port: 0,
        pid: 4120,
    };
    let k_conn = TcpEndpointKey {
        ip_version: 4,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
        local_port: 54321,
        remote_addr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        remote_port: 443,
        pid: 4120,
    };
    let k_v6 = TcpEndpointKey {
        ip_version: 6,
        local_addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0x10)),
        local_port: 55100,
        remote_addr: IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946)),
        remote_port: 443,
        pid: 7840,
    };

    let mut s0 = BTreeMap::new();
    s0.insert(
        k_conn.clone(),
        TcpEndpointState {
            state_code: 5,
            process_name: Some("firefox.exe".to_string()),
        },
    );

    let mut s1 = s0.clone();
    s1.insert(
        k_listen.clone(),
        TcpEndpointState {
            state_code: 2, // LISTEN
            process_name: Some("firefox.exe".to_string()),
        },
    );
    s1.insert(
        k_v6.clone(),
        TcpEndpointState {
            state_code: 5, // ESTABLISHED -> Open
            process_name: Some("cargo.exe".to_string()),
        },
    );

    let mut s2 = s1.clone();
    s2.remove(&k_conn); // Close

    Ok(vec![
        TcpSnapshot {
            captured_at: t0,
            entries: s0,
        },
        TcpSnapshot {
            captured_at: t0 + Duration::milliseconds(250),
            entries: s1,
        },
        TcpSnapshot {
            captured_at: t0 + Duration::milliseconds(500),
            entries: s2,
        },
    ])
}

#[allow(clippy::too_many_arguments)]
fn make_kn_v4_28(
    event_id: u16,
    ts: DateTime<Utc>,
    pid: u32,
    size: u32,
    daddr: Ipv4Addr,
    saddr: Ipv4Addr,
    dport: u16,
    sport: u16,
    conn_id: u32,
) -> RawEtwRecord {
    let mut data = Vec::with_capacity(28);
    data.extend_from_slice(&pid.to_le_bytes());
    data.extend_from_slice(&size.to_le_bytes());
    data.extend_from_slice(&daddr.octets());
    data.extend_from_slice(&saddr.octets());
    data.extend_from_slice(&dport.to_be_bytes());
    data.extend_from_slice(&sport.to_be_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&conn_id.to_le_bytes());
    RawEtwRecord {
        provider_guid: KERNEL_NETWORK_GUID_STR.to_string(),
        event_id,
        version: 0,
        timestamp_utc: ts,
        header_process_id: u32::MAX, // Tests that decoder prefers UserData[0..4] PID!
        activity_id: [0; 16],
        is_64bit: true,
        user_data: data,
    }
}

#[allow(clippy::too_many_arguments)]
fn make_kn_v4_send_36(
    ts: DateTime<Utc>,
    pid: u32,
    size: u32,
    daddr: Ipv4Addr,
    saddr: Ipv4Addr,
    dport: u16,
    sport: u16,
    conn_id: u32,
) -> RawEtwRecord {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&pid.to_le_bytes());
    data.extend_from_slice(&size.to_le_bytes());
    data.extend_from_slice(&daddr.octets());
    data.extend_from_slice(&saddr.octets());
    data.extend_from_slice(&dport.to_be_bytes());
    data.extend_from_slice(&sport.to_be_bytes());
    data.extend_from_slice(&10u32.to_le_bytes());
    data.extend_from_slice(&12u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&conn_id.to_le_bytes());
    RawEtwRecord {
        provider_guid: KERNEL_NETWORK_GUID_STR.to_string(),
        event_id: 10,
        version: 0,
        timestamp_utc: ts,
        header_process_id: pid,
        activity_id: [0; 16],
        is_64bit: true,
        user_data: data,
    }
}

#[allow(clippy::too_many_arguments)]
fn make_kn_v6(
    event_id: u16,
    ts: DateTime<Utc>,
    pid: u32,
    size: u32,
    daddr: Ipv6Addr,
    saddr: Ipv6Addr,
    dport: u16,
    sport: u16,
    conn_id: u32,
) -> RawEtwRecord {
    let mut data = Vec::with_capacity(60);
    data.extend_from_slice(&pid.to_le_bytes());
    data.extend_from_slice(&size.to_le_bytes());
    data.extend_from_slice(&daddr.octets());
    data.extend_from_slice(&saddr.octets());
    data.extend_from_slice(&dport.to_be_bytes());
    data.extend_from_slice(&sport.to_be_bytes());
    if event_id == 26 {
        data.extend_from_slice(&[0u8; 8]); // startime + endtime
    }
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&conn_id.to_le_bytes());
    RawEtwRecord {
        provider_guid: KERNEL_NETWORK_GUID_STR.to_string(),
        event_id,
        version: 0,
        timestamp_utc: ts,
        header_process_id: 4,
        activity_id: [0; 16],
        is_64bit: true,
        user_data: data,
    }
}

pub fn load_kernel_network_records(cfg: &OfflineConfig) -> NetResult<Vec<RawEtwRecord>> {
    check_scenario_guard(cfg)?;
    if is_empty_scenario(cfg) {
        return Ok(Vec::new());
    }
    if let Some(etl) = &cfg.etl_path {
        return read_etl_or_json_records(etl, KERNEL_NETWORK_GUID_STR);
    }
    if let Some(path) = find_fixture_file(cfg, "kernel_network.json") {
        return read_json_fixture(&path);
    }

    let t0 = base_ts();
    let local_v4 = Ipv4Addr::new(192, 168, 1, 50);
    let remote_v4 = Ipv4Addr::new(93, 184, 216, 34);
    let dns_v4 = Ipv4Addr::new(1, 1, 1, 1);
    let local_v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0x10);
    let remote_v6 = Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946);

    Ok(vec![
        make_kn_v4_send_36(t0, 4120, 1_400, remote_v4, local_v4, 443, 54321, 101),
        make_kn_v4_28(
            11,
            t0 + Duration::milliseconds(150),
            4120,
            16_384,
            local_v4,
            remote_v4,
            54321,
            443,
            101,
        ),
        make_kn_v4_28(
            42,
            t0 + Duration::milliseconds(200),
            2048,
            64,
            dns_v4,
            local_v4,
            53,
            58012,
            102,
        ),
        make_kn_v4_28(
            43,
            t0 + Duration::milliseconds(225),
            2048,
            192,
            local_v4,
            dns_v4,
            58012,
            53,
            102,
        ),
        make_kn_v6(
            26,
            t0 + Duration::milliseconds(500),
            7840,
            4_096,
            remote_v6,
            local_v6,
            443,
            55100,
            103,
        ),
        make_kn_v6(
            27,
            t0 + Duration::milliseconds(1500),
            7840,
            32_768,
            local_v6,
            remote_v6,
            55100,
            443,
            103,
        ),
    ])
}

fn encode_sockaddr_v4_prefixed(ip: Ipv4Addr, port: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(20);
    b.extend_from_slice(&16u32.to_le_bytes());
    b.extend_from_slice(&2u16.to_le_bytes()); // AF_INET
    b.extend_from_slice(&port.to_be_bytes());
    b.extend_from_slice(&ip.octets());
    b.extend_from_slice(&[0u8; 8]);
    b
}

pub fn load_tcpip_records(cfg: &OfflineConfig) -> NetResult<Vec<RawEtwRecord>> {
    check_scenario_guard(cfg)?;
    if is_empty_scenario(cfg) {
        return Ok(Vec::new());
    }
    if let Some(etl) = &cfg.etl_path {
        return read_etl_or_json_records(etl, TCPIP_GUID_STR);
    }
    if let Some(path) = find_fixture_file(cfg, "tcpip_errors.json") {
        return read_json_fixture(&path);
    }

    let t0 = base_ts();
    let local = Ipv4Addr::new(192, 168, 1, 50);

    // 1) ID 1002 endpoint context for TCB 0xDEAD_BEEF_0001 + ID 1351 RTO timeout
    let mut d1002 = Vec::new();
    d1002.extend_from_slice(&0xDEAD_BEEF_0001u64.to_le_bytes());
    d1002.extend_from_slice(&encode_sockaddr_v4_prefixed(local, 55001));
    d1002.extend_from_slice(&encode_sockaddr_v4_prefixed(Ipv4Addr::new(198, 51, 100, 20), 443));
    d1002.extend_from_slice(&3u32.to_le_bytes()); // SYN_SENT
    d1002.extend_from_slice(&0u32.to_le_bytes());

    let mut d1351 = Vec::new();
    d1351.extend_from_slice(&0xDEAD_BEEF_0001u64.to_le_bytes());
    d1351.extend_from_slice(&1u32.to_le_bytes());
    d1351.extend_from_slice(&2u32.to_le_bytes()); // rexmit_count=2
    d1351.extend_from_slice(&200u32.to_le_bytes());
    d1351.extend_from_slice(&1000u32.to_le_bytes());

    // 2) ID 1018 STATUS_CONNECTION_REFUSED
    let mut d1018 = Vec::new();
    d1018.extend_from_slice(&encode_sockaddr_v4_prefixed(local, 55002));
    d1018.extend_from_slice(&encode_sockaddr_v4_prefixed(Ipv4Addr::new(127, 0, 0, 1), 9999));
    d1018.extend_from_slice(&0xC000_0236u32.to_le_bytes()); // STATUS_CONNECTION_REFUSED
    d1018.extend_from_slice(&7840u32.to_le_bytes());
    d1018.extend_from_slice(&1u32.to_le_bytes());
    d1018.extend_from_slice(&0xDEAD_BEEF_0002u64.to_le_bytes());

    // 3) ID 1034 STATUS_IO_TIMEOUT
    let mut d1034 = Vec::new();
    d1034.extend_from_slice(&encode_sockaddr_v4_prefixed(local, 55003));
    d1034.extend_from_slice(&encode_sockaddr_v4_prefixed(Ipv4Addr::new(203, 0, 113, 55), 8443));
    d1034.extend_from_slice(&0xC000_00B5u32.to_le_bytes()); // STATUS_IO_TIMEOUT
    d1034.extend_from_slice(&4120u32.to_le_bytes());
    d1034.extend_from_slice(&1u32.to_le_bytes());
    d1034.extend_from_slice(&0xDEAD_BEEF_0003u64.to_le_bytes());

    Ok(vec![
        RawEtwRecord {
            provider_guid: TCPIP_GUID_STR.to_string(),
            event_id: 1002,
            version: 0,
            timestamp_utc: t0,
            header_process_id: 4120,
            activity_id: [0; 16],
            is_64bit: true,
            user_data: d1002,
        },
        RawEtwRecord {
            provider_guid: TCPIP_GUID_STR.to_string(),
            event_id: 1351,
            version: 1,
            timestamp_utc: t0 + Duration::milliseconds(300),
            header_process_id: 4,
            activity_id: [0; 16],
            is_64bit: true,
            user_data: d1351,
        },
        RawEtwRecord {
            provider_guid: TCPIP_GUID_STR.to_string(),
            event_id: 1018,
            version: 1,
            timestamp_utc: t0 + Duration::milliseconds(450),
            header_process_id: 7840,
            activity_id: [0; 16],
            is_64bit: true,
            user_data: d1018,
        },
        RawEtwRecord {
            provider_guid: TCPIP_GUID_STR.to_string(),
            event_id: 1034,
            version: 1,
            timestamp_utc: t0 + Duration::milliseconds(700),
            header_process_id: 4120,
            activity_id: [0; 16],
            is_64bit: true,
            user_data: d1034,
        },
    ])
}

fn push_utf16z(buf: &mut Vec<u8>, s: &str) {
    for u in s.encode_utf16() {
        buf.extend_from_slice(&u.to_le_bytes());
    }
    buf.extend_from_slice(&0u16.to_le_bytes());
}

pub fn load_dns_client_records(cfg: &OfflineConfig) -> NetResult<(Vec<RawEtwRecord>, Vec<RawDnsCacheEntry>)> {
    check_scenario_guard(cfg)?;
    if is_empty_scenario(cfg) {
        return Ok((Vec::new(), Vec::new()));
    }
    let cache = if let Some(path) = find_fixture_file(cfg, "dns_cache.json") {
        read_json_fixture(&path)?
    } else {
        vec![RawDnsCacheEntry {
            name: "crates.io".to_string(),
            record_type: 1,
            data_length: 4,
            flags: 0x2000,
        }]
    };

    if let Some(etl) = &cfg.etl_path {
        let recs = read_etl_or_json_records(etl, DNS_CLIENT_GUID_STR)?;
        return Ok((recs, cache));
    }
    if let Some(path) = find_fixture_file(cfg, "dns_client.json") {
        let recs = read_json_fixture(&path)?;
        return Ok((recs, cache));
    }

    let t0 = base_ts();
    let act1 = [1u8; 16];
    let act2 = [2u8; 16];

    // 3006 QueryCalled -> 3008 QueryCompleted (example.com, A, 18ms)
    let mut d3006 = Vec::new();
    push_utf16z(&mut d3006, "example.com");
    d3006.extend_from_slice(&1u32.to_le_bytes());
    d3006.extend_from_slice(&0u64.to_le_bytes());
    push_utf16z(&mut d3006, "1.1.1.1");
    d3006.extend_from_slice(&[0u8; 16]);

    let mut d3008 = Vec::new();
    push_utf16z(&mut d3008, "example.com");
    d3008.extend_from_slice(&1u32.to_le_bytes());
    d3008.extend_from_slice(&0u64.to_le_bytes());
    d3008.extend_from_slice(&0u32.to_le_bytes());
    push_utf16z(&mut d3008, "93.184.216.34");

    // 3019 WireQuery -> 3020 WireResponse (NXDOMAIN)
    let mut d3019 = Vec::new();
    push_utf16z(&mut d3019, "nonexistent.invalid");
    d3019.extend_from_slice(&28u32.to_le_bytes()); // AAAA
    d3019.extend_from_slice(&12u32.to_le_bytes());
    d3019.extend_from_slice(&1u32.to_le_bytes());
    d3019.extend_from_slice(&7840u32.to_le_bytes());

    let mut d3020 = Vec::new();
    push_utf16z(&mut d3020, "nonexistent.invalid");
    d3020.extend_from_slice(&28u32.to_le_bytes());
    d3020.extend_from_slice(&1u32.to_le_bytes());
    d3020.extend_from_slice(&12u32.to_le_bytes());
    d3020.extend_from_slice(&9003u32.to_le_bytes()); // NXDOMAIN
    push_utf16z(&mut d3020, "");
    d3020.extend_from_slice(&7840u32.to_le_bytes());

    Ok((
        vec![
            RawEtwRecord {
                provider_guid: DNS_CLIENT_GUID_STR.to_string(),
                event_id: 3006,
                version: 0,
                timestamp_utc: t0,
                header_process_id: 4120,
                activity_id: act1,
                is_64bit: true,
                user_data: d3006,
            },
            RawEtwRecord {
                provider_guid: DNS_CLIENT_GUID_STR.to_string(),
                event_id: 3008,
                version: 0,
                timestamp_utc: t0 + Duration::milliseconds(18),
                header_process_id: 4120,
                activity_id: act1,
                is_64bit: true,
                user_data: d3008,
            },
            RawEtwRecord {
                provider_guid: DNS_CLIENT_GUID_STR.to_string(),
                event_id: 3019,
                version: 1,
                timestamp_utc: t0 + Duration::milliseconds(100),
                header_process_id: 7840,
                activity_id: act2,
                is_64bit: true,
                user_data: d3019,
            },
            RawEtwRecord {
                provider_guid: DNS_CLIENT_GUID_STR.to_string(),
                event_id: 3020,
                version: 1,
                timestamp_utc: t0 + Duration::milliseconds(142),
                header_process_id: 7840,
                activity_id: act2,
                is_64bit: true,
                user_data: d3020,
            },
        ],
        cache,
    ))
}

pub fn load_counter_snapshots(cfg: &OfflineConfig) -> NetResult<(Option<CounterSnapshot>, CounterSnapshot)> {
    check_scenario_guard(cfg)?;
    if is_empty_scenario(cfg) {
        return Ok((
            None,
            CounterSnapshot {
                captured_at_ns: 0,
                values: BTreeMap::new(),
            },
        ));
    }
    if let Some(path) = find_fixture_file(cfg, "counters.json") {
        let curr: CounterSnapshot = read_json_fixture(&path)?;
        return Ok((None, curr));
    }

    let mut prev_vals = BTreeMap::new();
    prev_vals.insert(
        ("IPv4".to_string(), "IPv4.InReceives".to_string()),
        CounterSample {
            value: u64::from(u32::MAX - 50), // Exercises wrap-safe 32-bit delta
            kind: CounterKind::Counter32,
        },
    );
    prev_vals.insert(
        ("TCP".to_string(), "TCPv4.InSegs".to_string()),
        CounterSample {
            value: 1_250_000,
            kind: CounterKind::Counter32,
        },
    );
    prev_vals.insert(
        ("TCP".to_string(), "TCPv4.CurrEstab".to_string()),
        CounterSample {
            value: 14,
            kind: CounterKind::Gauge,
        },
    );
    prev_vals.insert(
        ("UDP".to_string(), "UDPv4.InDatagrams".to_string()),
        CounterSample {
            value: 92_000,
            kind: CounterKind::Counter32,
        },
    );
    prev_vals.insert(
        ("ICMP".to_string(), "ICMPv4.InMsgs".to_string()),
        CounterSample {
            value: 410,
            kind: CounterKind::Counter32,
        },
    );

    let mut curr_vals = BTreeMap::new();
    curr_vals.insert(
        ("IPv4".to_string(), "IPv4.InReceives".to_string()),
        CounterSample {
            value: 49, // Wrapped across 2^32 => delta = 100 over 2s = 50.0/sec
            kind: CounterKind::Counter32,
        },
    );
    curr_vals.insert(
        ("TCP".to_string(), "TCPv4.InSegs".to_string()),
        CounterSample {
            value: 1_250_400,
            kind: CounterKind::Counter32,
        },
    );
    curr_vals.insert(
        ("TCP".to_string(), "TCPv4.CurrEstab".to_string()),
        CounterSample {
            value: 12,
            kind: CounterKind::Gauge,
        },
    );
    curr_vals.insert(
        ("UDP".to_string(), "UDPv4.InDatagrams".to_string()),
        CounterSample {
            value: 92_120,
            kind: CounterKind::Counter32,
        },
    );
    curr_vals.insert(
        ("ICMP".to_string(), "ICMPv4.InMsgs".to_string()),
        CounterSample {
            value: 416,
            kind: CounterKind::Counter32,
        },
    );
    curr_vals.insert(
        ("IPv6".to_string(), "IPv6.InReceives".to_string()),
        CounterSample {
            value: 18_420,
            kind: CounterKind::Counter32,
        },
    );

    let prev = CounterSnapshot {
        captured_at_ns: 1_000_000_000,
        values: prev_vals,
    };
    let curr = CounterSnapshot {
        captured_at_ns: 3_000_000_000,
        values: curr_vals,
    };
    Ok((Some(prev), curr))
}

pub fn load_adapter_snapshots(cfg: &OfflineConfig) -> NetResult<(Option<AdapterSnapshot>, AdapterSnapshot)> {
    check_scenario_guard(cfg)?;
    if is_empty_scenario(cfg) {
        return Ok((
            None,
            AdapterSnapshot {
                captured_at_ns: 0,
                rows: BTreeMap::new(),
            },
        ));
    }
    if let Some(path) = find_fixture_file(cfg, "adapters.json") {
        let rows: Vec<RawAdapterRow> = read_json_fixture(&path)?;
        let map = rows.into_iter().map(|r| (r.luid, r)).collect();
        return Ok((
            None,
            AdapterSnapshot {
                captured_at_ns: 1_000_000_000,
                rows: map,
            },
        ));
    }

    let mut prev_rows = BTreeMap::new();
    prev_rows.insert(
        1,
        RawAdapterRow {
            luid: 1,
            interface_index: 12,
            adapter_name: "Ethernet".to_string(),
            description: "Intel(R) Ethernet Controller I225-V".to_string(),
            media_state: "Connected (Up)".to_string(),
            link_speed: Some(1_000_000_000),
            bytes_sent: 100_000,
            bytes_recvd: 500_000,
            errors: 0,
            discards: 0,
        },
    );
    prev_rows.insert(
        2,
        RawAdapterRow {
            luid: 2,
            interface_index: 15,
            adapter_name: "Wi-Fi".to_string(),
            description: "Intel(R) Wi-Fi 6E AX210 160MHz".to_string(),
            media_state: "Disconnected (Down)".to_string(),
            link_speed: None,
            bytes_sent: 24_000,
            bytes_recvd: 82_000,
            errors: 1,
            discards: 2,
        },
    );

    let mut curr_rows = BTreeMap::new();
    curr_rows.insert(
        1,
        RawAdapterRow {
            luid: 1,
            interface_index: 12,
            adapter_name: "Ethernet".to_string(),
            description: "Intel(R) Ethernet Controller I225-V".to_string(),
            media_state: "Connected (Up)".to_string(),
            link_speed: Some(1_000_000_000),
            bytes_sent: 150_000,
            bytes_recvd: 750_000,
            errors: 0,
            discards: 0,
        },
    );
    curr_rows.insert(
        2,
        RawAdapterRow {
            luid: 2,
            interface_index: 15,
            adapter_name: "Wi-Fi".to_string(),
            description: "Intel(R) Wi-Fi 6E AX210 160MHz".to_string(),
            media_state: "Disconnected (Down)".to_string(),
            link_speed: None,
            bytes_sent: 24_000,
            bytes_recvd: 82_000,
            errors: 1,
            discards: 2,
        },
    );
    curr_rows.insert(
        3,
        RawAdapterRow {
            luid: 3,
            interface_index: 1,
            adapter_name: "Loopback Pseudo-Interface 1".to_string(),
            description: "Software Loopback Interface 1".to_string(),
            media_state: "Connected (Up)".to_string(),
            link_speed: Some(10_737_418_240),
            bytes_sent: 4_096,
            bytes_recvd: 4_096,
            errors: 0,
            discards: 0,
        },
    );

    Ok((
        Some(AdapterSnapshot {
            captured_at_ns: 1_000_000_000,
            rows: prev_rows,
        }),
        AdapterSnapshot {
            captured_at_ns: 3_000_000_000,
            rows: curr_rows,
        },
    ))
}

pub fn load_interfaces(cfg: &OfflineConfig) -> NetResult<Vec<RawInterfaceConfig>> {
    check_scenario_guard(cfg)?;
    if is_empty_scenario(cfg) {
        return Ok(Vec::new());
    }
    if let Some(path) = find_fixture_file(cfg, "interfaces.json") {
        return read_json_fixture(&path);
    }

    let eth_dns = parse_reg_dns_list("1.1.1.1, 8.8.8.8 1.0.0.1");
    Ok(vec![
        RawInterfaceConfig {
            interface_name: "Ethernet".to_string(),
            description: "Intel(R) Ethernet Controller I225-V".to_string(),
            guid: "{A1B2C3D4-1111-2222-3333-444455556666}".to_string(),
            mac_address: Some(MacAddr::new([0xA0, 0x36, 0x9F, 0x11, 0x22, 0x33])),
            operational_status: "Up".to_string(),
            if_type: "Ethernet".to_string(),
            speed_mbps: Some(1000),
            ipv4: vec!["192.168.1.50/24".to_string()],
            ipv6: vec!["fe80::10/64".to_string()],
            gateway: vec!["192.168.1.1".to_string()],
            dns_servers: eth_dns.clone(),
            dhcp_enabled: true,
            reg_config: Some(RawTcpipRegConfig {
                enable_dhcp: Some(true),
                dhcp_server: Some("192.168.1.1".to_string()),
                name_servers: Vec::new(),
                dhcp_name_servers: eth_dns,
                ip_addresses: vec!["192.168.1.50".to_string()],
                subnet_masks: vec!["255.255.255.0".to_string()],
                default_gateways: vec!["192.168.1.1".to_string()],
                domain: Some("lan".to_string()),
            }),
        },
        RawInterfaceConfig {
            interface_name: "Wi-Fi".to_string(),
            description: "Intel(R) Wi-Fi 6E AX210 160MHz".to_string(),
            guid: "{B2C3D4E5-7777-8888-9999-000011112222}".to_string(),
            mac_address: Some(MacAddr::new([0xFC, 0xF8, 0xAE, 0xAA, 0xBB, 0xCC])),
            operational_status: "Down".to_string(),
            if_type: "Wi-Fi (802.11)".to_string(),
            speed_mbps: None,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            gateway: Vec::new(),
            dns_servers: parse_reg_dns_list("9.9.9.9"),
            dhcp_enabled: false,
            reg_config: None,
        },
        RawInterfaceConfig {
            interface_name: "Loopback Pseudo-Interface 1".to_string(),
            description: "Software Loopback Interface 1".to_string(),
            guid: "{00000000-0000-0000-0000-000000000000}".to_string(),
            mac_address: None,
            operational_status: "Up".to_string(),
            if_type: "Loopback".to_string(),
            speed_mbps: Some(10737),
            ipv4: vec!["127.0.0.1/8".to_string()],
            ipv6: vec!["::1/128".to_string()],
            gateway: Vec::new(),
            dns_servers: Vec::new(),
            dhcp_enabled: false,
            reg_config: None,
        },
    ])
}

fn load_routes_inner(cfg: &OfflineConfig) -> NetResult<Vec<RawRouteRow>> {
    check_scenario_guard(cfg)?;
    if is_empty_scenario(cfg) {
        return Ok(Vec::new());
    }
    if let Some(path) = find_fixture_file(cfg, "routes.json") {
        return read_json_fixture(&path);
    }

    Ok(vec![
        RawRouteRow {
            destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_length: 0,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            interface_index: 12,
            interface_alias: Some("Ethernet".to_string()),
            metric: 25,
            protocol: "DHCP".to_string(),
            age_secs: 3600,
        },
        RawRouteRow {
            destination: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            prefix_length: 24,
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            interface_index: 12,
            interface_alias: Some("Ethernet".to_string()),
            metric: 281,
            protocol: "Local".to_string(),
            age_secs: 3600,
        },
        RawRouteRow {
            destination: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
            prefix_length: 64,
            next_hop: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            interface_index: 12,
            interface_alias: Some("Ethernet".to_string()),
            metric: 256,
            protocol: "Local".to_string(),
            age_secs: 1800,
        },
    ])
}

pub fn load_routes(cfg: &OfflineConfig) -> NetResult<Vec<RawRouteRow>> {
    let store = get_or_init_store(cfg)?;
    let guard = store
        .lock()
        .map_err(|_| NetError::Internal("offline mutation state mutex poisoned".to_string()))?;
    Ok(guard.routes.clone())
}

pub fn add_offline_route(
    cfg: &OfflineConfig,
    destination: IpAddr,
    prefix_length: u8,
    next_hop: IpAddr,
    interface_index: Option<u32>,
    interface_alias: Option<&str>,
    metric: u32,
) -> NetResult<()> {
    let store = get_or_init_store(cfg)?;
    let mut guard = store
        .lock()
        .map_err(|_| NetError::Internal("offline mutation state mutex poisoned".to_string()))?;

    let resolved_idx = interface_index.unwrap_or(12);
    let resolved_alias = interface_alias.map(ToOwned::to_owned).or_else(|| {
        if resolved_idx == 12 {
            Some("Ethernet".to_string())
        } else {
            None
        }
    });

    if let Some(alias) = interface_alias
        && !alias.eq_ignore_ascii_case("Ethernet")
        && !alias.eq_ignore_ascii_case("Wi-Fi")
        && !alias.eq_ignore_ascii_case("Loopback Pseudo-Interface 1")
    {
        return Err(NetError::HardwareNotFound(format!(
            "interface alias '{alias}' not found"
        )));
    }

    let exists = guard.routes.iter().any(|r| {
        r.destination == destination
            && r.prefix_length == prefix_length
            && r.next_hop == next_hop
            && r.interface_index == resolved_idx
    });
    if exists {
        return Err(NetError::InvalidInput("route already exists".to_string()));
    }

    guard.routes.push(RawRouteRow {
        destination,
        prefix_length,
        next_hop,
        interface_index: resolved_idx,
        interface_alias: resolved_alias,
        metric,
        protocol: "NetMgmt".to_string(),
        age_secs: 0,
    });
    Ok(())
}

pub fn delete_offline_route(
    cfg: &OfflineConfig,
    destination: IpAddr,
    prefix_length: u8,
    next_hop: IpAddr,
    interface_index: Option<u32>,
    interface_alias: Option<&str>,
) -> NetResult<()> {
    let store = get_or_init_store(cfg)?;
    let mut guard = store
        .lock()
        .map_err(|_| NetError::Internal("offline mutation state mutex poisoned".to_string()))?;

    let pos = guard
        .routes
        .iter()
        .position(|r| {
            let idx_ok = interface_index.map(|i| r.interface_index == i).unwrap_or(true);
            let alias_ok = interface_alias
                .map(|a| {
                    r.interface_alias
                        .as_deref()
                        .map(|ra| ra.eq_ignore_ascii_case(a))
                        .unwrap_or(false)
                })
                .unwrap_or(true);
            r.destination == destination
                && r.prefix_length == prefix_length
                && r.next_hop == next_hop
                && idx_ok
                && alias_ok
        })
        .ok_or_else(|| {
            NetError::HardwareNotFound(format!("route {destination}/{prefix_length} via {next_hop} not found"))
        })?;
    guard.routes.remove(pos);
    Ok(())
}

pub fn load_neighbors(cfg: &OfflineConfig) -> NetResult<Vec<RawNeighborRow>> {
    check_scenario_guard(cfg)?;
    if is_empty_scenario(cfg) {
        return Ok(Vec::new());
    }
    if let Some(path) = find_fixture_file(cfg, "neighbors.json") {
        return read_json_fixture(&path);
    }

    Ok(vec![
        RawNeighborRow {
            interface_index: 12,
            ip_address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            mac_address: Some(MacAddr::new([0x00, 0x50, 0x56, 0x10, 0x20, 0x30])),
            state: "Reachable".to_string(),
            is_router: true,
            is_unreachable: false,
        },
        RawNeighborRow {
            interface_index: 12,
            ip_address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 105)),
            mac_address: Some(MacAddr::new([0xDC, 0xA6, 0x32, 0x44, 0x55, 0x66])),
            state: "Stale".to_string(),
            is_router: false,
            is_unreachable: false,
        },
        RawNeighborRow {
            interface_index: 12,
            ip_address: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            mac_address: Some(MacAddr::new([0x00, 0x15, 0x5D, 0xAA, 0xBB, 0xCC])),
            state: "Reachable".to_string(),
            is_router: true,
            is_unreachable: false,
        },
    ])
}

pub fn load_paths(cfg: &OfflineConfig) -> NetResult<Vec<RawPathRow>> {
    check_scenario_guard(cfg)?;
    if is_empty_scenario(cfg) {
        return Ok(Vec::new());
    }
    if let Some(path) = find_fixture_file(cfg, "paths.json") {
        return read_json_fixture(&path);
    }

    Ok(vec![
        RawPathRow {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            destination_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            link_speed_tx: Some(1_000_000_000),
            link_speed_rx: Some(1_000_000_000),
            rtt_mean_ms: Some(14),
            rtt_deviation_ms: Some(3),
            mtu: 1500,
            is_reachable: true,
        },
        RawPathRow {
            source_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0x10)),
            destination_ip: IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946)),
            next_hop: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            link_speed_tx: None,
            link_speed_rx: None,
            rtt_mean_ms: Some(19),
            rtt_deviation_ms: Some(4),
            mtu: 1480,
            is_reachable: true,
        },
    ])
}

pub fn offline_process_name(pid: u32) -> Option<String> {
    annotate_pid_meta(pid).0
}

pub fn offline_process_path(pid: u32) -> Option<String> {
    annotate_pid_meta(pid).1
}
