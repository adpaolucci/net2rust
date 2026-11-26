use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{RawAdapterRow, tcp_state_name};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CounterKind {
    Counter32,
    Counter64,
    Gauge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterSample {
    pub value: u64,
    pub kind: CounterKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterSnapshot {
    pub captured_at_ns: u64,
    pub values: BTreeMap<(String, String), CounterSample>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CounterRow {
    pub counter_group: String,
    pub metric_name: String,
    pub value: u64,
    pub delta_per_sec: Option<f64>,
}

/// Compute wrap-safe counter deltas and per-second rates between consecutive snapshots.
pub fn diff_counters(prev: Option<&CounterSnapshot>, curr: &CounterSnapshot) -> Vec<CounterRow> {
    let elapsed_secs = prev.and_then(|p| {
        if curr.captured_at_ns > p.captured_at_ns {
            Some((curr.captured_at_ns - p.captured_at_ns) as f64 / 1_000_000_000.0)
        } else {
            None
        }
    });

    curr.values
        .iter()
        .map(|((group, metric), curr_sample)| {
            let delta_per_sec = match (prev, elapsed_secs) {
                (Some(p), Some(dt)) if dt > 0.0 => {
                    p.values
                        .get(&(group.clone(), metric.clone()))
                        .and_then(|prev_sample| match curr_sample.kind {
                            CounterKind::Counter32 => {
                                let c = curr_sample.value & 0xFFFF_FFFF;
                                let pv = prev_sample.value & 0xFFFF_FFFF;
                                let delta = if c >= pv { c - pv } else { (1u64 << 32) - pv + c };
                                Some(delta as f64 / dt)
                            }
                            CounterKind::Counter64 => {
                                let delta = curr_sample.value.saturating_sub(prev_sample.value);
                                Some(delta as f64 / dt)
                            }
                            CounterKind::Gauge => None,
                        })
                }
                _ => None,
            };

            CounterRow {
                counter_group: group.clone(),
                metric_name: metric.clone(),
                value: curr_sample.value,
                delta_per_sec,
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterSnapshot {
    pub captured_at_ns: u64,
    pub rows: BTreeMap<u64, RawAdapterRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdapterWatchRow {
    pub adapter_name: String,
    pub description: String,
    pub media_state: String,
    pub link_speed: Option<u64>,
    pub bytes_sent: u64,
    pub bytes_recvd: u64,
    pub rx_rate_bps: Option<f64>,
    pub tx_rate_bps: Option<f64>,
    pub errors: u64,
    pub discards: u64,
}

/// Compute per-adapter Rx/Tx byte-per-second rates between consecutive `MIB_IF_TABLE2` snapshots.
pub fn diff_adapters(prev: Option<&AdapterSnapshot>, curr: &AdapterSnapshot) -> Vec<AdapterWatchRow> {
    let elapsed_secs = prev.and_then(|p| {
        if curr.captured_at_ns > p.captured_at_ns {
            Some((curr.captured_at_ns - p.captured_at_ns) as f64 / 1_000_000_000.0)
        } else {
            None
        }
    });

    curr.rows
        .iter()
        .map(|(luid, row)| {
            let (rx_rate_bps, tx_rate_bps) = match (prev, elapsed_secs) {
                (Some(p), Some(dt)) if dt > 0.0 => match p.rows.get(luid) {
                    Some(prev_row) => {
                        let rx = row.bytes_recvd.saturating_sub(prev_row.bytes_recvd) as f64 / dt;
                        let tx = row.bytes_sent.saturating_sub(prev_row.bytes_sent) as f64 / dt;
                        (Some(rx), Some(tx))
                    }
                    None => (None, None),
                },
                _ => (None, None),
            };

            AdapterWatchRow {
                adapter_name: row.adapter_name.clone(),
                description: row.description.clone(),
                media_state: row.media_state.clone(),
                link_speed: row.link_speed,
                bytes_sent: row.bytes_sent,
                bytes_recvd: row.bytes_recvd,
                rx_rate_bps,
                tx_rate_bps,
                errors: row.errors,
                discards: row.discards,
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TcpEndpointKey {
    pub ip_version: u8,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpEndpointState {
    pub state_code: u32,
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpSnapshot {
    pub captured_at: DateTime<Utc>,
    pub entries: BTreeMap<TcpEndpointKey, TcpEndpointState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpLogEvent {
    pub event_time: DateTime<Utc>,
    pub event_type: String,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
    pub process_name: Option<String>,
}

/// Stateful diff engine comparing consecutive `GetExtendedTcpTable` snapshots to detect `Listen`, `Open`, and `Close`.
#[derive(Debug, Default)]
pub struct TcpDiffEngine {
    prev: Option<TcpSnapshot>,
    closed_keys: BTreeSet<TcpEndpointKey>,
}

impl TcpDiffEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn step(&mut self, curr: &TcpSnapshot) -> Vec<TcpLogEvent> {
        let mut events = Vec::new();
        if let Some(prev) = &self.prev {
            for (key, curr_state) in &curr.entries {
                match prev.entries.get(key) {
                    None => {
                        self.closed_keys.remove(key);
                        let event_type = if curr_state.state_code == 2 { "Listen" } else { "Open" };
                        events.push(TcpLogEvent {
                            event_time: curr.captured_at,
                            event_type: event_type.to_string(),
                            local_addr: key.local_addr,
                            local_port: key.local_port,
                            remote_addr: key.remote_addr,
                            remote_port: key.remote_port,
                            state: tcp_state_name(curr_state.state_code).to_string(),
                            pid: key.pid,
                            process_name: curr_state.process_name.clone(),
                        });
                    }
                    Some(prev_state) if prev_state.state_code != curr_state.state_code => {
                        let event_type = if curr_state.state_code == 2 {
                            self.closed_keys.remove(key);
                            Some("Listen")
                        } else if prev_state.state_code == 2 {
                            self.closed_keys.remove(key);
                            Some("Open")
                        } else if matches!(curr_state.state_code, 1 | 12) {
                            if self.closed_keys.insert(key.clone()) {
                                Some("Close")
                            } else {
                                None
                            }
                        } else {
                            self.closed_keys.remove(key);
                            None
                        };
                        if let Some(kind) = event_type {
                            events.push(TcpLogEvent {
                                event_time: curr.captured_at,
                                event_type: kind.to_string(),
                                local_addr: key.local_addr,
                                local_port: key.local_port,
                                remote_addr: key.remote_addr,
                                remote_port: key.remote_port,
                                state: tcp_state_name(curr_state.state_code).to_string(),
                                pid: key.pid,
                                process_name: curr_state.process_name.clone(),
                            });
                        }
                    }
                    _ => {}
                }
            }

            for (key, prev_state) in &prev.entries {
                if !curr.entries.contains_key(key) && !self.closed_keys.remove(key) {
                    events.push(TcpLogEvent {
                        event_time: curr.captured_at,
                        event_type: "Close".to_string(),
                        local_addr: key.local_addr,
                        local_port: key.local_port,
                        remote_addr: key.remote_addr,
                        remote_port: key.remote_port,
                        state: tcp_state_name(prev_state.state_code).to_string(),
                        pid: key.pid,
                        process_name: prev_state.process_name.clone(),
                    });
                }
            }
        }
        self.prev = Some(curr.clone());
        events
    }

    pub fn diff_sequence(snapshots: &[TcpSnapshot]) -> Vec<TcpLogEvent> {
        let mut engine = Self::new();
        let mut all = Vec::new();
        for snap in snapshots {
            all.extend(engine.step(snap));
        }
        all
    }
}
