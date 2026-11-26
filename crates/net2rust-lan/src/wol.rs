use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use guap_mcp::{ActionCommand, ActionRiskLevel, McpToolError};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use net2rust_core::{MacAddr, NetContext, NetError, NetResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::common::{encode_hex_lower, reject_unknown_json_keys};
use crate::fixtures;
use crate::oui::OuiDatabase;
use crate::resolve::{DnsBackend, LiveWinSockDnsBackend};
use crate::scan::{ArpBackend, LiveWin32ArpBackend};

pub const DEFAULT_WOL_PORT: u16 = 9;
pub const MAGIC_PACKET_LEN: usize = 102;

/// Builds the 102-byte Wake-on-LAN Magic Packet (`6x 0xFF` followed by `16x MAC`).
pub fn build_magic_packet(mac: MacAddr) -> [u8; MAGIC_PACKET_LEN] {
    let mut pkt = [0u8; MAGIC_PACKET_LEN];
    pkt[0..6].fill(0xFF);
    let octets = mac.octets();
    for chunk in pkt[6..MAGIC_PACKET_LEN].as_chunks_mut::<6>().0 {
        *chunk = octets;
    }
    pkt
}

pub trait WolTransport: Send + Sync {
    fn send_magic_packet(&self, target: SocketAddr, packet: &[u8; MAGIC_PACKET_LEN]) -> NetResult<()>;
}

#[derive(Debug, Default)]
pub struct LiveUdpWolTransport;

impl WolTransport for LiveUdpWolTransport {
    fn send_magic_packet(&self, target: SocketAddr, packet: &[u8; MAGIC_PACKET_LEN]) -> NetResult<()> {
        let bind_addr = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = UdpSocket::bind(bind_addr)?;
        if target.is_ipv4() {
            socket.set_broadcast(true)?;
        }
        let sent = socket.send_to(packet, target)?;
        if sent != MAGIC_PACKET_LEN {
            return Err(NetError::NetworkError(format!(
                "short UDP Magic Packet send: sent {sent} of {MAGIC_PACKET_LEN} bytes"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolHostRecord {
    pub ip: IpAddr,
    pub hostname: String,
    pub mac: MacAddr,
    pub vendor: String,
    pub broadcast_ip: IpAddr,
    pub wol_port: u64,
    pub status: String,
    pub last_seen: DateTime<Utc>,
}

pub struct WakeMeOnLanProvider {
    ctx: NetContext,
    arp: Arc<dyn ArpBackend>,
    dns: Arc<dyn DnsBackend>,
}

impl WakeMeOnLanProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self {
            ctx,
            arp: Arc::new(LiveWin32ArpBackend),
            dns: Arc::new(LiveWinSockDnsBackend),
        }
    }

    pub fn with_backends(mut self, arp: Arc<dyn ArpBackend>, dns: Arc<dyn DnsBackend>) -> Self {
        self.arp = arp;
        self.dns = dns;
        self
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "lan.wol",
            "WakeMeOnLan — Wake-on-LAN Host Inventory",
            vec![
                ColumnDef::new("ip", "IP Address", ColumnType::IpAddr).with_width_hint(130),
                ColumnDef::new("hostname", "Computer Name", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("mac", "MAC Address", ColumnType::MacAddr).with_width_hint(150),
                ColumnDef::new("vendor", "Network Adapter Company", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("broadcast_ip", "Broadcast Address", ColumnType::IpAddr).with_width_hint(130),
                ColumnDef::new("wol_port", "WoL Port", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("status", "Status", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("last_seen", "Last Seen", ColumnType::Timestamp).with_width_hint(170),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn collect_records(&self) -> NetResult<Vec<WolHostRecord>> {
        if self.ctx.is_offline() {
            return fixtures::load_wol_records(&self.ctx);
        }

        let now = Utc::now();
        let oui = OuiDatabase::for_context(&self.ctx)?;
        let ifaces = self.arp.local_interfaces().unwrap_or_default();
        let entries = self.arp.arp_table()?;
        let mut records = Vec::with_capacity(entries.len());

        for entry in entries {
            let ip = IpAddr::V4(entry.ip);
            let hostname = self.dns.reverse_lookup(ip).ok().flatten().unwrap_or_default();
            let vendor = oui.lookup_or_unknown(entry.mac);
            let broadcast = ifaces
                .iter()
                .find(|i| i.cidr.contains(entry.ip))
                .map(|i| IpAddr::V4(i.cidr.broadcast()))
                .unwrap_or(IpAddr::V4(Ipv4Addr::BROADCAST));
            let status = if entry.state == "Incomplete" {
                "Offline"
            } else {
                "Online"
            };
            records.push(WolHostRecord {
                ip,
                hostname,
                mac: entry.mac,
                vendor,
                broadcast_ip: broadcast,
                wol_port: u64::from(DEFAULT_WOL_PORT),
                status: status.to_string(),
                last_seen: now,
            });
        }
        Ok(records)
    }
}

impl TableProvider for WakeMeOnLanProvider {
    fn tool_id(&self) -> &'static str {
        "lan.wol"
    }

    fn description(&self) -> &'static str {
        "Discover LAN hosts with MAC addresses and Wake-on-LAN broadcast targets (WakeMeOnLan)"
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
                let magic = build_magic_packet(rec.mac);
                let detail = json!({
                    "ip": rec.ip.to_string(),
                    "hostname": rec.hostname,
                    "mac": rec.mac.to_colon_string(),
                    "vendor": rec.vendor,
                    "broadcast_ip": rec.broadcast_ip.to_string(),
                    "wol_port": rec.wol_port,
                    "magic_packet_hex": encode_hex_lower(&magic),
                });
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.ip.to_string()),
                        CellValue::Text(rec.hostname),
                        CellValue::Text(rec.mac.to_colon_string()),
                        CellValue::Text(rec.vendor),
                        CellValue::Text(rec.broadcast_ip.to_string()),
                        CellValue::Uint(rec.wol_port),
                        CellValue::Text(rec.status),
                        CellValue::Timestamp(rec.last_seen),
                    ],
                )
                .with_detail_json(detail)
                .with_raw_bytes(magic.to_vec())
            })
            .collect();

        apply_query(&schema, &rows, req)
    }
}

pub struct WolSendAction {
    ctx: NetContext,
    transport: Option<Arc<dyn WolTransport>>,
}

impl WolSendAction {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx, transport: None }
    }

    pub fn with_transport(ctx: NetContext, transport: Arc<dyn WolTransport>) -> Self {
        Self {
            ctx,
            transport: Some(transport),
        }
    }
}

impl ActionCommand for WolSendAction {
    fn command_id(&self) -> &'static str {
        "lan.wol.send"
    }

    fn description(&self) -> &'static str {
        "Send a 102-byte UDP Wake-on-LAN Magic Packet (port 9 or 7) to wake a host"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "mac": {
                    "type": "string",
                    "description": "Target MAC address (colon, dash, dot, or bare hex)"
                },
                "broadcast_ip": {
                    "type": "string",
                    "description": "Target IPv4/IPv6 broadcast or unicast address",
                    "default": "255.255.255.255"
                },
                "port": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 65535,
                    "default": 9,
                    "description": "Destination UDP port (typically 9 or 7)"
                },
                "repeat_count": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10,
                    "default": 1,
                    "description": "Number of Magic Packet copies to transmit"
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "Preview Magic Packet without transmitting on UDP socket",
                    "default": false
                },
                "confirm_destructive": {
                    "type": "boolean",
                    "description": "Must be true to permit mutating execution",
                    "default": false
                }
            },
            "required": ["mac"],
            "additionalProperties": false
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        reject_unknown_json_keys(
            args,
            &[
                "mac",
                "broadcast_ip",
                "port",
                "repeat_count",
                "dry_run",
                "confirm_destructive",
            ],
        )?;

        let mac_raw = args
            .get("mac")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing required string parameter 'mac'".into()))?;
        let mac = MacAddr::parse(mac_raw).map_err(|e| McpToolError::InvalidParams(e.to_string()))?;

        let broadcast_ip: IpAddr = match args.get("broadcast_ip") {
            None | Some(Value::Null) => IpAddr::V4(Ipv4Addr::BROADCAST),
            Some(Value::String(s)) => s
                .trim()
                .parse()
                .map_err(|e| McpToolError::InvalidParams(format!("invalid broadcast_ip '{s}': {e}")))?,
            Some(_) => {
                return Err(McpToolError::InvalidParams("'broadcast_ip' must be a string".into()));
            }
        };

        let port: u16 = match args.get("port") {
            None | Some(Value::Null) => DEFAULT_WOL_PORT,
            Some(v) => {
                let raw = v
                    .as_u64()
                    .ok_or_else(|| McpToolError::InvalidParams("'port' must be an integer 1..=65535".into()))?;
                u16::try_from(raw)
                    .ok()
                    .filter(|&p| p >= 1)
                    .ok_or_else(|| McpToolError::InvalidParams("'port' must be in range 1..=65535".into()))?
            }
        };

        let repeat_count: u8 = match args.get("repeat_count") {
            None | Some(Value::Null) => 1,
            Some(v) => {
                let raw = v
                    .as_u64()
                    .ok_or_else(|| McpToolError::InvalidParams("'repeat_count' must be an integer 1..=10".into()))?;
                u8::try_from(raw)
                    .ok()
                    .filter(|&c| (1..=10).contains(&c))
                    .ok_or_else(|| McpToolError::InvalidParams("'repeat_count' must be in range 1..=10".into()))?
            }
        };

        let packet = build_magic_packet(mac);
        let packet_hex = encode_hex_lower(&packet);
        let target = SocketAddr::new(broadcast_ip, port);

        if dry_run {
            return Ok(json!({
                "command": "lan.wol.send",
                "dry_run": true,
                "would_send": true,
                "sent": false,
                "mac": mac.to_colon_string(),
                "target": target.to_string(),
                "port": port,
                "repeat_count": repeat_count,
                "packet_bytes": MAGIC_PACKET_LEN,
                "packet_hex": packet_hex,
            }));
        }

        if let Some(transport) = &self.transport {
            for _ in 0..repeat_count {
                transport
                    .send_magic_packet(target, &packet)
                    .map_err(McpToolError::from)?;
            }
            return Ok(json!({
                "command": "lan.wol.send",
                "dry_run": false,
                "sent": true,
                "bytes_sent": MAGIC_PACKET_LEN * usize::from(repeat_count),
                "mac": mac.to_colon_string(),
                "target": target.to_string(),
                "port": port,
                "repeat_count": repeat_count,
                "packet_bytes": MAGIC_PACKET_LEN,
                "packet_hex": packet_hex,
            }));
        }

        if self.ctx.is_offline() {
            return Ok(json!({
                "command": "lan.wol.send",
                "dry_run": false,
                "offline_simulated": true,
                "sent": true,
                "bytes_sent": MAGIC_PACKET_LEN * usize::from(repeat_count),
                "mac": mac.to_colon_string(),
                "target": target.to_string(),
                "port": port,
                "repeat_count": repeat_count,
                "packet_bytes": MAGIC_PACKET_LEN,
                "packet_hex": packet_hex,
            }));
        }

        let live = LiveUdpWolTransport;
        for _ in 0..repeat_count {
            live.send_magic_packet(target, &packet).map_err(McpToolError::from)?;
        }

        Ok(json!({
            "command": "lan.wol.send",
            "dry_run": false,
            "sent": true,
            "bytes_sent": MAGIC_PACKET_LEN * usize::from(repeat_count),
            "mac": mac.to_colon_string(),
            "target": target.to_string(),
            "port": port,
            "repeat_count": repeat_count,
            "packet_bytes": MAGIC_PACKET_LEN,
            "packet_hex": packet_hex,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_magic_packet_layout_102_bytes() {
        let mac = MacAddr::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let pkt = build_magic_packet(mac);
        assert_eq!(pkt.len(), 102);
        assert_eq!(&pkt[0..6], &[0xff; 6]);
        for i in 0..16 {
            assert_eq!(&pkt[6 + i * 6..12 + i * 6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        }
    }

    struct CountingTransport {
        calls: AtomicUsize,
    }
    impl WolTransport for CountingTransport {
        fn send_magic_packet(&self, _target: SocketAddr, packet: &[u8; MAGIC_PACKET_LEN]) -> NetResult<()> {
            assert_eq!(packet.len(), 102);
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn test_wol_send_dry_run_and_loopback_udp() {
        let transport = Arc::new(CountingTransport {
            calls: AtomicUsize::new(0),
        });
        let action = WolSendAction::with_transport(NetContext::live(), transport.clone());

        let preview = action
            .execute(&json!({ "mac": "aa:bb:cc:dd:ee:ff", "port": 7 }), true)
            .unwrap();
        assert_eq!(preview["dry_run"], true);
        assert_eq!(preview["would_send"], true);
        assert_eq!(preview["sent"], false);
        assert_eq!(preview["packet_bytes"], 102);
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);

        // Live UDP loopback send using LiveUdpWolTransport on 127.0.0.1:0
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let port = receiver.local_addr().unwrap().port();

        let live_action = WolSendAction::new(NetContext::live());
        let res = live_action
            .execute(
                &json!({
                    "mac": "00:11:22:33:44:55",
                    "broadcast_ip": "127.0.0.1",
                    "port": port,
                    "repeat_count": 2
                }),
                false,
            )
            .unwrap();
        assert_eq!(res["sent"], true);
        assert_eq!(res["bytes_sent"], 204);

        let mut buf = [0u8; 256];
        let (n, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(n, 102);
        assert_eq!(
            buf[..102],
            build_magic_packet(MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
    }

    #[test]
    fn test_wol_send_rejects_unknown_and_non_object_args() {
        let transport = Arc::new(CountingTransport {
            calls: AtomicUsize::new(0),
        });
        let action = WolSendAction::with_transport(NetContext::live(), transport.clone());

        for dry_run in [true, false] {
            let err = action
                .execute(
                    &json!({
                        "mac": "aa:bb:cc:dd:ee:ff",
                        "confirm_destructive": true,
                        "dry_run": dry_run,
                        "unexpected_attacker_field": "payload"
                    }),
                    dry_run,
                )
                .unwrap_err();
            assert!(
                matches!(err, McpToolError::InvalidParams(ref msg) if msg.contains("unexpected_attacker_field")),
                "expected InvalidParams for unknown field when dry_run={dry_run}, got {err:?}"
            );
        }

        let non_obj_err = action.execute(&json!(["aa:bb:cc:dd:ee:ff"]), true).unwrap_err();
        assert!(matches!(non_obj_err, McpToolError::InvalidParams(_)));
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
    }
}
