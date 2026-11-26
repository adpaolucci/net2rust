use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use net2rust_core::{MacAddr, NetContext, NetError, NetResult};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::common::run_bounded;
use crate::fixtures;
use crate::oui::OuiDatabase;

pub const NBSTAT_PORT: u16 = 137;
const QTYPE_NBSTAT: u16 = 0x0021;
const QCLASS_IN: u16 = 0x0001;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NbstatNameEntry {
    pub name: String,
    pub suffix: u8,
    pub flags: u16,
    pub is_group: bool,
    pub is_active: bool,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NbstatResponse {
    pub txid: u16,
    pub entries: Vec<NbstatNameEntry>,
    pub mac: Option<MacAddr>,
    pub computer_name: Option<String>,
    pub workgroup: Option<String>,
    pub user_hint: Option<String>,
    pub is_master_browser: bool,
    pub is_domain_controller: bool,
}

impl NbstatResponse {
    pub fn services_summary(&self) -> String {
        let mut items = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            items.push(format!("{}<{:02X}>", entry.role, entry.suffix));
        }
        items.sort();
        items.dedup();
        items.join(", ")
    }
}

pub fn netbios_suffix_role(suffix: u8, is_group: bool) -> &'static str {
    match (suffix, is_group) {
        (0x00, false) => "Workstation",
        (0x00, true) => "Domain/Workgroup",
        (0x01, false) => "Messenger",
        (0x01, true) => "MasterBrowser",
        (0x03, _) => "Messenger",
        (0x06, _) => "RASServer",
        (0x1B, _) => "DomainMasterBrowser",
        (0x1C, _) => "DomainController",
        (0x1D, _) => "MasterBrowser",
        (0x1E, _) => "BrowserElection",
        (0x1F, _) => "NetDDE",
        (0x20, _) => "FileServer",
        (0x21, _) => "RASClient",
        (0x22, _) => "MSExchangeInterchange",
        (0x23, _) => "MSExchangeStore",
        (0x24, _) => "MSExchangeDirectory",
        (0xBE, _) => "NetworkMonitorAgent",
        (0xBF, _) => "NetworkMonitorApp",
        _ => "Service",
    }
}

/// RFC 1001 First-Level Encoding of a 16-byte NetBIOS name into a 34-byte DNS label.
pub fn encode_netbios_name(raw_name: &[u8; 16]) -> [u8; 34] {
    let mut out = [0u8; 34];
    out[0] = 0x20; // length = 32
    for (i, &b) in raw_name.iter().enumerate() {
        out[1 + i * 2] = b'A' + (b >> 4);
        out[1 + i * 2 + 1] = b'A' + (b & 0x0F);
    }
    out[33] = 0x00;
    out
}

/// Builds the 50-byte RFC 1001/1002 NBSTAT (`0x0021`) wildcard `*` query packet.
pub fn build_nbstat_query(txid: u16) -> [u8; 50] {
    let mut pkt = [0u8; 50];
    pkt[0..2].copy_from_slice(&txid.to_be_bytes());
    // Flags = 0x0000, QDCOUNT = 1, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
    pkt[4..6].copy_from_slice(&1u16.to_be_bytes());

    let mut wildcard = [0u8; 16];
    wildcard[0] = b'*';
    let encoded_name = encode_netbios_name(&wildcard);
    pkt[12..46].copy_from_slice(&encoded_name);

    pkt[46..48].copy_from_slice(&QTYPE_NBSTAT.to_be_bytes());
    pkt[48..50].copy_from_slice(&QCLASS_IN.to_be_bytes());
    pkt
}

/// Bounds-checked DNS/NBNS wire name skipper with pointer loop & depth protection.
fn skip_dns_name(packet: &[u8], start: usize) -> NetResult<usize> {
    let mut pos = start;
    let mut jumped = false;
    let mut return_pos = 0usize;
    let mut hops = 0usize;
    let mut seen_offsets = Vec::new();

    loop {
        if pos >= packet.len() {
            return Err(NetError::ParseError("truncated DNS/NetBIOS name".into()));
        }
        let len = packet[pos];
        if len == 0 {
            let next = pos + 1;
            return Ok(if jumped { return_pos } else { next });
        }
        match len & 0xC0 {
            0xC0 => {
                if pos + 1 >= packet.len() {
                    return Err(NetError::ParseError("truncated DNS compression pointer".into()));
                }
                let ptr_offset = (((len & 0x3F) as usize) << 8) | (packet[pos + 1] as usize);
                if ptr_offset >= packet.len() {
                    return Err(NetError::ParseError("DNS compression pointer out of bounds".into()));
                }
                if seen_offsets.contains(&ptr_offset) {
                    return Err(NetError::ParseError("DNS compression pointer loop detected".into()));
                }
                hops += 1;
                if hops > 16 {
                    return Err(NetError::ParseError("DNS compression pointer depth exceeded".into()));
                }
                seen_offsets.push(ptr_offset);
                if !jumped {
                    return_pos = pos + 2;
                    jumped = true;
                }
                pos = ptr_offset;
            }
            0x00 => {
                let label_len = len as usize;
                let next = pos
                    .checked_add(1 + label_len)
                    .ok_or_else(|| NetError::ParseError("DNS label length overflow".into()))?;
                if next > packet.len() {
                    return Err(NetError::ParseError("truncated DNS label".into()));
                }
                pos = next;
            }
            _ => {
                return Err(NetError::ParseError(format!("invalid DNS label type byte 0x{len:02x}")));
            }
        }
    }
}

/// Parses an RFC 1002 NBSTAT response packet with full bounds checking.
pub fn parse_nbstat_response(packet: &[u8], expected_txid: Option<u16>) -> NetResult<NbstatResponse> {
    if packet.len() < 12 {
        return Err(NetError::ParseError(format!(
            "NBSTAT packet too short ({} bytes < 12)",
            packet.len()
        )));
    }
    let txid = u16::from_be_bytes([packet[0], packet[1]]);
    if let Some(exp) = expected_txid
        && txid != exp
    {
        return Err(NetError::ParseError(format!(
            "NBSTAT transaction ID mismatch: expected 0x{exp:04x}, got 0x{txid:04x}"
        )));
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if (flags & 0x8000) == 0 {
        return Err(NetError::ParseError("NBSTAT packet is a query, not a response".into()));
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(NetError::ParseError(format!(
            "NBSTAT response returned error RCODE={rcode}"
        )));
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    if ancount == 0 {
        return Err(NetError::ParseError("NBSTAT response has zero answers".into()));
    }

    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_dns_name(packet, pos)?;
        if pos + 4 > packet.len() {
            return Err(NetError::ParseError("truncated NBSTAT question section".into()));
        }
        pos += 4;
    }

    // Read Answer RRs until we find TYPE == NBSTAT (0x0021)
    for _ in 0..ancount {
        pos = skip_dns_name(packet, pos)?;
        if pos + 10 > packet.len() {
            return Err(NetError::ParseError("truncated NBSTAT answer RR header".into()));
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let rclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
        let rdlength = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > packet.len() {
            return Err(NetError::ParseError("truncated NBSTAT answer RDATA".into()));
        }
        let rdata = &packet[pos..pos + rdlength];
        pos += rdlength;

        if rtype == QTYPE_NBSTAT && rclass == QCLASS_IN {
            return decode_nbstat_rdata(txid, rdata);
        }
    }

    Err(NetError::ParseError("no NBSTAT answer RR found in response".into()))
}

fn decode_nbstat_rdata(txid: u16, rdata: &[u8]) -> NetResult<NbstatResponse> {
    if rdata.is_empty() {
        return Err(NetError::ParseError("empty NBSTAT RDATA".into()));
    }
    let num_names = rdata[0] as usize;
    let names_end = 1 + num_names * 18;
    if rdata.len() < names_end {
        return Err(NetError::ParseError(format!(
            "NBSTAT RDATA truncated: expected >= {names_end} bytes for {num_names} names, got {}",
            rdata.len()
        )));
    }

    let mut entries = Vec::with_capacity(num_names);
    for idx in 0..num_names {
        let off = 1 + idx * 18;
        let rec = &rdata[off..off + 18];
        let raw_name = &rec[0..15];
        let name = String::from_utf8_lossy(raw_name)
            .trim_end_matches([' ', '\0'])
            .to_string();
        let suffix = rec[15];
        let flags = u16::from_be_bytes([rec[16], rec[17]]);
        let is_group = (flags & 0x8000) != 0;
        let is_active = (flags & 0x0400) != 0;
        let role = netbios_suffix_role(suffix, is_group).to_string();
        entries.push(NbstatNameEntry {
            name,
            suffix,
            flags,
            is_group,
            is_active,
            role,
        });
    }

    let mac = if rdata.len() >= names_end + 6 {
        let mut octets = [0u8; 6];
        octets.copy_from_slice(&rdata[names_end..names_end + 6]);
        let candidate = MacAddr::new(octets);
        if candidate.is_zero() { None } else { Some(candidate) }
    } else {
        None
    };

    let computer_name = entries
        .iter()
        .find(|e| e.suffix == 0x00 && !e.is_group && !e.name.is_empty())
        .or_else(|| {
            entries
                .iter()
                .find(|e| e.suffix == 0x20 && !e.is_group && !e.name.is_empty())
        })
        .map(|e| e.name.clone());

    let workgroup = entries
        .iter()
        .find(|e| (e.suffix == 0x00 || e.suffix == 0x1E) && e.is_group && !e.name.is_empty())
        .map(|e| e.name.clone());

    let user_hint = entries
        .iter()
        .find(|e| {
            e.suffix == 0x03 && !e.is_group && !e.name.is_empty() && computer_name.as_deref() != Some(e.name.as_str())
        })
        .map(|e| e.name.clone());

    let is_master_browser = entries
        .iter()
        .any(|e| matches!(e.suffix, 0x1D | 0x1B) || (e.suffix == 0x01 && e.is_group));

    let is_domain_controller = entries.iter().any(|e| e.suffix == 0x1C);

    Ok(NbstatResponse {
        txid,
        entries,
        mac,
        computer_name,
        workgroup,
        user_hint,
        is_master_browser,
        is_domain_controller,
    })
}

pub trait NetbiosBackend: Send + Sync {
    fn query_nbstat(&self, ip: Ipv4Addr, timeout: Duration) -> NetResult<Option<(NbstatResponse, f64)>>;
}

#[derive(Debug, Default)]
pub struct LiveUdpNetbiosBackend;

impl NetbiosBackend for LiveUdpNetbiosBackend {
    fn query_nbstat(&self, ip: Ipv4Addr, timeout: Duration) -> NetResult<Option<(NbstatResponse, f64)>> {
        query_nbstat_udp_socket(SocketAddr::new(IpAddr::V4(ip), NBSTAT_PORT), timeout, 0x4E42)
    }
}

/// Sends an NBSTAT query to an explicit `SocketAddr` (useful for both port 137 live
/// scanning and `127.0.0.1:0` loopback integration tests).
pub fn query_nbstat_udp_socket(
    target: SocketAddr,
    timeout: Duration,
    txid: u16,
) -> NetResult<Option<(NbstatResponse, f64)>> {
    let bind_addr = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind_addr)?;
    let effective_timeout = timeout.max(Duration::from_millis(50));
    socket.set_read_timeout(Some(effective_timeout))?;
    socket.set_write_timeout(Some(effective_timeout))?;

    let query = build_nbstat_query(txid);
    let started = Instant::now();
    socket.send_to(&query, target)?;

    let mut buf = [0u8; 4096];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, _peer)) => {
                let rtt_ms = started.elapsed().as_secs_f64() * 1000.0;
                match parse_nbstat_response(&buf[..len], Some(txid)) {
                    Ok(parsed) => return Ok(Some((parsed, rtt_ms))),
                    Err(_) => {
                        if started.elapsed() >= effective_timeout {
                            return Ok(None);
                        }
                    }
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(None);
            }
            Err(err) => return Err(NetError::Io(err)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetbiosHostRecord {
    pub ip: IpAddr,
    pub computer_name: String,
    pub workgroup: String,
    pub mac: Option<MacAddr>,
    pub vendor: String,
    pub is_master_browser: bool,
    pub is_domain_controller: bool,
    pub services: String,
    pub rtt_ms: f64,
    pub user_hint: Option<String>,
}

pub struct NetBScannerProvider {
    ctx: NetContext,
    targets: Vec<Ipv4Addr>,
    backend: Arc<dyn NetbiosBackend>,
}

impl NetBScannerProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self {
            ctx,
            targets: vec![Ipv4Addr::LOCALHOST],
            backend: Arc::new(LiveUdpNetbiosBackend),
        }
    }

    pub fn with_targets(mut self, targets: Vec<Ipv4Addr>) -> Self {
        self.targets = targets;
        self
    }

    pub fn with_backend(mut self, backend: Arc<dyn NetbiosBackend>) -> Self {
        self.backend = backend;
        self
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "lan.netbios",
            "NetBScanner — NetBIOS NBSTAT Scanner",
            vec![
                ColumnDef::new("ip", "IP Address", ColumnType::IpAddr).with_width_hint(130),
                ColumnDef::new("computer_name", "Computer Name", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("workgroup", "Workgroup / Domain", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("mac", "MAC Address", ColumnType::MacAddr).with_width_hint(150),
                ColumnDef::new("vendor", "Adapter Vendor", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("is_master_browser", "Master Browser", ColumnType::Bool).with_width_hint(110),
                ColumnDef::new("is_domain_controller", "Domain Controller", ColumnType::Bool).with_width_hint(120),
                ColumnDef::new("services", "NetBIOS Services", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("rtt_ms", "RTT (ms)", ColumnType::Float).with_width_hint(90),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn collect_records(&self) -> NetResult<Vec<NetbiosHostRecord>> {
        if self.ctx.is_offline() {
            return fixtures::load_netbios_records(&self.ctx);
        }
        let oui = OuiDatabase::for_context(&self.ctx)?;
        let timeout = self.ctx.timeout.min(Duration::from_millis(500));
        let probed = run_bounded(&self.targets, 16, |&ip| {
            self.backend.query_nbstat(ip, timeout).map(|opt| (ip, opt))
        });

        let mut records = Vec::new();
        for res in probed {
            if let Ok((ip, Some((resp, rtt_ms)))) = res {
                let vendor = resp
                    .mac
                    .map(|m| oui.lookup_or_unknown(m))
                    .unwrap_or_else(|| "Unknown".to_string());
                records.push(NetbiosHostRecord {
                    ip: IpAddr::V4(ip),
                    computer_name: resp.computer_name.clone().unwrap_or_default(),
                    workgroup: resp.workgroup.clone().unwrap_or_default(),
                    mac: resp.mac,
                    vendor,
                    is_master_browser: resp.is_master_browser,
                    is_domain_controller: resp.is_domain_controller,
                    services: resp.services_summary(),
                    rtt_ms,
                    user_hint: resp.user_hint,
                });
            }
        }
        Ok(records)
    }
}

impl TableProvider for NetBScannerProvider {
    fn tool_id(&self) -> &'static str {
        "lan.netbios"
    }

    fn description(&self) -> &'static str {
        "Scan hosts via RFC 1001/1002 UDP port 137 NBSTAT queries (NetBScanner)"
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
                let mac_cell = rec
                    .mac
                    .map(|m| CellValue::Text(m.to_colon_string()))
                    .unwrap_or(CellValue::Null);
                let detail = json!({
                    "ip": rec.ip.to_string(),
                    "computer_name": rec.computer_name,
                    "workgroup": rec.workgroup,
                    "mac": rec.mac.map(|m| m.to_colon_string()),
                    "vendor": rec.vendor,
                    "user_hint": rec.user_hint,
                    "is_master_browser": rec.is_master_browser,
                    "is_domain_controller": rec.is_domain_controller,
                    "services": rec.services,
                });
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.ip.to_string()),
                        CellValue::Text(rec.computer_name),
                        CellValue::Text(rec.workgroup),
                        mac_cell,
                        CellValue::Text(rec.vendor),
                        CellValue::Bool(rec.is_master_browser),
                        CellValue::Bool(rec.is_domain_controller),
                        CellValue::Text(rec.services),
                        CellValue::Float(rec.rtt_ms),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        apply_query(&schema, &rows, req)
    }
}

#[cfg(test)]
pub(crate) fn build_synthetic_nbstat_response(txid: u16, entries: &[(&str, u8, u16)], mac: [u8; 6]) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&0x8400u16.to_be_bytes()); // QR=1, AA=1, RCODE=0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT = 0
    pkt.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    let mut wildcard = [0u8; 16];
    wildcard[0] = b'*';
    pkt.extend_from_slice(&encode_netbios_name(&wildcard));
    pkt.extend_from_slice(&QTYPE_NBSTAT.to_be_bytes());
    pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes()); // TTL

    let rdlength = 1 + entries.len() * 18 + 6;
    pkt.extend_from_slice(&(rdlength as u16).to_be_bytes());
    pkt.push(entries.len() as u8);
    for &(name, suffix, flags) in entries {
        let mut padded = [b' '; 15];
        let bytes = name.as_bytes();
        let copy_len = bytes.len().min(15);
        padded[..copy_len].copy_from_slice(&bytes[..copy_len]);
        pkt.extend_from_slice(&padded);
        pkt.push(suffix);
        pkt.extend_from_slice(&flags.to_be_bytes());
    }
    pkt.extend_from_slice(&mac);
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nbstat_query_builder_rfc1001() {
        let pkt = build_nbstat_query(0xABCD);
        assert_eq!(pkt.len(), 50);
        assert_eq!(&pkt[0..2], &[0xAB, 0xCD]);
        assert_eq!(&pkt[4..6], &[0x00, 0x01]); // QDCOUNT=1
        assert_eq!(pkt[12], 0x20);
        // '*' = 0x2A -> ('A'+2)='C', ('A'+10)='K'; 0x00 -> "AA"
        assert_eq!(&pkt[13..45], b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(pkt[45], 0x00);
        assert_eq!(&pkt[46..48], &[0x00, 0x21]); // NBSTAT
        assert_eq!(&pkt[48..50], &[0x00, 0x01]); // IN
    }

    #[test]
    fn test_nbstat_response_decoder_and_loopback_socket() {
        let raw = build_synthetic_nbstat_response(
            0x1337,
            &[
                ("FILESERVER01", 0x00, 0x0400),
                ("CORP", 0x00, 0x8400),
                ("FILESERVER01", 0x20, 0x0400),
                ("CORP", 0x1C, 0x8400),
                ("__MSBROWSE__", 0x01, 0x8400),
                ("ALICE", 0x03, 0x0400),
            ],
            [0x00, 0x15, 0x5d, 0xaa, 0xbb, 0xcc],
        );

        let parsed = parse_nbstat_response(&raw, Some(0x1337)).unwrap();
        assert_eq!(parsed.computer_name.as_deref(), Some("FILESERVER01"));
        assert_eq!(parsed.workgroup.as_deref(), Some("CORP"));
        assert_eq!(parsed.user_hint.as_deref(), Some("ALICE"));
        assert!(parsed.is_master_browser);
        assert!(parsed.is_domain_controller);
        assert_eq!(parsed.mac, Some(MacAddr::new([0x00, 0x15, 0x5d, 0xaa, 0xbb, 0xcc])));

        // Ephemeral UDP loopback test (zero external traffic)
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut req = [0u8; 128];
            let (n, peer) = server.recv_from(&mut req).unwrap();
            assert_eq!(n, 50);
            let txid = u16::from_be_bytes([req[0], req[1]]);
            let resp = build_synthetic_nbstat_response(
                txid,
                &[("LABHOST", 0x00, 0x0400), ("WORKGROUP", 0x00, 0x8400)],
                [0x08, 0x00, 0x27, 0x11, 0x22, 0x33],
            );
            server.send_to(&resp, peer).unwrap();
        });

        let (resp, rtt) = query_nbstat_udp_socket(addr, Duration::from_secs(2), 0x4242)
            .unwrap()
            .expect("expected loopback NBSTAT reply");
        assert_eq!(resp.computer_name.as_deref(), Some("LABHOST"));
        assert_eq!(resp.workgroup.as_deref(), Some("WORKGROUP"));
        assert!(rtt >= 0.0);
        handle.join().unwrap();
    }

    #[test]
    fn test_nbstat_rejects_malformed_and_pointer_loops() {
        assert!(parse_nbstat_response(&[0u8; 5], None).is_err());

        // Self-referential DNS pointer loop at offset 12 -> 0xC0 0x0C
        let loop_pkt = vec![
            0x12, 0x34, 0x84, 0x00, // txid, flags
            0x00, 0x01, 0x00, 0x01, // qd=1, an=1
            0x00, 0x00, 0x00, 0x00, // ns=0, ar=0
            0xC0, 0x0C, 0x00, 0x21, 0x00, 0x01,
        ];
        assert!(parse_nbstat_response(&loop_pkt, Some(0x1234)).is_err());

        // Truncated RDATA claims 10 names with only 2 bytes
        let mut trunc = build_synthetic_nbstat_response(0x9999, &[], [0; 6]);
        let last = trunc.len() - 7; // index of num_names before 6-byte MAC
        trunc[last] = 10;
        assert!(parse_nbstat_response(&trunc, Some(0x9999)).is_err());
    }
}
