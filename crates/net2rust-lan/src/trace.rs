use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use net2rust_core::{NetContext, NetResult};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::fixtures;
use crate::geoip::GeoIpDatabase;
use crate::ping::{LivePingBackend, PingBackend, PingStatus};
use crate::resolve::{DnsBackend, LiveWinSockDnsBackend};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceHopRecord {
    pub target: String,
    pub hop: u64,
    pub ip: Option<IpAddr>,
    pub hostname: String,
    pub rtt_ms: Option<f64>,
    pub status: String,
    pub country_code: String,
    pub country_name: String,
    pub asn: String,
    pub as_org: String,
}

pub fn run_traceroute(
    target_label: &str,
    target_ip: IpAddr,
    max_hops: u8,
    timeout: Duration,
    ping: &dyn PingBackend,
    dns: &dyn DnsBackend,
    geoip: &GeoIpDatabase,
) -> NetResult<Vec<TraceHopRecord>> {
    let mut hops = Vec::new();
    let max_hops = max_hops.clamp(1, 64);

    for ttl in 1..=max_hops {
        let probe = ping.ping_icmp(target_ip, timeout, Some(ttl), b"GUAP-TRACE")?;
        let hop_ip = probe.responder;
        let hostname = match hop_ip {
            Some(ip) => dns.reverse_lookup(ip).ok().flatten().unwrap_or_default(),
            None => String::new(),
        };
        let geo = hop_ip.map(|ip| geoip.lookup(ip)).unwrap_or_default();
        let status_label = match probe.status {
            PingStatus::Succeeded => "Reply",
            PingStatus::TtlExpired => "TTL Expired",
            PingStatus::TimedOut => "Timed Out",
            PingStatus::Failed => "Failed",
        };

        hops.push(TraceHopRecord {
            target: target_label.to_string(),
            hop: u64::from(ttl),
            ip: hop_ip,
            hostname,
            rtt_ms: probe.rtt_ms,
            status: status_label.to_string(),
            country_code: geo.country_code,
            country_name: geo.country_name,
            asn: geo.asn,
            as_org: geo.as_org,
        });

        if probe.status == PingStatus::Succeeded && hop_ip == Some(target_ip) {
            break;
        }
    }

    Ok(hops)
}

pub struct GeoTracerouteProvider {
    ctx: NetContext,
    target: String,
    max_hops: u8,
    custom_target: bool,
    ping: Arc<dyn PingBackend>,
    dns: Arc<dyn DnsBackend>,
}

impl GeoTracerouteProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self {
            ctx,
            target: Ipv4Addr::LOCALHOST.to_string(),
            max_hops: 30,
            custom_target: false,
            ping: Arc::new(LivePingBackend),
            dns: Arc::new(LiveWinSockDnsBackend),
        }
    }

    pub fn with_target(mut self, target: impl Into<String>, max_hops: u8) -> Self {
        self.target = target.into();
        self.max_hops = max_hops;
        self.custom_target = true;
        self
    }

    pub fn with_backends(mut self, ping: Arc<dyn PingBackend>, dns: Arc<dyn DnsBackend>) -> Self {
        self.ping = ping;
        self.dns = dns;
        self
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "lan.trace",
            "GeoIP Traceroute",
            vec![
                ColumnDef::new("target", "Target", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("hop", "Hop", ColumnType::Uint).with_width_hint(60),
                ColumnDef::new("ip", "Hop IP", ColumnType::IpAddr).with_width_hint(130),
                ColumnDef::new("hostname", "Hostname", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("rtt_ms", "RTT (ms)", ColumnType::Float).with_width_hint(90),
                ColumnDef::new("status", "Status", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("country_code", "Country", ColumnType::Text).with_width_hint(80),
                ColumnDef::new("country_name", "Country Name", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("asn", "ASN", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("as_org", "AS Organization", ColumnType::Text).with_width_hint(200),
            ],
        )
        .with_default_sort(1, SortDirection::Asc)
    }

    fn collect_records(&self) -> NetResult<Vec<TraceHopRecord>> {
        if self.ctx.is_offline() && !self.custom_target {
            return fixtures::load_trace_records(&self.ctx);
        }
        let geoip = GeoIpDatabase::for_context(&self.ctx)?;
        let target_ip = if let Ok(ip) = self.target.trim().parse::<IpAddr>() {
            ip
        } else {
            self.dns
                .forward_lookup(&self.target)?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    net2rust_core::NetError::NetworkError(format!("cannot resolve trace target '{}'", self.target))
                })?
        };
        let timeout = self.ctx.timeout.min(Duration::from_secs(1));
        run_traceroute(
            &self.target,
            target_ip,
            self.max_hops,
            timeout,
            self.ping.as_ref(),
            self.dns.as_ref(),
            &geoip,
        )
    }
}

impl TableProvider for GeoTracerouteProvider {
    fn tool_id(&self) -> &'static str {
        "lan.trace"
    }

    fn description(&self) -> &'static str {
        "Trace network hops with ICMP TTL probes and offline GeoIP country/ASN enrichment"
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
                let detail = json!({
                    "target": rec.target,
                    "hop": rec.hop,
                    "ip": rec.ip.map(|i| i.to_string()),
                    "hostname": rec.hostname,
                    "status": rec.status,
                    "country_code": rec.country_code,
                    "asn": rec.asn,
                    "as_org": rec.as_org,
                });
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.target),
                        CellValue::Uint(rec.hop),
                        rec.ip
                            .map(|i| CellValue::Text(i.to_string()))
                            .unwrap_or(CellValue::Null),
                        CellValue::Text(rec.hostname),
                        rec.rtt_ms.map(CellValue::Float).unwrap_or(CellValue::Null),
                        CellValue::Text(rec.status),
                        CellValue::Text(rec.country_code),
                        CellValue::Text(rec.country_name),
                        CellValue::Text(rec.asn),
                        CellValue::Text(rec.as_org),
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
    use super::*;
    use crate::ping::PingProbeResult;

    struct MockTracePing;
    impl PingBackend for MockTracePing {
        fn ping_icmp(
            &self,
            target: IpAddr,
            _timeout: Duration,
            ttl: Option<u8>,
            _payload: &[u8],
        ) -> NetResult<PingProbeResult> {
            match ttl.unwrap_or(64) {
                1 => Ok(PingProbeResult {
                    responder: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    status: PingStatus::TtlExpired,
                    rtt_ms: Some(0.8),
                    ttl: Some(1),
                    error_detail: None,
                }),
                2 => Ok(PingProbeResult {
                    responder: None,
                    status: PingStatus::TimedOut,
                    rtt_ms: None,
                    ttl: None,
                    error_detail: Some("timeout".into()),
                }),
                _ => Ok(PingProbeResult {
                    responder: Some(target),
                    status: PingStatus::Succeeded,
                    rtt_ms: Some(11.4),
                    ttl: Some(58),
                    error_detail: None,
                }),
            }
        }

        fn ping_tcp(&self, _target: IpAddr, _port: u16, _timeout: Duration) -> NetResult<PingProbeResult> {
            unreachable!()
        }
    }

    struct MockTraceDns;
    impl DnsBackend for MockTraceDns {
        fn forward_lookup(&self, _host: &str) -> NetResult<Vec<IpAddr>> {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))])
        }
        fn reverse_lookup(&self, ip: IpAddr) -> NetResult<Option<String>> {
            if ip == IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)) {
                Ok(Some("dns.google".into()))
            } else {
                Ok(None)
            }
        }
    }

    #[test]
    fn test_traceroute_multi_hop_and_geoip_enrichment() {
        let provider = GeoTracerouteProvider::new(NetContext::live())
            .with_target("8.8.8.8", 10)
            .with_backends(Arc::new(MockTracePing), Arc::new(MockTraceDns));
        let data = provider.query(&TableQuery::default()).unwrap();
        assert_eq!(data.total_rows, 3);
        assert_eq!(data.rows[0].cells[1], CellValue::Uint(1));
        assert_eq!(data.rows[0].cells[5], CellValue::Text("TTL Expired".into()));
        assert_eq!(data.rows[0].cells[7], CellValue::Text("Private/LAN".into()));

        assert_eq!(data.rows[1].cells[1], CellValue::Uint(2));
        assert_eq!(data.rows[1].cells[5], CellValue::Text("Timed Out".into()));
        assert_eq!(data.rows[1].cells[2], CellValue::Null);

        assert_eq!(data.rows[2].cells[1], CellValue::Uint(3));
        assert_eq!(data.rows[2].cells[3], CellValue::Text("dns.google".into()));
        assert_eq!(data.rows[2].cells[5], CellValue::Text("Reply".into()));
        assert_eq!(data.rows[2].cells[6], CellValue::Text("US".into()));
        assert_eq!(data.rows[2].cells[8], CellValue::Text("AS15169".into()));

        // Custom target "127.0.0.1" under offline context still runs configured target/backends.
        let custom_offline = GeoTracerouteProvider::new(NetContext::offline(Default::default()))
            .with_target("127.0.0.1", 3)
            .with_backends(Arc::new(MockTracePing), Arc::new(MockTraceDns));
        let offline_data = custom_offline.query(&TableQuery::default()).unwrap();
        assert_eq!(offline_data.total_rows, 3);
        assert_eq!(offline_data.rows[0].cells[0], CellValue::Text("127.0.0.1".into()));
    }
}
