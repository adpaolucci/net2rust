use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, Utc};
use net2rust_core::{MacAddr, NetContext, NetError, NetResult};
use serde::de::DeserializeOwned;

use crate::netbios::NetbiosHostRecord;
use crate::oui::OuiDatabase;
use crate::ping::PingSummaryRecord;
use crate::resolve::ResolveRecord;
use crate::scan::{ConnectLogEngine, ConnectLogEvent, HostObservation, LanScanHostRecord, WnetDeviceRecord};
use crate::smb::{OpenFileRecord, ShareRecord};
use crate::speedtest::DownloadMeasurement;
use crate::trace::TraceHopRecord;
use crate::wol::WolHostRecord;

fn ts(rfc3339: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(rfc3339)
        .expect("valid static timestamp")
        .with_timezone(&Utc)
}

fn try_load_override<T: DeserializeOwned>(ctx: &NetContext, tool_id: &str) -> NetResult<Option<Vec<T>>> {
    let Some(dir) = ctx.offline_config().and_then(|c| c.fixture_dir.as_ref()) else {
        return Ok(None);
    };
    let sub = tool_id.strip_prefix("lan.").unwrap_or(tool_id);
    for candidate in [dir.join(format!("{tool_id}.json")), dir.join(format!("{sub}.json"))] {
        if candidate.is_file() {
            let text = std::fs::read_to_string(&candidate)?;
            let parsed: Vec<T> = serde_json::from_str(&text)
                .map_err(|e| NetError::ParseError(format!("invalid fixture {}: {e}", candidate.display())))?;
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}

pub fn load_ping_records(ctx: &NetContext) -> NetResult<Vec<PingSummaryRecord>> {
    if let Some(ov) = try_load_override(ctx, "lan.ping")? {
        return Ok(ov);
    }
    Ok(vec![
        PingSummaryRecord {
            host: "gateway.lan".into(),
            ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            protocol: "ICMP".into(),
            port: None,
            status: "Succeeded".into(),
            rtt_ms: Some(0.84),
            min_rtt_ms: Some(0.71),
            avg_rtt_ms: Some(0.82),
            max_rtt_ms: Some(0.95),
            sent: 4,
            succeeded: 4,
            failed: 0,
            loss_pct: 0.0,
            ttl: Some(64),
            last_checked: ts("2026-11-23T12:00:00Z"),
        },
        PingSummaryRecord {
            host: "filesrv.lan".into(),
            ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))),
            protocol: "TCP".into(),
            port: Some(445),
            status: "Succeeded".into(),
            rtt_ms: Some(1.42),
            min_rtt_ms: Some(1.10),
            avg_rtt_ms: Some(1.30),
            max_rtt_ms: Some(1.55),
            sent: 4,
            succeeded: 4,
            failed: 0,
            loss_pct: 0.0,
            ttl: None,
            last_checked: ts("2026-11-23T12:00:01Z"),
        },
        PingSummaryRecord {
            host: "printer-offline.lan".into(),
            ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99))),
            protocol: "ICMP".into(),
            port: None,
            status: "Timed Out".into(),
            rtt_ms: None,
            min_rtt_ms: None,
            avg_rtt_ms: None,
            max_rtt_ms: None,
            sent: 4,
            succeeded: 0,
            failed: 4,
            loss_pct: 100.0,
            ttl: None,
            last_checked: ts("2026-11-23T12:00:02Z"),
        },
    ])
}

pub fn load_trace_records(ctx: &NetContext) -> NetResult<Vec<TraceHopRecord>> {
    if let Some(ov) = try_load_override(ctx, "lan.trace")? {
        return Ok(ov);
    }
    Ok(vec![
        TraceHopRecord {
            target: "198.51.100.10".into(),
            hop: 1,
            ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            hostname: "gateway.lan".into(),
            rtt_ms: Some(0.65),
            status: "TTL Expired".into(),
            country_code: "--".into(),
            country_name: "Private/LAN".into(),
            asn: "AS0".into(),
            as_org: "RFC 1918 Private".into(),
        },
        TraceHopRecord {
            target: "198.51.100.10".into(),
            hop: 2,
            ip: Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
            hostname: "cgnat-core.isp.invalid".into(),
            rtt_ms: Some(4.80),
            status: "TTL Expired".into(),
            country_code: "--".into(),
            country_name: "Shared/CGNAT".into(),
            asn: "AS0".into(),
            as_org: "RFC 6598 CGNAT".into(),
        },
        TraceHopRecord {
            target: "198.51.100.10".into(),
            hop: 3,
            ip: None,
            hostname: String::new(),
            rtt_ms: None,
            status: "Timed Out".into(),
            country_code: "--".into(),
            country_name: "Unknown".into(),
            asn: "AS0".into(),
            as_org: "Unassigned / Unknown".into(),
        },
        TraceHopRecord {
            target: "198.51.100.10".into(),
            hop: 4,
            ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            hostname: "dns.google".into(),
            rtt_ms: Some(12.30),
            status: "Reply".into(),
            country_code: "US".into(),
            country_name: "United States".into(),
            asn: "AS15169".into(),
            as_org: "Google LLC".into(),
        },
    ])
}

pub fn load_scan_records(ctx: &NetContext) -> NetResult<Vec<LanScanHostRecord>> {
    if let Some(ov) = try_load_override(ctx, "lan.scan")? {
        return Ok(ov);
    }
    let oui = OuiDatabase::for_context(ctx)?;
    let mac1 = MacAddr::new([0x04, 0x18, 0xd6, 0x10, 0x20, 0x01]);
    let mac2 = MacAddr::new([0x00, 0x11, 0x32, 0x30, 0x40, 0x20]);
    let mac3 = MacAddr::new([0xb8, 0x27, 0xeb, 0x55, 0x66, 0x30]);

    Ok(vec![
        LanScanHostRecord {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            mac: Some(mac1),
            vendor: oui.lookup_or_unknown(mac1),
            hostname: "gateway.lan".into(),
            netbios_name: String::new(),
            workgroup: String::new(),
            alive: true,
            rtt_ms: Some(0.6),
            open_ports: vec![80, 443],
            discovery_method: "ARP+ICMP".into(),
        },
        LanScanHostRecord {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            mac: Some(mac2),
            vendor: oui.lookup_or_unknown(mac2),
            hostname: "filesrv.lan".into(),
            netbios_name: "FILESRV01".into(),
            workgroup: "CORP".into(),
            alive: true,
            rtt_ms: Some(1.1),
            open_ports: vec![22, 139, 445],
            discovery_method: "ARP+ICMP".into(),
        },
        LanScanHostRecord {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30)),
            mac: Some(mac3),
            vendor: oui.lookup_or_unknown(mac3),
            hostname: "sensor-pi.lan".into(),
            netbios_name: String::new(),
            workgroup: String::new(),
            alive: true,
            rtt_ms: Some(2.4),
            open_ports: vec![22],
            discovery_method: "ARP+ICMP".into(),
        },
    ])
}

pub fn load_wnetwatcher_records(ctx: &NetContext) -> NetResult<Vec<WnetDeviceRecord>> {
    if let Some(ov) = try_load_override(ctx, "lan.wnetwatcher")? {
        return Ok(ov);
    }
    let oui = OuiDatabase::for_context(ctx)?;
    let mac1 = MacAddr::new([0x04, 0x18, 0xd6, 0x10, 0x20, 0x01]);
    let mac2 = MacAddr::new([0x00, 0x15, 0x5d, 0xab, 0xcd, 0x01]);
    let mac3 = MacAddr::new([0xd8, 0x3a, 0xdd, 0x11, 0x22, 0x33]);

    Ok(vec![
        WnetDeviceRecord {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            device_name: "gateway.lan".into(),
            mac: mac1,
            vendor: oui.lookup_or_unknown(mac1),
            active: true,
            detection_count: 14,
            first_detected: ts("2026-11-23T09:00:00Z"),
            last_detected: ts("2026-11-23T12:00:00Z"),
            adapter: "Wi-Fi".into(),
        },
        WnetDeviceRecord {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 15)),
            device_name: "dev-workstation.lan".into(),
            mac: mac2,
            vendor: oui.lookup_or_unknown(mac2),
            active: true,
            detection_count: 14,
            first_detected: ts("2026-11-23T09:00:00Z"),
            last_detected: ts("2026-11-23T12:00:00Z"),
            adapter: "Ethernet (Self)".into(),
        },
        WnetDeviceRecord {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 45)),
            device_name: "lab-pi5.lan".into(),
            mac: mac3,
            vendor: oui.lookup_or_unknown(mac3),
            active: false,
            detection_count: 3,
            first_detected: ts("2026-11-23T10:15:00Z"),
            last_detected: ts("2026-11-23T10:45:00Z"),
            adapter: "Wi-Fi".into(),
        },
    ])
}

pub fn load_connect_log_events(ctx: &NetContext) -> NetResult<Vec<ConnectLogEvent>> {
    if let Some(ov) = try_load_override(ctx, "lan.connect-log")? {
        return Ok(ov);
    }
    let oui = OuiDatabase::for_context(ctx)?;
    let mac1 = MacAddr::new([0x04, 0x18, 0xd6, 0x10, 0x20, 0x01]);
    let mac2 = MacAddr::new([0xb8, 0x27, 0xeb, 0x55, 0x66, 0x30]);
    let mac2_new = MacAddr::new([0x00, 0x50, 0x56, 0x55, 0x66, 0x31]);

    let h1 = HostObservation {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        mac: mac1,
        device_name: "gateway.lan".into(),
        vendor: oui.lookup_or_unknown(mac1),
    };
    let h2 = HostObservation {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30)),
        mac: mac2,
        device_name: "sensor-pi.lan".into(),
        vendor: oui.lookup_or_unknown(mac2),
    };
    let h2_replaced = HostObservation {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30)),
        mac: mac2_new,
        device_name: "vm-sensor.lan".into(),
        vendor: oui.lookup_or_unknown(mac2_new),
    };

    let mut engine = ConnectLogEngine::new();
    let _ = engine.apply_snapshot(ts("2026-11-23T11:00:00Z"), &[h1.clone(), h2]);
    let _ = engine.apply_snapshot(ts("2026-11-23T11:15:00Z"), &[h1.clone(), h2_replaced]);
    let _ = engine.apply_snapshot(ts("2026-11-23T11:45:00Z"), &[h1]);
    Ok(engine.events().to_vec())
}

pub fn load_wol_records(ctx: &NetContext) -> NetResult<Vec<WolHostRecord>> {
    if let Some(ov) = try_load_override(ctx, "lan.wol")? {
        return Ok(ov);
    }
    let oui = OuiDatabase::for_context(ctx)?;
    let mac1 = MacAddr::new([0x00, 0x11, 0x32, 0x30, 0x40, 0x20]);
    let mac2 = MacAddr::new([0x00, 0x14, 0x22, 0x77, 0x88, 0x99]);
    Ok(vec![
        WolHostRecord {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            hostname: "filesrv.lan".into(),
            mac: mac1,
            vendor: oui.lookup_or_unknown(mac1),
            broadcast_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)),
            wol_port: 9,
            status: "Online".into(),
            last_seen: ts("2026-11-23T12:00:00Z"),
        },
        WolHostRecord {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            hostname: "build-node-02.lan".into(),
            mac: mac2,
            vendor: oui.lookup_or_unknown(mac2),
            broadcast_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)),
            wol_port: 9,
            status: "Offline".into(),
            last_seen: ts("2026-11-23T08:30:00Z"),
        },
    ])
}

pub fn load_netbios_records(ctx: &NetContext) -> NetResult<Vec<NetbiosHostRecord>> {
    if let Some(ov) = try_load_override(ctx, "lan.netbios")? {
        return Ok(ov);
    }
    let oui = OuiDatabase::for_context(ctx)?;
    let mac1 = MacAddr::new([0x00, 0x11, 0x32, 0x30, 0x40, 0x20]);
    let mac2 = MacAddr::new([0x00, 0x15, 0x5d, 0x12, 0x34, 0x56]);
    Ok(vec![
        NetbiosHostRecord {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            computer_name: "FILESRV01".into(),
            workgroup: "CORP".into(),
            mac: Some(mac1),
            vendor: oui.lookup_or_unknown(mac1),
            is_master_browser: true,
            is_domain_controller: false,
            services: "Domain/Workgroup<00>, FileServer<20>, MasterBrowser<1D>, Workstation<00>".into(),
            rtt_ms: 1.35,
            user_hint: Some("BACKUP_SVC".into()),
        },
        NetbiosHostRecord {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            computer_name: "DC01".into(),
            workgroup: "CORP".into(),
            mac: Some(mac2),
            vendor: oui.lookup_or_unknown(mac2),
            is_master_browser: true,
            is_domain_controller: true,
            services: "DomainController<1C>, DomainMasterBrowser<1B>, FileServer<20>, Workstation<00>".into(),
            rtt_ms: 0.92,
            user_hint: None,
        },
    ])
}

pub fn load_share_records(ctx: &NetContext) -> NetResult<Vec<ShareRecord>> {
    if let Some(ov) = try_load_override(ctx, "lan.shares")? {
        return Ok(ov);
    }
    Ok(vec![
        ShareRecord {
            server: "FILESRV01".into(),
            share_name: "Public".into(),
            unc_path: r"\\FILESRV01\Public".into(),
            share_type: "Disk".into(),
            local_path: Some(r"D:\Shares\Public".into()),
            current_uses: Some(3),
            max_uses: Some(100),
            remark: "Shared team documents".into(),
            source: "Fixture".into(),
        },
        ShareRecord {
            server: "FILESRV01".into(),
            share_name: "IPC$".into(),
            unc_path: r"\\FILESRV01\IPC$".into(),
            share_type: "IPC".into(),
            local_path: None,
            current_uses: Some(1),
            max_uses: None,
            remark: "Remote IPC".into(),
            source: "Fixture".into(),
        },
        ShareRecord {
            server: "PRINTSRV".into(),
            share_name: "LaserJet-01".into(),
            unc_path: r"\\PRINTSRV\LaserJet-01".into(),
            share_type: "Print".into(),
            local_path: None,
            current_uses: None,
            max_uses: None,
            remark: "Level-1 enumeration sample".into(),
            source: "Fixture".into(),
        },
    ])
}

pub fn load_open_file_records(ctx: &NetContext) -> NetResult<Vec<OpenFileRecord>> {
    if let Some(ov) = try_load_override(ctx, "lan.openfiles")? {
        return Ok(ov);
    }
    Ok(vec![
        OpenFileRecord {
            file_id: 101,
            pathname: r"D:\Shares\Public\Q4-Budget.xlsx".into(),
            username: "alice".into(),
            permissions: "Read+Write".into(),
            locks: 1,
            server: "FILESRV01".into(),
        },
        OpenFileRecord {
            file_id: 102,
            pathname: r"D:\Shares\Public\Architecture.pdf".into(),
            username: "bob".into(),
            permissions: "Read".into(),
            locks: 0,
            server: "FILESRV01".into(),
        },
        OpenFileRecord {
            file_id: 103,
            pathname: r"D:\Shares\Logs\audit.jsonl".into(),
            username: "svc-audit".into(),
            permissions: "Read+Write+Create".into(),
            locks: 2,
            server: "FILESRV01".into(),
        },
    ])
}

pub fn load_resolve_records(ctx: &NetContext) -> NetResult<Vec<ResolveRecord>> {
    if let Some(ov) = try_load_override(ctx, "lan.resolve")? {
        return Ok(ov);
    }
    let oui = OuiDatabase::for_context(ctx)?;
    let mac1 = MacAddr::new([0x00, 0x11, 0x32, 0x30, 0x40, 0x20]);
    let mac2 = MacAddr::new([0x04, 0x18, 0xd6, 0x10, 0x20, 0x01]);
    Ok(vec![
        ResolveRecord {
            query: "filesrv.lan".into(),
            ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))),
            hostname: "filesrv.lan".into(),
            mac: Some(mac1),
            vendor: oui.lookup_or_unknown(mac1),
            status: "Resolved".into(),
            duration_ms: 2,
        },
        ResolveRecord {
            query: "192.168.1.1".into(),
            ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            hostname: "gateway.lan".into(),
            mac: Some(mac2),
            vendor: oui.lookup_or_unknown(mac2),
            status: "Resolved".into(),
            duration_ms: 1,
        },
        ResolveRecord {
            query: "unknown-host.lan".into(),
            ip: None,
            hostname: "unknown-host.lan".into(),
            mac: None,
            vendor: String::new(),
            status: "Not Found".into(),
            duration_ms: 15,
        },
    ])
}

pub fn load_speedtest_records(ctx: &NetContext) -> NetResult<Vec<DownloadMeasurement>> {
    if let Some(ov) = try_load_override(ctx, "lan.speedtest")? {
        return Ok(ov);
    }
    Ok(vec![
        DownloadMeasurement {
            url: "http://127.0.0.1:18080/benchmark-10mb.bin".into(),
            status_code: 200,
            bytes_downloaded: 10_485_760,
            duration_ms: 420,
            speed_kbps: 24_380.95,
            speed_mbps: 199.7288,
            content_type: "application/octet-stream".into(),
            result: "Completed".into(),
            ttfb_ms: 1.8,
        },
        DownloadMeasurement {
            url: "https://mirror.example.invalid/missing.bin".into(),
            status_code: 404,
            bytes_downloaded: 0,
            duration_ms: 12,
            speed_kbps: 0.0,
            speed_mbps: 0.0,
            content_type: "text/plain".into(),
            result: "Failed".into(),
            ttfb_ms: 11.5,
        },
    ])
}
