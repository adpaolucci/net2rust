use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant};

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use net2rust_core::{NetContext, NetError, NetResult};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::fixtures;

#[derive(Debug, Clone)]
pub struct DownloadOptions {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub max_bytes: Option<u64>,
    pub max_duration: Option<Duration>,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(10),
            max_bytes: None,
            max_duration: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadMeasurement {
    pub url: String,
    pub status_code: u64,
    pub bytes_downloaded: u64,
    pub duration_ms: u64,
    pub speed_kbps: f64,
    pub speed_mbps: f64,
    pub content_type: String,
    pub result: String,
    pub ttfb_ms: f64,
}

pub trait DownloadTransport: Send + Sync {
    fn download(&self, url: &str, opts: &DownloadOptions) -> NetResult<DownloadMeasurement>;
}

pub fn validate_http_url(url: &str) -> NetResult<()> {
    let lower = url.trim().to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return Err(NetError::InvalidInput(format!(
            "unsupported URL scheme for speedtest (expected http:// or https://): {url}"
        )));
    }
    Ok(())
}

/// Computes `(speed_kbps, speed_mbps)` safely, returning `(0.0, 0.0)` when `duration <= 0` or `bytes == 0`.
pub fn compute_throughput(bytes: u64, elapsed: Duration) -> (f64, f64) {
    let secs = elapsed.as_secs_f64();
    if !secs.is_finite() || secs <= 0.0 || bytes == 0 {
        return (0.0, 0.0);
    }
    let kbps = (bytes as f64 / 1024.0) / secs;
    let mbps = (bytes as f64 * 8.0) / (secs * 1_000_000.0);
    (kbps, mbps)
}

#[derive(Debug, Default)]
pub struct UreqDownloadTransport;

impl DownloadTransport for UreqDownloadTransport {
    fn download(&self, url: &str, opts: &DownloadOptions) -> NetResult<DownloadMeasurement> {
        validate_http_url(url)?;

        let agent = ureq::AgentBuilder::new()
            .timeout_connect(opts.connect_timeout)
            .timeout_read(opts.read_timeout)
            .try_proxy_from_env(false)
            .redirects(5)
            .build();

        let t_req = Instant::now();
        let resp = match agent.get(url).set("Accept-Encoding", "identity").call() {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let ctype = r.header("Content-Type").unwrap_or("").to_string();
                return Ok(DownloadMeasurement {
                    url: url.to_string(),
                    status_code: u64::from(code),
                    bytes_downloaded: 0,
                    duration_ms: t_req.elapsed().as_millis() as u64,
                    speed_kbps: 0.0,
                    speed_mbps: 0.0,
                    content_type: ctype,
                    result: "Failed".to_string(),
                    ttfb_ms: t_req.elapsed().as_secs_f64() * 1000.0,
                });
            }
            Err(ureq::Error::Transport(t)) => {
                return Err(NetError::NetworkError(format!("HTTP transport error for {url}: {t}")));
            }
        };

        let ttfb_ms = t_req.elapsed().as_secs_f64() * 1000.0;
        let status_code = u64::from(resp.status());
        let content_type = resp.header("Content-Type").unwrap_or("").to_string();

        let mut reader = resp.into_reader();
        let mut buf = [0u8; 65_536];
        let mut bytes_downloaded = 0u64;
        let t_transfer = Instant::now();

        loop {
            if let Some(max_dur) = opts.max_duration
                && t_transfer.elapsed() >= max_dur
            {
                break;
            }
            if let Some(max_bytes) = opts.max_bytes
                && bytes_downloaded >= max_bytes
            {
                break;
            }

            let to_read = if let Some(max_bytes) = opts.max_bytes {
                let rem = usize::try_from(max_bytes.saturating_sub(bytes_downloaded)).unwrap_or(buf.len());
                buf.len().min(rem.max(1))
            } else {
                buf.len()
            };

            let n = reader
                .read(&mut buf[..to_read])
                .map_err(|e| NetError::NetworkError(format!("stream read error for {url}: {e}")))?;
            if n == 0 {
                break;
            }
            bytes_downloaded = bytes_downloaded.saturating_add(n as u64);
        }

        let transfer_elapsed = t_transfer.elapsed();
        let (speed_kbps, speed_mbps) = compute_throughput(bytes_downloaded, transfer_elapsed);
        Ok(DownloadMeasurement {
            url: url.to_string(),
            status_code,
            bytes_downloaded,
            duration_ms: transfer_elapsed.as_millis() as u64,
            speed_kbps,
            speed_mbps,
            content_type,
            result: "Completed".to_string(),
            ttfb_ms,
        })
    }
}

pub struct SpeedtestProvider {
    ctx: NetContext,
    urls: Vec<String>,
    options: DownloadOptions,
    transport: Arc<dyn DownloadTransport>,
}

impl SpeedtestProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self {
            ctx,
            urls: Vec::new(),
            options: DownloadOptions::default(),
            transport: Arc::new(UreqDownloadTransport),
        }
    }

    pub fn with_urls(mut self, urls: Vec<String>) -> Self {
        self.urls = urls;
        self
    }

    pub fn with_options(mut self, options: DownloadOptions) -> Self {
        self.options = options;
        self
    }

    pub fn with_transport(mut self, transport: Arc<dyn DownloadTransport>) -> Self {
        self.transport = transport;
        self
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "lan.speedtest",
            "HTTP/HTTPS Download Throughput",
            vec![
                ColumnDef::new("url", "URL", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("status_code", "HTTP Status", ColumnType::Uint).with_width_hint(90),
                ColumnDef::new("bytes_downloaded", "Bytes", ColumnType::BytesSize).with_width_hint(110),
                ColumnDef::new("duration_ms", "Duration", ColumnType::Duration).with_width_hint(100),
                ColumnDef::new("speed_kbps", "Speed (KB/s)", ColumnType::Float).with_width_hint(110),
                ColumnDef::new("speed_mbps", "Speed (Mbps)", ColumnType::Float).with_width_hint(110),
                ColumnDef::new("content_type", "Content-Type", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("result", "Result", ColumnType::Text).with_width_hint(110),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn collect_records(&self) -> NetResult<Vec<DownloadMeasurement>> {
        if self.ctx.is_offline() && self.urls.is_empty() {
            return fixtures::load_speedtest_records(&self.ctx);
        }
        if self.urls.is_empty() {
            // Safe zero-external-traffic default when no URL is explicitly passed in live mode.
            return Ok(Vec::new());
        }

        let mut out = Vec::with_capacity(self.urls.len());
        for url in &self.urls {
            match self.transport.download(url, &self.options) {
                Ok(m) => out.push(m),
                Err(NetError::InvalidInput(msg)) => return Err(NetError::InvalidInput(msg)),
                Err(err) => out.push(DownloadMeasurement {
                    url: url.clone(),
                    status_code: 0,
                    bytes_downloaded: 0,
                    duration_ms: 0,
                    speed_kbps: 0.0,
                    speed_mbps: 0.0,
                    content_type: String::new(),
                    result: format!("Failed: {err}"),
                    ttfb_ms: 0.0,
                }),
            }
        }
        Ok(out)
    }
}

impl TableProvider for SpeedtestProvider {
    fn tool_id(&self) -> &'static str {
        "lan.speedtest"
    }

    fn description(&self) -> &'static str {
        "Benchmark HTTP/HTTPS streaming download throughput via ureq"
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
                    "url": rec.url,
                    "status_code": rec.status_code,
                    "bytes_downloaded": rec.bytes_downloaded,
                    "duration_ms": rec.duration_ms,
                    "speed_kbps": rec.speed_kbps,
                    "speed_mbps": rec.speed_mbps,
                    "content_type": rec.content_type,
                    "result": rec.result,
                    "ttfb_ms": rec.ttfb_ms,
                });
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.url),
                        CellValue::Uint(rec.status_code),
                        CellValue::Bytes(rec.bytes_downloaded),
                        CellValue::Uint(rec.duration_ms),
                        CellValue::Float(rec.speed_kbps),
                        CellValue::Float(rec.speed_mbps),
                        CellValue::Text(rec.content_type),
                        CellValue::Text(rec.result),
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
    use std::io::Write as _;
    use std::net::TcpListener;

    use super::*;

    struct MockDownloadTransport;
    impl DownloadTransport for MockDownloadTransport {
        fn download(&self, url: &str, _opts: &DownloadOptions) -> NetResult<DownloadMeasurement> {
            validate_http_url(url)?;
            Ok(DownloadMeasurement {
                url: url.to_string(),
                status_code: 200,
                bytes_downloaded: 1_048_576,
                duration_ms: 500,
                speed_kbps: 2048.0,
                speed_mbps: 16.777216,
                content_type: "application/octet-stream".into(),
                result: "Completed".into(),
                ttfb_ms: 5.0,
            })
        }
    }

    #[test]
    fn test_throughput_zero_duration_guard_and_url_validation() {
        assert_eq!(compute_throughput(0, Duration::from_secs(1)), (0.0, 0.0));
        assert_eq!(compute_throughput(1024, Duration::ZERO), (0.0, 0.0));
        let (kbps, mbps) = compute_throughput(1_048_576, Duration::from_secs(1));
        assert!((kbps - 1024.0).abs() < 1e-6);
        assert!((mbps - 8.388608).abs() < 1e-6);

        assert!(validate_http_url("http://127.0.0.1:8080/test.bin").is_ok());
        assert!(validate_http_url("https://localhost/test.bin").is_ok());
        assert!(validate_http_url("ftp://127.0.0.1/file").is_err());
    }

    #[test]
    fn test_speedtest_mock_and_real_ureq_localhost_tcp_listener() {
        // 1) MockDownloadTransport
        let mock_provider = SpeedtestProvider::new(NetContext::live())
            .with_transport(Arc::new(MockDownloadTransport))
            .with_urls(vec!["http://localhost/payload.bin".into()]);
        let mock_data = mock_provider.query(&TableQuery::default()).unwrap();
        assert_eq!(mock_data.total_rows, 1);
        assert_eq!(mock_data.rows[0].cells[2], CellValue::Bytes(1_048_576));

        // 2) Real UreqDownloadTransport against ephemeral 127.0.0.1:0 TcpListener (512 KiB)
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let payload_len = 512 * 1024usize;

        let server_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut req_buf = [0u8; 2048];
            let n = stream.read(&mut req_buf).unwrap();
            let req_text = String::from_utf8_lossy(&req_buf[..n]);
            assert!(req_text.to_ascii_lowercase().contains("accept-encoding: identity"));

            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {payload_len}\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(header.as_bytes()).unwrap();
            let chunk = vec![0x5Au8; 65_536];
            for _ in 0..(payload_len / chunk.len()) {
                stream.write_all(&chunk).unwrap();
            }
            stream.flush().unwrap();
        });

        let url = format!("http://127.0.0.1:{port}/test.bin");
        let live_provider = SpeedtestProvider::new(NetContext::live()).with_urls(vec![url.clone()]);
        let data = live_provider.query(&TableQuery::default()).unwrap();
        server_thread.join().unwrap();

        assert_eq!(data.total_rows, 1);
        assert_eq!(data.rows[0].cells[0], CellValue::Text(url));
        assert_eq!(data.rows[0].cells[1], CellValue::Uint(200));
        assert_eq!(data.rows[0].cells[2], CellValue::Bytes(payload_len as u64));
        assert_eq!(data.rows[0].cells[7], CellValue::Text("Completed".into()));

        // 3) max_bytes cap + HTTP 404 status handling against 127.0.0.1:0
        let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let port2 = listener2.local_addr().unwrap().port();
        let t2 = std::thread::spawn(move || {
            for idx in 0..2 {
                let (mut stream, _) = listener2.accept().unwrap();
                let mut req_buf = [0u8; 1024];
                let _ = std::io::Read::read(&mut stream, &mut req_buf);
                if idx == 0 {
                    let hdr = "HTTP/1.1 200 OK\r\nContent-Length: 131072\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(hdr.as_bytes());
                    let _ = stream.write_all(&vec![0x11u8; 131_072]);
                } else {
                    let hdr = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found";
                    let _ = stream.write_all(hdr.as_bytes());
                }
            }
        });

        let capped = SpeedtestProvider::new(NetContext::live())
            .with_options(DownloadOptions {
                max_bytes: Some(32_768),
                ..Default::default()
            })
            .with_urls(vec![
                format!("http://127.0.0.1:{port2}/big.bin"),
                format!("http://127.0.0.1:{port2}/missing"),
            ]);
        let capped_data = capped.query(&TableQuery::default()).unwrap();
        t2.join().unwrap();
        assert_eq!(capped_data.total_rows, 2);
        let big_row = capped_data
            .rows
            .iter()
            .find(|r| matches!(&r.cells[0], CellValue::Text(u) if u.ends_with("/big.bin")))
            .unwrap();
        assert_eq!(big_row.cells[2], CellValue::Bytes(32_768));
        assert_eq!(big_row.cells[7], CellValue::Text("Completed".into()));

        let missing_row = capped_data
            .rows
            .iter()
            .find(|r| matches!(&r.cells[0], CellValue::Text(u) if u.ends_with("/missing")))
            .unwrap();
        assert_eq!(missing_row.cells[1], CellValue::Uint(404));
        assert_eq!(missing_row.cells[7], CellValue::Text("Failed".into()));
    }
}
