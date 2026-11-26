use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use net2rust_core::{NetError, NetResult};

/// Maximum WHOIS TCP:43 response payload (512 KiB).
const MAX_WHOIS_BYTES: u64 = 512 * 1024;
/// Maximum HTTP RDAP JSON payload (2 MiB).
const MAX_RDAP_BYTES: usize = 2 * 1024 * 1024;

/// Synchronous TCP:43 WHOIS transport abstraction.
pub trait WhoisTransport: Send + Sync {
    fn query_whois(&self, server: &str, port: u16, query: &str, timeout: Duration) -> NetResult<String>;
}

/// Synchronous HTTP/HTTPS RDAP JSON transport abstraction.
pub trait RdapTransport: Send + Sync {
    fn get_rdap_json(&self, url: &str, timeout: Duration) -> NetResult<RdapHttpResponse>;
}

#[derive(Debug, Clone)]
pub struct RdapHttpResponse {
    pub final_url: String,
    pub status: u16,
    pub body: serde_json::Value,
}

/// Synchronous UDP/TCP RFC 1035 DNS wire transport abstraction.
pub trait DnsTransport: Send + Sync {
    fn exchange(&self, server: SocketAddr, query_packet: &[u8], use_tcp: bool, timeout: Duration)
    -> NetResult<Vec<u8>>;
}

/// Standard TCP:43 WHOIS client using `std::net::TcpStream` with optional localhost overrides.
#[derive(Debug, Clone, Default)]
pub struct StdWhoisTransport {
    pub endpoint_overrides: HashMap<String, SocketAddr>,
}

impl StdWhoisTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_override(mut self, host_or_host_port: impl Into<String>, addr: SocketAddr) -> Self {
        self.endpoint_overrides
            .insert(host_or_host_port.into().to_ascii_lowercase(), addr);
        self
    }

    fn resolve_target(&self, server: &str, port: u16) -> NetResult<SocketAddr> {
        let host_port = format!("{}:{}", server.to_ascii_lowercase(), port);
        if let Some(addr) = self.endpoint_overrides.get(&host_port) {
            return Ok(*addr);
        }
        let host_only = server.to_ascii_lowercase();
        if let Some(addr) = self.endpoint_overrides.get(&host_only) {
            return Ok(*addr);
        }
        (server, port)
            .to_socket_addrs()
            .map_err(|e| NetError::NetworkError(format!("WHOIS DNS resolution failed for {server}:{port}: {e}")))?
            .next()
            .ok_or_else(|| NetError::NetworkError(format!("no socket addresses resolved for {server}:{port}")))
    }
}

impl WhoisTransport for StdWhoisTransport {
    fn query_whois(&self, server: &str, port: u16, query: &str, timeout: Duration) -> NetResult<String> {
        let addr = self.resolve_target(server, port)?;
        let mut stream = TcpStream::connect_timeout(&addr, timeout)
            .map_err(|e| NetError::NetworkError(format!("WHOIS connect {server}:{port} ({addr}) failed: {e}")))?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let line = format!("{query}\r\n");
        stream.write_all(line.as_bytes())?;
        stream.flush()?;

        let mut buf = Vec::new();
        stream.take(MAX_WHOIS_BYTES).read_to_end(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }
}

/// Standard HTTP/HTTPS RDAP client built on `ureq 2.12` with optional base-URL overrides.
#[derive(Debug, Clone, Default)]
pub struct UreqRdapTransport {
    pub base_url_overrides: HashMap<String, String>,
}

impl UreqRdapTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_base_override(
        mut self,
        original_prefix: impl Into<String>,
        replacement_prefix: impl Into<String>,
    ) -> Self {
        self.base_url_overrides
            .insert(original_prefix.into(), replacement_prefix.into());
        self
    }

    fn rewrite_url(&self, url: &str) -> String {
        for (prefix, replacement) in &self.base_url_overrides {
            if let Some(rest) = url.strip_prefix(prefix.as_str()) {
                return format!("{replacement}{rest}");
            }
        }
        url.to_string()
    }
}

impl RdapTransport for UreqRdapTransport {
    fn get_rdap_json(&self, url: &str, timeout: Duration) -> NetResult<RdapHttpResponse> {
        let target_url = self.rewrite_url(url);
        let agent = ureq::AgentBuilder::new()
            .timeout(timeout)
            .redirects(5)
            .user_agent("net2rust-osint/0.1")
            .build();

        let resp = agent
            .get(&target_url)
            .set("Accept", "application/rdap+json, application/json")
            .call()
            .map_err(|e| NetError::NetworkError(format!("RDAP request '{target_url}' failed: {e}")))?;

        let status = resp.status();
        let final_url = resp.get_url().to_string();
        let mut raw = Vec::new();
        resp.into_reader()
            .take((MAX_RDAP_BYTES + 1) as u64)
            .read_to_end(&mut raw)?;
        if raw.len() > MAX_RDAP_BYTES {
            return Err(NetError::ParseError(format!(
                "RDAP response from '{final_url}' exceeded {MAX_RDAP_BYTES} bytes"
            )));
        }

        let body: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|e| NetError::ParseError(format!("invalid RDAP JSON from '{final_url}': {e}")))?;

        Ok(RdapHttpResponse {
            final_url,
            status,
            body,
        })
    }
}

/// Standard UDP/TCP DNS wire transport using `std::net`.
#[derive(Debug, Clone, Default)]
pub struct StdDnsTransport {
    pub server_overrides: HashMap<SocketAddr, SocketAddr>,
}

impl StdDnsTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_override(mut self, logical: SocketAddr, actual: SocketAddr) -> Self {
        self.server_overrides.insert(logical, actual);
        self
    }

    fn effective_server(&self, server: SocketAddr) -> SocketAddr {
        self.server_overrides.get(&server).copied().unwrap_or(server)
    }
}

impl DnsTransport for StdDnsTransport {
    fn exchange(
        &self,
        server: SocketAddr,
        query_packet: &[u8],
        use_tcp: bool,
        timeout: Duration,
    ) -> NetResult<Vec<u8>> {
        let target = self.effective_server(server);
        if use_tcp {
            let mut stream = TcpStream::connect_timeout(&target, timeout)
                .map_err(|e| NetError::NetworkError(format!("DNS TCP connect {target} failed: {e}")))?;
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))?;

            let len_u16 = u16::try_from(query_packet.len())
                .map_err(|_| NetError::InvalidInput("DNS TCP query exceeds 65535 bytes".into()))?;
            stream.write_all(&len_u16.to_be_bytes())?;
            stream.write_all(query_packet)?;
            stream.flush()?;

            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf)?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;
            let mut resp = vec![0u8; resp_len];
            stream.read_exact(&mut resp)?;
            Ok(resp)
        } else {
            let bind_addr = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
            let sock = UdpSocket::bind(bind_addr)?;
            sock.set_read_timeout(Some(timeout))?;
            sock.set_write_timeout(Some(timeout))?;
            sock.connect(target)?;
            sock.send(query_packet)?;

            let mut buf = [0u8; 4096];
            let n = sock.recv(&mut buf)?;
            Ok(buf[..n].to_vec())
        }
    }
}

/// Deterministic in-memory mock WHOIS transport for offline fixtures and unit tests.
#[derive(Debug, Clone, Default)]
pub struct MockWhoisTransport {
    exact_responses: HashMap<(String, String), String>,
    server_defaults: HashMap<String, String>,
    recorded_queries: Arc<Mutex<Vec<(String, u16, String)>>>,
}

impl MockWhoisTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, server: impl Into<String>, query: impl Into<String>, response: impl Into<String>) {
        self.exact_responses.insert(
            (server.into().to_ascii_lowercase(), query.into().to_ascii_lowercase()),
            response.into(),
        );
    }

    pub fn insert_server_default(&mut self, server: impl Into<String>, response: impl Into<String>) {
        self.server_defaults
            .insert(server.into().to_ascii_lowercase(), response.into());
    }

    pub fn recorded_queries(&self) -> Vec<(String, u16, String)> {
        self.recorded_queries
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

impl WhoisTransport for MockWhoisTransport {
    fn query_whois(&self, server: &str, port: u16, query: &str, _timeout: Duration) -> NetResult<String> {
        if let Ok(mut guard) = self.recorded_queries.lock() {
            guard.push((server.to_string(), port, query.to_string()));
        }
        let srv_key = server.to_ascii_lowercase();
        let qry_key = query.trim().to_ascii_lowercase();
        if let Some(resp) = self.exact_responses.get(&(srv_key.clone(), qry_key)) {
            return Ok(resp.clone());
        }
        if let Some(resp) = self.server_defaults.get(&srv_key) {
            return Ok(resp.clone());
        }
        Err(NetError::NetworkError(format!(
            "no offline WHOIS fixture for server='{server}' query='{query}'"
        )))
    }
}

/// Deterministic in-memory mock RDAP transport for offline fixtures and unit tests.
#[derive(Debug, Clone, Default)]
pub struct MockRdapTransport {
    responses: HashMap<String, serde_json::Value>,
}

impl MockRdapTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, url: impl Into<String>, body: serde_json::Value) {
        self.responses.insert(url.into().to_ascii_lowercase(), body);
    }
}

impl RdapTransport for MockRdapTransport {
    fn get_rdap_json(&self, url: &str, _timeout: Duration) -> NetResult<RdapHttpResponse> {
        let key = url.to_ascii_lowercase();
        let body = self
            .responses
            .get(&key)
            .cloned()
            .ok_or_else(|| NetError::NetworkError(format!("no offline RDAP fixture for '{url}'")))?;
        Ok(RdapHttpResponse {
            final_url: url.to_string(),
            status: 200,
            body,
        })
    }
}

/// Deterministic in-memory mock DNS transport for offline fixtures and unit tests.
pub type MockDnsHandler = Arc<dyn Fn(SocketAddr, &[u8], bool) -> NetResult<Vec<u8>> + Send + Sync>;

#[derive(Clone)]
pub struct MockDnsTransport {
    handler: MockDnsHandler,
}

impl MockDnsTransport {
    pub fn new<F>(handler: F) -> Self
    where
        F: Fn(SocketAddr, &[u8], bool) -> NetResult<Vec<u8>> + Send + Sync + 'static,
    {
        Self {
            handler: Arc::new(handler),
        }
    }
}

impl DnsTransport for MockDnsTransport {
    fn exchange(
        &self,
        server: SocketAddr,
        query_packet: &[u8],
        use_tcp: bool,
        _timeout: Duration,
    ) -> NetResult<Vec<u8>> {
        (self.handler)(server, query_packet, use_tcp)
    }
}
