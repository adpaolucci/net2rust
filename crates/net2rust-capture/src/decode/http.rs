//! Shared HTTP/1.0 & HTTP/1.1 request/response parser over reassembled TCP streams
//! with chunked body decoding, pipelined request-response pairing, and strict R4 redaction.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::capture::CapturedPacket;
use crate::decode::tcp_stream::{ReassembledStream, StreamKey, TcpStreamReassembler};
use crate::r4_guard::{
    REDACTED_MARKER, is_cleartext_credential_port, is_sensitive_header_name, sanitize_header_value,
    scrub_url_credentials,
};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

const HTTP_METHODS: &[&str] = &[
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
];

#[derive(Debug, Clone)]
pub struct HttpHeader {
    pub name: String,
    pub sanitized_value: String,
    pub raw_cookie_value: Option<String>,
    pub was_sensitive: bool,
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub timestamp: Option<DateTime<Utc>>,
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub headers: Vec<HttpHeader>,
    pub body_len: usize,
    pub had_sensitive_material: bool,
    pub raw_sanitized_headers: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub timestamp: Option<DateTime<Utc>>,
    pub status_code: u16,
    pub reason: String,
    pub content_type: Option<String>,
    pub server: Option<String>,
    pub headers: Vec<HttpHeader>,
    pub body: Vec<u8>,
    pub decoded_body_len: usize,
    pub body_truncated: bool,
    pub content_encoding: Option<String>,
    pub had_sensitive_material: bool,
    pub raw_sanitized_headers: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct HttpTransaction {
    pub timestamp: Option<DateTime<Utc>>,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub request: Option<HttpRequest>,
    pub response: Option<HttpResponse>,
    pub had_sensitive_material: bool,
}

fn find_header_end(buf: &[u8]) -> Option<(usize, usize)> {
    let limit = buf.len().min(MAX_HEADER_BYTES);
    let slice = &buf[..limit];
    for i in 0..slice.len() {
        if i + 4 <= slice.len() && &slice[i..i + 4] == b"\r\n\r\n" {
            return Some((i, i + 4));
        }
        if i + 2 <= slice.len() && &slice[i..i + 2] == b"\n\n" {
            return Some((i, i + 2));
        }
    }
    None
}

fn parse_headers_block(lines: &[&str], redact_sensitive_headers: bool) -> (Vec<HttpHeader>, bool, Vec<u8>) {
    let mut headers = Vec::new();
    let mut had_sensitive = false;
    let mut sanitized_wire = Vec::new();

    for line in lines {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.is_empty() {
            continue;
        }
        let Some((name, val)) = trimmed.split_once(':') else {
            continue;
        };
        let name_clean = name.trim().to_string();
        let val_clean = val.trim();
        let lower = name_clean.to_ascii_lowercase();
        let sensitive_hdr = is_sensitive_header_name(&name_clean);
        let sanitized = sanitize_header_value(&name_clean, val_clean, redact_sensitive_headers);

        if sensitive_hdr || sanitized != val_clean || sanitized.contains(REDACTED_MARKER) {
            had_sensitive = true;
        }

        let raw_cookie_value = if matches!(lower.as_str(), "cookie" | "set-cookie" | "set-cookie2") {
            Some(sanitized.clone())
        } else {
            None
        };

        sanitized_wire.extend_from_slice(name_clean.as_bytes());
        sanitized_wire.extend_from_slice(b": ");
        sanitized_wire.extend_from_slice(sanitized.as_bytes());
        sanitized_wire.extend_from_slice(b"\r\n");

        headers.push(HttpHeader {
            name: name_clean,
            sanitized_value: sanitized,
            raw_cookie_value,
            was_sensitive: sensitive_hdr,
        });
    }

    (headers, had_sensitive, sanitized_wire)
}

fn header_value<'a>(headers: &'a [HttpHeader], target: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(target))
        .map(|h| h.sanitized_value.as_str())
}

fn decode_chunked_body(buf: &[u8]) -> Option<(Vec<u8>, usize, usize, bool)> {
    let mut pos = 0usize;
    let mut decoded = Vec::new();
    let mut total_len = 0usize;
    let mut truncated = false;

    loop {
        if pos >= buf.len() {
            return None;
        }
        let line_end = buf[pos..].windows(2).position(|w| w == b"\r\n")?;
        let line = std::str::from_utf8(&buf[pos..pos + line_end]).ok()?;
        let size_str = line.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_str, 16).ok()?;
        pos += line_end + 2;

        if chunk_size == 0 {
            // Consume trailer headers until blank CRLF (or single CRLF if no trailers)
            while pos + 2 <= buf.len() {
                if &buf[pos..pos + 2] == b"\r\n" {
                    pos += 2;
                    return Some((decoded, total_len, pos, truncated));
                }
                let t_end = buf[pos..].windows(2).position(|w| w == b"\r\n")?;
                pos += t_end + 2;
            }
            return Some((decoded, total_len, pos, truncated));
        }

        let next_pos = pos.checked_add(chunk_size).and_then(|e| e.checked_add(2))?;
        if next_pos > buf.len() {
            return None;
        }
        total_len = total_len.saturating_add(chunk_size);
        let avail = MAX_BODY_BYTES.saturating_sub(decoded.len());
        if avail > 0 {
            let take = chunk_size.min(avail);
            decoded.extend_from_slice(&buf[pos..pos + take]);
            if take < chunk_size {
                truncated = true;
            }
        } else {
            truncated = true;
        }
        pos = next_pos;
    }
}

fn consume_body(
    buf: &[u8],
    headers: &[HttpHeader],
    is_response: bool,
    status_code: Option<u16>,
    method: Option<&str>,
    is_http_1_0: bool,
    stream_closed: bool,
) -> (Vec<u8>, usize, usize, bool) {
    if is_response {
        if let Some(code) = status_code
            && ((100..200).contains(&code) || code == 204 || code == 304)
        {
            return (Vec::new(), 0, 0, false);
        }
        if method == Some("HEAD") {
            return (Vec::new(), 0, 0, false);
        }
    }

    let is_chunked = header_value(headers, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);

    if is_chunked {
        if let Some(res) = decode_chunked_body(buf) {
            return res;
        }
        // Malformed/incomplete chunked stream: salvage what fits safely
        let take = buf.len().min(MAX_BODY_BYTES);
        return (buf[..take].to_vec(), buf.len(), buf.len(), take < buf.len());
    }

    if let Some(cl_str) = header_value(headers, "content-length")
        && let Ok(cl) = cl_str.trim().parse::<usize>()
    {
        let avail = buf.len();
        let consumed = cl.min(avail);
        let keep = consumed.min(MAX_BODY_BYTES);
        return (buf[..keep].to_vec(), cl, consumed, keep < consumed);
    }

    if is_response && (is_http_1_0 || stream_closed) {
        let keep = buf.len().min(MAX_BODY_BYTES);
        return (buf[..keep].to_vec(), buf.len(), buf.len(), keep < buf.len());
    }

    (Vec::new(), 0, 0, false)
}

#[derive(Debug)]
enum ParsedStreamItem {
    Request(HttpRequest),
    Response(HttpResponse),
}

fn is_interim_1xx(status_code: u16) -> bool {
    (100..200).contains(&status_code) && status_code != 101
}

fn pop_effective_response(resps: &mut VecDeque<HttpResponse>) -> Option<HttpResponse> {
    let mut interim_sensitive = false;
    while resps.len() > 1 && resps.front().is_some_and(|r| is_interim_1xx(r.status_code)) {
        if let Some(interim) = resps.pop_front() {
            interim_sensitive |= interim.had_sensitive_material;
        }
    }
    let mut resp = resps.pop_front()?;
    if interim_sensitive {
        resp.had_sensitive_material = true;
    }
    Some(resp)
}

fn is_response_stream(stream: &ReassembledStream) -> bool {
    let Some((hdr_end_rel, _)) = find_header_end(&stream.data) else {
        return false;
    };
    let Ok(hdr_text) = std::str::from_utf8(&stream.data[..hdr_end_rel]) else {
        return false;
    };
    hdr_text
        .lines()
        .next()
        .map(|l| l.trim_end_matches('\r').starts_with("HTTP/1."))
        .unwrap_or(false)
}

fn parse_stream_messages(
    stream: &ReassembledStream,
    redact_sensitive_headers: bool,
    expected_methods: &[&str],
) -> Vec<ParsedStreamItem> {
    if is_cleartext_credential_port(stream.key.src_port) || is_cleartext_credential_port(stream.key.dst_port) {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut resp_idx = 0usize;
    let buf = &stream.data;

    while pos < buf.len() {
        let Some((hdr_end_rel, body_start_rel)) = find_header_end(&buf[pos..]) else {
            break;
        };
        let hdr_slice = &buf[pos..pos + hdr_end_rel];
        let Ok(hdr_text) = std::str::from_utf8(hdr_slice) else {
            break;
        };
        let mut lines = hdr_text.lines();
        let Some(start_line) = lines.next() else {
            break;
        };
        let start_clean = start_line.trim_end_matches('\r');
        let rest_lines: Vec<&str> = lines.collect();
        let ts = stream.timestamp_at(pos);

        if start_clean.starts_with("HTTP/1.") {
            let mut parts = start_clean.splitn(3, ' ');
            let version = parts.next().unwrap_or("");
            let code_str = parts.next().unwrap_or("");
            let reason = parts.next().unwrap_or("").to_string();
            let Ok(status_code) = code_str.parse::<u16>() else {
                break;
            };
            let is_http_1_0 = version == "HTTP/1.0";
            let (headers, mut had_sensitive, mut raw_sanitized) =
                parse_headers_block(&rest_lines, redact_sensitive_headers);
            if matches!(status_code, 401 | 407) {
                had_sensitive = true;
            }
            let content_type = header_value(&headers, "content-type").map(|s| s.to_string());
            let server = header_value(&headers, "server").map(|s| s.to_string());
            let content_encoding = header_value(&headers, "content-encoding").map(|s| s.to_string());

            let req_method = if is_interim_1xx(status_code) {
                None
            } else {
                let m = expected_methods.get(resp_idx).copied();
                resp_idx += 1;
                m
            };

            let body_buf = &buf[pos + body_start_rel..];
            let (body, decoded_len, consumed, truncated) = consume_body(
                body_buf,
                &headers,
                true,
                Some(status_code),
                req_method,
                is_http_1_0,
                stream.closed,
            );

            let mut wire = format!("{start_clean}\r\n").into_bytes();
            wire.append(&mut raw_sanitized);
            wire.extend_from_slice(b"\r\n");

            out.push(ParsedStreamItem::Response(HttpResponse {
                timestamp: ts,
                status_code,
                reason,
                content_type,
                server,
                headers,
                body,
                decoded_body_len: decoded_len,
                body_truncated: truncated,
                content_encoding,
                had_sensitive_material: had_sensitive,
                raw_sanitized_headers: wire,
            }));
            pos += body_start_rel + consumed;
            continue;
        }

        // Check request start line: "<METHOD> <target> HTTP/1.x"
        let parts: Vec<&str> = start_clean.split_whitespace().collect();
        if parts.len() == 3 && HTTP_METHODS.contains(&parts[0]) && parts[2].starts_with("HTTP/1.") {
            let method = parts[0].to_string();
            let raw_target = parts[1];
            let scrubbed_path = scrub_url_credentials(raw_target);
            let path_was_scrubbed = scrubbed_path != raw_target;

            let (headers, mut had_sensitive, mut raw_sanitized) =
                parse_headers_block(&rest_lines, redact_sensitive_headers);
            if path_was_scrubbed {
                had_sensitive = true;
            }
            let host = header_value(&headers, "host").map(|s| s.to_string());
            let user_agent = header_value(&headers, "user-agent").map(|s| s.to_string());

            let body_buf = &buf[pos + body_start_rel..];
            let (_body, decoded_len, consumed, _truncated) = consume_body(
                body_buf,
                &headers,
                false,
                None,
                Some(method.as_str()),
                parts[2] == "HTTP/1.0",
                stream.closed,
            );

            let mut wire = format!("{method} {scrubbed_path} {}\r\n", parts[2]).into_bytes();
            wire.append(&mut raw_sanitized);
            wire.extend_from_slice(b"\r\n");

            out.push(ParsedStreamItem::Request(HttpRequest {
                timestamp: ts,
                method,
                path: scrubbed_path,
                host,
                user_agent,
                headers,
                body_len: decoded_len,
                had_sensitive_material: had_sensitive,
                raw_sanitized_headers: wire,
            }));
            pos += body_start_rel + consumed;
            continue;
        }

        break;
    }

    out
}

pub fn extract_http_transactions(packets: &[CapturedPacket], redact_sensitive_headers: bool) -> Vec<HttpTransaction> {
    let mut reassembler = TcpStreamReassembler::new();
    reassembler.ingest_packets(packets);
    let streams = reassembler.finalize();

    let mut req_streams: HashMap<StreamKey, VecDeque<HttpRequest>> = HashMap::new();
    let mut resp_streams: HashMap<StreamKey, VecDeque<HttpResponse>> = HashMap::new();
    let mut stream_order: Vec<StreamKey> = Vec::new();
    let mut deferred_resp_streams: Vec<ReassembledStream> = Vec::new();

    for stream in streams {
        if is_response_stream(&stream) {
            deferred_resp_streams.push(stream);
            continue;
        }
        let items = parse_stream_messages(&stream, redact_sensitive_headers, &[]);
        if items.is_empty() {
            continue;
        }
        let mut reqs = VecDeque::new();
        let mut resps = VecDeque::new();
        for item in items {
            match item {
                ParsedStreamItem::Request(r) => reqs.push_back(r),
                ParsedStreamItem::Response(r) => resps.push_back(r),
            }
        }
        if !reqs.is_empty() {
            if !req_streams.contains_key(&stream.key) {
                stream_order.push(stream.key);
            }
            req_streams.insert(stream.key, reqs);
        }
        if !resps.is_empty() {
            resp_streams.insert(stream.key, resps);
        }
    }

    for stream in deferred_resp_streams {
        let methods: Vec<&str> = req_streams
            .get(&stream.key.reverse())
            .map(|reqs| reqs.iter().map(|r| r.method.as_str()).collect())
            .unwrap_or_default();
        let items = parse_stream_messages(&stream, redact_sensitive_headers, &methods);
        if items.is_empty() {
            continue;
        }
        let mut resps = VecDeque::new();
        for item in items {
            if let ParsedStreamItem::Response(r) = item {
                resps.push_back(r);
            }
        }
        if !resps.is_empty() {
            resp_streams.insert(stream.key, resps);
        }
    }

    let mut transactions = Vec::new();

    for client_key in stream_order {
        let Some(mut reqs) = req_streams.remove(&client_key) else {
            continue;
        };
        let server_key = client_key.reverse();
        let mut resps = resp_streams.remove(&server_key).unwrap_or_default();

        while let Some(req) = reqs.pop_front() {
            let resp = pop_effective_response(&mut resps);
            let had_sensitive =
                req.had_sensitive_material || resp.as_ref().map(|r| r.had_sensitive_material).unwrap_or(false);
            transactions.push(HttpTransaction {
                timestamp: req.timestamp.or_else(|| resp.as_ref().and_then(|r| r.timestamp)),
                src_ip: client_key.src_ip,
                src_port: client_key.src_port,
                dst_ip: client_key.dst_ip,
                dst_port: client_key.dst_port,
                request: Some(req),
                response: resp,
                had_sensitive_material: had_sensitive,
            });
        }
        while let Some(resp) = pop_effective_response(&mut resps) {
            let had_sensitive = resp.had_sensitive_material;
            transactions.push(HttpTransaction {
                timestamp: resp.timestamp,
                src_ip: server_key.dst_ip,
                src_port: server_key.dst_port,
                dst_ip: server_key.src_ip,
                dst_port: server_key.src_port,
                request: None,
                response: Some(resp),
                had_sensitive_material: had_sensitive,
            });
        }
    }

    // Any unpaired server->client responses
    for (server_key, mut resps) in resp_streams {
        while let Some(resp) = pop_effective_response(&mut resps) {
            let had_sensitive = resp.had_sensitive_material;
            transactions.push(HttpTransaction {
                timestamp: resp.timestamp,
                src_ip: server_key.dst_ip,
                src_port: server_key.dst_port,
                dst_ip: server_key.src_ip,
                dst_port: server_key.src_port,
                request: None,
                response: Some(resp),
                had_sensitive_material: had_sensitive,
            });
        }
    }

    transactions
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::capture::LinkType;
    use crate::capture::fixtures::{base_timestamp, build_eth_frame, build_ipv4_packet, build_tcp_segment};

    #[test]
    fn test_decode_chunked_body_overflow_returns_none_without_panic() {
        // 18 bytes before chunk data -> pos = 18; chunk_size = 0xffffffffffffffed -> pos + chunk_size = usize::MAX
        let payload = b"ffffffffffffffed\r\nAAAA";
        assert!(decode_chunked_body(payload).is_none());

        // Exact usize::MAX and usize::MAX - pos boundaries (portable across 32/64-bit)
        for delta in [0usize, 1, 2] {
            let line = format!("{:x}\r\n", usize::MAX - delta);
            let mut buf = line.into_bytes();
            buf.extend_from_slice(b"AAAA");
            assert!(decode_chunked_body(&buf).is_none());
        }

        // End-to-end through extract_http_transactions
        let client_ip = Ipv4Addr::new(10, 0, 0, 1);
        let server_ip = Ipv4Addr::new(10, 0, 0, 2);
        let cmac = [1, 2, 3, 4, 5, 6];
        let smac = [6, 5, 4, 3, 2, 1];
        let req = b"GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n";
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffed\r\nAAAA";
        let pkts = vec![
            CapturedPacket {
                packet_no: 1,
                timestamp: Some(base_timestamp()),
                link_type: LinkType::Ethernet,
                original_len: 0,
                interface_id: None,
                interface_name: None,
                data: build_eth_frame(
                    smac,
                    cmac,
                    0x0800,
                    None,
                    &build_ipv4_packet(
                        client_ip,
                        server_ip,
                        6,
                        &build_tcp_segment(50000, 80, 100, 1, 0x18, req),
                    ),
                ),
            },
            CapturedPacket {
                packet_no: 2,
                timestamp: Some(base_timestamp()),
                link_type: LinkType::Ethernet,
                original_len: 0,
                interface_id: None,
                interface_name: None,
                data: build_eth_frame(
                    cmac,
                    smac,
                    0x0800,
                    None,
                    &build_ipv4_packet(
                        server_ip,
                        client_ip,
                        6,
                        &build_tcp_segment(80, 50000, 200, 100, 0x18, resp),
                    ),
                ),
            },
        ];
        let txns = extract_http_transactions(&pkts, true);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].response.as_ref().unwrap().status_code, 200);
    }

    #[test]
    fn test_pipelined_head_followed_by_get_framing() {
        let client_ip = Ipv4Addr::new(192, 168, 1, 10);
        let server_ip = Ipv4Addr::new(93, 184, 216, 34);
        let cmac = [0x08, 0x00, 0x27, 0x01, 0x02, 0x03];
        let smac = [0x00, 0x50, 0x56, 0x04, 0x05, 0x06];

        let req_pipe = b"HEAD /big.bin HTTP/1.1\r\nHost: example.com\r\n\r\nGET /after-head.txt HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let resp_pipe = b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\nContent-Type: application/octet-stream\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello";

        let pkts = vec![
            CapturedPacket {
                packet_no: 1,
                timestamp: Some(base_timestamp()),
                link_type: LinkType::Ethernet,
                original_len: req_pipe.len() as u32,
                interface_id: None,
                interface_name: None,
                data: build_eth_frame(
                    smac,
                    cmac,
                    0x0800,
                    None,
                    &build_ipv4_packet(
                        client_ip,
                        server_ip,
                        6,
                        &build_tcp_segment(51000, 80, 1000, 5000, 0x18, req_pipe),
                    ),
                ),
            },
            CapturedPacket {
                packet_no: 2,
                timestamp: Some(base_timestamp()),
                link_type: LinkType::Ethernet,
                original_len: resp_pipe.len() as u32,
                interface_id: None,
                interface_name: None,
                data: build_eth_frame(
                    cmac,
                    smac,
                    0x0800,
                    None,
                    &build_ipv4_packet(
                        server_ip,
                        client_ip,
                        6,
                        &build_tcp_segment(80, 51000, 5000, 1000 + req_pipe.len() as u32, 0x18, resp_pipe),
                    ),
                ),
            },
        ];

        let txns = extract_http_transactions(&pkts, true);
        assert_eq!(txns.len(), 2);
        let head_txn = &txns[0];
        assert_eq!(head_txn.request.as_ref().unwrap().method, "HEAD");
        assert_eq!(head_txn.request.as_ref().unwrap().path, "/big.bin");
        assert_eq!(head_txn.response.as_ref().unwrap().status_code, 200);
        assert_eq!(head_txn.response.as_ref().unwrap().decoded_body_len, 0);
        assert!(head_txn.response.as_ref().unwrap().body.is_empty());

        let get_txn = &txns[1];
        assert_eq!(get_txn.request.as_ref().unwrap().method, "GET");
        assert_eq!(get_txn.request.as_ref().unwrap().path, "/after-head.txt");
        assert_eq!(get_txn.response.as_ref().unwrap().status_code, 200);
        assert_eq!(get_txn.response.as_ref().unwrap().decoded_body_len, 5);
        assert_eq!(get_txn.response.as_ref().unwrap().body, b"hello");
    }

    #[test]
    fn test_pipelined_1xx_interim_responses_multi_1xx_101_and_trailing_orphan() {
        let client_ip = Ipv4Addr::new(192, 168, 1, 10);
        let server_ip = Ipv4Addr::new(93, 184, 216, 34);
        let cmac = [0x08, 0x00, 0x27, 0x01, 0x02, 0x03];
        let smac = [0x00, 0x50, 0x56, 0x04, 0x05, 0x06];

        let make_pkts = |cport: u16, req_bytes: &[u8], resp_bytes: &[u8]| -> Vec<CapturedPacket> {
            vec![
                CapturedPacket {
                    packet_no: 1,
                    timestamp: Some(base_timestamp()),
                    link_type: LinkType::Ethernet,
                    original_len: req_bytes.len() as u32,
                    interface_id: None,
                    interface_name: None,
                    data: build_eth_frame(
                        smac,
                        cmac,
                        0x0800,
                        None,
                        &build_ipv4_packet(
                            client_ip,
                            server_ip,
                            6,
                            &build_tcp_segment(cport, 80, 1000, 5000, 0x18, req_bytes),
                        ),
                    ),
                },
                CapturedPacket {
                    packet_no: 2,
                    timestamp: Some(base_timestamp()),
                    link_type: LinkType::Ethernet,
                    original_len: resp_bytes.len() as u32,
                    interface_id: None,
                    interface_name: None,
                    data: build_eth_frame(
                        cmac,
                        smac,
                        0x0800,
                        None,
                        &build_ipv4_packet(
                            server_ip,
                            client_ip,
                            6,
                            &build_tcp_segment(80, cport, 5000, 1000 + req_bytes.len() as u32, 0x18, resp_bytes),
                        ),
                    ),
                },
            ]
        };

        // 1. HEAD + GET where GET receives multiple 1xx (103 + 100) before 200 OK "hello"
        let req1 = b"HEAD /big.bin HTTP/1.1\r\nHost: example.com\r\n\r\nGET /after-head.txt HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let resp1 = b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let txns1 = extract_http_transactions(&make_pkts(51001, req1, resp1), true);
        assert_eq!(txns1.len(), 2);
        assert_eq!(txns1[0].request.as_ref().unwrap().method, "HEAD");
        assert_eq!(txns1[0].response.as_ref().unwrap().status_code, 200);
        assert_eq!(txns1[0].response.as_ref().unwrap().decoded_body_len, 0);
        assert_eq!(txns1[1].request.as_ref().unwrap().method, "GET");
        assert_eq!(txns1[1].request.as_ref().unwrap().path, "/after-head.txt");
        assert_eq!(txns1[1].response.as_ref().unwrap().status_code, 200);
        assert_eq!(txns1[1].response.as_ref().unwrap().decoded_body_len, 5);
        assert_eq!(txns1[1].response.as_ref().unwrap().body, b"hello");

        // 2. 101 Switching Protocols is NOT skipped (it is the final HTTP/1.1 response)
        let req2 = b"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let resp2 = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let txns2 = extract_http_transactions(&make_pkts(51002, req2, resp2), true);
        assert_eq!(txns2.len(), 1);
        assert_eq!(txns2[0].response.as_ref().unwrap().status_code, 101);

        // 3. Trailing orphan 100 Continue on truncated stream stays cleanly attached to POST
        let req3 = b"GET /ok HTTP/1.1\r\nHost: example.com\r\n\r\nPOST /upload HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 10\r\n\r\n";
        let resp3 = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 100 Continue\r\n\r\n";
        let txns3 = extract_http_transactions(&make_pkts(51003, req3, resp3), true);
        assert_eq!(txns3.len(), 2);
        assert_eq!(txns3[0].response.as_ref().unwrap().status_code, 200);
        assert_eq!(txns3[1].request.as_ref().unwrap().method, "POST");
        assert_eq!(txns3[1].response.as_ref().unwrap().status_code, 100);
    }
}
