use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use guap_mcp::McpToolError;
use net2rust_core::{NetError, NetResult};
use serde_json::Value;

/// Converts an IPv4 address into the network-byte-order `u32` expected by
/// Win32 `IPAddr` APIs (`IcmpSendEcho2`, `SendARP`, `IN_ADDR.S_un.S_addr`).
#[inline]
pub fn ipv4_to_win32_u32(ip: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(ip.octets())
}

/// Converts a Win32 network-byte-order `u32` (`IPAddr`) back to `Ipv4Addr`.
#[inline]
pub fn win32_u32_to_ipv4(raw: u32) -> Ipv4Addr {
    Ipv4Addr::from(raw.to_ne_bytes())
}

/// Runs `worker` across `items` using a bounded `std::thread::scope` pool,
/// preserving the original item order in the returned `Vec`.
pub fn run_bounded<T, R, F>(items: &[T], max_workers: usize, worker: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
{
    if items.is_empty() {
        return Vec::new();
    }
    let worker_count = items.len().min(max_workers.max(1));
    if worker_count == 1 {
        return items.iter().map(worker).collect();
    }

    let cursor = AtomicUsize::new(0);
    let results: Mutex<Vec<(usize, R)>> = Mutex::new(Vec::with_capacity(items.len()));

    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            scope.spawn(|| {
                loop {
                    let idx = cursor.fetch_add(1, Ordering::Relaxed);
                    if idx >= items.len() {
                        break;
                    }
                    let out = worker(&items[idx]);
                    if let Ok(mut guard) = results.lock() {
                        guard.push((idx, out));
                    }
                }
            });
        }
    });

    let mut collected = results.into_inner().unwrap_or_default();
    collected.sort_by_key(|(idx, _)| *idx);
    collected.into_iter().map(|(_, r)| r).collect()
}

/// Formats raw bytes as lowercase hex without spaces.
pub fn encode_hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Enforces `additionalProperties: false` for MCP `ActionCommand` arguments.
pub(crate) fn reject_unknown_json_keys(args: &Value, allowed: &[&str]) -> Result<(), McpToolError> {
    let obj = args
        .as_object()
        .ok_or_else(|| McpToolError::InvalidParams("tool arguments must be a JSON object".into()))?;
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(McpToolError::InvalidParams(format!("unknown parameter: {key}")));
        }
    }
    Ok(())
}

/// Parses a single RFC-4180 CSV line into fields, supporting `"..."` quoted commas,
/// escaped `""` quotes, and whitespace trimming on unquoted fields / around outer quotes.
pub fn parse_csv_fields(line: &str) -> NetResult<Vec<String>> {
    if line.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut fields = Vec::new();
    let mut chars = line.chars().peekable();

    loop {
        while matches!(chars.peek(), Some(' ' | '\t')) {
            chars.next();
        }

        match chars.peek().copied() {
            None => {
                fields.push(String::new());
                break;
            }
            Some(',') => {
                chars.next();
                fields.push(String::new());
            }
            Some('"') => {
                chars.next();
                let mut field = String::new();
                loop {
                    match chars.next() {
                        None => {
                            return Err(NetError::ParseError("unclosed quoted field in CSV line".into()));
                        }
                        Some('"') => {
                            if chars.peek() == Some(&'"') {
                                chars.next();
                                field.push('"');
                            } else {
                                break;
                            }
                        }
                        Some(ch) => field.push(ch),
                    }
                }

                while matches!(chars.peek(), Some(' ' | '\t')) {
                    chars.next();
                }

                match chars.next() {
                    None => {
                        fields.push(field);
                        break;
                    }
                    Some(',') => {
                        fields.push(field);
                    }
                    Some(other) => {
                        return Err(NetError::ParseError(format!(
                            "unexpected character '{other}' after closing quote in CSV line"
                        )));
                    }
                }
            }
            Some(_) => {
                let mut field = String::new();
                loop {
                    match chars.next() {
                        None => {
                            fields.push(field.trim_end().to_string());
                            return Ok(fields);
                        }
                        Some(',') => {
                            fields.push(field.trim_end().to_string());
                            break;
                        }
                        Some('"') => {
                            return Err(NetError::ParseError(
                                "unexpected quote inside unquoted CSV field".into(),
                            ));
                        }
                        Some(ch) => field.push(ch),
                    }
                }
            }
        }
    }

    Ok(fields)
}

#[cfg(windows)]
pub(crate) fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
pub(crate) unsafe fn pwstr_to_string(ptr: windows::core::PWSTR) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: Caller guarantees `ptr` points to a valid NUL-terminated UTF-16 buffer.
    let wide = unsafe { ptr.as_wide() };
    String::from_utf16_lossy(wide)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_win32_endianness_roundtrip() {
        let ip = Ipv4Addr::new(192, 168, 1, 10);
        let raw = ipv4_to_win32_u32(ip);
        if cfg!(target_endian = "little") {
            assert_eq!(raw, 0x0a01_a8c0);
        } else {
            assert_eq!(raw, 0xc0a8_010a);
        }
        assert_eq!(win32_u32_to_ipv4(raw), ip);
    }

    #[test]
    fn test_run_bounded_preserves_order() {
        let items: Vec<u32> = (0..50).collect();
        let out = run_bounded(&items, 8, |x| x * 3 + 1);
        let expected: Vec<u32> = items.iter().map(|x| x * 3 + 1).collect();
        assert_eq!(out, expected);
    }

    #[test]
    fn test_parse_csv_fields_rfc4180() {
        let fields =
            parse_csv_fields(r#"1.1.1.0/24, KR , "Korea, Republic of" , AS13335 , "Cloudflare, Inc.""#).unwrap();
        assert_eq!(
            fields,
            vec!["1.1.1.0/24", "KR", "Korea, Republic of", "AS13335", "Cloudflare, Inc."]
        );

        let escaped = parse_csv_fields(r#"00:50:56, "Acme ""Lab"", Inc." "#).unwrap();
        assert_eq!(escaped, vec!["00:50:56", r#"Acme "Lab", Inc."#]);

        assert!(parse_csv_fields(r#"00:50:56,"unclosed, Inc."#).is_err());
        assert!(parse_csv_fields(r#"00:50:56,"extra"junk"#).is_err());
        assert!(parse_csv_fields(r#"00:50:56,bad"quote"#).is_err());
    }

    #[test]
    fn test_reject_unknown_json_keys() {
        assert!(reject_unknown_json_keys(&serde_json::json!({"a": 1}), &["a", "b"]).is_ok());
        assert!(matches!(
            reject_unknown_json_keys(&serde_json::json!({"a": 1, "c": 2}), &["a", "b"]),
            Err(McpToolError::InvalidParams(msg)) if msg.contains("c")
        ));
        assert!(matches!(
            reject_unknown_json_keys(&serde_json::json!([1, 2]), &["a"]),
            Err(McpToolError::InvalidParams(_))
        ));
    }
}
