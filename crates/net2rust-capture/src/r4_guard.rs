//! Defense-in-depth R4 enforcement: zero credential extraction, header/cookie/URL redaction,
//! and sanitization of `Row::detail_json` and `Row::raw_bytes`.

use net2rust_core::{sanitize_cookie_header, sanitize_http_header};

pub const REDACTED_MARKER: &str = "[REDACTED]";

const AUTH_PARAM_KEYWORDS: &[&str] = &[
    "session",
    "token",
    "auth",
    "jwt",
    "sid",
    "passwd",
    "password",
    "pwd",
    "secret",
    "csrf",
    "xsrf",
    "bearer",
    "apikey",
    "api_key",
    "credential",
    "access_token",
    "refresh_token",
    "id_token",
];

const EXTRA_SENSITIVE_HEADERS: &[&str] = &[
    "www-authenticate",
    "proxy-authenticate",
    "authentication-info",
    "proxy-authentication-info",
];

const COOKIE_ATTRIBUTES: &[&str] = &[
    "path",
    "domain",
    "httponly",
    "secure",
    "samesite",
    "max-age",
    "expires",
    "partitioned",
    "priority",
];

const URL_BEARING_HEADERS: &[&str] = &[
    "referer",
    "referrer",
    "location",
    "content-location",
    "origin",
    "link",
    "refresh",
    "x-original-url",
    "x-rewrite-url",
    "destination",
];

const CLEARTEXT_CREDENTIAL_PORTS: &[u16] = &[21, 23, 25, 110, 143, 587];

pub fn is_sensitive_cookie_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    AUTH_PARAM_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

pub fn is_sensitive_header_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    if EXTRA_SENSITIVE_HEADERS.contains(&lower.as_str()) {
        return true;
    }
    sanitize_http_header(&lower, "probe_value") == REDACTED_MARKER
}

/// Sanitize a `Cookie`, `Set-Cookie`, or `Set-Cookie2` header value enforcing both
/// `net2rust_core::sanitize_cookie_header` and `r4_guard::AUTH_PARAM_KEYWORDS` (including `pwd`).
pub fn sanitize_cookie_header_r4(value: &str) -> String {
    let mut out_parts = Vec::new();

    for raw_part in value.split(';') {
        let trimmed = raw_part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((name, _val)) = trimmed.split_once('=') {
            let clean_name = name.trim();
            let lower_name = clean_name.to_ascii_lowercase();
            let is_attribute = COOKIE_ATTRIBUTES.contains(&lower_name.as_str());
            if !is_attribute && is_sensitive_cookie_name(clean_name) {
                out_parts.push(format!("{clean_name}={REDACTED_MARKER}"));
            } else {
                out_parts.push(sanitize_cookie_header(trimmed));
            }
        } else {
            out_parts.push(trimmed.to_string());
        }
    }

    out_parts.join("; ")
}

/// Sanitize a single HTTP header value per R4.
///
/// Even if `redact_sensitive_headers` is `false`, auth/credential headers (`Authorization`,
/// `Proxy-Authorization`, `X-Api-Key`, `WWW-Authenticate`, `X-Session-Id`, `X-Bearer-Token`,
/// `Api-Key`, `Auth-Token`, etc.), auth/session cookies (including `pwd`), and URL credentials
/// (`scheme://user:pass@host`, `?token=`, etc.) are ALWAYS redacted per R4.
pub fn sanitize_header_value(name: &str, value: &str, redact_sensitive_headers: bool) -> String {
    let lower = name.trim().to_ascii_lowercase();
    if matches!(lower.as_str(), "cookie" | "set-cookie" | "set-cookie2") {
        // Even when redact_sensitive_headers == false, auth/session cookies stay redacted.
        return sanitize_cookie_header_r4(value);
    }

    if lower == "host" {
        return scrub_host_header_userinfo(value);
    }

    if is_sensitive_header_name(&lower) {
        return REDACTED_MARKER.to_string();
    }

    let core_sanitized = sanitize_http_header(name, value);
    if core_sanitized == REDACTED_MARKER {
        return REDACTED_MARKER.to_string();
    }

    if URL_BEARING_HEADERS.contains(&lower.as_str()) || contains_url_userinfo(&core_sanitized) {
        return scrub_url_credentials(&core_sanitized);
    }

    if redact_sensitive_headers && contains_cleartext_credential_pattern(core_sanitized.as_bytes()) {
        return REDACTED_MARKER.to_string();
    }

    core_sanitized
}

/// Sanitize a single cookie's value by cookie name.
pub fn sanitize_cookie_pair_value(cookie_name: &str, value: &str, redact_sensitive_headers: bool) -> String {
    if is_sensitive_cookie_name(cookie_name) {
        return REDACTED_MARKER.to_string();
    }
    if redact_sensitive_headers && contains_cleartext_credential_pattern(value.as_bytes()) {
        return REDACTED_MARKER.to_string();
    }
    value.to_string()
}

fn is_scheme_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')
}

fn has_valid_scheme_before(bytes: &[u8], scheme_end: usize) -> bool {
    let mut start = scheme_end;
    while start > 0 && is_scheme_char(bytes[start - 1]) {
        start -= 1;
    }
    start < scheme_end && bytes[start].is_ascii_alphabetic()
}

fn authority_end(bytes: &[u8], after_scheme: usize) -> usize {
    let mut i = after_scheme;
    while i < bytes.len() {
        if matches!(
            bytes[i],
            b'/' | b'?' | b'#' | b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'\'' | b'<' | b'>' | b';' | b','
        ) {
            break;
        }
        i += 1;
    }
    i
}

/// Returns `true` if `text` contains any `scheme://userinfo@host` URL with non-empty userinfo.
pub fn contains_url_userinfo(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find("://") {
        let scheme_end = search_from + rel;
        let after_scheme = scheme_end + 3;
        if has_valid_scheme_before(bytes, scheme_end) {
            let auth_end = authority_end(bytes, after_scheme);
            let authority = &text[after_scheme..auth_end];
            if let Some(at_pos) = authority.rfind('@')
                && at_pos > 0
            {
                return true;
            }
        }
        search_from = after_scheme;
    }
    false
}

/// Scrub `scheme://userinfo@host` authority credentials and sensitive query parameters
/// (`?token=...`, `?password=...`, `?pwd=...`, etc.) from request paths or URLs.
pub fn scrub_url_credentials(path_or_url: &str) -> String {
    let bytes = path_or_url.as_bytes();
    let mut scrubbed_userinfo = String::with_capacity(path_or_url.len());
    let mut cursor = 0usize;

    while let Some(rel) = path_or_url[cursor..].find("://") {
        let scheme_end = cursor + rel;
        let after_scheme = scheme_end + 3;
        if has_valid_scheme_before(bytes, scheme_end) {
            let auth_end = authority_end(bytes, after_scheme);
            let authority = &path_or_url[after_scheme..auth_end];
            if let Some(at_pos) = authority.rfind('@')
                && at_pos > 0
            {
                scrubbed_userinfo.push_str(&path_or_url[cursor..after_scheme]);
                scrubbed_userinfo.push_str(REDACTED_MARKER);
                scrubbed_userinfo.push_str(&authority[at_pos..]);
                cursor = auth_end;
                continue;
            }
        }
        scrubbed_userinfo.push_str(&path_or_url[cursor..after_scheme]);
        cursor = after_scheme;
    }
    scrubbed_userinfo.push_str(&path_or_url[cursor..]);

    scrub_url_query_params(&scrubbed_userinfo)
}

/// Scrub sensitive query parameters (`?token=...`, `?password=...`, etc.) from request paths or URLs.
pub fn scrub_url_query_params(path_or_url: &str) -> String {
    let (before_frag, frag) = match path_or_url.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (path_or_url, None),
    };

    let Some((base, query)) = before_frag.split_once('?') else {
        return path_or_url.to_string();
    };

    let mut out_params = Vec::new();
    for pair in query.split('&') {
        if let Some((key, _val)) = pair.split_once('=') {
            let lower_key = key.trim().to_ascii_lowercase();
            if AUTH_PARAM_KEYWORDS.iter().any(|kw| lower_key.contains(kw)) {
                out_params.push(format!("{key}={REDACTED_MARKER}"));
            } else {
                out_params.push(pair.to_string());
            }
        } else {
            out_params.push(pair.to_string());
        }
    }

    let mut rebuilt = format!("{base}?{}", out_params.join("&"));
    if let Some(f) = frag {
        rebuilt.push('#');
        rebuilt.push_str(f);
    }
    rebuilt
}

/// Returns `true` if a `Host` header value carries authority userinfo (`user:pass@host` or `user@host`).
pub fn host_header_has_userinfo(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.contains("://") {
        return contains_url_userinfo(trimmed);
    }
    let auth_end = authority_end(trimmed.as_bytes(), 0);
    let authority = &trimmed[..auth_end];
    authority.rfind('@').is_some_and(|at_pos| at_pos > 0)
}

/// Scrub authority userinfo (`user:pass@host` or `user@host`) from a `Host` header value.
pub fn scrub_host_header_userinfo(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return trimmed.to_string();
    }
    if trimmed.contains("://") {
        return scrub_url_credentials(trimmed);
    }
    let auth_end = authority_end(trimmed.as_bytes(), 0);
    let authority = &trimmed[..auth_end];
    if let Some(at_pos) = authority.rfind('@')
        && at_pos > 0
    {
        return format!("{REDACTED_MARKER}{}", &trimmed[at_pos..]);
    }
    trimmed.to_string()
}

pub fn is_cleartext_credential_port(port: u16) -> bool {
    CLEARTEXT_CREDENTIAL_PORTS.contains(&port)
}

const KNOWN_SASL_MECHS: &[&str] = &[
    "plain",
    "login",
    "cram-md5",
    "digest-md5",
    "xoauth2",
    "oauthbearer",
    "ntlm",
    "external",
    "gssapi",
    "anonymous",
    "otp",
    "skey",
    "securid",
    "oauth10a",
    "saml20",
    "openid20",
    "srp",
    "kerberos_v4",
    "kerberos_v5",
    "nmas_login",
    "nmas_authen",
];

fn is_sasl_mechanism_token(tok: &str) -> bool {
    !tok.is_empty()
        && tok.len() <= 20
        && tok
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        && tok.bytes().any(|b| b.is_ascii_alphabetic())
}

fn is_likely_sasl_mech(tok: &str) -> bool {
    if !is_sasl_mechanism_token(tok) {
        return false;
    }
    let lower = tok.to_ascii_lowercase();
    if KNOWN_SASL_MECHS.contains(&lower.as_str())
        || lower.starts_with("scram-")
        || lower.starts_with("gs2-")
        || lower.starts_with("eap-")
        || lower.starts_with("9798-")
    {
        return true;
    }
    // Accept arbitrary uppercase SASL mechanism tokens (e.g., `AUTH MYMECH`) or hyphenated/numbered tokens
    tok.bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
        || tok.contains('-')
        || tok.bytes().any(|b| b.is_ascii_digit())
}

fn is_imap_tag(tok: &str) -> bool {
    !tok.is_empty()
        && tok.len() <= 16
        && tok
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn starts_with_http_frame(text: &str) -> bool {
    let first_non_empty = text.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("");
    if first_non_empty.starts_with("HTTP/1.") {
        return true;
    }
    let parts: Vec<&str> = first_non_empty.split_whitespace().collect();
    parts.len() == 3
        && matches!(
            parts[0],
            "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH"
        )
        && parts[2].starts_with("HTTP/1.")
}

fn is_cmd_verb(tok: &str, upper: &str, lower: &str) -> bool {
    tok == upper || tok == lower
}

fn is_titlecase_word(tok: &str) -> bool {
    let mut chars = tok.chars();
    match chars.next() {
        Some(first) if first.is_ascii_uppercase() => {
            let mut has_lower = false;
            for c in chars {
                if !c.is_ascii_lowercase() {
                    return false;
                }
                has_lower = true;
            }
            has_lower
        }
        _ => false,
    }
}

fn is_cleartext_auth_command_payload(text: &str) -> bool {
    if starts_with_http_frame(text) {
        return false;
    }

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.is_empty() || tokens[0].ends_with(':') {
            continue;
        }

        // SMTP / POP3: AUTH <MECH> [initial-response] (case-insensitive per RFC 5321 / RFC 4954 / RFC 1734)
        if (tokens.len() == 2 || tokens.len() == 3)
            && tokens[0].eq_ignore_ascii_case("AUTH")
            && is_likely_sasl_mech(tokens[1])
        {
            return true;
        }

        // IMAP untagged: AUTHENTICATE <MECH> [initial-response] (case-insensitive per RFC 3501)
        if (tokens.len() == 2 || tokens.len() == 3)
            && tokens[0].eq_ignore_ascii_case("AUTHENTICATE")
            && is_likely_sasl_mech(tokens[1])
        {
            return true;
        }

        // IMAP tagged: <tag> AUTHENTICATE <MECH> [initial-response]
        if (tokens.len() == 3 || tokens.len() == 4)
            && is_imap_tag(tokens[0])
            && tokens[1].eq_ignore_ascii_case("AUTHENTICATE")
            && is_likely_sasl_mech(tokens[2])
        {
            return true;
        }

        // POP3 / FTP: USER <username> (reject TitleCase prose like "User Guide")
        if tokens.len() == 2
            && (is_cmd_verb(tokens[0], "USER", "user")
                || (tokens[0].eq_ignore_ascii_case("USER") && !is_titlecase_word(tokens[1])))
            && !tokens[1].ends_with(':')
            && !tokens[1].ends_with(',')
            && !tokens[1].ends_with('.')
        {
            return true;
        }

        // POP3 / FTP: PASS <password> (single-token or multi-word; case-insensitive verb per RFC 1939 / RFC 959)
        if tokens.len() >= 2 && tokens[0].eq_ignore_ascii_case("PASS") {
            return true;
        }

        // IMAP LOGIN: LOGIN <user> <pass> or <tag> LOGIN <user> <pass>
        if tokens.len() >= 3 && tokens[0].eq_ignore_ascii_case("LOGIN") {
            return true;
        }
        if tokens.len() >= 4
            && is_imap_tag(tokens[0])
            && tokens[1].eq_ignore_ascii_case("LOGIN")
            && (is_cmd_verb(tokens[1], "LOGIN", "login")
                || !is_titlecase_word(tokens[0])
                || !is_titlecase_word(tokens[1])
                || tokens[0].bytes().any(|b| b.is_ascii_digit())
                || tokens.iter().skip(2).any(|t| !is_titlecase_word(t)))
        {
            return true;
        }
    }

    false
}

/// Returns `true` if a packet initiates or occurs on a cleartext authentication protocol/stream.
pub fn is_cleartext_auth_initiation(src_port: Option<u16>, dst_port: Option<u16>, payload: &[u8]) -> bool {
    let p1 = src_port.unwrap_or(0);
    let p2 = dst_port.unwrap_or(0);
    if is_cleartext_credential_port(p1) || is_cleartext_credential_port(p2) {
        return true;
    }
    if payload.is_empty() {
        return false;
    }
    let text = String::from_utf8_lossy(payload);
    is_cleartext_auth_command_payload(&text)
}

/// Detect common cleartext credential markers in raw TCP/UDP payloads so `capture.sniff`
/// and `Row::raw_bytes` never leak them.
pub fn contains_cleartext_credential_pattern(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    let text = String::from_utf8_lossy(payload);
    if contains_url_userinfo(&text) || is_cleartext_auth_command_payload(&text) {
        return true;
    }

    let lower = text.to_ascii_lowercase();

    for line in lower.lines() {
        if let Some((hdr_name, val)) = line.split_once(':') {
            let trimmed = hdr_name.trim();
            if !trimmed.is_empty()
                && trimmed
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            {
                if is_sensitive_header_name(trimmed) || matches!(trimmed, "cookie" | "set-cookie" | "set-cookie2") {
                    return true;
                }
                if trimmed == "host" && host_header_has_userinfo(val) {
                    return true;
                }
            }
        }
    }

    let markers = [
        "authorization:",
        "proxy-authorization:",
        "www-authenticate:",
        "proxy-authenticate:",
        "authentication-info:",
        "proxy-authentication-info:",
        "x-api-key:",
        "api-key:",
        "x-auth:",
        "x-auth-token:",
        "auth-token:",
        "x-token:",
        "x-access-token:",
        "access-token:",
        "x-csrf-token:",
        "x-xsrf-token:",
        "x-secret:",
        "x-session-id:",
        "x-session-token:",
        "x-jwt",
        "x-amz-security-token:",
        "x-bearer-token:",
        "bearer ",
        "cookie:",
        "set-cookie:",
        "set-cookie2:",
        "password=",
        "passwd=",
        "pwd=",
        "secret=",
        "token=",
        "apikey=",
        "api_key=",
        "session=",
        "jsessionid=",
        "phpsessid=",
        "auth_sid=",
        "credential=",
        "access_token=",
        "refresh_token=",
        "id_token=",
    ];

    markers.iter().any(|m| lower.contains(m))
}

/// Format an R4-safe summary for continuation packets on a tainted cleartext authentication flow.
pub fn safe_tainted_flow_summary(base_proto: &str, payload_len: usize) -> String {
    format!("{base_proto} payload={payload_len}B [R4: authentication stream omitted]")
}

/// Produce a strictly R4-safe payload summary for `capture.sniff` (never emits cleartext
/// credentials for POP3/IMAP/FTP/SMTP/Telnet or credential-bearing HTTP payloads).
pub fn safe_payload_summary(src_port: Option<u16>, dst_port: Option<u16>, payload: &[u8], base_proto: &str) -> String {
    if payload.is_empty() {
        return format!("{base_proto} len=0");
    }

    let p1 = src_port.unwrap_or(0);
    let p2 = dst_port.unwrap_or(0);
    if is_cleartext_credential_port(p1) || is_cleartext_credential_port(p2) {
        return format!(
            "{base_proto} port={p2} payload={}B [R4 cleartext-protocol body suppressed]",
            payload.len()
        );
    }

    if contains_cleartext_credential_pattern(payload) {
        return format!(
            "{base_proto} payload={}B [R4 sensitive headers/params redacted]",
            payload.len()
        );
    }

    // Only emit a short ASCII first-line hint for benign traffic (e.g. HTTP method line).
    let text = String::from_utf8_lossy(&payload[..payload.len().min(96)]);
    let first_line = text.lines().next().unwrap_or("").trim();
    if first_line.is_empty() || !first_line.bytes().all(|b| (0x20..=0x7e).contains(&b) || b == b'\t') {
        return format!("{base_proto} payload={}B", payload.len());
    }

    let scrubbed = scrub_url_credentials(first_line);
    format!("{base_proto} {scrubbed}")
}

/// Determine whether a frame's raw payload should be omitted from `Row::raw_bytes` for R4 safety.
pub fn should_omit_raw_bytes(src_port: Option<u16>, dst_port: Option<u16>, payload: &[u8]) -> bool {
    let p1 = src_port.unwrap_or(0);
    let p2 = dst_port.unwrap_or(0);
    is_cleartext_credential_port(p1)
        || is_cleartext_credential_port(p2)
        || contains_cleartext_credential_pattern(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_url_query_params() {
        assert_eq!(
            scrub_url_query_params("/assets/app.js?token=leak123&v=2"),
            "/assets/app.js?token=[REDACTED]&v=2"
        );
        assert_eq!(
            scrub_url_query_params("https://example.com/login?user=alice&password=hunter2#top"),
            "https://example.com/login?user=alice&password=[REDACTED]#top"
        );
        assert_eq!(scrub_url_query_params("/index.html"), "/index.html");
    }

    #[test]
    fn test_sanitize_header_value_www_auth_and_cookies() {
        assert_eq!(
            sanitize_header_value("WWW-Authenticate", "Basic realm=\"Admin\"", true),
            REDACTED_MARKER
        );
        assert_eq!(
            sanitize_header_value("Authorization", "Basic dXNlcjpzZWNyZXQ=", false),
            REDACTED_MARKER
        );
        assert_eq!(
            sanitize_header_value("Cookie", "theme=dark; JSESSIONID=s1; auth_token=t1", true),
            "theme=dark; JSESSIONID=[REDACTED]; auth_token=[REDACTED]"
        );
    }

    #[test]
    fn test_cleartext_suppression() {
        let sum = safe_payload_summary(Some(50000), Some(110), b"PASS hunter2\r\n", "TCP");
        assert!(!sum.contains("hunter2"));
        assert!(sum.contains("suppressed"));

        let http_sum = safe_payload_summary(
            Some(50000),
            Some(80),
            b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n",
            "TCP",
        );
        assert!(!http_sum.contains("dXNlcjpzZWNyZXQ="));
        assert!(http_sum.contains("redacted"));
    }

    #[test]
    fn test_scrub_url_credentials_and_userinfo_detection() {
        assert_eq!(
            scrub_url_credentials("http://alice:hunter2@example.com/admin?token=abc&v=1#frag"),
            "http://[REDACTED]@example.com/admin?token=[REDACTED]&v=1#frag"
        );
        assert_eq!(
            scrub_url_credentials("https://onlyuser@example.com/path"),
            "https://[REDACTED]@example.com/path"
        );
        // '@' in path or query parameter value (not in authority) must not trigger false userinfo redaction
        assert_eq!(
            scrub_url_credentials("https://example.com/users/@alice?email=alice@example.com&pwd=pw1"),
            "https://example.com/users/@alice?email=alice@example.com&pwd=[REDACTED]"
        );
        assert!(contains_url_userinfo(
            "GET http://alice:hunter2@example.com/admin HTTP/1.1"
        ));
        assert!(!contains_url_userinfo("GET /users/@alice?email=a@b.com HTTP/1.1"));
        assert!(contains_cleartext_credential_pattern(
            b"GET http://alice:hunter2@example.com/admin HTTP/1.1\r\n\r\n"
        ));
    }

    #[test]
    fn test_extended_sensitive_headers_pwd_cookie_and_url_headers_unconditional() {
        for hdr in [
            "X-Session-Id",
            "X-Bearer-Token",
            "Api-Key",
            "Auth-Token",
            "Access-Token",
        ] {
            assert!(is_sensitive_header_name(hdr), "{hdr} should be sensitive");
            let payload = format!("GET /api HTTP/1.1\r\n{hdr}: secret_val\r\n\r\n");
            assert!(
                contains_cleartext_credential_pattern(payload.as_bytes()),
                "pattern check missed {hdr}"
            );
            assert!(should_omit_raw_bytes(Some(50000), Some(80), payload.as_bytes()));
        }

        // pwd cookie consistency regardless of redact_sensitive_headers
        assert_eq!(
            sanitize_header_value("Cookie", "theme=light; my_pwd=s3cr3t", false),
            "theme=light; my_pwd=[REDACTED]"
        );
        assert_eq!(
            sanitize_header_value("Set-Cookie", "my_pwd=s3cr3t; Path=/; HttpOnly", false),
            "my_pwd=[REDACTED]; Path=/; HttpOnly"
        );

        // URL-bearing headers scrubbed unconditionally even when redact_sensitive_headers == false
        assert_eq!(
            sanitize_header_value("Referer", "https://alice:hunter2@example.com/login?token=t1", false),
            "https://[REDACTED]@example.com/login?token=[REDACTED]"
        );
        assert_eq!(
            sanitize_header_value("Location", "https://example.com/cb?access_token=tok99", false),
            "https://example.com/cb?access_token=[REDACTED]"
        );
    }

    #[test]
    fn test_cleartext_auth_initiation_sasl_mechanisms_and_no_http_false_positives() {
        for cmd in [
            b"AUTH PLAIN\r\n".as_slice(),
            b"AUTH LOGIN\r\n".as_slice(),
            b"AUTH CRAM-MD5\r\n".as_slice(),
            b"AUTH XOAUTH2\r\n".as_slice(),
            b"auth xoauth2\r\n".as_slice(),
            b"AUTH OAUTHBEARER dXNlcj1hbGljZQ==\r\n".as_slice(),
            b"AUTH SCRAM-SHA-256\r\n".as_slice(),
            b"AUTH SCRAM-SHA-1-PLUS\r\n".as_slice(),
            b"AUTH DIGEST-MD5\r\n".as_slice(),
            b"AUTH NTLM\r\n".as_slice(),
            b"AUTH EXTERNAL\r\n".as_slice(),
            b"a001 AUTHENTICATE XOAUTH2\r\n".as_slice(),
            b"a002 LOGIN alice hunter2\r\n".as_slice(),
            b"USER alice\r\n".as_slice(),
            b"PASS hunter2\r\n".as_slice(),
        ] {
            assert!(
                is_cleartext_auth_initiation(Some(53000), Some(5870), cmd),
                "expected auth initiation for {:?}",
                String::from_utf8_lossy(cmd)
            );
            assert!(
                contains_cleartext_credential_pattern(cmd),
                "expected pattern match for {:?}",
                String::from_utf8_lossy(cmd)
            );
        }

        // HTTP headers and unrelated prose must NOT trigger cleartext auth flow tainting
        for benign in [
            b"GET /login HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test/1.0\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nPlease login to your user account and pass the auth check\r\n".as_slice(),
            b"Auth Required\r\nUser Guide\r\nLogin Page\r\n".as_slice(),
        ] {
            assert!(
                !is_cleartext_auth_initiation(Some(53000), Some(80), benign),
                "false positive auth initiation for {:?}",
                String::from_utf8_lossy(benign)
            );
        }
    }

    #[test]
    fn test_host_header_userinfo_redaction_and_non_authority_at_preservation() {
        assert!(host_header_has_userinfo("dave:ADV_HOST_UI_PASS_601@example.com"));
        assert!(host_header_has_userinfo("alice@example.com:8080"));
        assert!(host_header_has_userinfo("dave:pass@[::1]:8080"));
        assert!(!host_header_has_userinfo("example.com"));
        assert!(!host_header_has_userinfo("example.com:8080"));

        for redact in [true, false] {
            assert_eq!(
                sanitize_header_value("Host", "dave:ADV_HOST_UI_PASS_601@example.com", redact),
                "[REDACTED]@example.com"
            );
            assert_eq!(
                sanitize_header_value("Host", "alice@example.com:8080", redact),
                "[REDACTED]@example.com:8080"
            );
            assert_eq!(
                sanitize_header_value("Host", "http://dave:pass@example.com", redact),
                "http://[REDACTED]@example.com"
            );
        }

        assert_eq!(
            sanitize_header_value("From", "alice@example.com", true),
            "alice@example.com"
        );

        let raw_http = b"GET /host-ui HTTP/1.1\r\nHost: dave:ADV_HOST_UI_PASS_601@example.com\r\n\r\n";
        assert!(contains_cleartext_credential_pattern(raw_http));
        assert!(should_omit_raw_bytes(Some(50000), Some(80), raw_http));

        let benign_at = b"GET /users/@alice?email=alice@example.com HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!contains_cleartext_credential_pattern(benign_at));
        assert!(!should_omit_raw_bytes(Some(50000), Some(80), benign_at));
    }

    #[test]
    fn test_mixed_case_auth_verbs_multiword_pass_and_prose_exclusions() {
        for (port, cmd) in [
            (5870u16, b"Auth XOAUTH2\r\n".as_slice()),
            (5870, b"Authenticate PLAIN\r\n".as_slice()),
            (1430, b"A001 Authenticate XOAUTH2\r\n".as_slice()),
            (1430, b"a001 authenticate scram-sha-256\r\n".as_slice()),
            (1100, b"Pass hunter2\r\n".as_slice()),
            (1100, b"pass my secret phrase\r\n".as_slice()),
            (1100, b"PASS my secret phrase\r\n".as_slice()),
            (1100, b"Pass my secret phrase\r\n".as_slice()),
            (1100, b"User alice\r\n".as_slice()),
            (1430, b"A001 Login alice hunter2\r\n".as_slice()),
            (1430, b"a001 login alice my secret\r\n".as_slice()),
        ] {
            assert!(
                is_cleartext_auth_initiation(Some(53000), Some(port), cmd),
                "expected auth initiation on port {port} for {:?}",
                String::from_utf8_lossy(cmd)
            );
            assert!(
                contains_cleartext_credential_pattern(cmd),
                "expected credential pattern match for {:?}",
                String::from_utf8_lossy(cmd)
            );
            assert!(
                should_omit_raw_bytes(Some(53000), Some(port), cmd),
                "expected raw_bytes omission for {:?}",
                String::from_utf8_lossy(cmd)
            );
        }

        for benign in [
            b"Auth Required\r\n".as_slice(),
            b"User Guide\r\n".as_slice(),
            b"Login Page\r\n".as_slice(),
            b"Please Login Right Now\r\n".as_slice(),
            b"Pass: header_value\r\n".as_slice(),
        ] {
            assert!(
                !is_cleartext_auth_initiation(Some(53000), Some(9999), benign),
                "unexpected auth initiation for benign prose {:?}",
                String::from_utf8_lossy(benign)
            );
            assert!(
                !contains_cleartext_credential_pattern(benign),
                "unexpected credential pattern for benign prose {:?}",
                String::from_utf8_lossy(benign)
            );
        }
    }

    #[test]
    fn test_imap_login_mixed_case_titlecase_args_and_non_digit_tags() {
        for cmd in [
            b"Login Alice Secret\r\n".as_slice(),
            b"lOgIn Alice Secret\r\n".as_slice(),
            b"TAG Login Alice Secret\r\n".as_slice(),
            b"imap Login Alice Secret\r\n".as_slice(),
            b"a Login Alice Secret\r\n".as_slice(),
            b"A Login Alice Secret\r\n".as_slice(),
            b"Please lOgIn Alice Secret\r\n".as_slice(),
            b"A001 Login Alice Secret\r\n".as_slice(),
        ] {
            assert!(
                is_cleartext_auth_initiation(Some(53000), Some(1430), cmd),
                "expected auth initiation for {:?}",
                String::from_utf8_lossy(cmd)
            );
            assert!(
                contains_cleartext_credential_pattern(cmd),
                "expected credential pattern match for {:?}",
                String::from_utf8_lossy(cmd)
            );
            assert!(
                should_omit_raw_bytes(Some(53000), Some(1430), cmd),
                "expected raw_bytes omission for {:?}",
                String::from_utf8_lossy(cmd)
            );
            let sum = safe_payload_summary(Some(53000), Some(1430), cmd, "TCP");
            assert!(!sum.contains("Secret"), "summary leaked Secret: {sum}");
            assert!(!sum.contains("Alice"), "summary leaked Alice: {sum}");
            assert!(sum.contains("redacted"), "expected redacted marker in summary: {sum}");
        }

        for benign in [b"Login Page\r\n".as_slice(), b"Please Login Right Now\r\n".as_slice()] {
            assert!(
                !is_cleartext_auth_initiation(Some(53000), Some(9999), benign),
                "unexpected auth initiation for benign prose {:?}",
                String::from_utf8_lossy(benign)
            );
            assert!(
                !contains_cleartext_credential_pattern(benign),
                "unexpected credential pattern for benign prose {:?}",
                String::from_utf8_lossy(benign)
            );
            assert!(
                !should_omit_raw_bytes(Some(53000), Some(9999), benign),
                "unexpected raw_bytes omission for benign prose {:?}",
                String::from_utf8_lossy(benign)
            );
        }
    }
}
