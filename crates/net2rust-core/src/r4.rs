pub const FORBIDDEN_WLAN_PROFILE_FLAG: u32 = 0x0000_0004;

const AUTH_COOKIE_KEYWORDS: &[&str] = &[
    "session",
    "token",
    "auth",
    "jwt",
    "sid",
    "passwd",
    "password",
    "secret",
    "csrf",
    "xsrf",
    "bearer",
    "apikey",
    "api_key",
    "credential",
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

const SENSITIVE_HEADER_NAMES: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth",
    "x-auth-token",
    "auth-token",
    "x-token",
    "x-access-token",
    "access-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-secret",
    "x-session-id",
    "x-session-token",
    "x-jwt",
    "x-jwt-token",
    "x-amz-security-token",
];

const SENSITIVE_HEADER_SUBSTRINGS: &[&str] = &[
    "api-key",
    "apikey",
    "auth-token",
    "access-token",
    "x-auth",
    "x-token",
    "session",
    "jwt",
    "bearer",
    "secret",
    "password",
    "passwd",
    "credential",
];

pub fn sanitize_cookie_header(value: &str) -> String {
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
            let is_sensitive = !is_attribute && AUTH_COOKIE_KEYWORDS.iter().any(|kw| lower_name.contains(kw));

            if is_sensitive {
                out_parts.push(format!("{clean_name}=[REDACTED]"));
            } else {
                out_parts.push(trimmed.to_string());
            }
        } else {
            out_parts.push(trimmed.to_string());
        }
    }

    out_parts.join("; ")
}

pub fn sanitize_http_header(name: &str, value: &str) -> String {
    let lower = name.trim().to_ascii_lowercase();
    if lower == "cookie" || lower == "set-cookie" || lower == "set-cookie2" {
        return sanitize_cookie_header(value);
    }

    if SENSITIVE_HEADER_NAMES.contains(&lower.as_str())
        || SENSITIVE_HEADER_SUBSTRINGS.iter().any(|sub| lower.contains(sub))
    {
        return "[REDACTED]".to_string();
    }

    value.to_string()
}

fn is_xml_ncname_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
}

struct OpeningKeyMaterialTag {
    open_start: usize,
    after_name: usize,
    prefix_range: Option<(usize, usize)>,
}

fn find_opening_keymaterial_tag(lower: &str, start: usize) -> Option<OpeningKeyMaterialTag> {
    const TAG_NAME: &str = "keymaterial";
    let bytes = lower.as_bytes();
    let mut pos = start;

    while let Some(rel) = lower[pos..].find(TAG_NAME) {
        let km_pos = pos + rel;
        let after_name = km_pos + TAG_NAME.len();
        let next_byte = bytes.get(after_name).copied();
        // Next byte must be ASCII whitespace, '/', or '>' so <keyMaterialType> is not matched.
        let is_tag_boundary = matches!(next_byte, Some(b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n'));
        if !is_tag_boundary {
            pos = after_name;
            continue;
        }

        if km_pos > start && bytes[km_pos - 1] == b'<' {
            return Some(OpeningKeyMaterialTag {
                open_start: km_pos - 1,
                after_name,
                prefix_range: None,
            });
        }

        if km_pos >= start + 3 && bytes[km_pos - 1] == b':' {
            let mut prefix_start = km_pos - 1;
            while prefix_start > start && is_xml_ncname_char(bytes[prefix_start - 1]) {
                prefix_start -= 1;
            }
            if prefix_start < km_pos - 1 && prefix_start > start && bytes[prefix_start - 1] == b'<' {
                return Some(OpeningKeyMaterialTag {
                    open_start: prefix_start - 1,
                    after_name,
                    prefix_range: Some((prefix_start, km_pos - 1)),
                });
            }
        }

        pos = after_name;
    }

    None
}

fn find_tag_close_quote_aware(bytes: &[u8], start: usize) -> Option<usize> {
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut i = start;

    while i < bytes.len() {
        let b = bytes[i];
        if in_single_quote {
            if b == b'\'' {
                in_single_quote = false;
            }
        } else if in_double_quote {
            if b == b'"' {
                in_double_quote = false;
            }
        } else {
            match b {
                b'\'' => in_single_quote = true,
                b'"' => in_double_quote = true,
                b'>' => return Some(i),
                _ => {}
            }
        }
        i += 1;
    }

    None
}

fn find_closing_keymaterial_tag(lower: &str, start: usize) -> Option<usize> {
    const TAG_NAME: &str = "keymaterial";
    let bytes = lower.as_bytes();
    let mut pos = start;

    while let Some(rel) = lower[pos..].find(TAG_NAME) {
        let km_pos = pos + rel;
        let after_km = km_pos + TAG_NAME.len();

        let has_close_prefix = if km_pos >= start + 2 && &bytes[km_pos - 2..km_pos] == b"</" {
            true
        } else if km_pos >= start + 4 && bytes[km_pos - 1] == b':' {
            let mut prefix_start = km_pos - 1;
            while prefix_start > start && is_xml_ncname_char(bytes[prefix_start - 1]) {
                prefix_start -= 1;
            }
            prefix_start < km_pos - 1 && prefix_start >= start + 2 && &bytes[prefix_start - 2..prefix_start] == b"</"
        } else {
            false
        };

        if has_close_prefix {
            let mut end = after_km;
            while end < bytes.len() && bytes[end].is_ascii_whitespace() {
                end += 1;
            }
            if end < bytes.len() && bytes[end] == b'>' {
                return Some(end + 1);
            }
        }

        pos = after_km;
    }

    None
}

pub fn sanitize_wlan_profile_xml(xml: &str) -> String {
    let lower = xml.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut result = String::with_capacity(xml.len());
    let mut cursor = 0usize;

    while let Some(OpeningKeyMaterialTag {
        open_start,
        after_name,
        prefix_range,
    }) = find_opening_keymaterial_tag(&lower, cursor)
    {
        // Copy everything before <[prefix:]keyMaterial...>
        result.push_str(&xml[cursor..open_start]);

        let redacted_elem = match prefix_range {
            Some((ps, pe)) => format!(
                "<{}:keyMaterial>[REDACTED]</{}:keyMaterial>",
                &xml[ps..pe],
                &xml[ps..pe]
            ),
            None => "<keyMaterial>[REDACTED]</keyMaterial>".to_string(),
        };

        // Find real closing '>' of the opening tag outside single/double quotes.
        let Some(gt_pos) = find_tag_close_quote_aware(bytes, after_name) else {
            // Malformed unclosed opening tag: redact remainder safely.
            result.push_str(&redacted_elem);
            return result;
        };
        let open_end = gt_pos + 1;

        // Treat as self-closing ONLY if '/' immediately precedes the real closing '>' outside quotes.
        if gt_pos > after_name && bytes[gt_pos - 1] == b'/' {
            result.push_str(&xml[open_start..open_end]);
            cursor = open_end;
            continue;
        }

        if let Some(close_end) = find_closing_keymaterial_tag(&lower, open_end) {
            result.push_str(&redacted_elem);
            cursor = close_end;
        } else {
            // Truncated XML missing closing tag: never leak partial key material.
            result.push_str(&redacted_elem);
            return result;
        }
    }

    result.push_str(&xml[cursor..]);
    result
}
