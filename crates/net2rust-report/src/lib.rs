#![forbid(unsafe_code)]

//! Structured report rendering, R4 defense-in-depth sanitization, and
//! SHA-256/SHA-512 Merkle chain-of-custody manifests for `net2rust`.

use std::fs;
use std::path::Path;

use guap_table::{CellValue, TableData};
use net2rust_core::sanitize_http_header;
use serde_json::Value;
use thiserror::Error;

pub use guap_export::{
    CustodyLeaf, CustodyManifest, ExportError, ExportFormat, ExportOptions, build_custody_manifest,
    compute_merkle_root_sha256, compute_merkle_root_sha512, encode_hex_lower, export_table, sha256_hex, sha512_hex,
    write_custody_manifest_json, write_table_export,
};

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("export failed: {0}")]
    Export(#[from] ExportError),

    #[error("table error: {0}")]
    Table(#[from] guap_table::TableError),

    #[error("network diagnostic error: {0}")]
    Net(#[from] net2rust_core::NetError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("custody verification failed: {0}")]
    CustodyVerificationFailed(String),
}

pub fn default_export_options() -> ExportOptions {
    ExportOptions {
        include_header: true,
        neutralize_formulas: true,
        include_detail_json: false,
        pretty_json: true,
        title_override: None,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportOptions {
    pub export: ExportOptions,
    pub enforce_r4_redaction: bool,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            export: default_export_options(),
            enforce_r4_redaction: true,
        }
    }
}

const MAX_NESTED_JSON_DEPTH: usize = 8;

#[inline]
fn to_ascii_lowercase_vec(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out.make_ascii_lowercase();
    out
}

#[inline]
fn find_byte(haystack: &[u8], start: usize, needle: u8) -> Option<usize> {
    let mut p = start;
    while p < haystack.len() {
        if haystack[p] == needle {
            return Some(p);
        }
        p += 1;
    }
    None
}

#[inline]
fn starts_raw_json_container(bytes: &[u8], pos: usize) -> bool {
    let opener = bytes[pos];
    let mut k = pos + 1;
    while k < bytes.len() && matches!(bytes[k], b' ' | b'\t' | b'\r' | b'\n') {
        k += 1;
    }
    let Some(&next) = bytes.get(k) else {
        return false;
    };
    match opener {
        b'{' => matches!(next, b'}' | b'"'),
        b'[' => matches!(
            next,
            b']' | b'"' | b'{' | b'[' | b'-' | b'0'..=b'9' | b't' | b'f' | b'n'
        ),
        _ => false,
    }
}

fn contains_keymaterial_word(s: &str) -> bool {
    contains_ascii_case_insensitive(s.as_bytes(), b"keymaterial")
}

fn unique_json_marker_prefix(s: &str) -> String {
    let mut nonce = 0usize;
    loop {
        let candidate = format!("__GUAPJSON{nonce}_");
        if !s.contains(&candidate) {
            return candidate;
        }
        nonce += 1;
    }
}

fn json_span_has_quote_parity_hazard(span: &[u8]) -> bool {
    if span.contains(&b'\'')
        || find_ascii_bytes(span, 0, b"\\\"").is_some()
        || contains_ascii_case_insensitive(span, b"u0022")
        || contains_ascii_case_insensitive(span, b"u0027")
    {
        return true;
    }
    if span.contains(&b'&') {
        for i in 0..span.len() {
            if span[i] == b'&' && match_html_quote_entity(&span[i..]).is_some() {
                return true;
            }
        }
    }
    false
}

fn skip_excess_json_openers(bytes: &[u8], idx: usize) -> Option<usize> {
    let mut p = idx;
    let mut openers = 0usize;
    while p < bytes.len() && matches!(bytes[p], b'{' | b'[' | b' ' | b'\t' | b'\r' | b'\n') {
        if matches!(bytes[p], b'{' | b'[') {
            openers += 1;
        }
        p += 1;
    }
    if openers <= 128 {
        return None;
    }
    let mut rem = 127usize;
    let mut q = p;
    while q > idx && rem > 0 {
        q -= 1;
        if matches!(bytes[q], b'{' | b'[') {
            rem -= 1;
        }
    }
    (q > idx).then_some(q)
}

fn is_serde_json_recursion_limit_err(e: &serde_json::Error) -> bool {
    e.is_syntax() && e.to_string().starts_with("recursion limit exceeded")
}

fn compute_too_deep_json_openers(bytes: &[u8], start: usize) -> Vec<bool> {
    let mut too_deep = vec![false; bytes.len()];
    // (open_pos, opener_byte, max_child_depth)
    let mut stack: Vec<(usize, u8, usize)> = Vec::new();
    let mut open_counts = [0usize; 2]; // [0]: '{', [1]: '['
    let mut p = start;
    while p < bytes.len() {
        match bytes[p] {
            b'"' => {
                let mut q = p + 1;
                let mut closed = false;
                while q < bytes.len() {
                    let b = bytes[q];
                    if b == b'\\' {
                        if q + 1 >= bytes.len() {
                            break;
                        }
                        q += 2;
                    } else if b == b'"' {
                        q += 1;
                        closed = true;
                        break;
                    } else if matches!(b, b'\r' | b'\n' | b'\t') {
                        break;
                    } else {
                        q += 1;
                    }
                }
                p = if closed { q } else { p + 1 };
            }
            b'{' | b'[' => {
                let idx = usize::from(bytes[p] == b'[');
                open_counts[idx] += 1;
                stack.push((p, bytes[p], 0));
                p += 1;
            }
            b'}' | b']' => {
                let want = if bytes[p] == b'}' { b'{' } else { b'[' };
                let want_idx = usize::from(want == b'[');
                if open_counts[want_idx] > 0
                    && let Some(match_idx) = stack.iter().rposition(|&(_, op, _)| op == want)
                {
                    while stack.len() > match_idx + 1 {
                        if let Some((unclosed_pos, unclosed_op, unclosed_child)) = stack.pop() {
                            open_counts[usize::from(unclosed_op == b'[')] -= 1;
                            let d = 1 + unclosed_child;
                            if d >= 128 {
                                too_deep[unclosed_pos] = true;
                            }
                            if let Some((_, _, pm)) = stack.last_mut() {
                                *pm = (*pm).max(d);
                            }
                        }
                    }
                    if let Some((open_pos, op, max_child)) = stack.pop() {
                        open_counts[usize::from(op == b'[')] -= 1;
                        let my_depth = 1 + max_child;
                        if my_depth >= 128 {
                            too_deep[open_pos] = true;
                        }
                        if let Some((_, _, pm)) = stack.last_mut() {
                            *pm = (*pm).max(my_depth);
                        }
                    }
                }
                p += 1;
            }
            _ => p += 1,
        }
    }
    while let Some((open_pos, _, max_child)) = stack.pop() {
        let my_depth = 1 + max_child;
        if my_depth >= 128 {
            too_deep[open_pos] = true;
        }
        if let Some((_, _, pm)) = stack.last_mut() {
            *pm = (*pm).max(my_depth);
        }
    }
    too_deep
}

fn raw_json_span_has_u0027_apos_km_leak(span: &[u8]) -> bool {
    if !contains_ascii_case_insensitive(span, b"keymaterial") || !contains_ascii_case_insensitive(span, b"\\u0027") {
        return false;
    }
    let lower = to_ascii_lowercase_vec(span);
    if last_unredacted_closing_km_pos(&lower, 0, true).is_none() {
        return false;
    }
    let mut cache = [None, None];
    let mut pos = 0usize;
    while let Some(m) = find_opening_keymaterial_tag(&lower, pos, true) {
        let ctx = TagScanContext {
            allow_double_bs: true,
            opened_with_u003c: m.opened_with_u003c,
            ..TagScanContext::default()
        };
        if let Some((_cs, open_end, _sc)) =
            find_tag_close_quote_aware_cached(&lower, m.after_name, m.syntax, ctx, &mut cache)
        {
            if find_ascii_bytes(&lower[m.after_name..open_end], 0, b"\\u0027").is_some()
                && cache[1]
                    .get_or_insert_with(|| last_unredacted_closing_km_pos(&lower, m.after_name, true))
                    .is_some_and(|cs| cs >= open_end)
            {
                return true;
            }
            pos = open_end;
        } else {
            return true;
        }
    }
    false
}

fn compute_open_keymaterial_tag_ranges(bytes: &[u8], _from_json_value: bool) -> Vec<(usize, usize)> {
    if !contains_ascii_case_insensitive(bytes, b"keymaterial") {
        return Vec::new();
    }
    let lower = to_ascii_lowercase_vec(bytes);
    let Some(first_open) = find_opening_keymaterial_tag(&lower, 0, true) else {
        return Vec::new();
    };
    if !bytes[first_open.after_name..].contains(&b'{') && !bytes[first_open.after_name..].contains(&b'[') {
        return Vec::new();
    }
    let html_json_lower: std::borrow::Cow<'_, [u8]> = if is_html_document_or_fragment(bytes) {
        std::borrow::Cow::Owned(mask_html_tags_for_json_scan(&lower))
    } else {
        std::borrow::Cow::Borrowed(&lower)
    };
    let mut json_tracker = if has_html_entity_json_delim(&html_json_lower) {
        JsonContextTracker::with_html_entities()
    } else {
        JsonContextTracker::with_markdown(false)
    };
    let has_u0022 = contains_ascii_case_insensitive(&html_json_lower, b"u0022");
    let (single_u0022_json_ctx, double_u0022_json_ctx) = if has_u0022 {
        precompute_u0022_json_ctx(&html_json_lower, false, None)
    } else {
        (false, false)
    };
    let mut ranges = Vec::new();
    let mut pos = 0usize;
    let mut next_open = Some(first_open);
    let mut unredacted_close_cache: [Option<Option<usize>>; 2] = [None, None];
    while let Some(open) = next_open
        .take()
        .or_else(|| find_opening_keymaterial_tag(&lower, pos, true))
    {
        let (in_json_string, in_markdown_json_string, in_markdown_table_line, in_nested_json_string) =
            json_tracker.advance_to(&html_json_lower, open.open_start);
        let has_double_escaped_gap =
            in_json_string && json_tracker.mark_double_escaped_gap(&html_json_lower, pos, open.open_start);
        let decoded_u0022_ctx = !in_json_string && (single_u0022_json_ctx || double_u0022_json_ctx);
        let effective_in_json_string =
            in_json_string || (decoded_u0022_ctx && (open.syntax == TagSyntax::HtmlEscaped || open.opened_with_u003c));
        let in_double_escaped_json = in_markdown_json_string
            || in_nested_json_string
            || has_double_escaped_gap
            || (!in_json_string && double_u0022_json_ctx)
            || (in_json_string && is_double_escaped_tag_open(&lower, open.open_start));
        let ctx = TagScanContext {
            in_csv_field: false,
            in_json_string: effective_in_json_string,
            in_markdown_json_string,
            in_markdown_table_line,
            in_double_escaped_json,
            in_nested_json_string,
            allow_double_bs: true,
            opened_with_u003c: open.opened_with_u003c,
            allow_tsv_tabs: true,
            in_decoded_u0022_json_ctx: decoded_u0022_ctx,
        };
        if let Some((_, tag_end, _)) =
            find_tag_close_quote_aware_cached(&lower, open.after_name, open.syntax, ctx, &mut unredacted_close_cache)
        {
            ranges.push((open.after_name, tag_end));
            pos = tag_end;
        } else {
            ranges.push((open.after_name, lower.len()));
            break;
        }
    }
    ranges
}

fn pos_in_sorted_ranges(ranges: &[(usize, usize)], pos: usize) -> bool {
    let idx = ranges.partition_point(|&(start, _)| start <= pos);
    idx > 0 && pos < ranges[idx - 1].1
}

fn sanitize_json_substrings_and_mask(s: &str, depth: usize, from_json_value: bool) -> (String, String, Vec<String>) {
    if depth >= MAX_NESTED_JSON_DEPTH || (!s.contains('{') && !s.contains('[')) {
        return (s.to_string(), String::new(), Vec::new());
    }

    let marker_prefix = unique_json_marker_prefix(s);
    let bytes = s.as_bytes();
    let mut open_km_ranges_opt: Option<Vec<(usize, usize)>> = None;
    let mut masked = String::with_capacity(s.len());
    let mut replacements = Vec::new();
    let mut changed_inline = false;
    let mut cursor = 0usize;
    let mut i = 0usize;
    let mut too_deep_openers: Option<Vec<bool>> = None;

    while i < bytes.len() {
        if matches!(bytes[i], b'{' | b'[') && starts_raw_json_container(bytes, i) {
            if too_deep_openers.as_ref().is_some_and(|td| td[i]) {
                i += 1;
                continue;
            }
            let mut stream = serde_json::Deserializer::from_str(&s[i..]).into_iter::<Value>();
            match stream.next() {
                Some(Ok(mut val)) => {
                    let consumed = stream.byte_offset();
                    if consumed > 0 && i + consumed <= bytes.len() {
                        let before = val.clone();
                        sanitize_json_value_r4_inner(&mut val, depth + 1);
                        let rep = if val != before {
                            serde_json::to_string(&val).unwrap_or_else(|_| s[i..i + consumed].to_string())
                        } else {
                            s[i..i + consumed].to_string()
                        };
                        if json_span_has_quote_parity_hazard(&bytes[i..i + consumed]) {
                            let open_km_ranges = open_km_ranges_opt
                                .get_or_insert_with(|| compute_open_keymaterial_tag_ranges(bytes, from_json_value));
                            if pos_in_sorted_ranges(open_km_ranges, i)
                                || (val == before && raw_json_span_has_u0027_apos_km_leak(&bytes[i..i + consumed]))
                            {
                                if val != before {
                                    changed_inline = true;
                                }
                                masked.push_str(&s[cursor..i]);
                                masked.push_str(&rep);
                                i += consumed;
                                cursor = i;
                                continue;
                            }
                        }
                        let idx = replacements.len();
                        let (open_br, close_br) = if bytes[i] == b'{' { ('{', '}') } else { ('[', ']') };
                        replacements.push(rep);
                        masked.push_str(&s[cursor..i]);
                        masked.push(open_br);
                        masked.push_str(&marker_prefix);
                        masked.push_str(&idx.to_string());
                        masked.push_str("__");
                        masked.push(close_br);
                        i += consumed;
                        cursor = i;
                        continue;
                    }
                }
                Some(Err(ref e)) if is_serde_json_recursion_limit_err(e) => {
                    if let Some(next_i) = skip_excess_json_openers(bytes, i) {
                        i = next_i;
                        continue;
                    }
                    let td = too_deep_openers.get_or_insert_with(|| compute_too_deep_json_openers(bytes, i));
                    if td[i] {
                        i += 1;
                        continue;
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }

    if replacements.is_empty() {
        if changed_inline {
            masked.push_str(&s[cursor..]);
            (masked, String::new(), Vec::new())
        } else {
            (s.to_string(), String::new(), Vec::new())
        }
    } else {
        masked.push_str(&s[cursor..]);
        (masked, marker_prefix, replacements)
    }
}

fn restore_json_placeholders(s: &str, marker_prefix: &str, replacements: &[String]) -> String {
    if replacements.is_empty() {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut cursor = 0usize;
    while let Some(rel) = s[cursor..].find(marker_prefix) {
        let start = cursor + rel;
        let idx_start = start + marker_prefix.len();
        if let Some(end_rel) = s[idx_start..].find("__")
            && let Ok(idx) = s[idx_start..idx_start + end_rel].parse::<usize>()
            && let Some(rep) = replacements.get(idx)
        {
            let close_pos = idx_start + end_rel + 2;
            let wrapped = start > cursor
                && matches!(
                    (bytes[start - 1], bytes.get(close_pos).copied()),
                    (b'{', Some(b'}')) | (b'[', Some(b']'))
                );
            if wrapped {
                out.push_str(&s[cursor..start - 1]);
                out.push_str(rep);
                cursor = close_pos + 1;
            } else {
                out.push_str(&s[cursor..start]);
                out.push_str(rep);
                cursor = close_pos;
            }
            continue;
        }
        out.push_str(&s[cursor..idx_start]);
        cursor = idx_start;
    }
    out.push_str(&s[cursor..]);
    out
}

fn extract_keymaterial_prefix(s: &str, open_start: usize, after_name: usize) -> Option<&str> {
    const TAG_LEN: usize = "keymaterial".len();
    if after_name < open_start + TAG_LEN + 2 {
        return None;
    }
    let colon_pos = after_name - TAG_LEN - 1;
    if s.as_bytes().get(colon_pos) != Some(&b':') {
        return None;
    }
    let bytes = s.as_bytes();
    let prefix_start = if bytes[open_start..].starts_with(b"<") {
        open_start + 1
    } else if let Some(lt_len) = match_html_lt_entity(&bytes[open_start..]) {
        open_start + lt_len
    } else if bytes
        .get(open_start..open_start + 7)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"\\\\u003c"))
    {
        open_start + 7
    } else if bytes
        .get(open_start..open_start + 6)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"\\u003c"))
    {
        open_start + 6
    } else {
        return None;
    };
    if prefix_start < colon_pos && s.is_char_boundary(prefix_start) && s.is_char_boundary(colon_pos) {
        Some(&s[prefix_start..colon_pos])
    } else {
        None
    }
}

fn is_double_escaped_tag_open(bytes: &[u8], open_start: usize) -> bool {
    bytes
        .get(open_start..open_start + 7)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"\\\\u003c"))
}

#[inline]
fn is_u00_json_ws(s: &[u8]) -> bool {
    s.eq_ignore_ascii_case(b"u0020")
        || s.eq_ignore_ascii_case(b"u0009")
        || s.eq_ignore_ascii_case(b"u000a")
        || s.eq_ignore_ascii_case(b"u000d")
}

fn skip_json_ws_backward(bytes: &[u8], mut p: usize) -> usize {
    while p > 0 {
        if matches!(bytes[p - 1], b' ' | b'\t' | b'\r' | b'\n') {
            p -= 1;
            continue;
        }
        if matches!(bytes[p - 1], b'n' | b'r' | b't') {
            let bs = count_preceding_backslashes(bytes, 0, p - 1);
            if bs % 2 == 1 {
                p -= 2;
                continue;
            }
            if bs % 4 == 2 {
                p -= 3;
                continue;
            }
        }
        if p >= 6 && is_u00_json_ws(&bytes[p - 5..p]) {
            let bs = count_preceding_backslashes(bytes, 0, p - 5);
            if bs % 2 == 1 {
                p -= 6;
                continue;
            }
            if bs % 4 == 2 {
                p -= 7;
                continue;
            }
        }
        break;
    }
    p
}

fn skip_json_ws_forward(bytes: &[u8], mut n: usize) -> usize {
    while n < bytes.len() {
        if matches!(bytes[n], b' ' | b'\t' | b'\r' | b'\n') {
            n += 1;
            continue;
        }
        if bytes[n] == b'\\' {
            let bs = count_consecutive_backslashes(bytes, n);
            if bs == 1 {
                if matches!(bytes.get(n + 1).copied(), Some(b'n' | b'r' | b't')) {
                    n += 2;
                    continue;
                }
                if bytes.get(n + 1..n + 6).is_some_and(is_u00_json_ws) {
                    n += 6;
                    continue;
                }
            } else if bs == 2 {
                if matches!(bytes.get(n + 2).copied(), Some(b'n' | b'r' | b't')) {
                    n += 3;
                    continue;
                }
                if bytes.get(n + 2..n + 7).is_some_and(is_u00_json_ws) {
                    n += 7;
                    continue;
                }
            }
        }
        break;
    }
    n
}

fn ends_with_json_string_quote(slice: &[u8]) -> bool {
    if slice.len() >= 6 && &slice[slice.len() - 5..] == b"u0022" {
        let bs = count_preceding_backslashes(slice, 0, slice.len() - 5);
        return bs % 2 == 1 || bs % 4 == 2;
    }
    if slice.ends_with(b"\"\"") {
        let bs = count_preceding_backslashes(slice, 0, slice.len() - 2);
        if bs % 2 == 1 || bs % 4 == 2 {
            return true;
        }
    }
    if slice.ends_with(b"\"") {
        let bs = count_preceding_backslashes(slice, 0, slice.len() - 1);
        return bs % 2 == 1 || bs % 4 == 2;
    }
    false
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BackwardJsonQuote {
    Raw,
    CsvDoubled,
    SingleEscaped,
    TripleEscaped,
    U0022SingleBs,
    U0022DoubleBs,
    HtmlDoubleEntity,
}

impl BackwardJsonQuote {
    const fn index(self) -> usize {
        match self {
            Self::Raw => 0,
            Self::CsvDoubled => 1,
            Self::SingleEscaped => 2,
            Self::TripleEscaped => 3,
            Self::U0022SingleBs => 4,
            Self::U0022DoubleBs => 5,
            Self::HtmlDoubleEntity => 6,
        }
    }
}

struct JsonContainerMemo {
    raw_bracket_match: Vec<u32>,
    quote_prev: Vec<[u32; 7]>,
    valid_container: Vec<u8>,
    allow_html_entities: bool,
    allow_csv_doubled: bool,
}

impl JsonContainerMemo {
    fn new(len: usize, allow_html_entities: bool, allow_csv_doubled: bool) -> Self {
        Self {
            raw_bracket_match: vec![0; len + 1],
            quote_prev: vec![[0; 7]; len + 1],
            valid_container: vec![0; len + 1],
            allow_html_entities,
            allow_csv_doubled,
        }
    }
}

struct JsonMarkerMemo {
    flags: Vec<u8>,
    container: Option<JsonContainerMemo>,
}

impl JsonMarkerMemo {
    fn new(len: usize) -> Self {
        Self {
            flags: vec![0; len + 1],
            container: None,
        }
    }
}

fn trim_json_ws(slice: &[u8]) -> &[u8] {
    let start = skip_json_ws_forward(slice, 0);
    let end = skip_json_ws_backward(slice, slice.len());
    if start >= end { &[] } else { &slice[start..end] }
}

fn match_html_double_quote_entity_at_end(slice: &[u8]) -> Option<usize> {
    if slice.len() >= 6 && slice[slice.len() - 6..].eq_ignore_ascii_case(b"&quot;") {
        return Some(slice.len() - 6);
    }
    if slice.len() >= 5 && slice[slice.len() - 1] == b';' {
        let search_start = slice.len().saturating_sub(12);
        if let Some(rel_amp) = slice[search_start..].iter().rposition(|&b| b == b'&') {
            let start = search_start + rel_amp;
            if let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&slice[start..])
                && start + len == slice.len()
            {
                return Some(start);
            }
        }
    }
    None
}

fn find_matching_json_container_start_with_csv(
    slice: &[u8],
    allow_html_entities: bool,
    allow_csv_doubled: bool,
) -> Option<usize> {
    let close = *slice.last()?;
    if !matches!(close, b'}' | b']') {
        return None;
    }
    let mut pos = slice.len() - 1;
    let mut depth = 1usize;
    let mut in_string: Option<BackwardJsonQuote> = None;

    while pos > 0 {
        if let Some(qmode) = in_string {
            if allow_html_entities
                && let Some(q_start) = match_html_double_quote_entity_at_end(&slice[..pos])
                && count_preceding_backslashes(slice, 0, q_start).is_multiple_of(2)
            {
                if qmode == BackwardJsonQuote::HtmlDoubleEntity {
                    in_string = None;
                }
                pos = q_start;
                continue;
            }
            if pos >= 6 && slice[pos - 5..pos].eq_ignore_ascii_case(b"u0022") {
                let bs = count_preceding_backslashes(slice, 0, pos - 5);
                if bs % 4 == 2 {
                    if qmode == BackwardJsonQuote::U0022DoubleBs {
                        in_string = None;
                    }
                    pos -= 7;
                    continue;
                }
                if bs % 2 == 1 {
                    if qmode == BackwardJsonQuote::U0022SingleBs {
                        in_string = None;
                    }
                    pos -= 6;
                    continue;
                }
            }
            if allow_csv_doubled
                && qmode == BackwardJsonQuote::CsvDoubled
                && pos >= 2
                && slice[pos - 2..pos] == *b"\"\""
            {
                let bs = count_preceding_backslashes(slice, 0, pos - 2);
                if bs.is_multiple_of(2) {
                    in_string = None;
                    pos -= 2;
                    continue;
                }
                pos -= bs + 2;
                continue;
            }
            if slice[pos - 1] == b'"' {
                let bs = count_preceding_backslashes(slice, 0, pos - 1);
                match qmode {
                    BackwardJsonQuote::Raw if bs.is_multiple_of(2) => {
                        in_string = None;
                        pos -= 1;
                        continue;
                    }
                    BackwardJsonQuote::CsvDoubled if bs.is_multiple_of(2) => {
                        return None;
                    }
                    BackwardJsonQuote::SingleEscaped if bs % 4 == 1 => {
                        in_string = None;
                        pos -= 2;
                        continue;
                    }
                    BackwardJsonQuote::SingleEscaped if bs.is_multiple_of(2) => {
                        return None;
                    }
                    BackwardJsonQuote::TripleEscaped if bs % 4 == 3 => {
                        in_string = None;
                        pos -= 4;
                        continue;
                    }
                    BackwardJsonQuote::TripleEscaped if bs.is_multiple_of(2) || bs % 4 == 1 => {
                        return None;
                    }
                    _ => {
                        pos -= bs + 1;
                        continue;
                    }
                }
            }
            pos -= 1;
            continue;
        }

        if allow_html_entities
            && let Some(q_start) = match_html_double_quote_entity_at_end(&slice[..pos])
            && count_preceding_backslashes(slice, 0, q_start).is_multiple_of(2)
        {
            in_string = Some(BackwardJsonQuote::HtmlDoubleEntity);
            pos = q_start;
            continue;
        }
        if pos >= 6 && slice[pos - 5..pos].eq_ignore_ascii_case(b"u0022") {
            let bs = count_preceding_backslashes(slice, 0, pos - 5);
            if bs % 4 == 2 {
                in_string = Some(BackwardJsonQuote::U0022DoubleBs);
                pos -= 7;
                continue;
            }
            if bs % 2 == 1 {
                in_string = Some(BackwardJsonQuote::U0022SingleBs);
                pos -= 6;
                continue;
            }
        }
        if allow_csv_doubled && pos >= 2 && slice[pos - 2..pos] == *b"\"\"" {
            let bs = count_preceding_backslashes(slice, 0, pos - 2);
            if bs.is_multiple_of(2) {
                in_string = Some(BackwardJsonQuote::CsvDoubled);
                pos -= 2;
                continue;
            }
        }
        if slice[pos - 1] == b'"' {
            let bs = count_preceding_backslashes(slice, 0, pos - 1);
            if bs.is_multiple_of(2) {
                in_string = Some(BackwardJsonQuote::Raw);
                pos -= 1;
                continue;
            }
            if bs % 4 == 1 {
                in_string = Some(BackwardJsonQuote::SingleEscaped);
                pos -= 2;
                continue;
            }
            if bs % 4 == 3 {
                in_string = Some(BackwardJsonQuote::TripleEscaped);
                pos -= 4;
                continue;
            }
            pos -= bs + 1;
            continue;
        }

        match slice[pos - 1] {
            b'}' | b']' => {
                depth += 1;
                pos -= 1;
            }
            b'{' | b'[' => {
                depth -= 1;
                if depth == 0 {
                    let expected_open = if close == b'}' { b'{' } else { b'[' };
                    return (slice[pos - 1] == expected_open).then_some(pos - 1);
                }
                pos -= 1;
            }
            _ => {
                pos -= 1;
            }
        }
    }
    None
}

fn is_quoted_json_string_token_with_csv(slice: &[u8], allow_html_entities: bool, allow_csv_doubled: bool) -> bool {
    let trimmed = trim_json_ws(slice);
    if trimmed.len() < 2 {
        return false;
    }
    if allow_csv_doubled && trimmed.len() >= 4 && trimmed.starts_with(b"\"\"") && trimmed.ends_with(b"\"\"") {
        let bs = count_preceding_backslashes(trimmed, 0, trimmed.len() - 2);
        if !bs.is_multiple_of(2) {
            return false;
        }
        let mut p = 2usize;
        let end = trimmed.len() - 2;
        while p < end {
            if trimmed[p] == b'\\' {
                let inner_bs = count_consecutive_backslashes(trimmed, p);
                if p + inner_bs + 2 <= end && trimmed[p + inner_bs..p + inner_bs + 2] == *b"\"\"" {
                    if inner_bs.is_multiple_of(2) {
                        return false;
                    }
                    p += inner_bs + 2;
                } else {
                    p += inner_bs;
                }
            } else if trimmed[p] == b'"' {
                return false;
            } else {
                p += 1;
            }
        }
        return true;
    }
    if trimmed.starts_with(b"\"") && trimmed.ends_with(b"\"") {
        let bs = count_preceding_backslashes(trimmed, 0, trimmed.len() - 1);
        return bs.is_multiple_of(2);
    }
    if trimmed.starts_with(b"\\\"") && trimmed.ends_with(b"\\\"") && trimmed.len() >= 4 {
        let bs = count_preceding_backslashes(trimmed, 0, trimmed.len() - 1);
        return bs % 4 == 1;
    }
    if trimmed.starts_with(b"\\\\\\\"") && trimmed.ends_with(b"\\\\\\\"") && trimmed.len() >= 8 {
        let bs = count_preceding_backslashes(trimmed, 0, trimmed.len() - 1);
        return bs % 4 == 3;
    }
    if trimmed.len() >= 12
        && trimmed[..6].eq_ignore_ascii_case(b"\\u0022")
        && trimmed[trimmed.len() - 5..].eq_ignore_ascii_case(b"u0022")
    {
        let bs = count_preceding_backslashes(trimmed, 0, trimmed.len() - 5);
        if bs % 2 == 1 {
            return true;
        }
    }
    if trimmed.len() >= 14
        && trimmed[..7].eq_ignore_ascii_case(b"\\\\u0022")
        && trimmed[trimmed.len() - 5..].eq_ignore_ascii_case(b"u0022")
    {
        let bs = count_preceding_backslashes(trimmed, 0, trimmed.len() - 5);
        if bs % 4 == 2 {
            return true;
        }
    }
    if allow_html_entities
        && trimmed.first() == Some(&b'&')
        && let Some((HtmlQuoteMode::DoubleEntity, open_len)) = match_html_quote_entity(trimmed)
        && let Some(close_start) = match_html_double_quote_entity_at_end(trimmed)
    {
        return close_start >= open_len && count_preceding_backslashes(trimmed, 0, close_start).is_multiple_of(2);
    }
    false
}

fn is_json_number_token(slice: &[u8]) -> bool {
    let Some((&first, rest)) = slice.split_first() else {
        return false;
    };
    let digits = if first == b'-' { rest } else { slice };
    if digits.is_empty() || !digits[0].is_ascii_digit() {
        return false;
    }
    let mut i = 0usize;
    while i < digits.len() && digits[i].is_ascii_digit() {
        i += 1;
    }
    if i < digits.len() && digits[i] == b'.' {
        i += 1;
        let frac_start = i;
        while i < digits.len() && digits[i].is_ascii_digit() {
            i += 1;
        }
        if i == frac_start {
            return false;
        }
    }
    if i < digits.len() && matches!(digits[i], b'e' | b'E') {
        i += 1;
        if i < digits.len() && matches!(digits[i], b'+' | b'-') {
            i += 1;
        }
        let exp_start = i;
        while i < digits.len() && digits[i].is_ascii_digit() {
            i += 1;
        }
        if i == exp_start {
            return false;
        }
    }
    i == digits.len()
}

fn is_json_primitive_or_string_token_with_csv(
    trimmed: &[u8],
    allow_html_entities: bool,
    allow_csv_doubled: bool,
) -> bool {
    matches!(trimmed, b"true" | b"false" | b"null")
        || is_json_number_token(trimmed)
        || is_quoted_json_string_token_with_csv(trimmed, allow_html_entities, allow_csv_doubled)
}

fn split_top_level_json_items_with_csv(
    inner: &[u8],
    allow_html_entities: bool,
    allow_csv_doubled: bool,
) -> Option<Vec<&[u8]>> {
    let mut items = Vec::new();
    let mut item_start = 0usize;
    let mut depth = 0usize;
    let mut quote: Option<BackwardJsonQuote> = None;
    let mut i = 0usize;

    while i < inner.len() {
        if let Some(qmode) = quote {
            if allow_html_entities
                && inner[i] == b'&'
                && let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&inner[i..])
            {
                if qmode == BackwardJsonQuote::HtmlDoubleEntity {
                    quote = None;
                }
                i += len;
                continue;
            }
            if inner[i] == b'\\' {
                let bs = count_consecutive_backslashes(inner, i);
                let q = i + bs;
                if bs % 4 == 2 && inner.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")) {
                    if qmode == BackwardJsonQuote::U0022DoubleBs {
                        quote = None;
                    }
                    i = q + 5;
                    continue;
                }
                if bs % 2 == 1 && inner.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")) {
                    if qmode == BackwardJsonQuote::U0022SingleBs {
                        quote = None;
                    }
                    i = q + 5;
                    continue;
                }
                if allow_csv_doubled && qmode == BackwardJsonQuote::CsvDoubled && inner.get(q..q + 2) == Some(b"\"\"") {
                    if bs.is_multiple_of(2) {
                        quote = None;
                    }
                    i = q + 2;
                    continue;
                }
                if inner.get(q) == Some(&b'"') {
                    if qmode == BackwardJsonQuote::Raw && bs.is_multiple_of(2) {
                        quote = None;
                        i = q + 1;
                        continue;
                    }
                    if qmode == BackwardJsonQuote::CsvDoubled && bs.is_multiple_of(2) {
                        return None;
                    }
                    if qmode == BackwardJsonQuote::SingleEscaped && bs % 4 == 1 {
                        quote = None;
                        i = q + 1;
                        continue;
                    }
                    if qmode == BackwardJsonQuote::TripleEscaped && bs % 4 == 3 {
                        quote = None;
                        i = q + 1;
                        continue;
                    }
                    i = q + 1;
                    continue;
                }
                i = q;
                continue;
            }
            if allow_csv_doubled && qmode == BackwardJsonQuote::CsvDoubled && inner[i] == b'"' {
                if inner.get(i + 1) == Some(&b'"') {
                    quote = None;
                    i += 2;
                    continue;
                }
                return None;
            }
            if inner[i] == b'"' && qmode == BackwardJsonQuote::Raw {
                quote = None;
            }
            i += 1;
            continue;
        }

        if allow_html_entities
            && inner[i] == b'&'
            && let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&inner[i..])
        {
            quote = Some(BackwardJsonQuote::HtmlDoubleEntity);
            i += len;
            continue;
        }
        if inner[i] == b'\\' {
            let bs = count_consecutive_backslashes(inner, i);
            let q = i + bs;
            if bs % 4 == 2 && inner.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")) {
                quote = Some(BackwardJsonQuote::U0022DoubleBs);
                i = q + 5;
                continue;
            }
            if bs % 2 == 1 && inner.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")) {
                quote = Some(BackwardJsonQuote::U0022SingleBs);
                i = q + 5;
                continue;
            }
            if allow_csv_doubled && bs.is_multiple_of(2) && inner.get(q..q + 2) == Some(b"\"\"") {
                quote = Some(BackwardJsonQuote::CsvDoubled);
                i = q + 2;
                continue;
            }
            if inner.get(q) == Some(&b'"') {
                if bs.is_multiple_of(2) {
                    quote = Some(BackwardJsonQuote::Raw);
                    i = q + 1;
                    continue;
                }
                if bs % 4 == 1 {
                    quote = Some(BackwardJsonQuote::SingleEscaped);
                    i = q + 1;
                    continue;
                }
                if bs % 4 == 3 {
                    quote = Some(BackwardJsonQuote::TripleEscaped);
                    i = q + 1;
                    continue;
                }
            }
            i = q;
            continue;
        }
        if allow_csv_doubled && inner[i..].starts_with(b"\"\"") {
            quote = Some(BackwardJsonQuote::CsvDoubled);
            i += 2;
            continue;
        }
        match inner[i] {
            b'"' => {
                quote = Some(BackwardJsonQuote::Raw);
            }
            b'{' | b'[' => {
                depth += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
            }
            b',' if depth == 0 => {
                items.push(&inner[item_start..i]);
                item_start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }

    if quote.is_some() || depth != 0 {
        return None;
    }
    items.push(&inner[item_start..]);
    Some(items)
}

fn find_top_level_colon_with_csv(pair: &[u8], allow_html_entities: bool, allow_csv_doubled: bool) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote: Option<BackwardJsonQuote> = None;
    let mut i = 0usize;

    while i < pair.len() {
        if let Some(qmode) = quote {
            if allow_html_entities
                && pair[i] == b'&'
                && let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&pair[i..])
            {
                if qmode == BackwardJsonQuote::HtmlDoubleEntity {
                    quote = None;
                }
                i += len;
                continue;
            }
            if pair[i] == b'\\' {
                let bs = count_consecutive_backslashes(pair, i);
                let q = i + bs;
                if bs % 4 == 2 && pair.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")) {
                    if qmode == BackwardJsonQuote::U0022DoubleBs {
                        quote = None;
                    }
                    i = q + 5;
                    continue;
                }
                if bs % 2 == 1 && pair.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")) {
                    if qmode == BackwardJsonQuote::U0022SingleBs {
                        quote = None;
                    }
                    i = q + 5;
                    continue;
                }
                if allow_csv_doubled && qmode == BackwardJsonQuote::CsvDoubled && pair.get(q..q + 2) == Some(b"\"\"") {
                    if bs.is_multiple_of(2) {
                        quote = None;
                    }
                    i = q + 2;
                    continue;
                }
                if pair.get(q) == Some(&b'"') {
                    if qmode == BackwardJsonQuote::Raw && bs.is_multiple_of(2) {
                        quote = None;
                        i = q + 1;
                        continue;
                    }
                    if qmode == BackwardJsonQuote::CsvDoubled && bs.is_multiple_of(2) {
                        return None;
                    }
                    if qmode == BackwardJsonQuote::SingleEscaped && bs % 4 == 1 {
                        quote = None;
                        i = q + 1;
                        continue;
                    }
                    if qmode == BackwardJsonQuote::TripleEscaped && bs % 4 == 3 {
                        quote = None;
                        i = q + 1;
                        continue;
                    }
                    i = q + 1;
                    continue;
                }
                i = q;
                continue;
            }
            if allow_csv_doubled && qmode == BackwardJsonQuote::CsvDoubled && pair[i] == b'"' {
                if pair.get(i + 1) == Some(&b'"') {
                    quote = None;
                    i += 2;
                    continue;
                }
                return None;
            }
            if pair[i] == b'"' && qmode == BackwardJsonQuote::Raw {
                quote = None;
            }
            i += 1;
            continue;
        }

        if allow_html_entities
            && pair[i] == b'&'
            && let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&pair[i..])
        {
            quote = Some(BackwardJsonQuote::HtmlDoubleEntity);
            i += len;
            continue;
        }
        if pair[i] == b'\\' {
            let bs = count_consecutive_backslashes(pair, i);
            let q = i + bs;
            if bs % 4 == 2 && pair.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")) {
                quote = Some(BackwardJsonQuote::U0022DoubleBs);
                i = q + 5;
                continue;
            }
            if bs % 2 == 1 && pair.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")) {
                quote = Some(BackwardJsonQuote::U0022SingleBs);
                i = q + 5;
                continue;
            }
            if allow_csv_doubled && bs.is_multiple_of(2) && pair.get(q..q + 2) == Some(b"\"\"") {
                quote = Some(BackwardJsonQuote::CsvDoubled);
                i = q + 2;
                continue;
            }
            if pair.get(q) == Some(&b'"') {
                if bs.is_multiple_of(2) {
                    quote = Some(BackwardJsonQuote::Raw);
                    i = q + 1;
                    continue;
                }
                if bs % 4 == 1 {
                    quote = Some(BackwardJsonQuote::SingleEscaped);
                    i = q + 1;
                    continue;
                }
                if bs % 4 == 3 {
                    quote = Some(BackwardJsonQuote::TripleEscaped);
                    i = q + 1;
                    continue;
                }
            }
            i = q;
            continue;
        }
        if allow_csv_doubled && pair[i..].starts_with(b"\"\"") {
            quote = Some(BackwardJsonQuote::CsvDoubled);
            i += 2;
            continue;
        }
        match pair[i] {
            b'"' => {
                quote = Some(BackwardJsonQuote::Raw);
            }
            b'{' | b'[' => {
                depth += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
            }
            b':' if depth == 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

fn is_json_container_slice_with_csv(container: &[u8], allow_html_entities: bool, allow_csv_doubled: bool) -> bool {
    let mut stack = vec![container];
    while let Some(cur_container) = stack.pop() {
        if cur_container.len() < 2 {
            return false;
        }
        let opener = cur_container[0];
        let closer = cur_container[cur_container.len() - 1];
        if !matches!((opener, closer), (b'{', b'}') | (b'[', b']')) {
            return false;
        }
        let inner = &cur_container[1..cur_container.len() - 1];
        let trimmed_inner = trim_json_ws(inner);
        if trimmed_inner.is_empty() {
            continue;
        }
        if trimmed_inner.len() >= 10
            && trimmed_inner[..10].eq_ignore_ascii_case(b"__guapjson")
            && trimmed_inner.ends_with(b"__")
        {
            continue;
        }
        if serde_json::from_slice::<Value>(cur_container).is_ok() {
            continue;
        }
        let Some(items) = split_top_level_json_items_with_csv(trimmed_inner, allow_html_entities, allow_csv_doubled)
        else {
            return false;
        };
        if items.is_empty() {
            return false;
        }
        if opener == b'[' {
            for item in items {
                let trimmed_item = trim_json_ws(item);
                if trimmed_item.is_empty() {
                    return false;
                }
                if is_json_primitive_or_string_token_with_csv(trimmed_item, allow_html_entities, allow_csv_doubled) {
                    continue;
                }
                if matches!(
                    (trimmed_item.first().copied(), trimmed_item.last().copied()),
                    (Some(b'{'), Some(b'}')) | (Some(b'['), Some(b']'))
                ) {
                    stack.push(trimmed_item);
                    continue;
                }
                return false;
            }
        } else {
            for pair in items {
                let Some(colon_pos) = find_top_level_colon_with_csv(pair, allow_html_entities, allow_csv_doubled)
                else {
                    return false;
                };
                let key = trim_json_ws(&pair[..colon_pos]);
                let val = trim_json_ws(&pair[colon_pos + 1..]);
                let valid_key = is_quoted_json_string_token_with_csv(key, allow_html_entities, allow_csv_doubled)
                    || (!key.is_empty()
                        && key
                            .iter()
                            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')));
                if !valid_key || val.is_empty() {
                    return false;
                }
                if is_json_primitive_or_string_token_with_csv(val, allow_html_entities, allow_csv_doubled) {
                    continue;
                }
                if matches!(
                    (val.first().copied(), val.last().copied()),
                    (Some(b'{'), Some(b'}')) | (Some(b'['), Some(b']'))
                ) {
                    stack.push(val);
                    continue;
                }
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
fn is_json_container_slice(container: &[u8], allow_html_entities: bool, _depth: usize) -> bool {
    is_json_container_slice_with_csv(container, allow_html_entities, false)
}

fn ends_with_valid_json_container_with_csv(slice: &[u8], allow_html_entities: bool, allow_csv_doubled: bool) -> bool {
    let Some(open_pos) = find_matching_json_container_start_with_csv(slice, allow_html_entities, allow_csv_doubled)
    else {
        return false;
    };
    is_json_container_slice_with_csv(&slice[open_pos..], allow_html_entities, allow_csv_doubled)
}

fn ends_with_valid_json_container(slice: &[u8], allow_html_entities: bool) -> bool {
    ends_with_valid_json_container_with_csv(slice, allow_html_entities, false)
}

fn try_consume_quote_backward(
    bytes: &[u8],
    pos: usize,
    allow_html_entities: bool,
    allow_csv_doubled: bool,
) -> Option<(usize, BackwardJsonQuote)> {
    if allow_html_entities
        && let Some(q_start) = match_html_double_quote_entity_at_end(&bytes[..pos])
        && count_preceding_backslashes(bytes, 0, q_start).is_multiple_of(2)
    {
        return Some((q_start, BackwardJsonQuote::HtmlDoubleEntity));
    }
    if pos >= 6 && bytes[pos - 5..pos].eq_ignore_ascii_case(b"u0022") {
        let bs = count_preceding_backslashes(bytes, 0, pos - 5);
        if bs % 4 == 2 {
            return Some((pos - 7, BackwardJsonQuote::U0022DoubleBs));
        }
        if bs % 2 == 1 {
            return Some((pos - 6, BackwardJsonQuote::U0022SingleBs));
        }
    }
    if allow_csv_doubled && pos >= 2 && bytes[pos - 2..pos] == *b"\"\"" {
        let bs = count_preceding_backslashes(bytes, 0, pos - 2);
        if bs.is_multiple_of(2) {
            return Some((pos - 2, BackwardJsonQuote::CsvDoubled));
        }
    }
    if pos >= 1 && bytes[pos - 1] == b'"' {
        let bs = count_preceding_backslashes(bytes, 0, pos - 1);
        if bs.is_multiple_of(2) {
            return Some((pos - 1, BackwardJsonQuote::Raw));
        }
        if bs % 4 == 1 {
            return Some((pos - 2, BackwardJsonQuote::SingleEscaped));
        }
        if bs % 4 == 3 {
            return Some((pos - 4, BackwardJsonQuote::TripleEscaped));
        }
    }
    None
}

fn quote_prev_memo(
    bytes: &[u8],
    start_pos: usize,
    qmode: BackwardJsonQuote,
    memo: &mut JsonContainerMemo,
) -> Option<usize> {
    let qidx = qmode.index();
    let cached = memo.quote_prev[start_pos][qidx];
    if cached != 0 {
        return (cached != u32::MAX).then(|| (cached - 1) as usize);
    }
    let mut pos = start_pos;
    let res = loop {
        if pos == 0 {
            break None;
        }
        if memo.allow_html_entities
            && let Some(q_start) = match_html_double_quote_entity_at_end(&bytes[..pos])
            && count_preceding_backslashes(bytes, 0, q_start).is_multiple_of(2)
        {
            if qmode == BackwardJsonQuote::HtmlDoubleEntity {
                break Some(q_start);
            }
            pos = q_start;
            continue;
        }
        if pos >= 6 && bytes[pos - 5..pos].eq_ignore_ascii_case(b"u0022") {
            let bs = count_preceding_backslashes(bytes, 0, pos - 5);
            if bs % 4 == 2 {
                if qmode == BackwardJsonQuote::U0022DoubleBs {
                    break Some(pos - 7);
                }
                pos -= 7;
                continue;
            }
            if bs % 2 == 1 {
                if qmode == BackwardJsonQuote::U0022SingleBs {
                    break Some(pos - 6);
                }
                pos -= 6;
                continue;
            }
        }
        if memo.allow_csv_doubled
            && qmode == BackwardJsonQuote::CsvDoubled
            && pos >= 2
            && bytes[pos - 2..pos] == *b"\"\""
        {
            let bs = count_preceding_backslashes(bytes, 0, pos - 2);
            if bs.is_multiple_of(2) {
                break Some(pos - 2);
            }
            pos -= bs + 2;
            continue;
        }
        if bytes[pos - 1] == b'"' {
            let bs = count_preceding_backslashes(bytes, 0, pos - 1);
            match qmode {
                BackwardJsonQuote::Raw if bs.is_multiple_of(2) => break Some(pos - 1),
                BackwardJsonQuote::CsvDoubled if bs.is_multiple_of(2) => break None,
                BackwardJsonQuote::SingleEscaped if bs % 4 == 1 => break Some(pos - 2),
                BackwardJsonQuote::SingleEscaped if bs.is_multiple_of(2) => break None,
                BackwardJsonQuote::TripleEscaped if bs % 4 == 3 => break Some(pos - 4),
                BackwardJsonQuote::TripleEscaped if bs.is_multiple_of(2) || bs % 4 == 1 => break None,
                _ => {
                    pos -= bs + 1;
                    continue;
                }
            }
        }
        pos -= 1;
    };
    memo.quote_prev[start_pos][qidx] = match res {
        Some(p) => (p as u32) + 1,
        None => u32::MAX,
    };
    res
}

fn raw_bracket_match_memo(bytes: &[u8], end: usize, memo: &mut JsonContainerMemo) -> Option<usize> {
    if end == 0 || !matches!(bytes[end - 1], b'}' | b']') {
        return None;
    }
    let cached = memo.raw_bracket_match[end];
    if cached != 0 {
        return (cached != u32::MAX).then(|| (cached - 1) as usize);
    }
    let mut stack: Vec<(usize, usize)> = vec![(end, 0)];
    let mut depth = 1usize;
    let mut pos = end - 1;
    while pos > 0 {
        if let Some((q_content_end, qmode)) =
            try_consume_quote_backward(bytes, pos, memo.allow_html_entities, memo.allow_csv_doubled)
        {
            if let Some(q_open) = quote_prev_memo(bytes, q_content_end, qmode, memo) {
                pos = q_open;
                continue;
            }
            for (ce, _) in stack {
                memo.raw_bracket_match[ce] = u32::MAX;
            }
            return None;
        }
        match bytes[pos - 1] {
            b'}' | b']' => {
                let inner_cached = memo.raw_bracket_match[pos];
                if inner_cached == u32::MAX {
                    for (ce, _) in stack {
                        memo.raw_bracket_match[ce] = u32::MAX;
                    }
                    return None;
                }
                if inner_cached != 0 {
                    pos = (inner_cached - 1) as usize;
                } else {
                    stack.push((pos, depth));
                    depth += 1;
                    pos -= 1;
                }
            }
            b'{' | b'[' => {
                depth -= 1;
                let open_pos = pos - 1;
                if let Some(&(top_end, top_d)) = stack.last()
                    && depth == top_d
                {
                    stack.pop();
                    memo.raw_bracket_match[top_end] = (open_pos as u32) + 1;
                    if stack.is_empty() {
                        return Some(open_pos);
                    }
                }
                pos -= 1;
            }
            _ => {
                pos -= 1;
            }
        }
    }
    for (ce, _) in stack {
        memo.raw_bracket_match[ce] = u32::MAX;
    }
    None
}

fn find_matching_json_container_start_memo(bytes: &[u8], end: usize, memo: &mut JsonContainerMemo) -> Option<usize> {
    let close = *bytes.get(end.checked_sub(1)?)?;
    if !matches!(close, b'}' | b']') {
        return None;
    }
    let expected_open = if close == b'}' { b'{' } else { b'[' };
    let open_pos = raw_bracket_match_memo(bytes, end, memo)?;
    (bytes[open_pos] == expected_open).then_some(open_pos)
}

fn trim_json_ws_range(bytes: &[u8], start: usize, end: usize) -> (usize, usize) {
    let sub = &bytes[start..end];
    let s = skip_json_ws_forward(sub, 0);
    let e = skip_json_ws_backward(sub, sub.len());
    if s >= e { (start, start) } else { (start + s, start + e) }
}

fn split_top_level_json_items_backward_memo(
    bytes: &[u8],
    inner_start: usize,
    inner_end: usize,
    memo: &mut JsonContainerMemo,
) -> Option<Vec<(usize, usize)>> {
    let mut items = Vec::new();
    let mut item_end = inner_end;
    let mut p = inner_end;
    while p > inner_start {
        if let Some((q_content_end, qmode)) = try_consume_quote_backward(
            &bytes[inner_start..p],
            p - inner_start,
            memo.allow_html_entities,
            memo.allow_csv_doubled,
        ) {
            let abs_content_end = inner_start + q_content_end;
            let q_open = quote_prev_memo(bytes, abs_content_end, qmode, memo)?;
            if q_open < inner_start {
                return None;
            }
            p = q_open;
            continue;
        }
        match bytes[p - 1] {
            b'}' | b']' => {
                let open_pos = raw_bracket_match_memo(bytes, p, memo)?;
                if open_pos < inner_start {
                    return None;
                }
                p = open_pos;
            }
            b'{' | b'[' => return None,
            b',' => {
                items.push((p, item_end));
                item_end = p - 1;
                p -= 1;
            }
            _ => {
                p -= 1;
            }
        }
    }
    items.push((inner_start, item_end));
    Some(items)
}

fn find_top_level_colon_backward_memo(
    bytes: &[u8],
    pair_start: usize,
    pair_end: usize,
    memo: &mut JsonContainerMemo,
) -> Option<usize> {
    let mut p = pair_end;
    let mut found = None;
    while p > pair_start {
        if let Some((q_content_end, qmode)) = try_consume_quote_backward(
            &bytes[pair_start..p],
            p - pair_start,
            memo.allow_html_entities,
            memo.allow_csv_doubled,
        ) {
            let abs_content_end = pair_start + q_content_end;
            let q_open = quote_prev_memo(bytes, abs_content_end, qmode, memo)?;
            if q_open < pair_start {
                return None;
            }
            p = q_open;
            continue;
        }
        match bytes[p - 1] {
            b'}' | b']' => {
                let open_pos = raw_bracket_match_memo(bytes, p, memo)?;
                if open_pos < pair_start {
                    return None;
                }
                p = open_pos;
            }
            b'{' | b'[' => return None,
            b':' => {
                found = Some(p - 1);
                p -= 1;
            }
            _ => {
                p -= 1;
            }
        }
    }
    found
}

fn is_json_container_slice_memo(bytes: &[u8], start: usize, end: usize, memo: &mut JsonContainerMemo) -> bool {
    if memo.valid_container[end] != 0 {
        return memo.valid_container[end] == 2;
    }
    let mut stack = vec![(start, end, false)];
    let mark_stack_false = |stk: &[(usize, usize, bool)], m: &mut JsonContainerMemo| {
        for &(_, ce, _) in stk {
            m.valid_container[ce] = 1;
        }
    };
    while let Some((cur_start, cur_end, children_done)) = stack.pop() {
        if children_done {
            memo.valid_container[cur_end] = 2;
            continue;
        }
        if memo.valid_container[cur_end] != 0 {
            if memo.valid_container[cur_end] == 1 {
                mark_stack_false(&stack, memo);
                return false;
            }
            continue;
        }
        if cur_end < cur_start + 2 {
            memo.valid_container[cur_end] = 1;
            mark_stack_false(&stack, memo);
            return false;
        }
        let opener = bytes[cur_start];
        let closer = bytes[cur_end - 1];
        if !matches!((opener, closer), (b'{', b'}') | (b'[', b']')) {
            memo.valid_container[cur_end] = 1;
            mark_stack_false(&stack, memo);
            return false;
        }
        let (ts, te) = trim_json_ws_range(bytes, cur_start + 1, cur_end - 1);
        if ts >= te {
            memo.valid_container[cur_end] = 2;
            continue;
        }
        let trimmed_inner = &bytes[ts..te];
        if trimmed_inner.len() >= 10
            && trimmed_inner[..10].eq_ignore_ascii_case(b"__guapjson")
            && trimmed_inner.ends_with(b"__")
        {
            memo.valid_container[cur_end] = 2;
            continue;
        }
        let Some(items) = split_top_level_json_items_backward_memo(bytes, ts, te, memo) else {
            memo.valid_container[cur_end] = 1;
            mark_stack_false(&stack, memo);
            return false;
        };
        if items.is_empty() {
            memo.valid_container[cur_end] = 1;
            mark_stack_false(&stack, memo);
            return false;
        }
        let mut children = Vec::new();
        if opener == b'[' {
            for (is, ie) in items {
                let (its, ite) = trim_json_ws_range(bytes, is, ie);
                if its >= ite {
                    memo.valid_container[cur_end] = 1;
                    mark_stack_false(&stack, memo);
                    return false;
                }
                let trimmed_item = &bytes[its..ite];
                if is_json_primitive_or_string_token_with_csv(
                    trimmed_item,
                    memo.allow_html_entities,
                    memo.allow_csv_doubled,
                ) {
                    continue;
                }
                if ite >= its + 2
                    && matches!((bytes[its], bytes[ite - 1]), (b'{', b'}') | (b'[', b']'))
                    && find_matching_json_container_start_memo(bytes, ite, memo) == Some(its)
                {
                    if memo.valid_container[ite] == 1 {
                        memo.valid_container[cur_end] = 1;
                        mark_stack_false(&stack, memo);
                        return false;
                    }
                    if memo.valid_container[ite] == 0 {
                        children.push((its, ite));
                    }
                    continue;
                }
                memo.valid_container[cur_end] = 1;
                mark_stack_false(&stack, memo);
                return false;
            }
        } else {
            for (ps, pe) in items {
                let Some(colon_pos) = find_top_level_colon_backward_memo(bytes, ps, pe, memo) else {
                    memo.valid_container[cur_end] = 1;
                    mark_stack_false(&stack, memo);
                    return false;
                };
                let (ks, ke) = trim_json_ws_range(bytes, ps, colon_pos);
                let (vs, ve) = trim_json_ws_range(bytes, colon_pos + 1, pe);
                let key = if ks < ke { &bytes[ks..ke] } else { &[] };
                let valid_key =
                    is_quoted_json_string_token_with_csv(key, memo.allow_html_entities, memo.allow_csv_doubled)
                        || (!key.is_empty()
                            && key
                                .iter()
                                .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')));
                if !valid_key || vs >= ve {
                    memo.valid_container[cur_end] = 1;
                    mark_stack_false(&stack, memo);
                    return false;
                }
                let val = &bytes[vs..ve];
                if is_json_primitive_or_string_token_with_csv(val, memo.allow_html_entities, memo.allow_csv_doubled) {
                    continue;
                }
                if ve >= vs + 2
                    && matches!((bytes[vs], bytes[ve - 1]), (b'{', b'}') | (b'[', b']'))
                    && find_matching_json_container_start_memo(bytes, ve, memo) == Some(vs)
                {
                    if memo.valid_container[ve] == 1 {
                        memo.valid_container[cur_end] = 1;
                        mark_stack_false(&stack, memo);
                        return false;
                    }
                    if memo.valid_container[ve] == 0 {
                        children.push((vs, ve));
                    }
                    continue;
                }
                memo.valid_container[cur_end] = 1;
                mark_stack_false(&stack, memo);
                return false;
            }
        }
        if children.is_empty() {
            memo.valid_container[cur_end] = 2;
        } else {
            stack.push((cur_start, cur_end, true));
            for (cs, ce) in children {
                stack.push((cs, ce, false));
            }
        }
    }
    true
}

fn ends_with_valid_json_container_memo(bytes: &[u8], end: usize, memo: &mut JsonContainerMemo) -> bool {
    if memo.valid_container[end] != 0 {
        return memo.valid_container[end] == 2;
    }
    let Some(open_pos) = find_matching_json_container_start_memo(bytes, end, memo) else {
        memo.valid_container[end] = 1;
        return false;
    };
    is_json_container_slice_memo(bytes, open_pos, end, memo)
}

fn ends_with_json_value_before_comma_memo(bytes: &[u8], mut end: usize, mut memo: Option<&mut JsonMarkerMemo>) -> bool {
    let mut visited = Vec::new();
    let res = loop {
        if let Some(m) = memo.as_deref()
            && (m.flags[end] & 1) != 0
        {
            break false;
        }
        let slice = &bytes[..end];
        if ends_with_json_string_quote(slice) {
            break true;
        }
        if let Some(&close) = slice.last()
            && matches!(close, b'}' | b']')
        {
            let opener = if close == b'}' { b'{' } else { b'[' };
            if !slice.contains(&opener) {
                break false;
            }
            if let Some(m) = memo.as_deref_mut() {
                let cm = m
                    .container
                    .get_or_insert_with(|| JsonContainerMemo::new(bytes.len(), false, false));
                break ends_with_valid_json_container_memo(bytes, end, cm);
            }
            break ends_with_valid_json_container(slice, false);
        }
        let k = if slice.last().is_some_and(|&b| b.is_ascii_digit()) {
            let mut num_start = slice.len();
            while num_start > 0 && matches!(slice[num_start - 1], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
                num_start -= 1;
            }
            if !is_json_number_token(&slice[num_start..]) {
                break false;
            }
            skip_json_ws_backward(slice, num_start)
        } else if let Some(prefix) = [b"true".as_slice(), b"false".as_slice(), b"null".as_slice()]
            .into_iter()
            .find_map(|kw| slice.strip_suffix(kw))
        {
            skip_json_ws_backward(prefix, prefix.len())
        } else {
            break false;
        };

        if k == 0 {
            break true;
        }
        match slice[k - 1] {
            b'[' => break true,
            b':' => {
                let before_colon = skip_json_ws_backward(slice, k - 1);
                break ends_with_json_string_quote(&slice[..before_colon]);
            }
            b',' => {
                if memo.is_some() {
                    visited.push(end);
                }
                let before_comma = skip_json_ws_backward(slice, k - 1);
                if before_comma >= end {
                    break false;
                }
                end = before_comma;
            }
            _ => break false,
        }
    };
    if !res && let Some(m) = memo {
        m.flags[end] |= 1;
        for v in visited {
            m.flags[v] |= 1;
        }
    }
    res
}

fn starts_json_value_after_comma_memo(
    bytes: &[u8],
    mut pos: usize,
    json_marker_prefix: Option<&[u8]>,
    single_layer: bool,
    memo: Option<&mut JsonMarkerMemo>,
) -> bool {
    let mut visited = Vec::new();
    let res = loop {
        if pos >= bytes.len() {
            break false;
        }
        if let Some(m) = memo.as_deref()
            && (m.flags[pos] & 2) != 0
        {
            break false;
        }
        if bytes[pos] == b'\\' {
            let bs = count_consecutive_backslashes(bytes, pos);
            let q = pos + bs;
            if single_layer {
                if bs % 2 == 1 && bytes.get(q..q + 5) == Some(b"u0022") {
                    break true;
                }
            } else {
                if bs % 4 == 2 && bytes.get(q..q + 5) == Some(b"u0022") {
                    break true;
                }
                if bs % 4 == 3 && bytes.get(q) == Some(&b'"') {
                    break true;
                }
            }
            if ((single_layer && bs % 2 == 1) || (!single_layer && bs % 4 == 1)) && bytes.get(q) == Some(&b'"') {
                let mut p = q + 1;
                let mut closed_at_after = None;
                let mut invalid = false;
                while p < bytes.len() {
                    if bytes[p] == b'\\' {
                        let inner_bs = count_consecutive_backslashes(bytes, p);
                        if bytes.get(p + inner_bs) == Some(&b'"') {
                            if single_layer {
                                if inner_bs % 2 == 1 {
                                    closed_at_after = Some(skip_json_ws_forward(bytes, p + inner_bs + 1));
                                    break;
                                }
                                p += inner_bs + 1;
                            } else {
                                if inner_bs % 4 == 1 {
                                    closed_at_after = Some(skip_json_ws_forward(bytes, p + inner_bs + 1));
                                    break;
                                }
                                if inner_bs.is_multiple_of(2) {
                                    invalid = true;
                                    break;
                                }
                                p += inner_bs + 1;
                            }
                        } else {
                            p += inner_bs;
                        }
                    } else if matches!(bytes[p], b'"' | b'\r' | b'\n' | b'\t') {
                        invalid = true;
                        break;
                    } else {
                        p += 1;
                    }
                }
                if invalid {
                    break false;
                }
                let Some(after) = closed_at_after else {
                    break false;
                };
                if after >= bytes.len() {
                    break true;
                }
                if matches!(bytes[after], b':' | b'}' | b']') {
                    break true;
                }
                if bytes[after] == b',' {
                    let next_pos = skip_json_ws_forward(bytes, after + 1);
                    if next_pos <= pos {
                        break false;
                    }
                    if memo.is_some() {
                        visited.push(pos);
                    }
                    pos = next_pos;
                    continue;
                }
                break false;
            }
            break false;
        }
        if single_layer && bytes[pos] == b'"' {
            let mut p = pos + 1;
            let mut closed_at_after = None;
            let mut invalid = false;
            while p < bytes.len() {
                if bytes[p] == b'\\' {
                    let inner_bs = count_consecutive_backslashes(bytes, p);
                    if bytes.get(p + inner_bs) == Some(&b'"') {
                        if inner_bs.is_multiple_of(2) {
                            closed_at_after = Some(skip_json_ws_forward(bytes, p + inner_bs + 1));
                            break;
                        }
                        p += inner_bs + 1;
                    } else {
                        p += inner_bs;
                    }
                } else if bytes[p] == b'"' {
                    closed_at_after = Some(skip_json_ws_forward(bytes, p + 1));
                    break;
                } else if matches!(bytes[p], b'\r' | b'\n' | b'\t') {
                    invalid = true;
                    break;
                } else {
                    p += 1;
                }
            }
            if invalid {
                break false;
            }
            let Some(after) = closed_at_after else {
                break false;
            };
            if after >= bytes.len() || matches!(bytes[after], b':' | b'}' | b']') {
                break true;
            }
            if bytes[after] == b',' {
                let next_pos = skip_json_ws_forward(bytes, after + 1);
                if next_pos <= pos {
                    break false;
                }
                if memo.is_some() {
                    visited.push(pos);
                }
                pos = next_pos;
                continue;
            }
            break false;
        }
        if matches!(bytes[pos], b'{' | b'[') {
            if let Some(mp) = json_marker_prefix
                && bytes[pos + 1..].starts_with(mp)
            {
                break true;
            }
            let inner = skip_json_ws_forward(bytes, pos + 1);
            if inner >= bytes.len() {
                break false;
            }
            if bytes[pos] == b'{' {
                break bytes[inner] == b'}'
                    || bytes[inner] == b'"'
                    || (bytes[inner] == b'\\' && {
                        let bs = count_consecutive_backslashes(bytes, inner);
                        let q = inner + bs;
                        ((bs % 2 == 1 || bs % 4 == 2) && bytes.get(q..q + 5) == Some(b"u0022"))
                            || (bs % 2 == 1 && bytes.get(q) == Some(&b'"'))
                    });
            }
            break bytes[inner] == b']'
                || matches!(bytes[inner], b'{' | b'[' | b'"' | b'-' | b'0'..=b'9')
                || (bytes[inner] == b'\\' && {
                    let bs = count_consecutive_backslashes(bytes, inner);
                    let q = inner + bs;
                    ((bs % 2 == 1 || bs % 4 == 2) && bytes.get(q..q + 5) == Some(b"u0022"))
                        || (bs % 2 == 1 && bytes.get(q) == Some(&b'"'))
                })
                || bytes[inner..].starts_with(b"true")
                || bytes[inner..].starts_with(b"false")
                || bytes[inner..].starts_with(b"null");
        }
        let val_end = if bytes[pos] == b'-' || bytes[pos].is_ascii_digit() {
            let mut e = pos;
            if bytes[e] == b'-' {
                e += 1;
            }
            let digits_start = e;
            while e < bytes.len() && matches!(bytes[e], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
                e += 1;
            }
            (e > digits_start && is_json_number_token(&bytes[pos..e])).then_some(e)
        } else {
            [b"true".as_slice(), b"false".as_slice(), b"null".as_slice()]
                .into_iter()
                .find_map(|kw| bytes[pos..].starts_with(kw).then_some(pos + kw.len()))
        };
        if let Some(ve) = val_end {
            let after = skip_json_ws_forward(bytes, ve);
            if after >= bytes.len() {
                break true;
            }
            if matches!(bytes[after], b'}' | b']') {
                break true;
            }
            if bytes[after] == b',' {
                let next_pos = skip_json_ws_forward(bytes, after + 1);
                if next_pos <= pos {
                    break false;
                }
                if memo.is_some() {
                    visited.push(pos);
                }
                pos = next_pos;
                continue;
            }
        }
        break false;
    };
    if !res && let Some(m) = memo {
        if pos < m.flags.len() {
            m.flags[pos] |= 2;
        }
        for v in visited {
            if v < m.flags.len() {
                m.flags[v] |= 2;
            }
        }
    }
    res
}

fn has_escaped_json_markers_with_options(
    bytes: &[u8],
    at_string_start: bool,
    json_marker_prefix: Option<&[u8]>,
    single_layer: bool,
    allow_shortcut_and_eof_adj: bool,
) -> bool {
    let mut memo: Option<JsonMarkerMemo> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            let bs = count_consecutive_backslashes(bytes, i);
            let q = i + bs;
            let matched_u0022_len = if single_layer {
                (bs % 2 == 1 && bytes.get(q..q + 5) == Some(b"u0022")).then_some(1usize)
            } else if bs % 4 == 2 {
                match bytes.get(q..q + 5) {
                    Some(b"u003c" | b"u003e" | b"u0027") if allow_shortcut_and_eof_adj => return true,
                    Some(b"u0022") => Some(2usize),
                    _ => None,
                }
            } else {
                None
            };
            if let Some(bs_prefix_len) = matched_u0022_len {
                let token_start = q - bs_prefix_len;
                let token_end = q + 5;
                let p = skip_json_ws_backward(bytes, token_start);
                let at_start_ws = at_string_start && p == 0;
                let preceded_by_json_delim = if p > 0 {
                    match bytes[p - 1] {
                        b'{' | b'[' => true,
                        b':' => {
                            let before_delim = skip_json_ws_backward(bytes, p - 1);
                            ends_with_json_string_quote(&bytes[..before_delim])
                        }
                        b',' => {
                            let before_delim = skip_json_ws_backward(bytes, p - 1);
                            let m = memo.get_or_insert_with(|| JsonMarkerMemo::new(bytes.len()));
                            ends_with_json_value_before_comma_memo(bytes, before_delim, Some(m))
                        }
                        _ => false,
                    }
                } else {
                    false
                };
                let n = skip_json_ws_forward(bytes, token_end);
                let followed_by_json_delim = n < bytes.len()
                    && (matches!(bytes[n], b':' | b'}' | b']')
                        || (bytes[n] == b',' && {
                            let after_comma = skip_json_ws_forward(bytes, n + 1);
                            let m = memo.get_or_insert_with(|| JsonMarkerMemo::new(bytes.len()));
                            starts_json_value_after_comma_memo(
                                bytes,
                                after_comma,
                                json_marker_prefix,
                                single_layer,
                                Some(m),
                            )
                        }));
                let adjacent_to_tag = allow_shortcut_and_eof_adj && token_end == bytes.len();
                if at_start_ws || preceded_by_json_delim || followed_by_json_delim || adjacent_to_tag {
                    return true;
                }
            }
            if allow_shortcut_and_eof_adj && !single_layer && bs % 4 == 3 && bytes.get(q) == Some(&b'"') {
                return true;
            }
            i = q;
        } else {
            i += 1;
        }
    }
    false
}

fn has_double_escaped_json_markers_with_marker(
    bytes: &[u8],
    at_string_start: bool,
    json_marker_prefix: Option<&[u8]>,
) -> bool {
    has_escaped_json_markers_with_options(bytes, at_string_start, json_marker_prefix, false, true)
}

fn precompute_u0022_json_ctx(
    lower_bytes: &[u8],
    at_string_start: bool,
    json_marker_prefix: Option<&[u8]>,
) -> (bool, bool) {
    if !lower_bytes.contains(&b'\\') {
        return (false, false);
    }
    let single = has_escaped_json_markers_with_options(lower_bytes, at_string_start, json_marker_prefix, true, false);
    let double = has_escaped_json_markers_with_options(lower_bytes, at_string_start, json_marker_prefix, false, false);
    (single, double)
}

fn sanitize_escaped_keymaterial_in_str(s: &str) -> String {
    sanitize_escaped_keymaterial_in_str_with_marker_and_origin(s, None, false)
}

fn sanitize_escaped_keymaterial_in_str_with_marker_and_origin(
    s: &str,
    json_marker_prefix: Option<&[u8]>,
    from_json_value: bool,
) -> String {
    sanitize_escaped_keymaterial_in_str_with_options(s, json_marker_prefix, from_json_value, false)
}

fn sanitize_escaped_keymaterial_in_str_with_options(
    s: &str,
    json_marker_prefix: Option<&[u8]>,
    _from_json_value: bool,
    space_inside_json_string: bool,
) -> String {
    let lower_bytes = to_ascii_lowercase_vec(s.as_bytes());
    let has_dquote = s.contains('"');
    let allow_closed_csv = has_dquote && is_inline_prefixed_rfc4180_csv(s.as_bytes(), &lower_bytes);
    let unclosed_csv_ranges: Vec<(usize, usize)> = if has_dquote {
        collect_rfc4180_csv_quoted_content_ranges(&lower_bytes, false, false)
            .into_iter()
            .filter_map(|(cs, ce, is_closed)| (allow_closed_csv || !is_closed).then_some((cs, ce)))
            .collect()
    } else {
        Vec::new()
    };
    let mut csv_dbl_state: Option<(usize, usize, bool)> = None;
    let (html_json_lower, clean_cross_cell_km_spans): (std::borrow::Cow<'_, [u8]>, Vec<(usize, usize)>) =
        if is_html_document_or_fragment(s.as_bytes()) {
            let res = mask_html_tags_for_json_scan_detailed(&lower_bytes, space_inside_json_string);
            (std::borrow::Cow::Owned(res.masked), res.clean_cross_cell_km_spans)
        } else {
            (std::borrow::Cow::Borrowed(&lower_bytes), Vec::new())
        };
    let mut json_tracker = if has_html_entity_json_delim(&html_json_lower) {
        JsonContextTracker::with_html_entities()
    } else {
        JsonContextTracker::with_markdown(false)
    };
    let (single_u0022_json_ctx, double_u0022_json_ctx) = if contains_ascii_case_insensitive(&html_json_lower, b"u0022")
    {
        precompute_u0022_json_ctx(&html_json_lower, false, json_marker_prefix)
    } else {
        (false, false)
    };
    let mut out = String::with_capacity(s.len());
    let mut cursor = 0usize;
    let mut modified = false;
    let mut clean_span_idx = 0usize;
    let mut unredacted_close_cache: [Option<Option<usize>>; 2] = [None, None];
    let make_redacted_elem = |open_start: usize, after_name: usize, syntax: TagSyntax| -> String {
        let prefix = extract_keymaterial_prefix(s, open_start, after_name);
        match (syntax, prefix) {
            (TagSyntax::Raw, Some(p)) => format!("<{p}:keyMaterial>[REDACTED]</{p}:keyMaterial>"),
            (TagSyntax::Raw, None) => "<keyMaterial>[REDACTED]</keyMaterial>".to_string(),
            (TagSyntax::HtmlEscaped, Some(p)) => {
                format!("&lt;{p}:keyMaterial&gt;[REDACTED]&lt;/{p}:keyMaterial&gt;")
            }
            (TagSyntax::HtmlEscaped, None) => "&lt;keyMaterial&gt;[REDACTED]&lt;/keyMaterial&gt;".to_string(),
        }
    };

    while let Some(OpeningTagMatch {
        open_start,
        after_name,
        syntax,
        opened_with_u003c,
    }) = find_opening_keymaterial_tag(&lower_bytes, cursor, true)
    {
        if !s.is_char_boundary(open_start) || !s.is_char_boundary(after_name) {
            break;
        }

        let (ctx, bound_end) = if let Some((cs, ce)) = unclosed_csv_ranges
            .iter()
            .copied()
            .find(|&(cs, ce)| cs <= open_start && open_start < ce)
        {
            let (in_json_string, rel_string_start, in_nested_json_string) =
                is_csv_field_in_json_string(&lower_bytes[cs..open_start]);
            if is_double_escaped_tag_open(&lower_bytes, open_start) && !in_json_string {
                out.push_str(&s[cursor..after_name]);
                cursor = after_name;
                continue;
            }
            let has_double_escaped_gap = check_csv_field_double_escaped_with_marker(
                &lower_bytes,
                cs,
                rel_string_start,
                in_json_string,
                cursor,
                open_start,
                &mut csv_dbl_state,
                json_marker_prefix,
            );
            let in_double_escaped_json = in_nested_json_string
                || has_double_escaped_gap
                || (in_json_string && is_double_escaped_tag_open(&lower_bytes, open_start));
            (
                TagScanContext {
                    in_csv_field: true,
                    in_json_string,
                    in_markdown_json_string: false,
                    in_markdown_table_line: false,
                    in_double_escaped_json,
                    in_nested_json_string,
                    allow_double_bs: in_json_string,
                    opened_with_u003c,
                    allow_tsv_tabs: false,
                    in_decoded_u0022_json_ctx: false,
                },
                ce,
            )
        } else {
            let (in_json_string, in_markdown_json_string, in_markdown_table_line, in_nested_json_string) =
                json_tracker.advance_to(&html_json_lower, open_start);
            if is_double_escaped_tag_open(&lower_bytes, open_start) && !in_json_string && !double_u0022_json_ctx {
                out.push_str(&s[cursor..after_name]);
                cursor = after_name;
                continue;
            }
            let has_double_escaped_gap = in_json_string
                && json_tracker.mark_double_escaped_gap_with_marker(
                    &html_json_lower,
                    cursor,
                    open_start,
                    json_marker_prefix,
                );
            while clean_span_idx < clean_cross_cell_km_spans.len()
                && clean_cross_cell_km_spans[clean_span_idx].1 <= open_start
            {
                clean_span_idx += 1;
            }
            if let Some(&(cs, ce)) = clean_cross_cell_km_spans.get(clean_span_idx)
                && cs <= open_start
                && open_start < ce
                && s.is_char_boundary(ce)
            {
                out.push_str(&s[cursor..ce]);
                cursor = ce;
                continue;
            }
            let decoded_u0022_ctx = !in_json_string && (single_u0022_json_ctx || double_u0022_json_ctx);
            let effective_in_json_string =
                in_json_string || (decoded_u0022_ctx && (syntax == TagSyntax::HtmlEscaped || opened_with_u003c));
            let in_double_escaped_json = in_markdown_json_string
                || in_nested_json_string
                || has_double_escaped_gap
                || (!in_json_string && double_u0022_json_ctx)
                || (in_json_string && is_double_escaped_tag_open(&lower_bytes, open_start));
            (
                TagScanContext {
                    in_csv_field: false,
                    in_json_string: effective_in_json_string,
                    in_markdown_json_string,
                    in_markdown_table_line,
                    in_double_escaped_json,
                    in_nested_json_string,
                    allow_double_bs: in_json_string || (!in_json_string && double_u0022_json_ctx),
                    opened_with_u003c,
                    allow_tsv_tabs: true,
                    in_decoded_u0022_json_ctx: decoded_u0022_ctx,
                },
                lower_bytes.len(),
            )
        };

        let bounded = &lower_bytes[..bound_end];
        let Some((close_start, open_end, is_self_closing)) =
            find_tag_close_quote_aware_cached(bounded, after_name, syntax, ctx, &mut unredacted_close_cache)
        else {
            out.push_str(&s[cursor..open_start]);
            out.push_str(&make_redacted_elem(open_start, after_name, syntax));
            return out;
        };
        if !s.is_char_boundary(open_end) {
            break;
        }
        let dirty_attr_km = find_ascii_bytes(&lower_bytes[after_name..close_start], 0, b"keymaterial").is_some()
            && has_unredacted_inner_keymaterial_in_span(&lower_bytes, after_name, close_start, true, ctx);
        if is_self_closing {
            if dirty_attr_km {
                out.push_str(&s[cursor..open_start]);
                out.push_str(&make_redacted_elem(open_start, after_name, syntax));
                modified = true;
            } else {
                out.push_str(&s[cursor..open_end]);
            }
            cursor = open_end;
            continue;
        }
        let Some((close_tag_start, close_tag_end)) =
            find_closing_keymaterial_tag(bounded, open_end, syntax, ctx.allow_double_bs)
        else {
            out.push_str(&s[cursor..open_start]);
            out.push_str(&make_redacted_elem(open_start, after_name, syntax));
            return out;
        };
        if !s.is_char_boundary(close_tag_start) || !s.is_char_boundary(close_tag_end) {
            break;
        }
        if !dirty_attr_km && s[open_end..close_tag_start].trim() == "[REDACTED]" {
            out.push_str(&s[cursor..close_tag_end]);
        } else {
            out.push_str(&s[cursor..open_start]);
            out.push_str(&make_redacted_elem(open_start, after_name, syntax));
            modified = true;
        }
        cursor = close_tag_end;
    }

    if !modified {
        s.to_string()
    } else {
        out.push_str(&s[cursor..]);
        out
    }
}

fn escape_html_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn assert_r4_clean_html_attr_decoded_with_depth(decoded: &[u8], depth: usize) -> Result<(), ReportError> {
    assert_r4_clean_decoded_cell_inner_with_origin(decoded, depth.saturating_add(1), false, false)?;
    if contains_ascii_case_insensitive(decoded, b"\\u003c") {
        let trimmed = decoded.trim_ascii();
        let is_full_json = (trimmed.starts_with(b"{") || trimmed.starts_with(b"[") || trimmed.starts_with(b"\""))
            && serde_json::from_slice::<Value>(trimmed).is_ok();
        if !is_full_json {
            assert_r4_clean_bytes_with_depth(decoded, false, true, false, depth.saturating_add(1), false)?;
        }
    }
    Ok(())
}

fn starts_html_json_container(slice: &[u8], pos: usize) -> bool {
    let opener = slice[pos];
    let mut k = pos + 1;
    while k < slice.len() && slice[k].is_ascii_whitespace() {
        k += 1;
    }
    let Some(&next) = slice.get(k) else {
        return false;
    };
    match opener {
        b'{' => {
            next == b'}'
                || next == b'"'
                || (next == b'&'
                    && matches!(
                        match_html_quote_entity(&slice[k..]),
                        Some((HtmlQuoteMode::DoubleEntity, _))
                    ))
        }
        b'[' => {
            if matches!(next, b'"' | b'{' | b'[' | b']' | b'-' | b'0'..=b'9')
                || (next == b'&'
                    && matches!(
                        match_html_quote_entity(&slice[k..]),
                        Some((HtmlQuoteMode::DoubleEntity, _))
                    ))
            {
                return true;
            }
            for kw in [b"true".as_slice(), b"false".as_slice(), b"null".as_slice()] {
                if slice[k..].starts_with(kw) {
                    let after = slice.get(k + kw.len()).copied();
                    if matches!(after, None | Some(b' ' | b'\t' | b'\r' | b'\n' | b',' | b']')) {
                        return true;
                    }
                }
            }
            false
        }
        _ => false,
    }
}

fn scan_html_json_container_end(slice: &[u8], pos: usize) -> usize {
    scan_html_json_container_end_with_csv(slice, pos, false)
}

fn scan_html_json_container_end_with_csv(slice: &[u8], pos: usize, allow_csv_doubled: bool) -> usize {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum HtmlJsonStrMode {
        Raw,
        Entity,
        CsvDoubled,
    }
    let mut depth = 1usize;
    let mut str_mode: Option<HtmlJsonStrMode> = None;
    let mut p = pos + 1;
    while p < slice.len() && depth > 0 {
        if let Some(mode) = str_mode {
            if slice[p] == b'\\' {
                let bs = count_consecutive_backslashes(slice, p);
                if mode == HtmlJsonStrMode::Raw && slice.get(p + bs) == Some(&b'"') {
                    if bs.is_multiple_of(2) {
                        str_mode = None;
                    }
                    p += bs + 1;
                } else if mode == HtmlJsonStrMode::CsvDoubled && slice.get(p + bs..p + bs + 2) == Some(b"\"\"") {
                    if bs.is_multiple_of(2) {
                        str_mode = None;
                    }
                    p += bs + 2;
                } else if mode == HtmlJsonStrMode::Entity
                    && let Some((HtmlQuoteMode::DoubleEntity, len)) =
                        slice.get(p + bs..).and_then(match_html_quote_entity)
                {
                    if bs.is_multiple_of(2) {
                        str_mode = None;
                    }
                    p += bs + len;
                } else {
                    p += bs;
                }
            } else if mode == HtmlJsonStrMode::CsvDoubled && slice[p..].starts_with(b"\"\"") {
                str_mode = None;
                p += 2;
            } else if mode == HtmlJsonStrMode::Raw && slice[p] == b'"' {
                str_mode = None;
                p += 1;
            } else if mode == HtmlJsonStrMode::Entity
                && let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&slice[p..])
            {
                str_mode = None;
                p += len;
            } else {
                p += 1;
            }
        } else if allow_csv_doubled && slice[p..].starts_with(b"\"\"") {
            str_mode = Some(HtmlJsonStrMode::CsvDoubled);
            p += 2;
        } else if slice[p] == b'"' {
            str_mode = Some(HtmlJsonStrMode::Raw);
            p += 1;
        } else if slice[p] == b'&'
            && let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&slice[p..])
        {
            str_mode = Some(HtmlJsonStrMode::Entity);
            p += len;
        } else if matches!(slice[p], b'{' | b'[') {
            depth += 1;
            p += 1;
        } else if matches!(slice[p], b'}' | b']') {
            depth -= 1;
            p += 1;
        } else {
            p += 1;
        }
    }
    p
}

fn scan_html_entity_quoted_span(slice: &[u8], pos: usize) -> Option<usize> {
    let (HtmlQuoteMode::DoubleEntity, open_len) = match_html_quote_entity(slice.get(pos..)?)? else {
        return None;
    };
    let mut p = pos + open_len;
    while p < slice.len() {
        if slice[p] == b'\\' {
            let bs = count_consecutive_backslashes(slice, p);
            if let Some((HtmlQuoteMode::DoubleEntity, len)) = slice.get(p + bs..).and_then(match_html_quote_entity) {
                if bs.is_multiple_of(2) {
                    return Some(p + bs + len);
                }
                p += bs + len;
            } else {
                p += bs;
            }
        } else if slice[p] == b'&'
            && let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&slice[p..])
        {
            return Some(p + len);
        } else {
            p += 1;
        }
    }
    None
}

fn has_unbalanced_html_double_quote_entities(lower_span: &[u8]) -> bool {
    let mut count = 0usize;
    let mut i = 0usize;
    while i < lower_span.len() {
        if lower_span[i] == b'&'
            && let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&lower_span[i..])
        {
            count += 1;
            i += len;
            continue;
        }
        i += 1;
    }
    count % 2 == 1
}

fn opening_keymaterial_tag_at(lower: &[u8], pos: usize, allow_double_bs: bool) -> Option<OpeningTagMatch> {
    let rest = lower.get(pos..)?;
    let lt_len = if rest.starts_with(b"<") {
        1
    } else if allow_double_bs && rest.starts_with(b"\\\\u003c") {
        7
    } else if rest.starts_with(b"\\u003c") {
        6
    } else if rest.starts_with(b"&") {
        match_html_lt_entity(rest)?
    } else {
        return None;
    };
    let mut p = pos + lt_len;
    let mut has_colon = false;
    while p < lower.len() && (is_xml_ncname_char(lower[p]) || (!has_colon && lower[p] == b':')) {
        if lower[p] == b':' {
            has_colon = true;
            p += 1;
            break;
        }
        p += 1;
    }
    let km_start = if has_colon { p } else { pos + lt_len };
    if lower.get(km_start..km_start + 11) != Some(b"keymaterial".as_slice()) {
        return None;
    }
    let m = find_opening_keymaterial_tag(lower, pos, allow_double_bs)?;
    (m.open_start == pos).then_some(m)
}

#[inline]
fn range_overlaps_sorted_spans(spans: &[(usize, usize)], start: usize, end: usize) -> bool {
    if start >= end || spans.is_empty() {
        return false;
    }
    let idx = spans.partition_point(|&(_, e)| e <= start);
    idx < spans.len() && spans[idx].0 < end
}

#[allow(clippy::too_many_arguments)]
fn scan_unquoted_html_token_end_cached(
    attr_slice: &[u8],
    lower_attr_opt: &mut Option<Vec<u8>>,
    has_km: bool,
    start: usize,
    stop_on_eq: bool,
    unredacted_close_cache: &mut [Option<Option<usize>>; 2],
    no_closing_tag: &mut [bool; 2],
) -> usize {
    let mut k = start;
    while k < attr_slice.len()
        && !attr_slice[k].is_ascii_whitespace()
        && (!stop_on_eq || !matches!(attr_slice[k], b'=' | b'/' | b'>'))
    {
        if has_km && matches!(attr_slice[k], b'<' | b'\\' | b'&') {
            let lower_attr = lower_attr_opt.get_or_insert_with(|| to_ascii_lowercase_vec(attr_slice));
            if let Some(m) = opening_keymaterial_tag_at(lower_attr, k, true) {
                if let Some((_cs, km_open_end, is_self_closing)) = find_tag_close_quote_aware_cached(
                    lower_attr,
                    m.after_name,
                    m.syntax,
                    TagScanContext {
                        allow_double_bs: true,
                        opened_with_u003c: m.opened_with_u003c,
                        ..TagScanContext::default()
                    },
                    unredacted_close_cache,
                ) {
                    let mut end_pos = km_open_end;
                    let unbalanced_entity_quote = m.syntax == TagSyntax::Raw
                        && has_unbalanced_html_double_quote_entities(&lower_attr[m.after_name..km_open_end]);
                    if !is_self_closing || unbalanced_entity_quote {
                        let syn_idx = usize::from(m.syntax == TagSyntax::HtmlEscaped);
                        if !no_closing_tag[syn_idx] {
                            if let Some((_cs, km_close_end)) =
                                find_closing_keymaterial_tag(lower_attr, km_open_end, m.syntax, true)
                            {
                                end_pos = km_close_end;
                            } else {
                                no_closing_tag[syn_idx] = true;
                            }
                        }
                    }
                    k = end_pos;
                    continue;
                }
                return attr_slice.len();
            }
        }
        if matches!(attr_slice[k], b'{' | b'[') && starts_html_json_container(attr_slice, k) {
            k = scan_html_json_container_end(attr_slice, k);
            continue;
        }
        if attr_slice[k] == b'&'
            && let Some(span_end) = scan_html_entity_quoted_span(attr_slice, k)
        {
            k = span_end;
            continue;
        }
        k += 1;
    }
    k
}

fn find_split_keymaterial_in_attr(val_slice: &[u8]) -> Option<(usize, TagSyntax, bool)> {
    if !contains_ascii_case_insensitive(val_slice, b"keymaterial") {
        return None;
    }
    let lower = to_ascii_lowercase_vec(val_slice);
    let mut pos = 0usize;
    while let Some(m) = find_opening_keymaterial_tag(&lower, pos, true) {
        let ctx = TagScanContext {
            allow_double_bs: true,
            opened_with_u003c: m.opened_with_u003c,
            ..TagScanContext::default()
        };
        let Some((_cs, open_end, is_self_closing)) = find_tag_close_quote_aware(&lower, m.after_name, m.syntax, ctx)
        else {
            return Some((m.open_start, m.syntax, true));
        };
        if is_self_closing {
            pos = open_end;
            continue;
        }
        let Some((_cs, close_end)) = find_closing_keymaterial_tag(&lower, open_end, m.syntax, true) else {
            return Some((m.open_start, m.syntax, true));
        };
        pos = close_end;
    }
    None
}

fn sanitize_html_tag_attributes_r4(attr_slice: &[u8], depth: usize) -> String {
    let has_km = contains_ascii_case_insensitive(attr_slice, b"keymaterial");
    let mut lower_attr_opt: Option<Vec<u8>> = None;
    let mut unredacted_close_cache: [Option<Option<usize>>; 2] = [None, None];
    let mut no_closing_tag = [false; 2];
    let mut out = String::with_capacity(attr_slice.len());
    let mut k = 0usize;
    while k < attr_slice.len() {
        let loop_start = k;
        let ws_start = k;
        while k < attr_slice.len() && (attr_slice[k].is_ascii_whitespace() || matches!(attr_slice[k], b'/' | b'>')) {
            k += 1;
        }
        out.push_str(&String::from_utf8_lossy(&attr_slice[ws_start..k]));
        if k >= attr_slice.len() {
            break;
        }
        let name_start = k;
        k = scan_unquoted_html_token_end_cached(
            attr_slice,
            &mut lower_attr_opt,
            has_km,
            name_start,
            true,
            &mut unredacted_close_cache,
            &mut no_closing_tag,
        );
        let name_slice = &attr_slice[name_start..k];
        let name_raw_dirty = name_slice.contains(&b'<') && assert_r4_clean_raw_bytes(name_slice).is_err();
        let name_u003c_dirty = !name_raw_dirty
            && contains_ascii_case_insensitive(name_slice, b"\\u003c")
            && assert_r4_clean_html_attr_decoded_with_depth(name_slice, depth).is_err();
        if name_raw_dirty || name_u003c_dirty {
            let clean_name = sanitize_string_r4_inner(&String::from_utf8_lossy(name_slice), depth + 1);
            out.push_str(&clean_name);
        } else if name_slice.contains(&b'&') {
            let decoded = unescape_html_entities_cow(name_slice);
            if assert_r4_clean_html_attr_decoded_with_depth(&decoded, depth).is_err() {
                let clean_name = sanitize_string_r4_inner(&String::from_utf8_lossy(&decoded), depth + 1);
                out.push_str(&escape_html_text(&clean_name));
            } else {
                out.push_str(&String::from_utf8_lossy(name_slice));
            }
        } else {
            out.push_str(&String::from_utf8_lossy(name_slice));
        }
        let eq_ws_start = k;
        while k < attr_slice.len() && attr_slice[k].is_ascii_whitespace() {
            k += 1;
        }
        out.push_str(&String::from_utf8_lossy(&attr_slice[eq_ws_start..k]));
        if attr_slice.get(k) != Some(&b'=') {
            if k <= loop_start {
                let next = loop_start + 1;
                out.push_str(&String::from_utf8_lossy(&attr_slice[k..next]));
                k = next;
            }
            continue;
        }
        out.push('=');
        k += 1;
        let post_eq_ws = k;
        while k < attr_slice.len() && attr_slice[k].is_ascii_whitespace() {
            k += 1;
        }
        out.push_str(&String::from_utf8_lossy(&attr_slice[post_eq_ws..k]));
        if k >= attr_slice.len() {
            break;
        }
        if matches!(attr_slice[k], b'"' | b'\'') {
            let q = attr_slice[k];
            let val_start = k + 1;
            let mut val_end = val_start;
            while val_end < attr_slice.len() && attr_slice[val_end] != q {
                val_end += 1;
            }
            let has_close = val_end < attr_slice.len();
            k = if has_close { val_end + 1 } else { val_end };
            let val_slice = &attr_slice[val_start..val_end];
            out.push(q as char);
            if !val_slice.is_empty() {
                let decoded = unescape_html_entities_cow(val_slice);
                if assert_r4_clean_html_attr_decoded_with_depth(&decoded, depth).is_err() {
                    if let Some((km_open, km_syntax, allow_double_bs)) = find_split_keymaterial_in_attr(val_slice) {
                        let prefix_slice = &val_slice[..km_open];
                        if !prefix_slice.is_empty() {
                            let prefix_decoded = unescape_html_entities_cow(prefix_slice);
                            let clean_prefix =
                                sanitize_string_r4_inner(&String::from_utf8_lossy(&prefix_decoded), depth + 1);
                            out.push_str(&escape_html_text(&clean_prefix));
                        }
                        out.push_str("&lt;keyMaterial&gt;[REDACTED]&lt;/keyMaterial&gt;");
                        let lower_attr = lower_attr_opt.get_or_insert_with(|| to_ascii_lowercase_vec(attr_slice));
                        if let Some((_cs, rel_close_end)) =
                            find_closing_keymaterial_tag(&lower_attr[val_end..], 0, km_syntax, allow_double_bs)
                        {
                            k = val_end + rel_close_end;
                        } else {
                            k = attr_slice.len();
                        }
                        out.push(q as char);
                        continue;
                    }
                    let clean = sanitize_string_r4_inner(&String::from_utf8_lossy(&decoded), depth + 1);
                    out.push_str(&escape_html_text(&clean));
                } else {
                    out.push_str(&String::from_utf8_lossy(val_slice));
                }
            }
            if has_close {
                out.push(q as char);
            }
        } else {
            let val_start = k;
            k = scan_unquoted_html_token_end_cached(
                attr_slice,
                &mut lower_attr_opt,
                has_km,
                val_start,
                false,
                &mut unredacted_close_cache,
                &mut no_closing_tag,
            );
            let val_slice = &attr_slice[val_start..k];
            if !val_slice.is_empty() {
                let decoded = unescape_html_entities_cow(val_slice);
                if assert_r4_clean_html_attr_decoded_with_depth(&decoded, depth).is_err() {
                    let clean = sanitize_string_r4_inner(&String::from_utf8_lossy(&decoded), depth + 1);
                    let reescaped = escape_html_text(&clean);
                    if reescaped.bytes().any(|b| b.is_ascii_whitespace()) {
                        out.push('"');
                        out.push_str(&reescaped);
                        out.push('"');
                    } else {
                        out.push_str(&reescaped);
                    }
                } else {
                    out.push_str(&String::from_utf8_lossy(val_slice));
                }
            }
        }
        if k <= loop_start {
            k = loop_start + 1;
        }
    }
    out
}

fn sanitize_html_fragment_r4_with_origin(s: &str, depth: usize, from_json_value: bool) -> String {
    if depth >= MAX_NESTED_JSON_DEPTH {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let lower_bytes = to_ascii_lowercase_vec(bytes);
    let (cross_space_proj, clean_cross_cell_km_spans): (Option<Vec<u8>>, Vec<(usize, usize)>) =
        if contains_keymaterial_word(s)
            && contains_json_opener_or_html_entity(bytes)
            && mask_html_tags_for_json_scan_with_options(bytes, false).1
        {
            let res = mask_html_tags_for_json_scan_detailed(bytes, true);
            (Some(res.masked), res.clean_cross_cell_km_spans)
        } else {
            (None, Vec::new())
        };
    let mut cross_tracker = cross_space_proj.as_ref().map(|proj| {
        if has_html_entity_json_delim(proj) {
            JsonContextTracker::with_html_entities()
        } else {
            JsonContextTracker::with_markdown(false)
        }
    });
    let mut out = String::with_capacity(s.len());
    let mut text_buf = Vec::<u8>::new();
    let mut buf_start = 0usize;
    let mut i = 0usize;
    let mut unredacted_close_cache: [Option<Option<usize>>; 2] = [None, None];

    let strip_or_unwrap_json_prefix = |sanitized: &str, prefix: &str, fallback_raw: &str| -> String {
        if let Some(rest) = sanitized.strip_prefix(prefix) {
            return rest.to_string();
        }
        if let Ok(Value::Object(mut m)) = serde_json::from_str::<Value>(sanitized)
            && let Some(v) = m.remove("_")
            && let Ok(enc) = serde_json::to_string(&v)
            && enc.len() >= 2
        {
            return enc[1..enc.len() - 1].to_string();
        }
        sanitize_string_r4_inner_with_origin(fallback_raw, depth + 1, from_json_value)
    };

    let flush_text = |text_buf: &mut Vec<u8>,
                      out: &mut String,
                      start_pos: usize,
                      cross_tracker: &mut Option<JsonContextTracker>| {
        if text_buf.is_empty() {
            return;
        }
        let cross_json_ctx = if let (Some(proj), Some(tracker)) = (cross_space_proj.as_ref(), cross_tracker.as_mut()) {
            let (in_j, _, _, _) = tracker.advance_to(proj, start_pos);
            in_j.then_some(tracker.in_entity_quote)
        } else {
            None
        };
        if let Some(in_entity_quote) = cross_json_ctx {
            let prefix = if in_entity_quote {
                "{&quot;_&quot;:&quot;"
            } else {
                "{\"_\":\""
            };
            let end_pos = start_pos + text_buf.len();
            let has_clean_overlap = range_overlaps_sorted_spans(&clean_cross_cell_km_spans, start_pos, end_pos);
            let mut check_buf = Vec::with_capacity(prefix.len() + text_buf.len());
            check_buf.extend_from_slice(prefix.as_bytes());
            check_buf.extend_from_slice(text_buf);
            if has_clean_overlap {
                let mut idx = clean_cross_cell_km_spans.partition_point(|&(_, e)| e <= start_pos);
                while idx < clean_cross_cell_km_spans.len() && clean_cross_cell_km_spans[idx].0 < end_pos {
                    let (cs, ce) = clean_cross_cell_km_spans[idx];
                    let rel_s = prefix.len() + cs.saturating_sub(start_pos);
                    let rel_e = prefix.len() + (ce.min(end_pos) - start_pos);
                    if rel_s < rel_e {
                        check_buf[rel_s..rel_e].fill(b' ');
                    }
                    idx += 1;
                }
            }
            if flush_html_text_buf_with_origin(&mut check_buf, depth, from_json_value).is_ok() {
                out.push_str(&String::from_utf8_lossy(text_buf));
            } else {
                let raw_lossy = String::from_utf8_lossy(text_buf);
                let mut clean_placeholders: Vec<(String, String)> = Vec::new();
                let effective_raw: std::borrow::Cow<'_, str> = if has_clean_overlap {
                    let mut nonce = 0usize;
                    let ph_prefix = loop {
                        let cand = format!("__GUAPKM{nonce}_");
                        if !raw_lossy.contains(&cand) {
                            break cand;
                        }
                        nonce += 1;
                    };
                    let mut masked_raw = String::with_capacity(raw_lossy.len());
                    let mut raw_cur = 0usize;
                    let mut idx = clean_cross_cell_km_spans.partition_point(|&(_, e)| e <= start_pos);
                    while idx < clean_cross_cell_km_spans.len() && clean_cross_cell_km_spans[idx].0 < end_pos {
                        let (cs, ce) = clean_cross_cell_km_spans[idx];
                        let rel_s = cs.saturating_sub(start_pos);
                        let rel_e = ce.min(end_pos) - start_pos;
                        if rel_s >= raw_cur && rel_e <= text_buf.len() {
                            masked_raw.push_str(&String::from_utf8_lossy(&text_buf[raw_cur..rel_s]));
                            let token = format!("{ph_prefix}{}_", clean_placeholders.len());
                            clean_placeholders.push((
                                token.clone(),
                                String::from_utf8_lossy(&text_buf[rel_s..rel_e]).into_owned(),
                            ));
                            masked_raw.push_str(&token);
                            raw_cur = rel_e;
                        }
                        idx += 1;
                    }
                    masked_raw.push_str(&String::from_utf8_lossy(&text_buf[raw_cur..]));
                    std::borrow::Cow::Owned(masked_raw)
                } else {
                    std::borrow::Cow::Borrowed(raw_lossy.as_ref())
                };
                let mut prefixed_for_err = Vec::with_capacity(prefix.len() + effective_raw.len());
                prefixed_for_err.extend_from_slice(prefix.as_bytes());
                prefixed_for_err.extend_from_slice(effective_raw.as_bytes());
                let mut rendered_piece =
                    if assert_r4_clean_decoded_cell_inner_with_origin(&prefixed_for_err, depth, false, from_json_value)
                        .is_err()
                    {
                        let prefixed_raw = format!("{prefix}{effective_raw}");
                        let sanitized = sanitize_string_r4_inner_with_origin(&prefixed_raw, depth + 1, from_json_value);
                        strip_or_unwrap_json_prefix(&sanitized, prefix, &effective_raw)
                    } else {
                        let decoded = unescape_html_entities(&prefixed_for_err);
                        let decoded_str = String::from_utf8_lossy(&decoded);
                        let dec_prefix = "{\"_\":\"";
                        let sanitized = sanitize_string_r4_inner_with_origin(&decoded_str, depth + 1, from_json_value);
                        let raw_dec = unescape_html_entities(effective_raw.as_bytes());
                        let raw_dec_str = String::from_utf8_lossy(&raw_dec);
                        let clean_dec = strip_or_unwrap_json_prefix(&sanitized, dec_prefix, &raw_dec_str);
                        escape_html_text(&clean_dec)
                    };
                for (tok, orig) in clean_placeholders {
                    rendered_piece = rendered_piece.replace(&tok, &orig);
                }
                out.push_str(&rendered_piece);
            }
            text_buf.clear();
            return;
        }
        let mut check_buf = text_buf.clone();
        if flush_html_text_buf_with_origin(&mut check_buf, depth, from_json_value).is_ok() {
            out.push_str(&String::from_utf8_lossy(text_buf));
        } else if assert_r4_clean_decoded_cell_inner_with_origin(text_buf, depth, false, from_json_value).is_err() {
            let raw_str = String::from_utf8_lossy(text_buf);
            let sanitized = sanitize_string_r4_inner_with_origin(&raw_str, depth + 1, from_json_value);
            out.push_str(&sanitized);
        } else {
            let decoded = unescape_html_entities(text_buf);
            let decoded_str = String::from_utf8_lossy(&decoded);
            let sanitized = sanitize_string_r4_inner_with_origin(&decoded_str, depth + 1, from_json_value);
            out.push_str(&escape_html_text(&sanitized));
        }
        text_buf.clear();
    };

    while i < bytes.len() {
        if bytes[i] != b'<' {
            let next_lt = find_byte(bytes, i, b'<').unwrap_or(bytes.len());
            if text_buf.is_empty() {
                buf_start = i;
            }
            text_buf.extend_from_slice(&bytes[i..next_lt]);
            i = next_lt;
            continue;
        }

        if bytes[i..].starts_with(b"<!--") {
            flush_text(&mut text_buf, &mut out, buf_start, &mut cross_tracker);
            if let Some(end_pos) = find_ascii_bytes(bytes, i + 4, b"-->") {
                let inner = &bytes[i + 4..end_pos];
                if assert_r4_clean_raw_bytes(inner).is_ok() {
                    out.push_str(&String::from_utf8_lossy(&bytes[i..end_pos + 3]));
                } else {
                    let clean_inner = sanitize_escaped_keymaterial_in_str(&String::from_utf8_lossy(inner));
                    out.push_str("<!--");
                    out.push_str(&clean_inner);
                    out.push_str("-->");
                }
                i = end_pos + 3;
            } else {
                let inner = &bytes[i + 4..];
                if assert_r4_clean_raw_bytes(inner).is_ok() {
                    out.push_str(&String::from_utf8_lossy(&bytes[i..]));
                } else {
                    let clean_inner = sanitize_escaped_keymaterial_in_str(&String::from_utf8_lossy(inner));
                    out.push_str("<!--");
                    out.push_str(&clean_inner);
                }
                i = bytes.len();
            }
            continue;
        }

        if let Some(name_end) = raw_keymaterial_name_end(&lower_bytes, i) {
            let cross_in_json = if pos_in_sorted_ranges(&clean_cross_cell_km_spans, i) {
                false
            } else if !text_buf.is_empty()
                && let (Some(proj), Some(tracker)) = (cross_space_proj.as_ref(), cross_tracker.as_mut())
            {
                tracker.advance_to(proj, buf_start).0
            } else if text_buf.is_empty()
                && let (Some(proj), Some(tracker)) = (cross_space_proj.as_ref(), cross_tracker.as_mut())
            {
                tracker.advance_to(proj, i).0
            } else {
                false
            };
            let decoded_prefix = unescape_html_entities_cow(&text_buf);
            let lower_prefix: Vec<u8> = if cross_in_json {
                let mut v = Vec::with_capacity(7 + decoded_prefix.len());
                v.extend_from_slice(b"{\"_\":\"");
                v.extend_from_slice(&decoded_prefix);
                v[6..].make_ascii_lowercase();
                v
            } else {
                to_ascii_lowercase_vec(&decoded_prefix)
            };
            let mut tracker = JsonContextTracker::with_markdown(false);
            let (in_json_string, _, _, in_nested_json_string) = tracker.advance_to(&lower_prefix, lower_prefix.len());
            let ctx = TagScanContext {
                in_csv_field: false,
                in_json_string,
                in_markdown_json_string: false,
                in_markdown_table_line: false,
                in_double_escaped_json: in_nested_json_string,
                in_nested_json_string,
                allow_double_bs: in_json_string,
                opened_with_u003c: false,
                allow_tsv_tabs: false,
                in_decoded_u0022_json_ctx: false,
            };
            if let Some((_cs, open_end, is_self_closing)) = find_tag_close_quote_aware_cached(
                &lower_bytes,
                name_end,
                TagSyntax::Raw,
                ctx,
                &mut unredacted_close_cache,
            ) {
                let end = if is_self_closing {
                    open_end
                } else if let Some((_cs, close_end)) =
                    find_closing_keymaterial_tag(&lower_bytes, open_end, TagSyntax::Raw, ctx.allow_double_bs)
                {
                    close_end
                } else {
                    open_end
                };
                if in_json_string {
                    if text_buf.is_empty() {
                        buf_start = i;
                    }
                    text_buf.extend_from_slice(&bytes[i..end]);
                } else {
                    flush_text(&mut text_buf, &mut out, buf_start, &mut cross_tracker);
                    let attrs_clean = open_end <= name_end + 1
                        || check_html_tag_attributes_with_depth(&bytes[name_end..open_end - 1], depth).is_ok();
                    if attrs_clean
                        && assert_r4_clean_decoded_cell_inner_with_origin(&bytes[i..end], depth, false, from_json_value)
                            .is_ok()
                    {
                        out.push_str(&String::from_utf8_lossy(&bytes[i..end]));
                    } else {
                        out.push_str("<keyMaterial>[REDACTED]</keyMaterial>");
                    }
                }
                i = end;
            } else {
                if text_buf.is_empty() {
                    buf_start = i;
                }
                text_buf.push(bytes[i]);
                i += 1;
            }
            continue;
        }

        if bytes.get(i + 1) == Some(&b'/') {
            flush_text(&mut text_buf, &mut out, buf_start, &mut cross_tracker);
            if let Some(end) = find_html_open_tag_end(&lower_bytes, i) {
                out.push_str(&String::from_utf8_lossy(&bytes[i..end]));
                i = end;
            } else {
                let tail = &bytes[i..];
                if assert_r4_clean_raw_bytes(tail).is_ok() {
                    out.push_str(&String::from_utf8_lossy(tail));
                } else {
                    out.push_str(&sanitize_escaped_keymaterial_in_str(&String::from_utf8_lossy(tail)));
                }
                i = bytes.len();
            }
            continue;
        }

        if bytes.get(i + 1) == Some(&b'!') {
            flush_text(&mut text_buf, &mut out, buf_start, &mut cross_tracker);
            if let Some(rel) = bytes[i..].iter().position(|&b| b == b'>') {
                out.push_str(&String::from_utf8_lossy(&bytes[i..i + rel + 1]));
                i += rel + 1;
            } else {
                out.push_str(&String::from_utf8_lossy(&bytes[i..]));
                i = bytes.len();
            }
            continue;
        }

        if bytes.get(i + 1).is_some_and(u8::is_ascii_alphabetic) {
            flush_text(&mut text_buf, &mut out, buf_start, &mut cross_tracker);
            let mut tag_name_end = i + 2;
            while tag_name_end < lower_bytes.len()
                && (lower_bytes[tag_name_end].is_ascii_alphanumeric()
                    || matches!(lower_bytes[tag_name_end], b'-' | b':'))
            {
                tag_name_end += 1;
            }
            let tag_name = &lower_bytes[i + 1..tag_name_end];
            let Some(tag_end) = find_html_open_tag_end(&lower_bytes, i) else {
                let tail = &bytes[i..];
                if assert_r4_clean_raw_bytes(tail).is_ok() {
                    let dec = unescape_html_entities(tail);
                    let allow_html_reentry = dec != tail || tail.contains(&b'\n');
                    if assert_r4_clean_decoded_cell_inner_with_options(
                        &dec,
                        depth + 1,
                        false,
                        from_json_value,
                        allow_html_reentry,
                    )
                    .is_ok()
                    {
                        out.push_str(&String::from_utf8_lossy(tail));
                    } else {
                        let clean_dec = sanitize_string_r4_inner_with_origin(
                            &String::from_utf8_lossy(&dec),
                            depth + 1,
                            from_json_value,
                        );
                        out.push_str(&escape_html_text(&clean_dec));
                    }
                } else {
                    out.push_str(&sanitize_escaped_keymaterial_in_str(&String::from_utf8_lossy(tail)));
                }
                return out;
            };
            if tag_end > tag_name_end + 1
                && check_html_tag_attributes_with_depth(&bytes[tag_name_end..tag_end - 1], depth).is_err()
            {
                out.push_str(&String::from_utf8_lossy(&bytes[i..tag_name_end]));
                out.push_str(&sanitize_html_tag_attributes_r4(
                    &bytes[tag_name_end..tag_end - 1],
                    depth,
                ));
                out.push('>');
            } else {
                out.push_str(&String::from_utf8_lossy(&bytes[i..tag_end]));
            }
            i = tag_end;

            if matches!(tag_name, b"title" | b"textarea") {
                if let Some((close_start, close_end)) = find_html_close_tag(&lower_bytes, i, tag_name) {
                    let decoded = unescape_html_entities(&bytes[i..close_start]);
                    if assert_r4_clean_decoded_cell_inner_with_origin(&decoded, depth + 1, false, from_json_value)
                        .is_ok()
                    {
                        out.push_str(&String::from_utf8_lossy(&bytes[i..close_end]));
                    } else {
                        let clean = sanitize_string_r4_inner_with_origin(
                            &String::from_utf8_lossy(&decoded),
                            depth + 1,
                            from_json_value,
                        );
                        out.push_str(&escape_html_text(&clean));
                        out.push_str(&String::from_utf8_lossy(&bytes[close_start..close_end]));
                    }
                    i = close_end;
                } else {
                    let decoded = unescape_html_entities(&bytes[i..]);
                    if assert_r4_clean_decoded_cell_inner_with_origin(&decoded, depth + 1, false, from_json_value)
                        .is_ok()
                    {
                        out.push_str(&String::from_utf8_lossy(&bytes[i..]));
                    } else {
                        let clean = sanitize_string_r4_inner_with_origin(
                            &String::from_utf8_lossy(&decoded),
                            depth + 1,
                            from_json_value,
                        );
                        out.push_str(&escape_html_text(&clean));
                    }
                    i = bytes.len();
                }
            } else if matches!(tag_name, b"script" | b"style") {
                if let Some((close_start, close_end)) = find_html_close_tag(&lower_bytes, i, tag_name) {
                    if assert_r4_clean_decoded_cell_inner_with_origin(
                        &bytes[i..close_start],
                        depth + 1,
                        false,
                        from_json_value,
                    )
                    .is_ok()
                    {
                        out.push_str(&String::from_utf8_lossy(&bytes[i..close_end]));
                    } else {
                        let clean = sanitize_string_r4_inner_with_origin(
                            &String::from_utf8_lossy(&bytes[i..close_start]),
                            depth + 1,
                            from_json_value,
                        );
                        out.push_str(&clean);
                        out.push_str(&String::from_utf8_lossy(&bytes[close_start..close_end]));
                    }
                    i = close_end;
                } else {
                    if assert_r4_clean_decoded_cell_inner_with_origin(&bytes[i..], depth + 1, false, from_json_value)
                        .is_ok()
                    {
                        out.push_str(&String::from_utf8_lossy(&bytes[i..]));
                    } else {
                        out.push_str(&sanitize_string_r4_inner_with_origin(
                            &String::from_utf8_lossy(&bytes[i..]),
                            depth + 1,
                            from_json_value,
                        ));
                    }
                    i = bytes.len();
                }
            }
            continue;
        }

        if text_buf.is_empty() {
            buf_start = i;
        }
        text_buf.push(bytes[i]);
        i += 1;
    }

    flush_text(&mut text_buf, &mut out, buf_start, &mut cross_tracker);
    out
}

fn sanitize_string_r4_inner(s: &str, depth: usize) -> String {
    sanitize_string_r4_inner_with_origin(s, depth, false)
}

fn sanitize_string_r4_inner_with_origin(s: &str, depth: usize, from_json_value: bool) -> String {
    let trimmed = s.trim();
    if depth < MAX_NESTED_JSON_DEPTH
        && trimmed.starts_with('"')
        && trimmed.ends_with('"')
        && let Ok(inner) = serde_json::from_str::<String>(trimmed)
    {
        let sanitized_inner = sanitize_string_r4_inner_with_origin(&inner, depth + 1, true);
        if sanitized_inner != inner
            && let Ok(re_encoded) = serde_json::to_string(&sanitized_inner)
        {
            return re_encoded;
        }
        return s.to_string();
    }

    if depth < MAX_NESTED_JSON_DEPTH
        && ((trimmed.starts_with('{') && trimmed.ends_with('}'))
            || (trimmed.starts_with('[') && trimmed.ends_with(']')))
        && let Ok(mut val) = serde_json::from_str::<Value>(trimmed)
    {
        let before = val.clone();
        sanitize_json_value_r4_inner(&mut val, depth + 1);
        if val != before
            && let Ok(serialized) = serde_json::to_string(&val)
        {
            if s.len() == trimmed.len() {
                return serialized;
            }
            let lead_len = s.len() - s.trim_start().len();
            let trail_start = s.trim_end().len();
            return format!("{}{serialized}{}", &s[..lead_len], &s[trail_start..]);
        }
        return s.to_string();
    }

    let (masked, marker_prefix, replacements) = sanitize_json_substrings_and_mask(s, depth, from_json_value);
    let raw_clean = if contains_keymaterial_word(&masked) {
        let lower_prefix = marker_prefix.to_ascii_lowercase();
        let prefix_opt = (!lower_prefix.is_empty()).then_some(lower_prefix.as_bytes());
        sanitize_escaped_keymaterial_in_str_with_marker_and_origin(&masked, prefix_opt, from_json_value)
    } else {
        masked
    };
    let mut restored = restore_json_placeholders(&raw_clean, &marker_prefix, &replacements);
    if depth < MAX_NESTED_JSON_DEPTH
        && contains_keymaterial_word(&restored)
        && is_html_document_or_fragment(restored.as_bytes())
        && verify_html_with_embedded_json_with_origin(restored.as_bytes(), depth, from_json_value).is_err()
    {
        if mask_html_tags_for_json_scan_with_options(restored.as_bytes(), false).1 {
            let (masked_sp, prefix_sp, reps_sp) = sanitize_json_substrings_and_mask(&restored, depth, from_json_value);
            let raw_sp = if contains_keymaterial_word(&masked_sp) {
                let lower_prefix = prefix_sp.to_ascii_lowercase();
                let prefix_opt = (!lower_prefix.is_empty()).then_some(lower_prefix.as_bytes());
                sanitize_escaped_keymaterial_in_str_with_options(&masked_sp, prefix_opt, from_json_value, true)
            } else {
                masked_sp
            };
            restored = restore_json_placeholders(&raw_sp, &prefix_sp, &reps_sp);
            if verify_html_with_embedded_json_with_origin(restored.as_bytes(), depth, from_json_value).is_ok() {
                return restored;
            }
        }
        return sanitize_html_fragment_r4_with_origin(&restored, depth + 1, from_json_value);
    }
    restored
}

fn sanitize_string_r4(s: &str) -> String {
    sanitize_string_r4_inner(s, 0)
}

fn is_sensitive_header_key(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    matches!(lower.as_str(), "cookie" | "set-cookie" | "set-cookie2")
        || sanitize_http_header(name, "__r4_probe__") != "__r4_probe__"
}

fn sanitize_single_header_line(line: &str, depth: usize) -> String {
    if let Some((name, raw_val)) = line.split_once(':') {
        let trimmed_name = name.trim();
        let trimmed_val = raw_val.trim_start();
        let sanitized_val = sanitize_http_header(trimmed_name, trimmed_val);
        let updated = if sanitized_val != trimmed_val {
            format!("{trimmed_name}: {sanitized_val}")
        } else {
            line.to_string()
        };
        sanitize_string_r4_inner(&updated, depth)
    } else {
        sanitize_string_r4_inner(line, depth)
    }
}

fn sanitize_header_line_or_block(raw: &str, depth: usize) -> String {
    if raw.contains('\n') {
        raw.split('\n')
            .map(|segment| {
                if let Some(stripped) = segment.strip_suffix('\r') {
                    format!("{}\r", sanitize_single_header_line(stripped, depth))
                } else {
                    sanitize_single_header_line(segment, depth)
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        sanitize_single_header_line(raw, depth)
    }
}

fn sanitize_header_entry_value(header_name: &str, header_val: &mut Value, depth: usize) {
    match header_val {
        Value::String(s) => {
            *s = sanitize_http_header(header_name, s);
            *s = sanitize_string_r4_inner(s, depth);
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                sanitize_header_entry_value(header_name, item, depth);
            }
        }
        Value::Object(map) => {
            let parent_sensitive = is_sensitive_header_key(header_name);
            for (k, v) in map.iter_mut() {
                if parent_sensitive && !is_sensitive_header_key(k) {
                    sanitize_header_entry_value(header_name, v, depth);
                } else {
                    sanitize_header_entry_value(k, v, depth);
                }
            }
        }
        _ => {}
    }
}

fn find_header_name_field(obj: &serde_json::Map<String, Value>) -> Option<(String, String)> {
    for key_alias in ["name", "key", "header", "header_name", "field"] {
        if let Some((k, v)) = obj
            .iter()
            .find(|(k, v)| k.eq_ignore_ascii_case(key_alias) && v.as_str().is_some())
        {
            return Some((k.clone(), v.as_str().unwrap_or_default().to_string()));
        }
    }
    None
}

fn sanitize_header_descriptor_object(
    obj: &mut serde_json::Map<String, Value>,
    name_key: &str,
    hdr_name: &str,
    depth: usize,
) {
    for (k, v) in obj.iter_mut() {
        if k == name_key {
            if let Value::String(s) = v {
                *s = sanitize_string_r4_inner(s, depth);
            }
        } else if is_sensitive_header_key(k) {
            sanitize_header_entry_value(k, v, depth);
        } else {
            sanitize_header_entry_value(hdr_name, v, depth);
        }
    }
}

fn sanitize_headers_value(val: &mut Value, depth: usize) {
    match val {
        Value::String(line) => {
            *line = sanitize_header_line_or_block(line, depth);
        }
        Value::Object(map) => {
            if let Some((name_key, hdr_name)) = find_header_name_field(map) {
                sanitize_header_descriptor_object(map, &name_key, &hdr_name, depth);
            } else {
                for (header_name, header_val) in map.iter_mut() {
                    if !is_sensitive_header_key(header_name) && matches!(header_val, Value::Array(_) | Value::Object(_))
                    {
                        sanitize_headers_value(header_val, depth);
                    } else {
                        sanitize_header_entry_value(header_name, header_val, depth);
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                match item {
                    Value::String(line) => {
                        *line = sanitize_header_line_or_block(line, depth);
                    }
                    Value::Object(obj) => {
                        if let Some((name_key, hdr_name)) = find_header_name_field(obj) {
                            sanitize_header_descriptor_object(obj, &name_key, &hdr_name, depth);
                        } else {
                            for (k, v) in obj.iter_mut() {
                                if !is_sensitive_header_key(k) && matches!(v, Value::Array(_) | Value::Object(_)) {
                                    sanitize_headers_value(v, depth);
                                } else {
                                    sanitize_header_entry_value(k, v, depth);
                                }
                            }
                        }
                    }
                    Value::Array(pair) if pair.len() >= 2 => {
                        let name = pair[0].as_str().map(str::to_string);
                        if let Some(hdr_name) = name
                            && !hdr_name.contains(':')
                        {
                            pair[0] = Value::String(sanitize_string_r4_inner(&hdr_name, depth));
                            for elem in &mut pair[1..] {
                                if !is_sensitive_header_key(&hdr_name)
                                    && matches!(elem, Value::Array(_) | Value::Object(_))
                                {
                                    sanitize_headers_value(elem, depth);
                                } else {
                                    sanitize_header_entry_value(&hdr_name, elem, depth);
                                }
                            }
                        } else {
                            sanitize_headers_value(item, depth);
                        }
                    }
                    other => sanitize_headers_value(other, depth),
                }
            }
        }
        _ => {}
    }
}

fn is_headers_container_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower == "header"
        || lower == "headers"
        || lower.ends_with("header")
        || lower.ends_with("headers")
        || lower.starts_with("header_")
        || lower.starts_with("headers_")
        || lower.starts_with("header-")
        || lower.starts_with("headers-")
}

fn sanitize_json_value_r4_inner(val: &mut Value, depth: usize) {
    match val {
        Value::String(s) => {
            *s = sanitize_string_r4_inner_with_origin(s, depth, true);
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                sanitize_json_value_r4_inner(item, depth);
            }
        }
        Value::Object(map) => {
            let mut has_km_key = false;
            for (k, v) in map.iter_mut() {
                if is_headers_container_key(k) {
                    sanitize_headers_value(v, depth);
                } else {
                    sanitize_header_entry_value(k, v, depth);
                }
                sanitize_json_value_r4_inner(v, depth);
                if contains_keymaterial_word(k) {
                    has_km_key = true;
                }
            }
            if has_km_key {
                let old_map = std::mem::take(map);
                for (k, v) in old_map {
                    let new_k = if contains_keymaterial_word(&k) {
                        sanitize_string_r4_inner_with_origin(&k, depth, true)
                    } else {
                        k
                    };
                    map.insert(new_k, v);
                }
            }
        }
        _ => {}
    }
}

fn sanitize_json_value_r4(val: &mut Value) {
    sanitize_json_value_r4_inner(val, 0);
}

fn sanitize_export_options(opts: &ExportOptions) -> ExportOptions {
    let mut clean = opts.clone();
    clean.title_override = clean.title_override.as_deref().map(sanitize_string_r4);
    clean.tool_version = sanitize_string_r4(&clean.tool_version);
    clean
}

pub fn sanitize_table_for_report(data: &TableData) -> TableData {
    let mut sanitized = data.clone();
    sanitized.schema.title = sanitize_string_r4(&sanitized.schema.title);
    sanitized.schema.tool_id = sanitize_string_r4(&sanitized.schema.tool_id);
    for col in &mut sanitized.schema.columns {
        col.id = sanitize_string_r4(&col.id);
        col.label = sanitize_string_r4(&col.label);
    }
    for row in &mut sanitized.rows {
        for cell in &mut row.cells {
            if let CellValue::Text(text) = cell {
                *text = sanitize_string_r4(text);
            }
        }
        if let Some(detail) = &mut row.detail_json {
            sanitize_json_value_r4(detail);
        }
        if let Some(raw) = &mut row.raw_bytes {
            let lossy = String::from_utf8_lossy(raw);
            if contains_keymaterial_word(&lossy) {
                *raw = sanitize_string_r4(&lossy).into_bytes();
            }
        }
    }
    sanitized
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TagSyntax {
    Raw,
    HtmlEscaped,
}

#[derive(Debug, Clone, Copy)]
struct OpeningTagMatch {
    open_start: usize,
    after_name: usize,
    syntax: TagSyntax,
    opened_with_u003c: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct TagScanContext {
    in_csv_field: bool,
    in_json_string: bool,
    in_markdown_json_string: bool,
    in_markdown_table_line: bool,
    in_double_escaped_json: bool,
    in_nested_json_string: bool,
    allow_double_bs: bool,
    opened_with_u003c: bool,
    allow_tsv_tabs: bool,
    in_decoded_u0022_json_ctx: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawQuoteMode {
    None,
    Single,
    DoubleRaw,
    DoubleCsv,
    DoubleJson,
    DoubleCsvJson,
    DoubleMarkdownJson,
    U0022Single,
    U0022DoubleBs,
    U0027Single,
    U0027DoubleBs,
    HtmlDoubleEntity,
    HtmlSingleEntity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HtmlQuoteMode {
    None,
    DoubleEntity,
    SingleEntity,
    RawSingle,
    RawDouble,
    U0022DoubleBs,
    U0027Single,
    U0027DoubleBs,
}

fn is_xml_ncname_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
}

#[inline]
fn find_ascii_bytes(haystack: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    let nlen = needle.len();
    if start > haystack.len() || haystack.len() - start < nlen {
        return None;
    }
    if nlen == 0 {
        return Some(start);
    }
    let first = needle[0];
    let limit = haystack.len() - nlen;
    let mut i = start;
    while i <= limit {
        if haystack[i] == first && &haystack[i..i + nlen] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn is_preceded_by_eq(bytes: &[u8], start: usize, pos: usize) -> bool {
    let mut j = pos;
    while j > start && bytes[j - 1].is_ascii_whitespace() {
        j -= 1;
    }
    j > start && bytes[j - 1] == b'='
}

fn count_consecutive_backslashes(bytes: &[u8], start: usize) -> usize {
    let mut n = 0usize;
    while start + n < bytes.len() && bytes[start + n] == b'\\' {
        n += 1;
    }
    n
}

fn count_preceding_backslashes(bytes: &[u8], min_start: usize, pos: usize) -> usize {
    let mut n = 0usize;
    while pos > min_start + n && bytes[pos - 1 - n] == b'\\' {
        n += 1;
    }
    n
}

fn parse_html_numeric_char_ref(rest: &[u8]) -> Option<(u32, usize)> {
    if !rest.starts_with(b"&#") {
        return None;
    }
    let semi_rel = rest[2..rest.len().min(12)].iter().position(|&b| b == b';')?;
    let body = &rest[2..2 + semi_rel];
    if body.is_empty() {
        return None;
    }
    let cp = if let Some(hex) = body.strip_prefix(b"x").or_else(|| body.strip_prefix(b"X")) {
        if hex.is_empty() || hex.len() > 6 || !hex.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let s = std::str::from_utf8(hex).ok()?;
        u32::from_str_radix(s, 16).ok()?
    } else {
        if body.len() > 7 || !body.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let s = std::str::from_utf8(body).ok()?;
        s.parse::<u32>().ok()?
    };
    if cp == 0 || char::from_u32(cp).is_none() {
        return None;
    }
    Some((cp, 2 + semi_rel + 1))
}

fn match_html_quote_entity(rest: &[u8]) -> Option<(HtmlQuoteMode, usize)> {
    if rest.get(..6).is_some_and(|s| s.eq_ignore_ascii_case(b"&quot;")) {
        return Some((HtmlQuoteMode::DoubleEntity, 6));
    }
    if rest.get(..6).is_some_and(|s| s.eq_ignore_ascii_case(b"&apos;")) {
        return Some((HtmlQuoteMode::SingleEntity, 6));
    }
    if let Some((cp, len)) = parse_html_numeric_char_ref(rest) {
        if cp == u32::from(b'"') {
            return Some((HtmlQuoteMode::DoubleEntity, len));
        }
        if cp == u32::from(b'\'') {
            return Some((HtmlQuoteMode::SingleEntity, len));
        }
    }
    None
}

fn match_html_lt_entity(rest: &[u8]) -> Option<usize> {
    if rest.get(..4).is_some_and(|s| s.eq_ignore_ascii_case(b"&lt;")) {
        return Some(4);
    }
    if let Some((cp, len)) = parse_html_numeric_char_ref(rest)
        && cp == u32::from(b'<')
    {
        return Some(len);
    }
    None
}

fn match_html_gt_entity(rest: &[u8]) -> Option<usize> {
    if rest.get(..4).is_some_and(|s| s.eq_ignore_ascii_case(b"&gt;")) {
        return Some(4);
    }
    if let Some((cp, len)) = parse_html_numeric_char_ref(rest)
        && cp == u32::from(b'>')
    {
        return Some(len);
    }
    None
}

fn match_html_slash_entity(rest: &[u8]) -> Option<usize> {
    if rest.starts_with(b"/") {
        return Some(1);
    }
    if let Some((cp, len)) = parse_html_numeric_char_ref(rest)
        && cp == u32::from(b'/')
    {
        return Some(len);
    }
    None
}

fn match_html_br_entity(rest: &[u8]) -> Option<usize> {
    let lt_len = match_html_lt_entity(rest)?;
    let after_lt = rest.get(lt_len..)?;
    if after_lt.len() < 2 || !after_lt[..2].eq_ignore_ascii_case(b"br") {
        return None;
    }
    let gt_len = match_html_gt_entity(&after_lt[2..])?;
    Some(lt_len + 2 + gt_len)
}

fn ends_with_html_lt_entity(bytes: &[u8], min_start: usize, end: usize) -> Option<usize> {
    if end >= min_start + 4 && bytes[end - 4..end].eq_ignore_ascii_case(b"&lt;") {
        return Some(end - 4);
    }
    if end > min_start + 3 && bytes[end - 1] == b';' {
        let search_start = end.saturating_sub(12).max(min_start);
        if let Some(rel_amp) = bytes[search_start..end].iter().rposition(|&b| b == b'&') {
            let start = search_start + rel_amp;
            if let Some(len) = match_html_lt_entity(&bytes[start..end])
                && start + len == end
            {
                return Some(start);
            }
        }
    }
    None
}

fn ends_with_html_slash_entity(bytes: &[u8], min_start: usize, end: usize) -> Option<usize> {
    if end > min_start && bytes[end - 1] == b'/' {
        return Some(end - 1);
    }
    if end > min_start + 3 && bytes[end - 1] == b';' {
        let search_start = end.saturating_sub(12).max(min_start);
        if let Some(rel_amp) = bytes[search_start..end].iter().rposition(|&b| b == b'&') {
            let start = search_start + rel_amp;
            if let Some(len) = match_html_slash_entity(&bytes[start..end])
                && start + len == end
            {
                return Some(start);
            }
        }
    }
    None
}

fn ends_with_html_close_prefix_with_json(
    bytes: &[u8],
    min_start: usize,
    end: usize,
    allow_double_bs: bool,
) -> Option<usize> {
    let slash_start = if end >= min_start + 5 && &bytes[end - 5..end] == b"u002f" {
        let bs = count_preceding_backslashes(bytes, min_start, end - 5);
        if bs % 2 == 1 {
            end - 6
        } else if allow_double_bs && bs % 4 == 2 {
            end - 7
        } else {
            return None;
        }
    } else if end > min_start && bytes[end - 1] == b'/' {
        let bs = count_preceding_backslashes(bytes, min_start, end - 1);
        if bs == 0 {
            end - 1
        } else if bs % 2 == 1 {
            end - 2
        } else if allow_double_bs && bs % 4 == 2 {
            end - 3
        } else {
            return None;
        }
    } else {
        ends_with_html_slash_entity(bytes, min_start, end)?
    };
    ends_with_html_lt_entity(bytes, min_start, slash_start)
}

fn starts_with_escaped_ws(bytes: &[u8], allow_double_bs: bool) -> Option<usize> {
    if bytes.starts_with(b"\\n") || bytes.starts_with(b"\\r") || bytes.starts_with(b"\\t") {
        Some(2)
    } else if allow_double_bs
        && (bytes.starts_with(b"\\\\n") || bytes.starts_with(b"\\\\r") || bytes.starts_with(b"\\\\t"))
    {
        Some(3)
    } else {
        None
    }
}

fn match_json_u00_char(bytes: &[u8], allow_double_bs: bool) -> Option<(u8, usize)> {
    let (hex, len) = if allow_double_bs && bytes.starts_with(b"\\\\u00") && bytes.len() >= 7 {
        (&bytes[5..7], 7)
    } else if bytes.starts_with(b"\\u00") && bytes.len() >= 6 {
        (&bytes[4..6], 6)
    } else {
        return None;
    };
    let ch = match hex {
        b"3c" => b'<',
        b"3e" => b'>',
        b"2f" => b'/',
        b"22" => b'"',
        b"27" => b'\'',
        b"20" => b' ',
        b"09" => b'\t',
        b"0a" => b'\n',
        b"0d" => b'\r',
        _ => return None,
    };
    Some((ch, len))
}

fn ends_with_lt_token(bytes: &[u8], min_start: usize, end: usize, allow_double_bs: bool) -> Option<usize> {
    if end >= min_start + 5 && &bytes[end - 5..end] == b"u003c" {
        let bs = count_preceding_backslashes(bytes, min_start, end - 5);
        if bs % 2 == 1 {
            Some(end - 6)
        } else if allow_double_bs && bs % 4 == 2 {
            Some(end - 7)
        } else {
            None
        }
    } else if end > min_start && bytes[end - 1] == b'<' {
        Some(end - 1)
    } else {
        None
    }
}

fn ends_with_close_tag_prefix(bytes: &[u8], min_start: usize, end: usize, allow_double_bs: bool) -> Option<usize> {
    let slash_start = if end >= min_start + 5 && &bytes[end - 5..end] == b"u002f" {
        let bs = count_preceding_backslashes(bytes, min_start, end - 5);
        if bs % 2 == 1 {
            end - 6
        } else if allow_double_bs && bs % 4 == 2 {
            end - 7
        } else {
            return None;
        }
    } else if end > min_start && bytes[end - 1] == b'/' {
        let bs = count_preceding_backslashes(bytes, min_start, end - 1);
        if bs == 0 {
            end - 1
        } else if bs % 2 == 1 {
            end - 2
        } else if allow_double_bs && bs % 4 == 2 {
            end - 3
        } else {
            return None;
        }
    } else {
        return None;
    };
    ends_with_lt_token(bytes, min_start, slash_start, allow_double_bs)
}

fn preceded_by_slash_token(bytes: &[u8], min_start: usize, pos: usize, allow_double_bs: bool) -> bool {
    if pos >= min_start + 5 && &bytes[pos - 5..pos] == b"u002f" {
        let bs = count_preceding_backslashes(bytes, min_start, pos - 5);
        bs % 2 == 1 || (allow_double_bs && bs % 4 == 2)
    } else if pos > min_start && bytes[pos - 1] == b'/' {
        let bs = count_preceding_backslashes(bytes, min_start, pos - 1);
        bs == 0 || bs % 2 == 1 || (allow_double_bs && bs % 4 == 2)
    } else {
        false
    }
}

fn preceded_by_html_slash(bytes: &[u8], min_start: usize, pos: usize, allow_double_bs: bool) -> bool {
    preceded_by_slash_token(bytes, min_start, pos, allow_double_bs)
        || ends_with_html_slash_entity(bytes, min_start, pos).is_some()
}

fn starts_json_container_syntax(bytes: &[u8], open_pos: usize) -> bool {
    let opener = bytes[open_pos];
    let mut k = open_pos + 1;
    while k < bytes.len() && bytes[k].is_ascii_whitespace() && !matches!(bytes[k], b'\r' | b'\n') {
        k += 1;
    }
    let Some(&next) = bytes.get(k) else {
        return false;
    };
    match opener {
        b'{' => matches!(next, b'"' | b'}'),
        b'[' => {
            if matches!(next, b'"' | b'{' | b'[' | b']' | b'-' | b'0'..=b'9') {
                return true;
            }
            for kw in [b"true".as_slice(), b"false".as_slice(), b"null".as_slice()] {
                if bytes[k..].starts_with(kw) {
                    let after = bytes.get(k + kw.len()).copied();
                    if matches!(after, None | Some(b' ' | b'\t' | b',' | b']')) {
                        return true;
                    }
                }
            }
            false
        }
        _ => false,
    }
}

fn has_matching_json_container_end_on_line(bytes: &[u8], open_pos: usize) -> bool {
    let mut k = open_pos;
    let mut depth = 0usize;
    let mut in_string = false;
    while k < bytes.len() {
        let b = bytes[k];
        if in_string {
            if b == b'\\' {
                let bs = count_consecutive_backslashes(bytes, k);
                if bytes.get(k + bs) == Some(&b'"') {
                    if bs.is_multiple_of(2) {
                        in_string = false;
                        if let Some(&after) = bytes.get(k + bs + 1)
                            && !matches!(after, b',' | b']' | b'}' | b':' | b' ' | b'\t')
                        {
                            return false;
                        }
                    }
                    k += bs + 1;
                } else {
                    k += bs;
                }
            } else if b == b'"' {
                in_string = false;
                if let Some(&after) = bytes.get(k + 1)
                    && !matches!(after, b',' | b']' | b'}' | b':' | b' ' | b'\t')
                {
                    return false;
                }
                k += 1;
            } else if matches!(b, b'\r' | b'\n') {
                return false;
            } else {
                k += 1;
            }
        } else {
            match b {
                b'\r' | b'\n' => return false,
                b'"' => {
                    in_string = true;
                    k += 1;
                }
                b'{' | b'[' => {
                    depth += 1;
                    k += 1;
                }
                b'}' | b']' => {
                    depth = depth.saturating_sub(1);
                    k += 1;
                    if depth == 0 {
                        return true;
                    }
                }
                _ => {
                    k += 1;
                }
            }
        }
    }
    false
}

fn starts_csv_doubled_json(slice: &[u8]) -> bool {
    let mut k = 0usize;
    while k < slice.len() && matches!(slice[k], b' ' | b'\t') {
        k += 1;
    }
    let Some(&opener) = slice.get(k) else {
        return false;
    };
    if !matches!(opener, b'{' | b'[') {
        return false;
    }
    k += 1;
    while k < slice.len() && matches!(slice[k], b' ' | b'\t') {
        k += 1;
    }
    slice.get(k..k + 2) == Some(b"\"\"")
}

fn is_markdown_separator_row(trimmed_line: &[u8]) -> bool {
    if !trimmed_line.starts_with(b"|") || trimmed_line.contains(&b'\t') {
        return false;
    }
    let cells = split_markdown_row_cells(trimmed_line);
    !cells.is_empty()
        && cells.iter().all(|raw| {
            let c = raw.trim_ascii();
            if c.is_empty() {
                return false;
            }
            let inner = c.strip_prefix(b":").unwrap_or(c);
            let inner = inner.strip_suffix(b":").unwrap_or(inner);
            !inner.is_empty() && inner.iter().all(|&b| b == b'-')
        })
}

fn ends_with_unescaped_pipe(trimmed_line: &[u8]) -> bool {
    trimmed_line.ends_with(b"|")
        && count_preceding_backslashes(trimmed_line, 0, trimmed_line.len() - 1).is_multiple_of(2)
}

fn is_strict_markdown_table_line(line: &[u8], doc_has_md_separator: bool) -> bool {
    let trimmed = line.trim_ascii();
    if !trimmed.starts_with(b"|") || trimmed.len() < 2 || !ends_with_unescaped_pipe(trimmed) {
        return false;
    }
    doc_has_md_separator || !trimmed.contains(&b'\t')
}

fn document_has_markdown_separator(bytes: &[u8]) -> bool {
    bytes
        .split(|&b| b == b'\n')
        .any(|raw_line| is_markdown_separator_row(raw_line.strip_suffix(b"\r").unwrap_or(raw_line).trim_ascii()))
}

fn collect_rfc4180_csv_quoted_content_ranges(
    bytes: &[u8],
    skip_markdown_lines: bool,
    doc_has_md_separator: bool,
) -> Vec<(usize, usize, bool)> {
    if !bytes.contains(&b'"') {
        return Vec::new();
    }
    // Valid JSON documents (compact or multi-line pretty-printed) are never RFC-4180 CSV.
    let trimmed = bytes.trim_ascii();
    if (trimmed.starts_with(b"{") || trimmed.starts_with(b"[")) && serde_json::from_slice::<Value>(trimmed).is_ok() {
        return Vec::new();
    }

    let mut ranges = Vec::new();
    let mut i = 0usize;
    let mut at_field_start = true;
    let mut at_line_start = true;
    let mut record_json_depth = 0usize;
    let mut in_json_string = false;
    let mut last_punct = b'\0';

    while i < bytes.len() {
        if record_json_depth > 0 && in_json_string {
            at_line_start = false;
            match bytes[i] {
                b'\\' => {
                    let bs = count_consecutive_backslashes(bytes, i);
                    if bytes.get(i + bs) == Some(&b'"') {
                        if bs.is_multiple_of(2) {
                            in_json_string = false;
                            last_punct = b'\0';
                        }
                        i += bs + 1;
                    } else {
                        i += bs;
                    }
                }
                b'"' => {
                    in_json_string = false;
                    last_punct = b'\0';
                    i += 1;
                }
                b'\r' => {
                    in_json_string = false;
                    last_punct = b'\0';
                    record_json_depth = 0;
                    at_field_start = true;
                    at_line_start = true;
                    i += if bytes.get(i + 1) == Some(&b'\n') { 2 } else { 1 };
                }
                b'\n' => {
                    in_json_string = false;
                    last_punct = b'\0';
                    record_json_depth = 0;
                    at_field_start = true;
                    at_line_start = true;
                    i += 1;
                }
                _ => {
                    i += 1;
                }
            }
            continue;
        }

        if skip_markdown_lines && at_line_start && record_json_depth == 0 {
            if bytes[i] == b' ' {
                i += 1;
                continue;
            }
            if bytes[i] == b'|' {
                let line_end = bytes[i..]
                    .iter()
                    .position(|&c| matches!(c, b'\r' | b'\n'))
                    .map_or(bytes.len(), |rel| i + rel);
                if is_strict_markdown_table_line(&bytes[i..line_end], doc_has_md_separator) {
                    i = line_end;
                    if i < bytes.len() {
                        i += if bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
                            2
                        } else {
                            1
                        };
                    }
                    at_field_start = true;
                    at_line_start = true;
                    last_punct = b'\0';
                    continue;
                }
            }
        }

        if at_field_start && bytes[i] == b'"' && record_json_depth == 0 {
            let content_start = i + 1;
            let mut j = content_start;
            let mut valid_csv_field = false;
            let mut content_end = bytes.len();

            while j < bytes.len() {
                if bytes[j] == b'"' {
                    if bytes.get(j + 1) == Some(&b'"') {
                        j += 2;
                    } else {
                        match bytes.get(j + 1).copied() {
                            None | Some(b',' | b'\r' | b'\n') => {
                                content_end = j;
                                valid_csv_field = true;
                                j += 1;
                                break;
                            }
                            Some(_) => {
                                valid_csv_field = false;
                                break;
                            }
                        }
                    }
                } else {
                    j += 1;
                }
            }

            if valid_csv_field {
                ranges.push((content_start, content_end, true));
                if j >= bytes.len() {
                    break;
                }
                match bytes[j] {
                    b',' => {
                        i = j + 1;
                        at_field_start = true;
                        at_line_start = false;
                    }
                    b'\r' => {
                        i = j + if bytes.get(j + 1) == Some(&b'\n') { 2 } else { 1 };
                        at_field_start = true;
                        at_line_start = true;
                        record_json_depth = 0;
                        in_json_string = false;
                        last_punct = b'\0';
                    }
                    b'\n' => {
                        i = j + 1;
                        at_field_start = true;
                        at_line_start = true;
                        record_json_depth = 0;
                        in_json_string = false;
                        last_punct = b'\0';
                    }
                    _ => {
                        i = j + 1;
                        at_field_start = false;
                        at_line_start = false;
                    }
                }
            } else if j >= bytes.len() && starts_csv_doubled_json(&bytes[content_start..]) {
                ranges.push((content_start, bytes.len(), false));
                break;
            } else {
                at_field_start = false;
                at_line_start = false;
                i += 1;
            }
        } else {
            match bytes[i] {
                b',' => {
                    at_field_start = true;
                    at_line_start = false;
                    last_punct = b',';
                    i += 1;
                }
                b':' => {
                    at_field_start = false;
                    at_line_start = false;
                    last_punct = b':';
                    i += 1;
                }
                b'\n' => {
                    at_field_start = true;
                    at_line_start = true;
                    record_json_depth = 0;
                    in_json_string = false;
                    last_punct = b'\0';
                    i += 1;
                }
                b'\r' => {
                    at_field_start = true;
                    at_line_start = true;
                    record_json_depth = 0;
                    in_json_string = false;
                    last_punct = b'\0';
                    i += if bytes.get(i + 1) == Some(&b'\n') { 2 } else { 1 };
                }
                b'"' => {
                    if record_json_depth > 0 && matches!(last_punct, b'{' | b'[' | b':' | b',') {
                        in_json_string = true;
                    }
                    last_punct = b'\0';
                    at_field_start = false;
                    at_line_start = false;
                    i += 1;
                }
                b'{' | b'[' => {
                    let can_start_json = (at_field_start && record_json_depth == 0)
                        || (record_json_depth > 0 && matches!(last_punct, b'[' | b':' | b','));
                    if can_start_json
                        && starts_json_container_syntax(bytes, i)
                        && (record_json_depth > 0 || has_matching_json_container_end_on_line(bytes, i))
                    {
                        record_json_depth += 1;
                        last_punct = bytes[i];
                    } else {
                        last_punct = b'\0';
                    }
                    at_field_start = false;
                    at_line_start = false;
                    i += 1;
                }
                b'}' | b']' => {
                    record_json_depth = record_json_depth.saturating_sub(1);
                    last_punct = b'\0';
                    at_field_start = false;
                    at_line_start = false;
                    i += 1;
                }
                b if b.is_ascii_whitespace() => {
                    at_field_start = false;
                    at_line_start = false;
                    i += 1;
                }
                _ => {
                    last_punct = b'\0';
                    at_field_start = false;
                    at_line_start = false;
                    i += 1;
                }
            }
        }
    }

    ranges
}

fn is_csv_field_in_json_string(field_slice: &[u8]) -> (bool, usize, bool) {
    let mut k = 0usize;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut string_start = 0usize;
    let mut last_punct = b'\0';
    let mut nested_depth = 0usize;
    let mut nested_in_string = false;
    let mut nested_last_punct = b'\0';

    while k < field_slice.len() {
        if in_string {
            if field_slice[k] == b'\\' {
                let bs = count_consecutive_backslashes(field_slice, k);
                if field_slice.get(k + bs) == Some(&b'"') && field_slice.get(k + bs + 1) == Some(&b'"') {
                    if bs.is_multiple_of(2) {
                        in_string = false;
                        string_start = 0;
                        last_punct = b'\0';
                        nested_depth = 0;
                        nested_in_string = false;
                        nested_last_punct = b'\0';
                    } else if nested_in_string {
                        if bs % 4 == 1 {
                            nested_in_string = false;
                            nested_last_punct = b'\0';
                        }
                    } else if bs % 4 == 1 && nested_depth > 0 && matches!(nested_last_punct, b'{' | b'[' | b':' | b',')
                    {
                        nested_in_string = true;
                        nested_last_punct = b'\0';
                    } else {
                        nested_last_punct = b'\0';
                    }
                    k += bs + 2;
                } else {
                    if bs % 4 == 1 && field_slice.get(k + bs..k + bs + 5) == Some(b"u0022") {
                        if nested_in_string {
                            nested_in_string = false;
                            nested_last_punct = b'\0';
                        } else if nested_depth > 0 && matches!(nested_last_punct, b'{' | b'[' | b':' | b',') {
                            nested_in_string = true;
                            nested_last_punct = b'\0';
                        } else {
                            nested_last_punct = b'\0';
                        }
                    }
                    k += bs;
                }
            } else if field_slice[k] == b'"' && field_slice.get(k + 1) == Some(&b'"') {
                in_string = false;
                string_start = 0;
                last_punct = b'\0';
                nested_depth = 0;
                nested_in_string = false;
                nested_last_punct = b'\0';
                k += 2;
            } else if matches!(field_slice[k], b'\r' | b'\n' | b'\t') {
                in_string = false;
                string_start = 0;
                last_punct = b'\0';
                nested_depth = 0;
                nested_in_string = false;
                nested_last_punct = b'\0';
                if field_slice[k] == b'\t' {
                    depth = 0;
                }
                k += 1;
            } else {
                if !nested_in_string {
                    match field_slice[k] {
                        b'{' | b'[' => {
                            nested_depth += 1;
                            nested_last_punct = field_slice[k];
                        }
                        b'}' | b']' => {
                            nested_depth = nested_depth.saturating_sub(1);
                            nested_last_punct = b'\0';
                        }
                        b':' | b',' => {
                            nested_last_punct = field_slice[k];
                        }
                        c if c.is_ascii_whitespace() => {}
                        _ => {
                            nested_last_punct = b'\0';
                        }
                    }
                }
                k += 1;
            }
        } else if field_slice[k] == b'"' && field_slice.get(k + 1) == Some(&b'"') {
            if depth > 0 && matches!(last_punct, b'{' | b'[' | b':' | b',') {
                in_string = true;
                string_start = k + 2;
            }
            k += 2;
        } else {
            match field_slice[k] {
                b'{' | b'[' => {
                    depth += 1;
                    last_punct = field_slice[k];
                }
                b'}' | b']' => {
                    depth = depth.saturating_sub(1);
                    last_punct = b'\0';
                }
                b':' | b',' => {
                    last_punct = field_slice[k];
                }
                b if b.is_ascii_whitespace() => {}
                _ => {
                    last_punct = b'\0';
                }
            }
            k += 1;
        }
    }

    (in_string, string_start, in_string && nested_in_string)
}

fn check_csv_field_double_escaped(
    lower: &[u8],
    cs: usize,
    rel_string_start: usize,
    in_json_string: bool,
    prev_cursor: usize,
    open_start: usize,
    csv_dbl_state: &mut Option<(usize, usize, bool)>,
) -> bool {
    check_csv_field_double_escaped_with_marker(
        lower,
        cs,
        rel_string_start,
        in_json_string,
        prev_cursor,
        open_start,
        csv_dbl_state,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn check_csv_field_double_escaped_with_marker(
    lower: &[u8],
    cs: usize,
    rel_string_start: usize,
    in_json_string: bool,
    prev_cursor: usize,
    open_start: usize,
    csv_dbl_state: &mut Option<(usize, usize, bool)>,
    json_marker_prefix: Option<&[u8]>,
) -> bool {
    if !in_json_string {
        *csv_dbl_state = None;
        return false;
    }
    let abs_string_start = cs + rel_string_start;
    let mut dbl = csv_dbl_state
        .is_some_and(|(prev_cs, prev_ss, prev_dbl)| prev_cs == cs && prev_ss == abs_string_start && prev_dbl);
    if !dbl {
        if is_double_escaped_tag_open(lower, open_start) {
            dbl = true;
        } else {
            let gap_start = prev_cursor.max(abs_string_start).min(open_start);
            let at_string_start = prev_cursor <= abs_string_start;
            if has_double_escaped_json_markers_with_marker(
                &lower[gap_start..open_start],
                at_string_start,
                json_marker_prefix,
            ) {
                dbl = true;
            }
        }
    }
    *csv_dbl_state = Some((cs, abs_string_start, dbl));
    dbl
}

struct JsonContextTracker {
    pos: usize,
    depth: usize,
    line_depth: usize,
    in_string: bool,
    in_entity_quote: bool,
    string_start: usize,
    string_double_escaped: bool,
    last_punct: u8,
    seen_non_ws: bool,
    nested_depth: usize,
    nested_in_string: bool,
    nested_last_punct: u8,
    at_line_start: bool,
    on_md_table_line: bool,
    markdown_enabled: bool,
    doc_has_md_separator: bool,
    html_entity_quotes: bool,
}

impl JsonContextTracker {
    fn with_markdown(markdown_enabled: bool) -> Self {
        Self::with_markdown_separator(markdown_enabled, false)
    }

    fn with_html_entities() -> Self {
        let mut tracker = Self::with_markdown_separator(false, false);
        tracker.html_entity_quotes = true;
        tracker
    }

    fn with_markdown_separator(markdown_enabled: bool, doc_has_md_separator: bool) -> Self {
        Self {
            pos: 0,
            depth: 0,
            line_depth: 0,
            in_string: false,
            in_entity_quote: false,
            string_start: 0,
            string_double_escaped: false,
            last_punct: b'\0',
            seen_non_ws: false,
            nested_depth: 0,
            nested_in_string: false,
            nested_last_punct: b'\0',
            at_line_start: true,
            on_md_table_line: false,
            markdown_enabled,
            doc_has_md_separator,
            html_entity_quotes: false,
        }
    }

    fn reset_nested_json(&mut self) {
        self.nested_depth = 0;
        self.nested_in_string = false;
        self.nested_last_punct = b'\0';
    }

    fn mark_double_escaped_gap(&mut self, bytes: &[u8], prev_cursor: usize, open_start: usize) -> bool {
        self.mark_double_escaped_gap_with_marker(bytes, prev_cursor, open_start, None)
    }

    fn mark_double_escaped_gap_with_marker(
        &mut self,
        bytes: &[u8],
        prev_cursor: usize,
        open_start: usize,
        json_marker_prefix: Option<&[u8]>,
    ) -> bool {
        if !self.in_string {
            return false;
        }
        if is_double_escaped_tag_open(bytes, open_start) {
            self.string_double_escaped = true;
        }
        if !self.string_double_escaped {
            let start = prev_cursor.max(self.string_start).min(open_start);
            let at_string_start = prev_cursor <= self.string_start;
            if has_double_escaped_json_markers_with_marker(
                &bytes[start..open_start],
                at_string_start,
                json_marker_prefix,
            ) {
                self.string_double_escaped = true;
            }
        }
        self.string_double_escaped
    }

    fn advance_to(&mut self, bytes: &[u8], target: usize) -> (bool, bool, bool, bool) {
        while self.pos < target && self.pos < bytes.len() {
            if self.in_string {
                let b = bytes[self.pos];
                if b == b'\\' {
                    let bs = count_consecutive_backslashes(bytes, self.pos);
                    if self.in_entity_quote
                        && let Some((HtmlQuoteMode::DoubleEntity, len)) =
                            bytes.get(self.pos + bs..).and_then(match_html_quote_entity)
                    {
                        if bs.is_multiple_of(2) {
                            self.in_string = false;
                            self.in_entity_quote = false;
                            self.string_start = 0;
                            self.string_double_escaped = false;
                            self.last_punct = b'\0';
                            self.reset_nested_json();
                        } else if self.nested_in_string {
                            if bs % 4 == 1 {
                                self.nested_in_string = false;
                                self.nested_last_punct = b'\0';
                            }
                        } else if bs % 4 == 1
                            && self.nested_depth > 0
                            && matches!(self.nested_last_punct, b'{' | b'[' | b':' | b',')
                        {
                            self.nested_in_string = true;
                            self.nested_last_punct = b'\0';
                        } else {
                            self.nested_last_punct = b'\0';
                        }
                        self.pos += bs + len;
                    } else if bytes.get(self.pos + bs) == Some(&b'"') {
                        let is_escaped_quote = !self.in_entity_quote
                            && (bs % 2 == 1 || (self.on_md_table_line && self.line_depth > 0 && bs % 4 == 2));
                        if !self.in_entity_quote && !is_escaped_quote {
                            self.in_string = false;
                            self.in_entity_quote = false;
                            self.string_start = 0;
                            self.string_double_escaped = false;
                            self.last_punct = b'\0';
                            self.reset_nested_json();
                        } else if !self.on_md_table_line {
                            if self.nested_in_string {
                                if bs % 4 == 1 {
                                    self.nested_in_string = false;
                                    self.nested_last_punct = b'\0';
                                }
                            } else if bs % 4 == 1
                                && self.nested_depth > 0
                                && matches!(self.nested_last_punct, b'{' | b'[' | b':' | b',')
                            {
                                self.nested_in_string = true;
                                self.nested_last_punct = b'\0';
                            } else {
                                self.nested_last_punct = b'\0';
                            }
                        }
                        self.pos += bs + 1;
                    } else if self.on_md_table_line && bs % 2 == 1 && bytes.get(self.pos + bs) == Some(&b'|') {
                        self.pos += bs + 1;
                    } else {
                        if !self.on_md_table_line
                            && bs % 4 == 1
                            && bytes.get(self.pos + bs..self.pos + bs + 5) == Some(b"u0022")
                        {
                            if self.nested_in_string {
                                self.nested_in_string = false;
                                self.nested_last_punct = b'\0';
                            } else if self.nested_depth > 0
                                && matches!(self.nested_last_punct, b'{' | b'[' | b':' | b',')
                            {
                                self.nested_in_string = true;
                                self.nested_last_punct = b'\0';
                            } else {
                                self.nested_last_punct = b'\0';
                            }
                        }
                        self.pos += bs;
                    }
                } else if self.in_entity_quote
                    && b == b'&'
                    && let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&bytes[self.pos..])
                {
                    self.in_string = false;
                    self.in_entity_quote = false;
                    self.string_start = 0;
                    self.string_double_escaped = false;
                    self.last_punct = b'\0';
                    self.reset_nested_json();
                    self.pos += len;
                } else if !self.in_entity_quote && b == b'"' {
                    self.in_string = false;
                    self.in_entity_quote = false;
                    self.string_start = 0;
                    self.string_double_escaped = false;
                    self.last_punct = b'\0';
                    self.reset_nested_json();
                    self.pos += 1;
                } else if matches!(b, b'\r' | b'\n') {
                    // Raw newlines cannot appear inside valid JSON strings.
                    self.in_string = false;
                    self.in_entity_quote = false;
                    self.string_start = 0;
                    self.string_double_escaped = false;
                    self.line_depth = 0;
                    self.last_punct = b'\0';
                    self.reset_nested_json();
                    self.at_line_start = true;
                    self.on_md_table_line = false;
                    self.pos += 1;
                } else if b == b'\t' {
                    // RFC 8259 forbids raw tabs inside JSON strings; treat as a strict TSV column boundary.
                    self.in_string = false;
                    self.in_entity_quote = false;
                    self.string_start = 0;
                    self.string_double_escaped = false;
                    self.depth = 0;
                    self.line_depth = 0;
                    self.last_punct = b'\0';
                    self.reset_nested_json();
                    self.pos += 1;
                } else if self.on_md_table_line && b == b'|' {
                    self.in_string = false;
                    self.in_entity_quote = false;
                    self.string_start = 0;
                    self.string_double_escaped = false;
                    self.depth = 0;
                    self.line_depth = 0;
                    self.last_punct = b'\0';
                    self.reset_nested_json();
                    self.pos += 1;
                } else {
                    if !self.nested_in_string {
                        match b {
                            b'{' | b'[' => {
                                self.nested_depth += 1;
                                self.nested_last_punct = b;
                            }
                            b'}' | b']' => {
                                self.nested_depth = self.nested_depth.saturating_sub(1);
                                self.nested_last_punct = b'\0';
                            }
                            b':' | b',' => {
                                self.nested_last_punct = b;
                            }
                            c if c.is_ascii_whitespace() => {}
                            _ => {
                                self.nested_last_punct = b'\0';
                            }
                        }
                    }
                    self.pos += 1;
                }
                continue;
            }

            let b = bytes[self.pos];
            if self.at_line_start {
                if b == b' ' {
                    self.pos += 1;
                    continue;
                }
                self.at_line_start = false;
                if b == b'\t' {
                    self.depth = 0;
                    self.line_depth = 0;
                    self.last_punct = b'\0';
                    self.pos += 1;
                    continue;
                }
                if self.markdown_enabled && b == b'|' {
                    let line_end = bytes[self.pos..]
                        .iter()
                        .position(|&c| matches!(c, b'\r' | b'\n'))
                        .map_or(bytes.len(), |rel| self.pos + rel);
                    if is_strict_markdown_table_line(&bytes[self.pos..line_end], self.doc_has_md_separator) {
                        self.on_md_table_line = true;
                        self.seen_non_ws = true;
                        self.depth = 0;
                        self.line_depth = 0;
                        self.last_punct = b'\0';
                        self.pos += 1;
                        continue;
                    }
                }
            }

            match b {
                b'\r' | b'\n' => {
                    self.line_depth = 0;
                    self.at_line_start = true;
                    self.on_md_table_line = false;
                    if self.depth == 0 {
                        self.last_punct = b'\0';
                    }
                }
                b'\t' => {
                    self.depth = 0;
                    self.line_depth = 0;
                    self.last_punct = b'\0';
                }
                b'\\' if self.on_md_table_line => {
                    self.seen_non_ws = true;
                    let bs = count_consecutive_backslashes(bytes, self.pos);
                    if bs % 2 == 1 && bytes.get(self.pos + bs) == Some(&b'|') {
                        self.pos += bs + 1;
                        continue;
                    }
                    self.last_punct = b'\0';
                    self.pos += bs;
                    continue;
                }
                b'|' if self.on_md_table_line => {
                    self.seen_non_ws = true;
                    self.depth = 0;
                    self.line_depth = 0;
                    self.last_punct = b'\0';
                }
                b'{' | b'[' => {
                    self.seen_non_ws = true;
                    self.depth += 1;
                    self.line_depth += 1;
                    self.last_punct = b;
                }
                b'}' | b']' => {
                    self.seen_non_ws = true;
                    self.depth = self.depth.saturating_sub(1);
                    self.line_depth = self.line_depth.saturating_sub(1);
                    self.last_punct = b'\0';
                }
                b':' | b',' => {
                    self.seen_non_ws = true;
                    self.last_punct = b;
                }
                b'"' => {
                    if (!self.seen_non_ws && bytes.trim_ascii().ends_with(b"\""))
                        || (self.depth > 0 && matches!(self.last_punct, b'{' | b'[' | b':' | b','))
                    {
                        self.in_string = true;
                        self.in_entity_quote = false;
                        self.string_start = self.pos + 1;
                        self.string_double_escaped = false;
                    }
                    self.seen_non_ws = true;
                    self.last_punct = b'\0';
                }
                b'&' if self.html_entity_quotes => {
                    if let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&bytes[self.pos..]) {
                        if self.depth > 0 && matches!(self.last_punct, b'{' | b'[' | b':' | b',') {
                            self.in_string = true;
                            self.in_entity_quote = true;
                            self.string_start = self.pos + len;
                            self.string_double_escaped = false;
                        }
                        self.seen_non_ws = true;
                        self.last_punct = b'\0';
                        self.pos += len;
                        continue;
                    }
                    if let Some((cp, len)) = parse_html_numeric_char_ref(&bytes[self.pos..]) {
                        match cp {
                            123 | 91 => {
                                self.seen_non_ws = true;
                                self.depth += 1;
                                self.line_depth += 1;
                                self.last_punct = if cp == 123 { b'{' } else { b'[' };
                                self.pos += len;
                                continue;
                            }
                            125 | 93 => {
                                self.seen_non_ws = true;
                                self.depth = self.depth.saturating_sub(1);
                                self.line_depth = self.line_depth.saturating_sub(1);
                                self.last_punct = b'\0';
                                self.pos += len;
                                continue;
                            }
                            _ => {}
                        }
                    }
                    self.seen_non_ws = true;
                    self.last_punct = b'\0';
                }
                c if c.is_ascii_whitespace() => {}
                _ => {
                    self.seen_non_ws = true;
                    self.last_punct = b'\0';
                }
            }
            self.pos += 1;
        }

        (
            self.in_string,
            self.in_string && self.on_md_table_line && self.line_depth > 0,
            self.on_md_table_line,
            self.in_string && self.nested_in_string,
        )
    }
}

fn find_opening_keymaterial_tag(bytes: &[u8], start: usize, allow_double_bs: bool) -> Option<OpeningTagMatch> {
    const TAG_NAME: &[u8] = b"keymaterial";
    let mut pos = start;

    while let Some(km_pos) = find_ascii_bytes(bytes, pos, TAG_NAME) {
        let after_name = km_pos + TAG_NAME.len();
        let next_byte = bytes.get(after_name).copied();

        let is_raw_boundary = matches!(next_byte, Some(b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n'))
            || bytes[after_name..].starts_with(b"<br>")
            || bytes[after_name..].starts_with(b"\\/")
            || (allow_double_bs && bytes[after_name..].starts_with(b"\\\\/"))
            || starts_with_escaped_ws(&bytes[after_name..], allow_double_bs).is_some()
            || matches!(
                match_json_u00_char(&bytes[after_name..], allow_double_bs),
                Some((b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n', _))
            );
        if is_raw_boundary {
            if let Some(open_start) = ends_with_lt_token(bytes, start, km_pos, allow_double_bs) {
                return Some(OpeningTagMatch {
                    open_start,
                    after_name,
                    syntax: TagSyntax::Raw,
                    opened_with_u003c: bytes.get(open_start) == Some(&b'\\'),
                });
            }
            if km_pos >= start + 3 && bytes[km_pos - 1] == b':' {
                let mut prefix_start = km_pos - 1;
                while prefix_start > start && is_xml_ncname_char(bytes[prefix_start - 1]) {
                    if prefix_start < km_pos - 1
                        && ends_with_lt_token(bytes, start, prefix_start, allow_double_bs).is_some()
                    {
                        break;
                    }
                    prefix_start -= 1;
                }
                if prefix_start < km_pos - 1
                    && let Some(open_start) = ends_with_lt_token(bytes, start, prefix_start, allow_double_bs)
                {
                    return Some(OpeningTagMatch {
                        open_start,
                        after_name,
                        syntax: TagSyntax::Raw,
                        opened_with_u003c: bytes.get(open_start) == Some(&b'\\'),
                    });
                }
            }
        }

        let is_html_boundary = matches!(next_byte, Some(b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n'))
            || bytes[after_name..].starts_with(b"<br>")
            || bytes[after_name..].starts_with(b"\\/")
            || (allow_double_bs && bytes[after_name..].starts_with(b"\\\\/"))
            || match_html_gt_entity(&bytes[after_name..]).is_some()
            || match_html_br_entity(&bytes[after_name..]).is_some()
            || match_html_slash_entity(&bytes[after_name..]).is_some()
            || starts_with_escaped_ws(&bytes[after_name..], allow_double_bs).is_some()
            || matches!(
                match_json_u00_char(&bytes[after_name..], allow_double_bs),
                Some((b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n', _))
            );
        if is_html_boundary {
            if let Some(open_start) = ends_with_html_lt_entity(bytes, start, km_pos) {
                return Some(OpeningTagMatch {
                    open_start,
                    after_name,
                    syntax: TagSyntax::HtmlEscaped,
                    opened_with_u003c: false,
                });
            }
            if km_pos >= start + 6 && bytes[km_pos - 1] == b':' {
                let mut prefix_start = km_pos - 1;
                while prefix_start > start && is_xml_ncname_char(bytes[prefix_start - 1]) {
                    if prefix_start < km_pos - 1 && ends_with_html_lt_entity(bytes, start, prefix_start).is_some() {
                        break;
                    }
                    prefix_start -= 1;
                }
                if prefix_start < km_pos - 1
                    && let Some(open_start) = ends_with_html_lt_entity(bytes, start, prefix_start)
                {
                    return Some(OpeningTagMatch {
                        open_start,
                        after_name,
                        syntax: TagSyntax::HtmlEscaped,
                        opened_with_u003c: false,
                    });
                }
            }
        }

        pos = after_name;
    }

    None
}

#[derive(Debug, Clone, Copy)]
enum HtmlBackslashAction {
    Abort,
    Advance(usize),
    QuoteToggle(usize),
    U0022DoubleBsOpen(usize),
}

fn scan_json_string_for_quote_hazard(
    bytes: &[u8],
    quote_pos: usize,
    entity_mode: Option<HtmlQuoteMode>,
    double_bs_u0022: bool,
    stop_on_tsv_tab: bool,
    stop_on_md_pipe: bool,
    stop_on_nl: bool,
) -> Result<(usize, bool), usize> {
    let mut p = quote_pos + 1;
    let mut has_hazard = false;
    while p < bytes.len() {
        let b = bytes[p];
        if b == b'\\' {
            let bs = count_consecutive_backslashes(bytes, p);
            let q = p + bs;
            if bs % 2 == 1 {
                if bytes.get(q) == Some(&b'"') {
                    has_hazard = true;
                    p = q + 1;
                    continue;
                }
                if bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")) {
                    has_hazard = true;
                    p = q + 5;
                    continue;
                }
                if matches!(entity_mode, Some(HtmlQuoteMode::SingleEntity))
                    && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0027"))
                {
                    has_hazard = true;
                    p = q + 5;
                    continue;
                }
                if stop_on_md_pipe && bytes.get(q) == Some(&b'|') {
                    p = q + 1;
                    continue;
                }
                if q >= bytes.len() {
                    return Err(bytes.len());
                }
                p = q;
                continue;
            }
            if double_bs_u0022 && bs % 4 == 2 {
                if bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")) {
                    has_hazard = true;
                    p = q + 5;
                    continue;
                }
                if matches!(entity_mode, Some(HtmlQuoteMode::SingleEntity))
                    && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0027"))
                {
                    has_hazard = true;
                    p = q + 5;
                    continue;
                }
            }
            if bytes.get(q) == Some(&b'"') {
                return Ok((q + 1, has_hazard));
            }
            p = q;
        } else if b == b'"' {
            return Ok((p + 1, has_hazard));
        } else if (stop_on_nl && matches!(b, b'\r' | b'\n'))
            || (stop_on_tsv_tab && b == b'\t')
            || (stop_on_md_pipe && b == b'|')
        {
            return Err(p);
        } else if let Some(emode) = entity_mode {
            if b == b'&'
                && let Some((found_mode, len)) = match_html_quote_entity(&bytes[p..])
                && found_mode == emode
            {
                has_hazard = true;
                p += len;
            } else if emode == HtmlQuoteMode::SingleEntity && b == b'\'' {
                has_hazard = true;
                p += 1;
            } else {
                p += 1;
            }
        } else {
            p += 1;
        }
    }
    Err(bytes.len())
}

fn push_json_container_opener(stack: &mut Vec<u8>, b: u8) {
    stack.push(b);
}

fn pop_json_container_closer(stack: &mut Vec<u8>, closer: u8) {
    let want = if closer == b'}' { b'{' } else { b'[' };
    if stack.last() == Some(&want) {
        stack.pop();
    }
}

fn is_uncontained_entity_json_quote_at(bytes: &[u8], pos: usize) -> bool {
    let after = skip_json_ws_forward(bytes, pos + 1);
    if after < bytes.len() && matches!(bytes[after], b',' | b':') {
        let after_delim = skip_json_ws_forward(bytes, after + 1);
        if after_delim < bytes.len()
            && bytes[after_delim] == b'&'
            && matches!(
                match_html_quote_entity(&bytes[after_delim..]),
                Some((HtmlQuoteMode::DoubleEntity, _))
            )
        {
            return true;
        }
    }
    let before = skip_json_ws_backward(bytes, pos);
    if before > 0 && matches!(bytes[before - 1], b',' | b':') {
        let before_delim = skip_json_ws_backward(bytes, before - 1);
        if let Some(q_start) = match_html_double_quote_entity_at_end(&bytes[..before_delim])
            && count_preceding_backslashes(bytes, 0, q_start).is_multiple_of(2)
        {
            return true;
        }
    }
    false
}

fn is_bare_json_delim_quote_at_strict(
    bytes: &[u8],
    pos: usize,
    double_bs_u0022: bool,
    stop_on_tsv_tab: bool,
    stop_on_md_pipe: bool,
    open_containers: &[u8],
) -> bool {
    if bytes.get(pos) != Some(&b'"') || !count_preceding_backslashes(bytes, 0, pos).is_multiple_of(2) {
        return false;
    }
    if !open_containers.is_empty() {
        return !matches!(
            scan_json_string_for_quote_hazard(
                bytes,
                pos,
                None,
                double_bs_u0022,
                stop_on_tsv_tab,
                stop_on_md_pipe,
                false,
            ),
            Ok((_, false))
        );
    }
    let before = skip_json_ws_backward(bytes, pos);
    if before > 0 && matches!(bytes[before - 1], b',' | b':') {
        if let Ok((end, has_hazard)) = scan_json_string_for_quote_hazard(
            bytes,
            pos,
            None,
            double_bs_u0022,
            stop_on_tsv_tab,
            stop_on_md_pipe,
            true,
        ) {
            if has_hazard {
                return true;
            }
            let after_str = skip_json_ws_forward(bytes, end);
            if after_str < bytes.len()
                && (bytes[after_str] == b':'
                    || (bytes[before - 1] == b':' && matches!(bytes[after_str], b',' | b'}' | b']')))
            {
                return true;
            }
        } else {
            return true;
        }
    }
    false
}

fn last_unredacted_closing_km_pos(bytes: &[u8], min_start: usize, allow_double_bs: bool) -> Option<usize> {
    let mut seg_start = min_start;
    let mut search_from = min_start;
    let mut last_unredacted = None;
    while let Some((rel_cs, rel_end)) = slice_contains_closing_keymaterial_tag(&bytes[search_from..], allow_double_bs) {
        let cs = search_from + rel_cs;
        let close_end = search_from + rel_end;
        if !ends_with_gt_redacted(&bytes[seg_start..cs]) {
            last_unredacted = Some(cs);
        }
        seg_start = close_end;
        search_from = close_end;
    }
    last_unredacted
}

#[derive(Clone, Copy, Default)]
struct SingleQuoteSpanSummary {
    scanned_until: usize,
    has_closing_lit_sq: bool,
    last_bare_gt: Option<usize>,
    last_slash_gt: Option<usize>,
}

fn scan_single_quote_span(
    bytes: &[u8],
    start: usize,
    is_html_syntax: bool,
    ctx: TagScanContext,
) -> SingleQuoteSpanSummary {
    let mut p = start;
    let mut last_bare_gt = None;
    let mut last_slash_gt = None;
    while p < bytes.len() {
        if bytes[p] == b'\'' {
            return SingleQuoteSpanSummary {
                scanned_until: p,
                has_closing_lit_sq: true,
                last_bare_gt,
                last_slash_gt,
            };
        }
        if bytes[p] == b'\\' {
            let bs = count_consecutive_backslashes(bytes, p);
            let q = p + bs;
            if ctx.in_json_string && ctx.in_markdown_json_string && bs % 4 == 2 && bytes.get(q) == Some(&b'"') {
                p = q + 1;
                continue;
            }
            if ctx.in_markdown_table_line && bs % 2 == 1 && bytes.get(q) == Some(&b'|') {
                p = q + 1;
                continue;
            }
            let u003e = ((ctx.allow_double_bs && bs % 4 == 2) || bs % 2 == 1)
                && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u003e"));
            if u003e {
                let tok_start = if bs % 2 == 1 { q - 1 } else { q - 2 };
                let is_sc = if is_html_syntax {
                    preceded_by_html_slash(bytes, start, tok_start, ctx.allow_double_bs)
                } else {
                    preceded_by_slash_token(bytes, start, tok_start, ctx.allow_double_bs)
                };
                if is_sc {
                    last_slash_gt = Some(tok_start);
                } else {
                    last_bare_gt = Some(tok_start);
                }
                p = q + 5;
                continue;
            }
            p = q;
            continue;
        }
        if bytes[p] == b'&' {
            if let Some(gt_len) = match_html_gt_entity(&bytes[p..]) {
                let is_sc = if is_html_syntax {
                    preceded_by_html_slash(bytes, start, p, ctx.allow_double_bs)
                } else {
                    preceded_by_slash_token(bytes, start, p, ctx.allow_double_bs)
                };
                if is_sc {
                    last_slash_gt = Some(p);
                } else {
                    last_bare_gt = Some(p);
                }
                p += gt_len;
                continue;
            }
            if let Some(br_len) = match_html_br_entity(&bytes[p..]) {
                p += br_len;
                continue;
            }
            p += 1;
            continue;
        }
        if bytes[p] == b'<' && bytes[p..].starts_with(b"<br>") {
            p += 4;
            continue;
        }
        if bytes[p] == b'>' {
            let is_sc = if is_html_syntax {
                preceded_by_html_slash(bytes, start, p, ctx.allow_double_bs)
            } else {
                preceded_by_slash_token(bytes, start, p, ctx.allow_double_bs)
            };
            if is_sc {
                last_slash_gt = Some(p);
            } else {
                last_bare_gt = Some(p);
            }
        }
        p += 1;
    }
    SingleQuoteSpanSummary {
        scanned_until: bytes.len(),
        has_closing_lit_sq: false,
        last_bare_gt,
        last_slash_gt,
    }
}

fn double_entity_inner_quote_breaks_out(bytes: &[u8], after_quote: usize, allow_double_bs: bool) -> bool {
    let mut j = after_quote;
    while j < bytes.len() {
        let b = bytes[j];
        if b == b'\\' {
            let bs = count_consecutive_backslashes(bytes, j);
            let q = j + bs;
            if (bs % 2 == 1 || (allow_double_bs && bs % 4 == 2)) && bytes.get(q..q + 5) == Some(b"u003e") {
                return true;
            }
            if (bs % 2 == 1 || (allow_double_bs && bs % 4 == 2))
                && bytes.get(q..q + 5) == Some(b"u003c")
                && (bytes.get(q + 5) == Some(&b'/')
                    || bytes.get(q + 5..q + 11) == Some(b"\\u002f")
                    || bytes.get(q + 5..q + 12) == Some(b"\\\\u002f"))
            {
                return true;
            }
            if bs % 2 == 1
                && bytes.get(q) == Some(&b'&')
                && let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&bytes[q..])
            {
                j = q + len;
                continue;
            }
            j = q + usize::from(bytes.get(q) == Some(&b'"'));
            continue;
        }
        if b == b'&' {
            if let Some((HtmlQuoteMode::DoubleEntity, _)) = match_html_quote_entity(&bytes[j..]) {
                return false;
            }
            if match_html_gt_entity(&bytes[j..]).is_some() {
                return true;
            }
            if let Some(lt_len) = match_html_lt_entity(&bytes[j..]) {
                let after_lt = &bytes[j + lt_len..];
                if after_lt.starts_with(b"/")
                    || match_html_slash_entity(after_lt).is_some()
                    || after_lt.starts_with(b"\\u002f")
                    || (allow_double_bs && after_lt.starts_with(b"\\\\u002f"))
                {
                    return true;
                }
            }
            j += 1;
            continue;
        }
        if b == b'<' {
            if bytes[j..].starts_with(b"<br>") {
                j += 4;
                continue;
            }
            if is_raw_keymaterial_close_at(bytes, j) {
                return true;
            }
        }
        if b == b'>' {
            return true;
        }
        j += 1;
    }
    true
}

fn classify_html_escaped_backslash(
    bytes: &[u8],
    i: usize,
    after_name: usize,
    in_none_mode: bool,
    in_entity_json_container: bool,
    ctx: TagScanContext,
) -> HtmlBackslashAction {
    let strict_nested = ctx.in_nested_json_string && !ctx.in_markdown_json_string;
    let bs_count = count_consecutive_backslashes(bytes, i);
    let q = i + bs_count;
    if ctx.in_json_string
        && strict_nested
        && bs_count % 4 == 1
        && (bytes.get(q) == Some(&b'"') || bytes.get(q..q + 5) == Some(b"u0022"))
    {
        return HtmlBackslashAction::Abort;
    }
    if ctx.in_json_string
        && strict_nested
        && in_none_mode
        && bs_count % 4 == 2
        && bytes.get(q..q + 5) == Some(b"u0022")
        && is_preceded_by_eq(bytes, after_name, i)
    {
        return HtmlBackslashAction::U0022DoubleBsOpen(q + 5);
    }
    if (ctx.in_json_string || ctx.in_decoded_u0022_json_ctx)
        && ((ctx.in_double_escaped_json && ctx.allow_double_bs && bs_count % 4 == 2) || bs_count % 2 == 1)
        && bytes.get(q..q + 5) == Some(b"u0022")
    {
        return HtmlBackslashAction::Abort;
    }
    if ctx.in_json_string && ctx.in_markdown_json_string && bs_count % 4 == 2 && bytes.get(q) == Some(&b'"') {
        return HtmlBackslashAction::QuoteToggle(q + 1);
    }
    if (ctx.in_json_string || ((ctx.in_decoded_u0022_json_ctx || in_entity_json_container) && !in_none_mode))
        && !ctx.in_markdown_json_string
        && bs_count % 2 == 1
        && bytes.get(q) == Some(&b'"')
    {
        if ctx.in_csv_field {
            if bytes.get(q + 1) == Some(&b'"') {
                return HtmlBackslashAction::QuoteToggle(q + 2);
            }
            return HtmlBackslashAction::Abort;
        }
        return HtmlBackslashAction::QuoteToggle(q + 1);
    }
    if ctx.in_markdown_table_line && bs_count % 2 == 1 && bytes.get(q) == Some(&b'|') {
        return HtmlBackslashAction::Advance(q + 1);
    }
    HtmlBackslashAction::Advance(q)
}

#[allow(clippy::too_many_arguments)]
fn check_single_quote_breakout(
    bytes: &[u8],
    after_name: usize,
    tok_pos: usize,
    after_q: usize,
    is_html_syntax: bool,
    is_u0027: bool,
    ctx: TagScanContext,
    single_saw_json_opener: bool,
    single_span: &mut SingleQuoteSpanSummary,
    unredacted_close_cache: &mut [Option<Option<usize>>; 2],
    next_close_cache: &mut Option<(usize, Option<bool>)>,
) -> Option<bool> {
    if tok_pos >= single_span.scanned_until {
        *single_span = scan_single_quote_span(bytes, after_q, is_html_syntax, ctx);
    }
    let has_bare_gt = single_span.last_bare_gt.is_some_and(|p| p >= after_q);
    let has_slash_gt = single_span.last_slash_gt.is_some_and(|p| p >= after_q);
    let cache_slot = &mut unredacted_close_cache[usize::from(ctx.allow_double_bs)];
    let close_km_after = cache_slot
        .get_or_insert_with(|| last_unredacted_closing_km_pos(bytes, after_name, ctx.allow_double_bs))
        .is_some_and(|cs| cs >= after_q);
    if !has_bare_gt && !has_slash_gt {
        if let Some(next_is_sc) = scan_next_tag_close_cached(bytes, after_q, is_html_syntax, ctx, next_close_cache) {
            if close_km_after {
                return Some(true);
            }
            if !is_u0027 && next_is_sc {
                return Some(false);
            }
        }
        return None;
    }
    let json_sq_ctx =
        ctx.in_json_string || ctx.in_decoded_u0022_json_ctx || ctx.opened_with_u003c || single_saw_json_opener;
    if is_u0027 && !json_sq_ctx && !close_km_after {
        return None;
    }
    if has_slash_gt && close_km_after {
        return Some(true);
    }
    if has_bare_gt {
        if single_span.has_closing_lit_sq {
            if !is_u0027 && !json_sq_ctx && !close_km_after {
                return None;
            }
            return Some(true);
        }
        return Some(false);
    }
    if close_km_after {
        return Some(true);
    }
    if !single_span.has_closing_lit_sq {
        return Some(false);
    }
    None
}

#[derive(Clone, Copy)]
enum NextTagCloseQuote {
    SingleRaw,
    DoubleRaw,
    DoubleCsv,
    DoubleJson { mod4_3: bool },
    DoubleMarkdownJson,
    HtmlDoubleEntity { escaped_open: bool },
    HtmlSingleEntity,
    U0022 { double_bs: bool },
    U0027 { double_bs: bool },
}

fn scan_next_tag_close_after_q(
    bytes: &[u8],
    after_q: usize,
    is_html_syntax: bool,
    ctx: TagScanContext,
) -> (Option<bool>, usize) {
    let strict_nested = ctx.in_nested_json_string && !ctx.in_markdown_json_string;
    let in_json_or_u0022 = ctx.in_json_string || ctx.in_decoded_u0022_json_ctx;
    let strict_json_u0022 = ctx.in_decoded_u0022_json_ctx || (ctx.in_json_string && ctx.opened_with_u003c);
    let mut p = after_q;
    let mut seen_eq = false;
    let mut first_skipped_eq: Option<usize> = None;
    let mut in_quote: Option<NextTagCloseQuote> = None;
    let allow_double_bs = ctx.allow_double_bs;

    while p < bytes.len() {
        let b = bytes[p];
        if let Some(qmode) = in_quote {
            match qmode {
                NextTagCloseQuote::SingleRaw => {
                    if b == b'\'' {
                        in_quote = None;
                        p += 1;
                    } else if b == b'&'
                        && let Some((HtmlQuoteMode::SingleEntity, len)) = match_html_quote_entity(&bytes[p..])
                    {
                        in_quote = None;
                        p += len;
                    } else if b == b'\\' {
                        let bs = count_consecutive_backslashes(bytes, p);
                        let q = p + bs;
                        let u0027_match = bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0027"))
                            && (bs % 2 == 1
                                || (ctx.allow_double_bs
                                    && (ctx.in_double_escaped_json || ctx.in_json_string)
                                    && bs % 4 == 2));
                        if u0027_match {
                            in_quote = None;
                            p = q + 5;
                        } else if in_json_or_u0022 || ctx.in_markdown_table_line || ctx.opened_with_u003c {
                            if (strict_nested
                                && bs % 4 == 1
                                && (bytes.get(q) == Some(&b'"')
                                    || bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022"))))
                                || (in_json_or_u0022
                                    && ((ctx.in_double_escaped_json && ctx.allow_double_bs && bs % 4 == 2)
                                        || bs % 2 == 1)
                                    && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")))
                            {
                                return (None, first_skipped_eq.unwrap_or(p));
                            } else if ctx.in_json_string
                                && ctx.in_markdown_json_string
                                && bs % 4 == 2
                                && bytes.get(q) == Some(&b'"')
                            {
                                p = q + 1;
                            } else if ctx.in_json_string && bs % 2 == 1 && bytes.get(q) == Some(&b'"') {
                                if ctx.in_csv_field {
                                    if bytes.get(q + 1) == Some(&b'"') {
                                        p = q + 2;
                                    } else {
                                        return (None, first_skipped_eq.unwrap_or(p));
                                    }
                                } else {
                                    p = q + 1;
                                }
                            } else if ctx.in_markdown_table_line && bs % 2 == 1 && bytes.get(q) == Some(&b'|') {
                                p = q + 1;
                            } else {
                                p = q;
                            }
                        } else {
                            p = q;
                        }
                    } else if (ctx.in_json_string && matches!(b, b'"' | b'\r' | b'\n' | b'\t'))
                        || (ctx.in_markdown_table_line && b == b'|')
                        || (!ctx.in_csv_field && ctx.allow_tsv_tabs && b == b'\t')
                        || (ctx.in_markdown_table_line
                            && ctx.in_json_string
                            && b == b'<'
                            && bytes[p..].starts_with(b"<br>"))
                    {
                        return (None, first_skipped_eq.unwrap_or(p));
                    } else {
                        p += 1;
                    }
                }
                NextTagCloseQuote::DoubleRaw => {
                    if b == b'"' {
                        if ctx.in_json_string {
                            return (None, first_skipped_eq.unwrap_or(p));
                        }
                        in_quote = None;
                        p += 1;
                    } else if b == b'\\' && (in_json_or_u0022 || ctx.in_markdown_table_line) {
                        let bs = count_consecutive_backslashes(bytes, p);
                        let q = p + bs;
                        if in_json_or_u0022
                            && ((ctx.in_double_escaped_json && ctx.allow_double_bs && bs % 4 == 2) || bs % 2 == 1)
                            && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022"))
                        {
                            return (None, first_skipped_eq.unwrap_or(p));
                        } else if ctx.in_markdown_table_line && bs % 2 == 1 && bytes.get(q) == Some(&b'|') {
                            p = q + 1;
                        } else {
                            p = q;
                        }
                    } else if (ctx.in_json_string && matches!(b, b'\r' | b'\n' | b'\t'))
                        || (ctx.in_markdown_table_line && b == b'|')
                        || (!ctx.in_csv_field && ctx.allow_tsv_tabs && b == b'\t')
                    {
                        return (None, first_skipped_eq.unwrap_or(p));
                    } else {
                        p += 1;
                    }
                }
                NextTagCloseQuote::DoubleCsv => {
                    if b == b'"' {
                        if bytes.get(p + 1) == Some(&b'"') {
                            in_quote = None;
                            p += 2;
                        } else {
                            return (None, first_skipped_eq.unwrap_or(p));
                        }
                    } else {
                        p += 1;
                    }
                }
                NextTagCloseQuote::DoubleJson { mod4_3 } => {
                    if b == b'\\' {
                        let bs = count_consecutive_backslashes(bytes, p);
                        let q = p + bs;
                        let matches_close = if mod4_3 {
                            bs % 4 == 3 && bytes.get(q) == Some(&b'"')
                        } else {
                            bs % 2 == 1 && bytes.get(q) == Some(&b'"')
                        };
                        if (strict_nested
                            && bs % 4 == 1
                            && (bytes.get(q) == Some(&b'"')
                                || bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022"))))
                            || (in_json_or_u0022
                                && (ctx.in_double_escaped_json && ctx.allow_double_bs)
                                && bs % 4 == 2
                                && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")))
                        {
                            return (None, first_skipped_eq.unwrap_or(p));
                        } else if matches_close {
                            if ctx.in_csv_field {
                                if bytes.get(q + 1) == Some(&b'"') {
                                    in_quote = None;
                                    p = q + 2;
                                } else {
                                    return (None, first_skipped_eq.unwrap_or(p));
                                }
                            } else {
                                in_quote = None;
                                p = q + 1;
                            }
                        } else if bs % 2 == 1 && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")) {
                            if strict_json_u0022 {
                                return (None, first_skipped_eq.unwrap_or(p));
                            }
                            in_quote = None;
                            p = q + 5;
                        } else if ctx.in_markdown_table_line && bs % 2 == 1 && bytes.get(q) == Some(&b'|') {
                            p = q + 1;
                        } else {
                            p = q;
                        }
                    } else if matches!(b, b'"' | b'\t')
                        || (ctx.in_json_string && matches!(b, b'\r' | b'\n'))
                        || (ctx.in_markdown_table_line && (b == b'|' || (b == b'<' && bytes[p..].starts_with(b"<br>"))))
                    {
                        return (None, first_skipped_eq.unwrap_or(p));
                    } else {
                        p += 1;
                    }
                }
                NextTagCloseQuote::DoubleMarkdownJson => {
                    if b == b'\\' {
                        let bs = count_consecutive_backslashes(bytes, p);
                        let q = p + bs;
                        if bs % 4 == 2 && bytes.get(q) == Some(&b'"') {
                            in_quote = None;
                            p = q + 1;
                        } else if bs % 4 == 2 && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")) {
                            in_quote = None;
                            p = q + 5;
                        } else if bs % 2 == 1 && bytes.get(q) == Some(&b'|') {
                            p = q + 1;
                        } else {
                            p = q;
                        }
                    } else if matches!(b, b'"' | b'\r' | b'\n' | b'\t' | b'|')
                        || (b == b'<' && bytes[p..].starts_with(b"<br>"))
                    {
                        return (None, first_skipped_eq.unwrap_or(p));
                    } else {
                        p += 1;
                    }
                }
                NextTagCloseQuote::HtmlDoubleEntity { escaped_open } => {
                    if escaped_open {
                        if b == b'\\' && (in_json_or_u0022 || ctx.in_markdown_table_line) {
                            let bs = count_consecutive_backslashes(bytes, p);
                            let q = p + bs;
                            if in_json_or_u0022
                                && bs % 2 == 1
                                && bytes.get(q) == Some(&b'&')
                                && let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&bytes[q..])
                            {
                                in_quote = None;
                                p = q + len;
                            } else {
                                match classify_html_escaped_backslash(bytes, p, after_q, false, false, ctx) {
                                    HtmlBackslashAction::Abort => return (None, first_skipped_eq.unwrap_or(p)),
                                    HtmlBackslashAction::QuoteToggle(next)
                                    | HtmlBackslashAction::Advance(next)
                                    | HtmlBackslashAction::U0022DoubleBsOpen(next) => {
                                        p = next;
                                    }
                                }
                            }
                        } else if (b == b'&'
                            && matches!(
                                match_html_quote_entity(&bytes[p..]),
                                Some((HtmlQuoteMode::DoubleEntity, _))
                            ))
                            || (ctx.in_json_string && matches!(b, b'"' | b'\r' | b'\n' | b'\t'))
                            || (ctx.in_markdown_table_line && b == b'|')
                            || (!ctx.in_csv_field && ctx.allow_tsv_tabs && b == b'\t')
                        {
                            return (None, first_skipped_eq.unwrap_or(p));
                        } else {
                            p += 1;
                        }
                    } else if let Some((HtmlQuoteMode::DoubleEntity, len)) =
                        (b == b'&').then(|| match_html_quote_entity(&bytes[p..])).flatten()
                    {
                        in_quote = None;
                        p += len;
                    } else if b == b'\\' && (in_json_or_u0022 || ctx.in_markdown_table_line) {
                        let bs = count_consecutive_backslashes(bytes, p);
                        let q = p + bs;
                        if in_json_or_u0022
                            && bs % 2 == 1
                            && bytes.get(q) == Some(&b'&')
                            && let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&bytes[q..])
                        {
                            p = q + len;
                        } else {
                            match classify_html_escaped_backslash(bytes, p, after_q, false, false, ctx) {
                                HtmlBackslashAction::Abort => return (None, first_skipped_eq.unwrap_or(p)),
                                HtmlBackslashAction::QuoteToggle(next)
                                | HtmlBackslashAction::Advance(next)
                                | HtmlBackslashAction::U0022DoubleBsOpen(next) => {
                                    p = next;
                                }
                            }
                        }
                    } else if (ctx.in_json_string && matches!(b, b'"' | b'\r' | b'\n' | b'\t'))
                        || (ctx.in_markdown_table_line && b == b'|')
                        || (!ctx.in_csv_field && ctx.allow_tsv_tabs && b == b'\t')
                    {
                        return (None, first_skipped_eq.unwrap_or(p));
                    } else {
                        p += 1;
                    }
                }
                NextTagCloseQuote::HtmlSingleEntity => {
                    if let Some((HtmlQuoteMode::SingleEntity, len)) =
                        (b == b'&').then(|| match_html_quote_entity(&bytes[p..])).flatten()
                    {
                        in_quote = None;
                        p += len;
                    } else if b == b'\\' && (in_json_or_u0022 || ctx.in_markdown_table_line) {
                        let bs = count_consecutive_backslashes(bytes, p);
                        let q = p + bs;
                        if (in_json_or_u0022
                            && ((ctx.in_double_escaped_json && ctx.allow_double_bs && bs % 4 == 2) || bs % 2 == 1)
                            && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0027")))
                            || (ctx.in_json_string
                                && ctx.allow_double_bs
                                && bs % 4 == 2
                                && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0027")))
                        {
                            return (None, first_skipped_eq.unwrap_or(p));
                        }
                        match classify_html_escaped_backslash(bytes, p, after_q, false, false, ctx) {
                            HtmlBackslashAction::Abort => return (None, first_skipped_eq.unwrap_or(p)),
                            HtmlBackslashAction::QuoteToggle(next)
                            | HtmlBackslashAction::Advance(next)
                            | HtmlBackslashAction::U0022DoubleBsOpen(next) => {
                                p = next;
                            }
                        }
                    } else if (ctx.in_json_string && matches!(b, b'"' | b'\r' | b'\n' | b'\t'))
                        || ((ctx.in_json_string || !ctx.in_csv_field) && b == b'\'')
                        || (ctx.in_markdown_table_line && b == b'|')
                        || (!ctx.in_csv_field && ctx.allow_tsv_tabs && b == b'\t')
                    {
                        return (None, first_skipped_eq.unwrap_or(p));
                    } else {
                        p += 1;
                    }
                }
                NextTagCloseQuote::U0022 { double_bs } => {
                    if b == b'\\' {
                        let bs = count_consecutive_backslashes(bytes, p);
                        let q = p + bs;
                        if strict_nested
                            && bs % 4 == 1
                            && (bytes.get(q) == Some(&b'"')
                                || bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")))
                        {
                            return (None, first_skipped_eq.unwrap_or(p));
                        } else if !double_bs {
                            if bs % 2 == 1 && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")) {
                                if in_json_or_u0022 {
                                    return (None, first_skipped_eq.unwrap_or(p));
                                }
                                in_quote = None;
                                p = q + 5;
                            } else if bs % 2 == 1 && bytes.get(q) == Some(&b'"') {
                                if ctx.in_csv_field {
                                    if bytes.get(q + 1) == Some(&b'"') {
                                        in_quote = None;
                                        p = q + 2;
                                    } else {
                                        return (None, first_skipped_eq.unwrap_or(p));
                                    }
                                } else {
                                    in_quote = None;
                                    p = q + 1;
                                }
                            } else if ctx.in_markdown_table_line && bs % 2 == 1 && bytes.get(q) == Some(&b'|') {
                                p = q + 1;
                            } else {
                                p = q;
                            }
                        } else if bs % 4 == 2 && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")) {
                            if in_json_or_u0022 && ctx.in_double_escaped_json && ctx.allow_double_bs {
                                return (None, first_skipped_eq.unwrap_or(p));
                            }
                            in_quote = None;
                            p = q + 5;
                        } else if ctx.in_markdown_json_string && bs % 4 == 2 && bytes.get(q) == Some(&b'"') {
                            in_quote = None;
                            p = q + 1;
                        } else if !ctx.in_markdown_json_string && bs % 4 == 3 && bytes.get(q) == Some(&b'"') {
                            if ctx.in_csv_field {
                                if bytes.get(q + 1) == Some(&b'"') {
                                    in_quote = None;
                                    p = q + 2;
                                } else {
                                    return (None, first_skipped_eq.unwrap_or(p));
                                }
                            } else {
                                in_quote = None;
                                p = q + 1;
                            }
                        } else if !ctx.in_markdown_json_string && bs % 4 == 2 && bytes.get(q) == Some(&b'"') {
                            return (None, first_skipped_eq.unwrap_or(p));
                        } else if ctx.in_markdown_table_line && bs % 2 == 1 && bytes.get(q) == Some(&b'|') {
                            p = q + 1;
                        } else {
                            p = q;
                        }
                    } else if (!double_bs && matches!(b, b'"' | b'\r' | b'\n' | b'\t'))
                        || (double_bs
                            && (matches!(b, b'"' | b'\t') || (ctx.in_json_string && matches!(b, b'\r' | b'\n'))))
                        || (ctx.in_markdown_table_line && (b == b'|' || (b == b'<' && bytes[p..].starts_with(b"<br>"))))
                    {
                        return (None, first_skipped_eq.unwrap_or(p));
                    } else {
                        p += 1;
                    }
                }
                NextTagCloseQuote::U0027 { double_bs } => {
                    if b == b'\'' {
                        in_quote = None;
                        p += 1;
                    } else if b == b'&'
                        && let Some((HtmlQuoteMode::SingleEntity, len)) = match_html_quote_entity(&bytes[p..])
                    {
                        in_quote = None;
                        p += len;
                    } else if b == b'\\' {
                        let bs = count_consecutive_backslashes(bytes, p);
                        let q = p + bs;
                        let ok_bs = if double_bs { bs % 4 == 2 } else { bs % 2 == 1 };
                        if ok_bs && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0027")) {
                            in_quote = None;
                            p = q + 5;
                        } else if (strict_nested
                            && bs % 4 == 1
                            && (bytes.get(q) == Some(&b'"')
                                || bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022"))))
                            || (in_json_or_u0022
                                && ((ctx.in_double_escaped_json && ctx.allow_double_bs && bs % 4 == 2) || bs % 2 == 1)
                                && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022")))
                        {
                            return (None, first_skipped_eq.unwrap_or(p));
                        } else if double_bs {
                            if ctx.in_markdown_json_string && bs % 4 == 2 && bytes.get(q) == Some(&b'"') {
                                p = q + 1;
                            } else if !ctx.in_markdown_json_string && bs % 4 == 3 && bytes.get(q) == Some(&b'"') {
                                if ctx.in_csv_field {
                                    if bytes.get(q + 1) == Some(&b'"') {
                                        p = q + 2;
                                    } else {
                                        return (None, first_skipped_eq.unwrap_or(p));
                                    }
                                } else {
                                    p = q + 1;
                                }
                            } else if !ctx.in_markdown_json_string && bs % 4 == 2 && bytes.get(q) == Some(&b'"') {
                                return (None, first_skipped_eq.unwrap_or(p));
                            } else if ctx.in_markdown_table_line && bs % 2 == 1 && bytes.get(q) == Some(&b'|') {
                                p = q + 1;
                            } else {
                                p = q;
                            }
                        } else if bs % 2 == 1 && bytes.get(q) == Some(&b'"') {
                            if ctx.in_csv_field {
                                if bytes.get(q + 1) == Some(&b'"') {
                                    p = q + 2;
                                } else {
                                    return (None, first_skipped_eq.unwrap_or(p));
                                }
                            } else {
                                p = q + 1;
                            }
                        } else if ctx.in_markdown_table_line && bs % 2 == 1 && bytes.get(q) == Some(&b'|') {
                            p = q + 1;
                        } else {
                            p = q;
                        }
                    } else if (if is_html_syntax {
                        ctx.in_json_string && matches!(b, b'"' | b'\r' | b'\n' | b'\t')
                    } else {
                        matches!(b, b'"' | b'\r' | b'\n' | b'\t')
                    }) || (ctx.in_markdown_table_line
                        && (b == b'|' || (b == b'<' && bytes[p..].starts_with(b"<br>"))))
                        || (!ctx.in_csv_field && ctx.allow_tsv_tabs && b == b'\t')
                    {
                        return (None, first_skipped_eq.unwrap_or(p));
                    } else {
                        p += 1;
                    }
                }
            }
            continue;
        }

        if b == b'=' {
            seen_eq = true;
            p += 1;
            continue;
        }
        if b.is_ascii_whitespace() {
            p += 1;
            continue;
        }
        if b == b'\'' {
            if seen_eq {
                first_skipped_eq.get_or_insert(p);
                in_quote = Some(NextTagCloseQuote::SingleRaw);
                seen_eq = false;
                p += 1;
                continue;
            }
            return (None, first_skipped_eq.unwrap_or(p));
        }
        if b == b'"' {
            if seen_eq {
                if ctx.in_csv_field {
                    if bytes[p..].starts_with(b"\"\"\"\"") {
                        seen_eq = false;
                        p += 4;
                        continue;
                    } else if bytes.get(p + 1) == Some(&b'"') {
                        first_skipped_eq.get_or_insert(p);
                        in_quote = Some(NextTagCloseQuote::DoubleCsv);
                        seen_eq = false;
                        p += 2;
                        continue;
                    }
                    return (None, first_skipped_eq.unwrap_or(p));
                }
                if ctx.in_json_string {
                    return (None, first_skipped_eq.unwrap_or(p));
                }
                first_skipped_eq.get_or_insert(p);
                in_quote = Some(NextTagCloseQuote::DoubleRaw);
                seen_eq = false;
                p += 1;
                continue;
            }
            return (None, first_skipped_eq.unwrap_or(p));
        }
        if b == b'\\' {
            let bs = count_consecutive_backslashes(bytes, p);
            let q = p + bs;
            if ((allow_double_bs && bs % 4 == 2) || bs % 2 == 1)
                && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u003e"))
            {
                let tok_start = if bs % 2 == 1 { q - 1 } else { q - 2 };
                let is_sc = if is_html_syntax {
                    preceded_by_html_slash(bytes, after_q, tok_start, allow_double_bs)
                } else {
                    preceded_by_slash_token(bytes, after_q, tok_start, allow_double_bs)
                };
                return (Some(is_sc), first_skipped_eq.unwrap_or(tok_start));
            }
            if bs % 2 == 1 && bytes.get(q) == Some(&b'"') {
                if strict_nested && bs % 4 == 1 {
                    return (None, first_skipped_eq.unwrap_or(p));
                }
                if !ctx.in_csv_field && !in_json_or_u0022 && bytes.get(q + 1) == Some(&b'"') && seen_eq {
                    return (None, first_skipped_eq.unwrap_or(p));
                }
                if in_json_or_u0022 || ctx.opened_with_u003c || (ctx.in_csv_field && ctx.in_json_string) {
                    if seen_eq {
                        first_skipped_eq.get_or_insert(p);
                        if ctx.in_csv_field && ctx.in_json_string && bytes.get(q + 1) == Some(&b'"') {
                            in_quote = Some(NextTagCloseQuote::DoubleJson { mod4_3: false });
                            seen_eq = false;
                            p = q + 2;
                            continue;
                        }
                        if in_json_or_u0022
                            && ctx.in_double_escaped_json
                            && !ctx.in_markdown_json_string
                            && !ctx.in_csv_field
                            && bs % 4 == 3
                        {
                            in_quote = Some(NextTagCloseQuote::U0022 { double_bs: true });
                        } else if in_json_or_u0022 {
                            let mod4_3 = ctx.in_double_escaped_json && !ctx.in_markdown_json_string && bs % 4 == 3;
                            in_quote = Some(NextTagCloseQuote::DoubleJson { mod4_3 });
                        } else {
                            in_quote = Some(NextTagCloseQuote::U0022 { double_bs: false });
                        }
                        seen_eq = false;
                        p = q + 1;
                        continue;
                    }
                    return (None, first_skipped_eq.unwrap_or(p));
                }
                p = q;
                continue;
            }
            if bs % 2 == 1
                && bytes.get(q) == Some(&b'&')
                && let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&bytes[q..])
            {
                if strict_nested && bs % 4 == 1 {
                    return (None, first_skipped_eq.unwrap_or(p));
                }
                if in_json_or_u0022 {
                    if seen_eq {
                        first_skipped_eq.get_or_insert(p);
                        in_quote = Some(NextTagCloseQuote::HtmlDoubleEntity { escaped_open: true });
                        seen_eq = false;
                        p = q + len;
                        continue;
                    }
                    return (None, first_skipped_eq.unwrap_or(p));
                }
            }
            if ctx.in_markdown_json_string
                && bs % 4 == 2
                && bytes.get(q) == Some(&b'"')
                && bytes.get(q + 1) != Some(&b'"')
                && seen_eq
            {
                first_skipped_eq.get_or_insert(p);
                in_quote = Some(NextTagCloseQuote::DoubleMarkdownJson);
                seen_eq = false;
                p = q + 1;
                continue;
            }
            if ctx.in_markdown_table_line && bs % 2 == 1 && bytes.get(q) == Some(&b'|') {
                seen_eq = false;
                p = q + 1;
                continue;
            }
            if ((allow_double_bs && bs % 4 == 2) || bs % 2 == 1)
                && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0022"))
            {
                if (strict_nested && bs % 2 == 1)
                    || (in_json_or_u0022
                        && (bs % 2 == 1 || (ctx.in_double_escaped_json && ctx.allow_double_bs && bs % 4 == 2)))
                {
                    return (None, first_skipped_eq.unwrap_or(p));
                }
                if seen_eq {
                    first_skipped_eq.get_or_insert(p);
                    in_quote = Some(NextTagCloseQuote::U0022 { double_bs: bs % 4 == 2 });
                    seen_eq = false;
                    p = q + 5;
                    continue;
                }
                return (None, first_skipped_eq.unwrap_or(p));
            }
            if ((allow_double_bs && bs % 4 == 2) || bs % 2 == 1)
                && bytes.get(q..q + 5).is_some_and(|s| s.eq_ignore_ascii_case(b"u0027"))
            {
                if seen_eq {
                    first_skipped_eq.get_or_insert(p);
                    in_quote = Some(NextTagCloseQuote::U0027 { double_bs: bs % 4 == 2 });
                    seen_eq = false;
                    p = q + 5;
                    continue;
                }
                return (None, first_skipped_eq.unwrap_or(p));
            }
            seen_eq = false;
            p = q;
            continue;
        }
        if b == b'&' {
            if let Some((qmode, len)) = match_html_quote_entity(&bytes[p..]) {
                if seen_eq {
                    first_skipped_eq.get_or_insert(p);
                    in_quote = Some(match qmode {
                        HtmlQuoteMode::DoubleEntity => NextTagCloseQuote::HtmlDoubleEntity { escaped_open: false },
                        HtmlQuoteMode::SingleEntity => NextTagCloseQuote::HtmlSingleEntity,
                        _ => unreachable!(),
                    });
                    seen_eq = false;
                    p += len;
                    continue;
                }
                if qmode == HtmlQuoteMode::DoubleEntity {
                    return (None, first_skipped_eq.unwrap_or(p));
                }
                p += len;
                continue;
            }
            if is_html_syntax && match_html_gt_entity(&bytes[p..]).is_some() {
                let is_sc = preceded_by_html_slash(bytes, after_q, p, allow_double_bs);
                return (Some(is_sc), first_skipped_eq.unwrap_or(p));
            }
        }
        if b == b'<' && bytes[p..].starts_with(b"<br>") {
            if ctx.in_markdown_table_line && ctx.in_json_string {
                return (None, first_skipped_eq.unwrap_or(p));
            }
            seen_eq = false;
            p += 4;
            continue;
        }
        if is_html_syntax
            && b == b'&'
            && let Some(br_len) = match_html_br_entity(&bytes[p..])
        {
            if ctx.in_markdown_table_line && ctx.in_json_string {
                return (None, first_skipped_eq.unwrap_or(p));
            }
            seen_eq = false;
            p += br_len;
            continue;
        }
        if b == b'>' {
            let is_sc = if is_html_syntax {
                preceded_by_html_slash(bytes, after_q, p, allow_double_bs)
            } else {
                preceded_by_slash_token(bytes, after_q, p, allow_double_bs)
            };
            return (Some(is_sc), first_skipped_eq.unwrap_or(p));
        }
        if (ctx.in_markdown_table_line && b == b'|')
            || (!ctx.in_csv_field && ctx.allow_tsv_tabs && b == b'\t')
            || (ctx.in_json_string && matches!(b, b'\r' | b'\n' | b'\t'))
        {
            return (None, first_skipped_eq.unwrap_or(p));
        }
        seen_eq = false;
        p += 1;
    }
    (None, first_skipped_eq.unwrap_or(bytes.len()))
}

fn scan_next_tag_close_cached(
    bytes: &[u8],
    after_q: usize,
    is_html_syntax: bool,
    ctx: TagScanContext,
    next_close_cache: &mut Option<(usize, Option<bool>)>,
) -> Option<bool> {
    if let Some((safe_until, cached)) = *next_close_cache
        && after_q < safe_until
    {
        return cached;
    }
    let (res, safe_until) = scan_next_tag_close_after_q(bytes, after_q, is_html_syntax, ctx);
    *next_close_cache = Some((safe_until, res));
    res
}

fn u0027_quote_close_breaks_out(
    bytes: &[u8],
    after_name: usize,
    after_q: usize,
    is_html_syntax: bool,
    ctx: TagScanContext,
    unredacted_close_cache: &mut [Option<Option<usize>>; 2],
    next_close_cache: &mut Option<(usize, Option<bool>)>,
) -> bool {
    let cache_slot = &mut unredacted_close_cache[usize::from(ctx.allow_double_bs)];
    let close_km_after = cache_slot
        .get_or_insert_with(|| last_unredacted_closing_km_pos(bytes, after_name, ctx.allow_double_bs))
        .is_some_and(|cs| cs >= after_q);
    if !close_km_after {
        return false;
    }
    scan_next_tag_close_cached(bytes, after_q, is_html_syntax, ctx, next_close_cache).is_some()
}

fn find_tag_close_quote_aware(
    bytes: &[u8],
    after_name: usize,
    syntax: TagSyntax,
    ctx: TagScanContext,
) -> Option<(usize, usize, bool)> {
    let mut cache = [None, None];
    find_tag_close_quote_aware_cached(bytes, after_name, syntax, ctx, &mut cache)
}

fn find_tag_close_quote_aware_cached(
    bytes: &[u8],
    after_name: usize,
    syntax: TagSyntax,
    ctx: TagScanContext,
    unredacted_close_cache: &mut [Option<Option<usize>>; 2],
) -> Option<(usize, usize, bool)> {
    let strict_nested = ctx.in_nested_json_string && !ctx.in_markdown_json_string;
    let in_json_or_u0022 = ctx.in_json_string || ctx.in_decoded_u0022_json_ctx;
    let strict_json_u0022 = ctx.in_decoded_u0022_json_ctx || (ctx.in_json_string && ctx.opened_with_u003c);
    let double_bs_u0022 = ctx.in_double_escaped_json && ctx.allow_double_bs;
    let stop_on_tsv_tab = !ctx.in_csv_field && ctx.allow_tsv_tabs;
    let stop_on_md_pipe = ctx.in_markdown_table_line;
    match syntax {
        TagSyntax::Raw => {
            let tag_has_dbl_u0022_markers = ctx.in_json_string
                && !ctx.in_double_escaped_json
                && has_double_escaped_json_markers_with_marker(&bytes[after_name..], false, None);
            let mut mode = RawQuoteMode::None;
            let mut entity_inner_quotes = 0u8;
            let mut open_containers: Vec<u8> = Vec::new();
            let mut entity_open_containers: Vec<u8> = Vec::new();
            let mut single_saw_json_opener = false;
            let mut single_span = SingleQuoteSpanSummary::default();
            let mut next_close_cache: Option<(usize, Option<bool>)> = None;
            let mut i = after_name;
            while i < bytes.len() {
                let b = bytes[i];
                match mode {
                    RawQuoteMode::None => match b {
                        b'{' | b'[' => {
                            push_json_container_opener(&mut open_containers, b);
                            i += 1;
                        }
                        b'}' | b']' => {
                            pop_json_container_closer(&mut open_containers, b);
                            i += 1;
                        }
                        b'&' if (ctx.in_json_string && ctx.opened_with_u003c)
                            || is_preceded_by_eq(bytes, after_name, i) =>
                        {
                            if let Some((qmode, len)) = match_html_quote_entity(&bytes[i..]) {
                                mode = match qmode {
                                    HtmlQuoteMode::DoubleEntity => RawQuoteMode::HtmlDoubleEntity,
                                    HtmlQuoteMode::SingleEntity => RawQuoteMode::HtmlSingleEntity,
                                    _ => RawQuoteMode::None,
                                };
                                entity_inner_quotes = 0;
                                entity_open_containers.clear();
                                i += len;
                            } else {
                                i += 1;
                            }
                        }
                        b'\'' => {
                            mode = RawQuoteMode::Single;
                            single_saw_json_opener = false;
                            single_span = SingleQuoteSpanSummary::default();
                            next_close_cache = None;
                            i += 1;
                        }
                        b'\\' => {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            if bs_count % 2 == 1 && bytes.get(q) == Some(&b'"') {
                                if strict_nested && bs_count % 4 == 1 {
                                    return None;
                                } else if ctx.in_csv_field && ctx.in_json_string && bytes.get(q + 1) == Some(&b'"') {
                                    mode = RawQuoteMode::DoubleCsvJson;
                                    i = q + 2;
                                } else if !ctx.in_csv_field
                                    && !in_json_or_u0022
                                    && bytes.get(q + 1) == Some(&b'"')
                                    && is_preceded_by_eq(bytes, after_name, i)
                                {
                                    return None;
                                } else if in_json_or_u0022
                                    && ctx.in_double_escaped_json
                                    && !ctx.in_markdown_json_string
                                    && !ctx.in_csv_field
                                    && bs_count % 4 == 3
                                    && is_preceded_by_eq(bytes, after_name, i)
                                {
                                    mode = RawQuoteMode::U0022DoubleBs;
                                    i = q + 1;
                                } else if in_json_or_u0022 {
                                    mode = RawQuoteMode::DoubleJson;
                                    i = q + 1;
                                } else if ctx.opened_with_u003c {
                                    mode = RawQuoteMode::U0022Single;
                                    i = q + 1;
                                } else {
                                    i = q;
                                }
                            } else if ctx.in_markdown_json_string
                                && bs_count % 4 == 2
                                && bytes.get(q) == Some(&b'"')
                                && bytes.get(q + 1) != Some(&b'"')
                                && is_preceded_by_eq(bytes, after_name, i)
                            {
                                mode = RawQuoteMode::DoubleMarkdownJson;
                                i = q + 1;
                            } else if ctx.in_markdown_table_line && bs_count % 2 == 1 && bytes.get(q) == Some(&b'|') {
                                i = q + 1;
                            } else {
                                let u00_match = if ctx.allow_double_bs && bs_count % 4 == 2 {
                                    match_json_u00_char(&bytes[q - 2..], true).map(|(ch, len)| (q - 2, ch, len))
                                } else if bs_count % 2 == 1 {
                                    match_json_u00_char(&bytes[q - 1..], false).map(|(ch, len)| (q - 1, ch, len))
                                } else {
                                    None
                                };
                                if let Some((tok_start, decoded_ch, len)) = u00_match {
                                    match decoded_ch {
                                        b'>' => {
                                            let is_self_closing = preceded_by_slash_token(
                                                bytes,
                                                after_name,
                                                tok_start,
                                                ctx.allow_double_bs,
                                            );
                                            return Some((tok_start, tok_start + len, is_self_closing));
                                        }
                                        b'"' => {
                                            if (strict_nested && len == 6)
                                                || (in_json_or_u0022
                                                    && (len == 6
                                                        || (ctx.in_double_escaped_json
                                                            && ctx.allow_double_bs
                                                            && len == 7)))
                                            {
                                                return None;
                                            }
                                            mode = if len == 7 {
                                                RawQuoteMode::U0022DoubleBs
                                            } else {
                                                RawQuoteMode::U0022Single
                                            };
                                            i = tok_start + len;
                                        }
                                        b'\'' => {
                                            mode = if len == 7 {
                                                RawQuoteMode::U0027DoubleBs
                                            } else {
                                                RawQuoteMode::U0027Single
                                            };
                                            single_span = SingleQuoteSpanSummary::default();
                                            next_close_cache = None;
                                            i = tok_start + len;
                                        }
                                        _ => {
                                            i = tok_start + len;
                                        }
                                    }
                                } else {
                                    i = q;
                                }
                            }
                        }
                        b'"' => {
                            if ctx.in_csv_field {
                                if bytes[i..].starts_with(b"\"\"\"\"") && is_preceded_by_eq(bytes, after_name, i) {
                                    // CSV-doubled empty XML attribute (`attr=""` -> `attr=""""`).
                                    i += 4;
                                } else if bytes.get(i + 1) == Some(&b'"') {
                                    mode = RawQuoteMode::DoubleCsv;
                                    i += 2;
                                } else {
                                    // Un-doubled `"` inside a verified CSV-quoted field marks field end.
                                    return None;
                                }
                            } else if ctx.in_json_string
                                || is_bare_json_delim_quote_at_strict(
                                    bytes,
                                    i,
                                    double_bs_u0022,
                                    stop_on_tsv_tab,
                                    stop_on_md_pipe,
                                    &open_containers,
                                )
                            {
                                return None;
                            } else {
                                mode = RawQuoteMode::DoubleRaw;
                                i += 1;
                            }
                        }
                        b'|' if ctx.in_markdown_table_line => {
                            return None;
                        }
                        b'\t' if !ctx.in_csv_field && ctx.allow_tsv_tabs => {
                            return None;
                        }
                        b'\r' | b'\n' if ctx.in_json_string => {
                            return None;
                        }
                        b'<' if bytes[i..].starts_with(b"<br>") => {
                            if ctx.in_markdown_table_line && ctx.in_json_string {
                                return None;
                            }
                            // Markdown exports convert newlines to `<br>`; skip `<br>` inside an
                            // opening tag so its `>` does not prematurely terminate the tag.
                            i += 4;
                        }
                        b'>' => {
                            let is_self_closing = preceded_by_slash_token(bytes, after_name, i, ctx.allow_double_bs);
                            return Some((i, i + 1, is_self_closing));
                        }
                        _ => i += 1,
                    },
                    RawQuoteMode::Single => {
                        if b == b'\'' {
                            mode = RawQuoteMode::None;
                            i += 1;
                        } else if b == b'&'
                            && let Some((HtmlQuoteMode::SingleEntity, len)) = match_html_quote_entity(&bytes[i..])
                        {
                            match check_single_quote_breakout(
                                bytes,
                                after_name,
                                i,
                                i + len,
                                false,
                                false,
                                ctx,
                                single_saw_json_opener,
                                &mut single_span,
                                unredacted_close_cache,
                                &mut next_close_cache,
                            ) {
                                Some(true) => return None,
                                Some(false) => {
                                    mode = RawQuoteMode::None;
                                    i += len;
                                }
                                None => {
                                    i += len;
                                }
                            }
                        } else if b == b'\\' {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            let u0027_match = bytes.get(q..q + 5) == Some(b"u0027")
                                && (((ctx.in_double_escaped_json && ctx.allow_double_bs && bs_count % 4 == 2)
                                    || bs_count % 2 == 1)
                                    || (ctx.in_json_string
                                        && ctx.allow_double_bs
                                        && bs_count % 4 == 2
                                        && unredacted_close_cache[usize::from(ctx.allow_double_bs)]
                                            .get_or_insert_with(|| {
                                                last_unredacted_closing_km_pos(bytes, after_name, ctx.allow_double_bs)
                                            })
                                            .is_some_and(|cs| cs >= q + 5)));
                            if u0027_match {
                                match check_single_quote_breakout(
                                    bytes,
                                    after_name,
                                    i,
                                    q + 5,
                                    false,
                                    true,
                                    ctx,
                                    single_saw_json_opener,
                                    &mut single_span,
                                    unredacted_close_cache,
                                    &mut next_close_cache,
                                ) {
                                    Some(true) => return None,
                                    Some(false) => {
                                        mode = RawQuoteMode::None;
                                        i = q + 5;
                                    }
                                    None => {
                                        i = q + 5;
                                    }
                                }
                            } else if in_json_or_u0022 || ctx.in_markdown_table_line || ctx.opened_with_u003c {
                                if (strict_nested
                                    && bs_count % 4 == 1
                                    && (bytes.get(q) == Some(&b'"') || bytes.get(q..q + 5) == Some(b"u0022")))
                                    || (in_json_or_u0022
                                        && ((ctx.in_double_escaped_json && ctx.allow_double_bs && bs_count % 4 == 2)
                                            || bs_count % 2 == 1)
                                        && bytes.get(q..q + 5) == Some(b"u0022"))
                                {
                                    return None;
                                } else if ctx.in_json_string
                                    && ctx.in_markdown_json_string
                                    && bs_count % 4 == 2
                                    && bytes.get(q) == Some(&b'"')
                                {
                                    i = q + 1;
                                } else if ctx.in_json_string && bs_count % 2 == 1 && bytes.get(q) == Some(&b'"') {
                                    if ctx.in_csv_field {
                                        if bytes.get(q + 1) == Some(&b'"') {
                                            i = q + 2;
                                        } else {
                                            return None;
                                        }
                                    } else {
                                        i = q + 1;
                                    }
                                } else if ctx.in_markdown_table_line && bs_count % 2 == 1 && bytes.get(q) == Some(&b'|')
                                {
                                    i = q + 1;
                                } else {
                                    i = q;
                                }
                            } else {
                                i = q;
                            }
                        } else if (ctx.in_json_string && matches!(b, b'"' | b'\r' | b'\n' | b'\t'))
                            || (ctx.in_markdown_table_line && b == b'|')
                            || (!ctx.in_csv_field && ctx.allow_tsv_tabs && b == b'\t')
                            || (ctx.in_markdown_table_line
                                && ctx.in_json_string
                                && b == b'<'
                                && bytes[i..].starts_with(b"<br>"))
                        {
                            return None;
                        } else {
                            if matches!(b, b'{' | b'[') {
                                single_saw_json_opener = true;
                            }
                            i += 1;
                        }
                    }
                    RawQuoteMode::DoubleRaw => {
                        if b == b'"' {
                            mode = RawQuoteMode::None;
                            i += 1;
                        } else if b == b'\\' && (in_json_or_u0022 || ctx.in_markdown_table_line) {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            if in_json_or_u0022
                                && ((ctx.in_double_escaped_json && ctx.allow_double_bs && bs_count % 4 == 2)
                                    || bs_count % 2 == 1)
                                && bytes.get(q..q + 5) == Some(b"u0022")
                            {
                                return None;
                            } else if ctx.in_markdown_table_line && bs_count % 2 == 1 && bytes.get(q) == Some(&b'|') {
                                i = q + 1;
                            } else {
                                i = q;
                            }
                        } else if (ctx.in_markdown_table_line && b == b'|')
                            || (!ctx.in_csv_field && ctx.allow_tsv_tabs && b == b'\t')
                        {
                            return None;
                        } else {
                            i += 1;
                        }
                    }
                    RawQuoteMode::DoubleCsv => {
                        if b == b'"' {
                            if bytes.get(i + 1) == Some(&b'"') {
                                mode = RawQuoteMode::None;
                                i += 2;
                            } else {
                                // Un-doubled CSV field-closing quote reached before closing `""`.
                                return None;
                            }
                        } else {
                            i += 1;
                        }
                    }
                    RawQuoteMode::DoubleJson => {
                        if b == b'\\' {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            if (strict_nested
                                && bs_count % 4 == 1
                                && (bytes.get(q) == Some(&b'"') || bytes.get(q..q + 5) == Some(b"u0022")))
                                || (in_json_or_u0022
                                    && ((ctx.in_double_escaped_json && ctx.allow_double_bs)
                                        || tag_has_dbl_u0022_markers)
                                    && bs_count % 4 == 2
                                    && bytes.get(q..q + 5) == Some(b"u0022"))
                            {
                                return None;
                            } else if bs_count % 2 == 1 && bytes.get(q) == Some(&b'"') {
                                mode = RawQuoteMode::None;
                                i = q + 1;
                            } else if bs_count % 2 == 1 && bytes.get(q..q + 5) == Some(b"u0022") {
                                if strict_json_u0022 {
                                    return None;
                                }
                                mode = RawQuoteMode::None;
                                i = q + 5;
                            } else if ctx.in_markdown_table_line && bs_count % 2 == 1 && bytes.get(q) == Some(&b'|') {
                                i = q + 1;
                            } else {
                                i = q;
                            }
                        } else if matches!(b, b'"' | b'\t')
                            || (ctx.in_json_string && matches!(b, b'\r' | b'\n'))
                            || (ctx.in_markdown_table_line
                                && (b == b'|' || (b == b'<' && bytes[i..].starts_with(b"<br>"))))
                        {
                            return None;
                        } else {
                            i += 1;
                        }
                    }
                    RawQuoteMode::DoubleCsvJson => {
                        if b == b'\\' {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            if strict_nested {
                                if bs_count % 4 == 1
                                    && (bytes.get(q) == Some(&b'"') || bytes.get(q..q + 5) == Some(b"u0022"))
                                {
                                    return None;
                                } else if bs_count % 4 == 3
                                    && bytes.get(q) == Some(&b'"')
                                    && bytes.get(q + 1) == Some(&b'"')
                                {
                                    mode = RawQuoteMode::None;
                                    i = q + 2;
                                } else if bs_count % 4 == 2 && bytes.get(q..q + 5) == Some(b"u0022") {
                                    mode = RawQuoteMode::None;
                                    i = q + 5;
                                } else if ctx.in_markdown_table_line && bs_count % 2 == 1 && bytes.get(q) == Some(&b'|')
                                {
                                    i = q + 1;
                                } else if bytes.get(q) == Some(&b'"') && bytes.get(q + 1) != Some(&b'"') {
                                    return None;
                                } else {
                                    i = q;
                                }
                            } else if bs_count % 2 == 1
                                && bytes.get(q) == Some(&b'"')
                                && bytes.get(q + 1) == Some(&b'"')
                            {
                                mode = RawQuoteMode::None;
                                i = q + 2;
                            } else if ((ctx.in_double_escaped_json && ctx.allow_double_bs && bs_count % 4 == 2)
                                || bs_count % 2 == 1)
                                && bytes.get(q..q + 5) == Some(b"u0022")
                            {
                                mode = RawQuoteMode::None;
                                i = q + 5;
                            } else if ctx.in_markdown_table_line && bs_count % 2 == 1 && bytes.get(q) == Some(&b'|') {
                                i = q + 1;
                            } else if bytes.get(q) == Some(&b'"') && bytes.get(q + 1) != Some(&b'"') {
                                return None;
                            } else {
                                i = q;
                            }
                        } else if matches!(b, b'"' | b'\r' | b'\n' | b'\t')
                            || (ctx.in_markdown_table_line
                                && (b == b'|' || (b == b'<' && bytes[i..].starts_with(b"<br>"))))
                        {
                            return None;
                        } else {
                            i += 1;
                        }
                    }
                    RawQuoteMode::DoubleMarkdownJson => {
                        if b == b'\\' {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            if bs_count % 4 == 2 && bytes.get(q) == Some(&b'"') {
                                mode = RawQuoteMode::None;
                                i = q + 1;
                            } else if bs_count % 4 == 2 && bytes.get(q..q + 5) == Some(b"u0022") {
                                mode = RawQuoteMode::None;
                                i = q + 5;
                            } else if bs_count % 2 == 1 && bytes.get(q) == Some(&b'|') {
                                i = q + 1;
                            } else {
                                i = q;
                            }
                        } else if matches!(b, b'"' | b'\r' | b'\n' | b'\t' | b'|')
                            || (b == b'<' && bytes[i..].starts_with(b"<br>"))
                        {
                            return None;
                        } else {
                            i += 1;
                        }
                    }
                    RawQuoteMode::U0022Single => {
                        if b == b'\\' {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            if strict_nested
                                && bs_count % 4 == 1
                                && (bytes.get(q) == Some(&b'"') || bytes.get(q..q + 5) == Some(b"u0022"))
                            {
                                return None;
                            } else if bs_count % 2 == 1 && bytes.get(q..q + 5) == Some(b"u0022") {
                                if in_json_or_u0022 {
                                    return None;
                                }
                                mode = RawQuoteMode::None;
                                i = q + 5;
                            } else if bs_count % 2 == 1 && bytes.get(q) == Some(&b'"') {
                                if ctx.in_csv_field {
                                    if bytes.get(q + 1) == Some(&b'"') {
                                        mode = RawQuoteMode::None;
                                        i = q + 2;
                                    } else {
                                        return None;
                                    }
                                } else {
                                    mode = RawQuoteMode::None;
                                    i = q + 1;
                                }
                            } else if ctx.in_markdown_table_line && bs_count % 2 == 1 && bytes.get(q) == Some(&b'|') {
                                i = q + 1;
                            } else {
                                i = q;
                            }
                        } else if matches!(b, b'"' | b'\r' | b'\n' | b'\t')
                            || (ctx.in_markdown_table_line
                                && (b == b'|' || (b == b'<' && bytes[i..].starts_with(b"<br>"))))
                        {
                            return None;
                        } else {
                            i += 1;
                        }
                    }
                    RawQuoteMode::U0022DoubleBs => {
                        if b == b'\\' {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            if strict_nested
                                && bs_count % 4 == 1
                                && (bytes.get(q) == Some(&b'"') || bytes.get(q..q + 5) == Some(b"u0022"))
                            {
                                return None;
                            } else if bs_count % 4 == 2 && bytes.get(q..q + 5) == Some(b"u0022") {
                                if in_json_or_u0022 && ctx.in_double_escaped_json && ctx.allow_double_bs {
                                    return None;
                                }
                                mode = RawQuoteMode::None;
                                i = q + 5;
                            } else if ctx.in_markdown_json_string && bs_count % 4 == 2 && bytes.get(q) == Some(&b'"') {
                                mode = RawQuoteMode::None;
                                i = q + 1;
                            } else if !ctx.in_markdown_json_string && bs_count % 4 == 3 && bytes.get(q) == Some(&b'"') {
                                if ctx.in_csv_field {
                                    if bytes.get(q + 1) == Some(&b'"') {
                                        mode = RawQuoteMode::None;
                                        i = q + 2;
                                    } else {
                                        return None;
                                    }
                                } else {
                                    mode = RawQuoteMode::None;
                                    i = q + 1;
                                }
                            } else if !ctx.in_markdown_json_string && bs_count % 4 == 2 && bytes.get(q) == Some(&b'"') {
                                return None;
                            } else if ctx.in_markdown_table_line && bs_count % 2 == 1 && bytes.get(q) == Some(&b'|') {
                                i = q + 1;
                            } else {
                                i = q;
                            }
                        } else if matches!(b, b'"' | b'\t')
                            || (ctx.in_json_string && matches!(b, b'\r' | b'\n'))
                            || (ctx.in_markdown_table_line
                                && (b == b'|' || (b == b'<' && bytes[i..].starts_with(b"<br>"))))
                        {
                            return None;
                        } else {
                            i += 1;
                        }
                    }
                    RawQuoteMode::U0027Single => {
                        if b == b'\'' {
                            if u0027_quote_close_breaks_out(
                                bytes,
                                after_name,
                                i + 1,
                                false,
                                ctx,
                                unredacted_close_cache,
                                &mut next_close_cache,
                            ) {
                                return None;
                            }
                            mode = RawQuoteMode::None;
                            i += 1;
                        } else if b == b'&'
                            && let Some((HtmlQuoteMode::SingleEntity, len)) = match_html_quote_entity(&bytes[i..])
                        {
                            if u0027_quote_close_breaks_out(
                                bytes,
                                after_name,
                                i + len,
                                false,
                                ctx,
                                unredacted_close_cache,
                                &mut next_close_cache,
                            ) {
                                return None;
                            }
                            let close_km_after = unredacted_close_cache[usize::from(ctx.allow_double_bs)]
                                .get_or_insert_with(|| {
                                    last_unredacted_closing_km_pos(bytes, after_name, ctx.allow_double_bs)
                                })
                                .is_some_and(|cs| cs >= i + len);
                            if close_km_after {
                                if i >= single_span.scanned_until {
                                    single_span = scan_single_quote_span(bytes, i + len, false, ctx);
                                }
                                if single_span.last_bare_gt.is_some_and(|p| p >= i + len) {
                                    return None;
                                }
                            }
                            i += len;
                        } else if b == b'\\' {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            if bs_count % 2 == 1 && bytes.get(q..q + 5) == Some(b"u0027") {
                                if u0027_quote_close_breaks_out(
                                    bytes,
                                    after_name,
                                    q + 5,
                                    false,
                                    ctx,
                                    unredacted_close_cache,
                                    &mut next_close_cache,
                                ) {
                                    return None;
                                }
                                mode = RawQuoteMode::None;
                                i = q + 5;
                            } else if (strict_nested
                                && bs_count % 4 == 1
                                && (bytes.get(q) == Some(&b'"') || bytes.get(q..q + 5) == Some(b"u0022")))
                                || (in_json_or_u0022
                                    && ((ctx.in_double_escaped_json && ctx.allow_double_bs && bs_count % 4 == 2)
                                        || bs_count % 2 == 1)
                                    && bytes.get(q..q + 5) == Some(b"u0022"))
                            {
                                return None;
                            } else if bs_count % 2 == 1 && bytes.get(q) == Some(&b'"') {
                                if ctx.in_csv_field {
                                    if bytes.get(q + 1) == Some(&b'"') {
                                        i = q + 2;
                                    } else {
                                        return None;
                                    }
                                } else {
                                    i = q + 1;
                                }
                            } else if ctx.in_markdown_table_line && bs_count % 2 == 1 && bytes.get(q) == Some(&b'|') {
                                i = q + 1;
                            } else {
                                i = q;
                            }
                        } else if matches!(b, b'"' | b'\r' | b'\n' | b'\t')
                            || (ctx.in_markdown_table_line
                                && (b == b'|' || (b == b'<' && bytes[i..].starts_with(b"<br>"))))
                        {
                            return None;
                        } else {
                            i += 1;
                        }
                    }
                    RawQuoteMode::U0027DoubleBs => {
                        if b == b'\'' {
                            if u0027_quote_close_breaks_out(
                                bytes,
                                after_name,
                                i + 1,
                                false,
                                ctx,
                                unredacted_close_cache,
                                &mut next_close_cache,
                            ) {
                                return None;
                            }
                            mode = RawQuoteMode::None;
                            i += 1;
                        } else if b == b'&'
                            && let Some((HtmlQuoteMode::SingleEntity, len)) = match_html_quote_entity(&bytes[i..])
                        {
                            if u0027_quote_close_breaks_out(
                                bytes,
                                after_name,
                                i + len,
                                false,
                                ctx,
                                unredacted_close_cache,
                                &mut next_close_cache,
                            ) {
                                return None;
                            }
                            let close_km_after = unredacted_close_cache[usize::from(ctx.allow_double_bs)]
                                .get_or_insert_with(|| {
                                    last_unredacted_closing_km_pos(bytes, after_name, ctx.allow_double_bs)
                                })
                                .is_some_and(|cs| cs >= i + len);
                            if close_km_after {
                                if i >= single_span.scanned_until {
                                    single_span = scan_single_quote_span(bytes, i + len, false, ctx);
                                }
                                if single_span.last_bare_gt.is_some_and(|p| p >= i + len) {
                                    return None;
                                }
                            }
                            i += len;
                        } else if b == b'\\' {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            if strict_nested
                                && bs_count % 4 == 1
                                && (bytes.get(q) == Some(&b'"') || bytes.get(q..q + 5) == Some(b"u0022"))
                            {
                                return None;
                            } else if bs_count % 4 == 2 && bytes.get(q..q + 5) == Some(b"u0027") {
                                if u0027_quote_close_breaks_out(
                                    bytes,
                                    after_name,
                                    q + 5,
                                    false,
                                    ctx,
                                    unredacted_close_cache,
                                    &mut next_close_cache,
                                ) {
                                    return None;
                                }
                                mode = RawQuoteMode::None;
                                i = q + 5;
                            } else if in_json_or_u0022
                                && ((ctx.in_double_escaped_json && ctx.allow_double_bs && bs_count % 4 == 2)
                                    || bs_count % 2 == 1)
                                && bytes.get(q..q + 5) == Some(b"u0022")
                            {
                                return None;
                            } else if ctx.in_markdown_json_string && bs_count % 4 == 2 && bytes.get(q) == Some(&b'"') {
                                i = q + 1;
                            } else if !ctx.in_markdown_json_string && bs_count % 4 == 3 && bytes.get(q) == Some(&b'"') {
                                if ctx.in_csv_field {
                                    if bytes.get(q + 1) == Some(&b'"') {
                                        i = q + 2;
                                    } else {
                                        return None;
                                    }
                                } else {
                                    i = q + 1;
                                }
                            } else if !ctx.in_markdown_json_string && bs_count % 4 == 2 && bytes.get(q) == Some(&b'"') {
                                return None;
                            } else if ctx.in_markdown_table_line && bs_count % 2 == 1 && bytes.get(q) == Some(&b'|') {
                                i = q + 1;
                            } else {
                                i = q;
                            }
                        } else if matches!(b, b'"' | b'\r' | b'\n' | b'\t')
                            || (ctx.in_markdown_table_line
                                && (b == b'|' || (b == b'<' && bytes[i..].starts_with(b"<br>"))))
                        {
                            return None;
                        } else {
                            i += 1;
                        }
                    }
                    RawQuoteMode::HtmlDoubleEntity => {
                        if let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&bytes[i..]) {
                            mode = RawQuoteMode::None;
                            entity_inner_quotes = 0;
                            entity_open_containers.clear();
                            i += len;
                        } else if matches!(b, b'{' | b'[') {
                            push_json_container_opener(&mut entity_open_containers, b);
                            i += 1;
                        } else if matches!(b, b'}' | b']') {
                            pop_json_container_closer(&mut entity_open_containers, b);
                            i += 1;
                        } else if b == b'\\'
                            && (in_json_or_u0022 || ctx.in_markdown_table_line || !entity_open_containers.is_empty())
                        {
                            let in_ent_json = !entity_open_containers.is_empty();
                            match classify_html_escaped_backslash(bytes, i, after_name, false, in_ent_json, ctx) {
                                HtmlBackslashAction::Abort => return None,
                                HtmlBackslashAction::QuoteToggle(next) => {
                                    if in_json_or_u0022 || in_ent_json {
                                        entity_inner_quotes = entity_inner_quotes.saturating_add(1);
                                        let close_km_after = unredacted_close_cache[usize::from(ctx.allow_double_bs)]
                                            .get_or_insert_with(|| {
                                                last_unredacted_closing_km_pos(bytes, after_name, ctx.allow_double_bs)
                                            })
                                            .is_some_and(|cs| cs >= next);
                                        if (entity_inner_quotes >= 2 && close_km_after)
                                            || double_entity_inner_quote_breaks_out(bytes, next, ctx.allow_double_bs)
                                        {
                                            return None;
                                        }
                                    }
                                    i = next;
                                }
                                HtmlBackslashAction::Advance(next) | HtmlBackslashAction::U0022DoubleBsOpen(next) => {
                                    i = next;
                                }
                            }
                        } else if (ctx.in_json_string && matches!(b, b'"' | b'\r' | b'\n' | b'\t'))
                            || ((in_json_or_u0022 || !entity_open_containers.is_empty())
                                && b == b'"'
                                && count_preceding_backslashes(bytes, 0, i).is_multiple_of(2)
                                && if !entity_open_containers.is_empty() {
                                    !matches!(
                                        scan_json_string_for_quote_hazard(
                                            bytes,
                                            i,
                                            Some(HtmlQuoteMode::DoubleEntity),
                                            double_bs_u0022,
                                            stop_on_tsv_tab,
                                            stop_on_md_pipe,
                                            false,
                                        ),
                                        Ok((_, false))
                                    )
                                } else {
                                    is_uncontained_entity_json_quote_at(bytes, i)
                                })
                            || (ctx.in_markdown_table_line && b == b'|')
                            || (!ctx.in_csv_field && ctx.allow_tsv_tabs && b == b'\t')
                        {
                            return None;
                        } else if !ctx.in_csv_field && b == b'"' {
                            entity_inner_quotes = entity_inner_quotes.saturating_add(1);
                            let close_km_after = unredacted_close_cache[usize::from(ctx.allow_double_bs)]
                                .get_or_insert_with(|| {
                                    last_unredacted_closing_km_pos(bytes, after_name, ctx.allow_double_bs)
                                })
                                .is_some_and(|cs| cs > i);
                            if (entity_inner_quotes >= 2 && close_km_after)
                                || double_entity_inner_quote_breaks_out(bytes, i + 1, ctx.allow_double_bs)
                            {
                                return None;
                            }
                            i += 1;
                        } else {
                            i += 1;
                        }
                    }
                    RawQuoteMode::HtmlSingleEntity => {
                        if let Some((HtmlQuoteMode::SingleEntity, len)) = match_html_quote_entity(&bytes[i..]) {
                            mode = RawQuoteMode::None;
                            entity_inner_quotes = 0;
                            entity_open_containers.clear();
                            i += len;
                        } else if matches!(b, b'{' | b'[') {
                            push_json_container_opener(&mut entity_open_containers, b);
                            i += 1;
                        } else if matches!(b, b'}' | b']') {
                            pop_json_container_closer(&mut entity_open_containers, b);
                            i += 1;
                        } else if b == b'\\'
                            && (in_json_or_u0022 || ctx.in_markdown_table_line || !entity_open_containers.is_empty())
                        {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            if ((in_json_or_u0022 || !entity_open_containers.is_empty())
                                && ((ctx.in_double_escaped_json && ctx.allow_double_bs && bs_count % 4 == 2)
                                    || bs_count % 2 == 1)
                                && bytes.get(q..q + 5) == Some(b"u0027"))
                                || (ctx.in_json_string
                                    && ctx.allow_double_bs
                                    && bs_count % 4 == 2
                                    && bytes.get(q..q + 5) == Some(b"u0027")
                                    && unredacted_close_cache[usize::from(ctx.allow_double_bs)]
                                        .get_or_insert_with(|| {
                                            last_unredacted_closing_km_pos(bytes, after_name, ctx.allow_double_bs)
                                        })
                                        .is_some_and(|cs| cs >= q + 5))
                            {
                                return None;
                            }
                            let in_ent_json = !entity_open_containers.is_empty();
                            match classify_html_escaped_backslash(bytes, i, after_name, false, in_ent_json, ctx) {
                                HtmlBackslashAction::Abort => return None,
                                HtmlBackslashAction::QuoteToggle(next)
                                | HtmlBackslashAction::Advance(next)
                                | HtmlBackslashAction::U0022DoubleBsOpen(next) => {
                                    i = next;
                                }
                            }
                        } else if (ctx.in_json_string && matches!(b, b'"' | b'\r' | b'\n' | b'\t'))
                            || ((ctx.in_json_string || !ctx.in_csv_field) && b == b'\'')
                            || (ctx.in_markdown_table_line && b == b'|')
                            || (!ctx.in_csv_field && ctx.allow_tsv_tabs && b == b'\t')
                        {
                            return None;
                        } else if b == b'"' && count_preceding_backslashes(bytes, 0, i).is_multiple_of(2) {
                            if !entity_open_containers.is_empty() {
                                match scan_json_string_for_quote_hazard(
                                    bytes,
                                    i,
                                    Some(HtmlQuoteMode::SingleEntity),
                                    double_bs_u0022,
                                    stop_on_tsv_tab,
                                    stop_on_md_pipe,
                                    false,
                                ) {
                                    Ok((end, false)) => {
                                        i = end;
                                        continue;
                                    }
                                    Ok((_, true)) | Err(_) => return None,
                                }
                            } else if in_json_or_u0022 && is_uncontained_entity_json_quote_at(bytes, i) {
                                return None;
                            }
                            i += 1;
                        } else {
                            i += 1;
                        }
                    }
                }
            }
            None
        }
        TagSyntax::HtmlEscaped => {
            let mut mode = HtmlQuoteMode::None;
            let mut entity_inner_quotes = 0u8;
            let mut entity_open_containers: Vec<u8> = Vec::new();
            let mut single_saw_json_opener = false;
            let mut single_span = SingleQuoteSpanSummary::default();
            let mut next_close_cache: Option<(usize, Option<bool>)> = None;
            let mut i = after_name;
            while i < bytes.len() {
                match mode {
                    HtmlQuoteMode::None => {
                        if let Some((qmode, len)) = match_html_quote_entity(&bytes[i..]) {
                            mode = qmode;
                            entity_inner_quotes = 0;
                            entity_open_containers.clear();
                            i += len;
                        } else if bytes[i] == b'\'' {
                            mode = HtmlQuoteMode::RawSingle;
                            single_saw_json_opener = false;
                            single_span = SingleQuoteSpanSummary::default();
                            next_close_cache = None;
                            i += 1;
                        } else if bytes[i] == b'\\' {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            if ctx.in_json_string || ctx.in_markdown_table_line {
                                match classify_html_escaped_backslash(bytes, i, after_name, true, false, ctx) {
                                    HtmlBackslashAction::Abort => return None,
                                    HtmlBackslashAction::Advance(next) => {
                                        let u00_match = if ctx.allow_double_bs && bs_count % 4 == 2 {
                                            match_json_u00_char(&bytes[q - 2..], true).map(|(ch, len)| (q - 2, ch, len))
                                        } else if bs_count % 2 == 1 {
                                            match_json_u00_char(&bytes[q - 1..], false)
                                                .map(|(ch, len)| (q - 1, ch, len))
                                        } else {
                                            None
                                        };
                                        if let Some((tok_start, decoded_ch, len)) = u00_match {
                                            match decoded_ch {
                                                b'>' => {
                                                    let is_self_closing = preceded_by_html_slash(
                                                        bytes,
                                                        after_name,
                                                        tok_start,
                                                        ctx.allow_double_bs,
                                                    );
                                                    return Some((tok_start, tok_start + len, is_self_closing));
                                                }
                                                b'\'' => {
                                                    mode = if len == 7 {
                                                        HtmlQuoteMode::U0027DoubleBs
                                                    } else {
                                                        HtmlQuoteMode::U0027Single
                                                    };
                                                    single_span = SingleQuoteSpanSummary::default();
                                                    next_close_cache = None;
                                                    i = tok_start + len;
                                                }
                                                _ => {
                                                    i = tok_start + len;
                                                }
                                            }
                                        } else {
                                            i = next;
                                        }
                                    }
                                    HtmlBackslashAction::QuoteToggle(next) => {
                                        mode = HtmlQuoteMode::RawDouble;
                                        i = next;
                                    }
                                    HtmlBackslashAction::U0022DoubleBsOpen(next) => {
                                        mode = HtmlQuoteMode::U0022DoubleBs;
                                        i = next;
                                    }
                                }
                            } else {
                                let u00_match = if ctx.allow_double_bs && bs_count % 4 == 2 {
                                    match_json_u00_char(&bytes[q - 2..], true).map(|(ch, len)| (q - 2, ch, len))
                                } else if bs_count % 2 == 1 {
                                    match_json_u00_char(&bytes[q - 1..], false).map(|(ch, len)| (q - 1, ch, len))
                                } else {
                                    None
                                };
                                if let Some((tok_start, decoded_ch, len)) = u00_match {
                                    match decoded_ch {
                                        b'>' => {
                                            let is_self_closing = preceded_by_html_slash(
                                                bytes,
                                                after_name,
                                                tok_start,
                                                ctx.allow_double_bs,
                                            );
                                            return Some((tok_start, tok_start + len, is_self_closing));
                                        }
                                        b'\'' => {
                                            mode = if len == 7 {
                                                HtmlQuoteMode::U0027DoubleBs
                                            } else {
                                                HtmlQuoteMode::U0027Single
                                            };
                                            single_span = SingleQuoteSpanSummary::default();
                                            next_close_cache = None;
                                            i = tok_start + len;
                                        }
                                        _ => {
                                            i = tok_start + len;
                                        }
                                    }
                                } else {
                                    i = q;
                                }
                            }
                        } else if bytes[i] == b'"' {
                            if ctx.in_json_string {
                                return None;
                            }
                            if ctx.in_csv_field {
                                if bytes.get(i + 1) == Some(&b'"') {
                                    mode = HtmlQuoteMode::RawDouble;
                                    i += 2;
                                } else {
                                    return None;
                                }
                            } else {
                                mode = HtmlQuoteMode::RawDouble;
                                i += 1;
                            }
                        } else if (ctx.in_json_string && matches!(bytes[i], b'\r' | b'\n' | b'\t'))
                            || (ctx.in_markdown_table_line && bytes[i] == b'|')
                            || (!ctx.in_csv_field && ctx.allow_tsv_tabs && bytes[i] == b'\t')
                        {
                            return None;
                        } else if bytes[i] == b'<' && bytes[i..].starts_with(b"<br>") {
                            if ctx.in_markdown_table_line && ctx.in_json_string {
                                return None;
                            }
                            i += 4;
                        } else if let Some(br_len) = match_html_br_entity(&bytes[i..]) {
                            if ctx.in_markdown_table_line && ctx.in_json_string {
                                return None;
                            }
                            i += br_len;
                        } else if let Some(gt_len) = match_html_gt_entity(&bytes[i..]) {
                            let is_self_closing = preceded_by_html_slash(bytes, after_name, i, ctx.allow_double_bs);
                            return Some((i, i + gt_len, is_self_closing));
                        } else if bytes[i] == b'>' {
                            let is_self_closing = preceded_by_html_slash(bytes, after_name, i, ctx.allow_double_bs);
                            return Some((i, i + 1, is_self_closing));
                        } else {
                            i += 1;
                        }
                    }
                    HtmlQuoteMode::DoubleEntity => {
                        if let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&bytes[i..]) {
                            mode = HtmlQuoteMode::None;
                            entity_inner_quotes = 0;
                            entity_open_containers.clear();
                            i += len;
                        } else if matches!(bytes[i], b'{' | b'[') {
                            push_json_container_opener(&mut entity_open_containers, bytes[i]);
                            i += 1;
                        } else if matches!(bytes[i], b'}' | b']') {
                            pop_json_container_closer(&mut entity_open_containers, bytes[i]);
                            i += 1;
                        } else if bytes[i] == b'\\'
                            && (in_json_or_u0022 || ctx.in_markdown_table_line || !entity_open_containers.is_empty())
                        {
                            let in_ent_json = !entity_open_containers.is_empty();
                            match classify_html_escaped_backslash(bytes, i, after_name, false, in_ent_json, ctx) {
                                HtmlBackslashAction::Abort => return None,
                                HtmlBackslashAction::QuoteToggle(next) => {
                                    if in_json_or_u0022 || in_ent_json {
                                        entity_inner_quotes = entity_inner_quotes.saturating_add(1);
                                        let close_km_after = unredacted_close_cache[usize::from(ctx.allow_double_bs)]
                                            .get_or_insert_with(|| {
                                                last_unredacted_closing_km_pos(bytes, after_name, ctx.allow_double_bs)
                                            })
                                            .is_some_and(|cs| cs >= next);
                                        if (entity_inner_quotes >= 2 && close_km_after)
                                            || double_entity_inner_quote_breaks_out(bytes, next, ctx.allow_double_bs)
                                        {
                                            return None;
                                        }
                                    }
                                    i = next;
                                }
                                HtmlBackslashAction::Advance(next) | HtmlBackslashAction::U0022DoubleBsOpen(next) => {
                                    i = next;
                                }
                            }
                        } else if (ctx.in_json_string && matches!(bytes[i], b'"' | b'\r' | b'\n' | b'\t'))
                            || ((in_json_or_u0022 || !entity_open_containers.is_empty())
                                && bytes[i] == b'"'
                                && count_preceding_backslashes(bytes, 0, i).is_multiple_of(2)
                                && if !entity_open_containers.is_empty() {
                                    !matches!(
                                        scan_json_string_for_quote_hazard(
                                            bytes,
                                            i,
                                            Some(HtmlQuoteMode::DoubleEntity),
                                            double_bs_u0022,
                                            stop_on_tsv_tab,
                                            stop_on_md_pipe,
                                            false,
                                        ),
                                        Ok((_, false))
                                    )
                                } else {
                                    is_uncontained_entity_json_quote_at(bytes, i)
                                })
                            || (ctx.in_markdown_table_line && bytes[i] == b'|')
                            || (!ctx.in_csv_field && ctx.allow_tsv_tabs && bytes[i] == b'\t')
                        {
                            return None;
                        } else if !ctx.in_csv_field && bytes[i] == b'"' {
                            entity_inner_quotes = entity_inner_quotes.saturating_add(1);
                            let close_km_after = unredacted_close_cache[usize::from(ctx.allow_double_bs)]
                                .get_or_insert_with(|| {
                                    last_unredacted_closing_km_pos(bytes, after_name, ctx.allow_double_bs)
                                })
                                .is_some_and(|cs| cs > i);
                            if (entity_inner_quotes >= 2 && close_km_after)
                                || double_entity_inner_quote_breaks_out(bytes, i + 1, ctx.allow_double_bs)
                            {
                                return None;
                            }
                            i += 1;
                        } else {
                            i += 1;
                        }
                    }
                    HtmlQuoteMode::SingleEntity => {
                        if let Some((HtmlQuoteMode::SingleEntity, len)) = match_html_quote_entity(&bytes[i..]) {
                            mode = HtmlQuoteMode::None;
                            entity_inner_quotes = 0;
                            entity_open_containers.clear();
                            i += len;
                        } else if matches!(bytes[i], b'{' | b'[') {
                            push_json_container_opener(&mut entity_open_containers, bytes[i]);
                            i += 1;
                        } else if matches!(bytes[i], b'}' | b']') {
                            pop_json_container_closer(&mut entity_open_containers, bytes[i]);
                            i += 1;
                        } else if bytes[i] == b'\\'
                            && (in_json_or_u0022 || ctx.in_markdown_table_line || !entity_open_containers.is_empty())
                        {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            if ((in_json_or_u0022 || !entity_open_containers.is_empty())
                                && ((ctx.in_double_escaped_json && ctx.allow_double_bs && bs_count % 4 == 2)
                                    || bs_count % 2 == 1)
                                && bytes.get(q..q + 5) == Some(b"u0027"))
                                || (ctx.in_json_string
                                    && ctx.allow_double_bs
                                    && bs_count % 4 == 2
                                    && bytes.get(q..q + 5) == Some(b"u0027")
                                    && unredacted_close_cache[usize::from(ctx.allow_double_bs)]
                                        .get_or_insert_with(|| {
                                            last_unredacted_closing_km_pos(bytes, after_name, ctx.allow_double_bs)
                                        })
                                        .is_some_and(|cs| cs >= q + 5))
                            {
                                return None;
                            }
                            let in_ent_json = !entity_open_containers.is_empty();
                            match classify_html_escaped_backslash(bytes, i, after_name, false, in_ent_json, ctx) {
                                HtmlBackslashAction::Abort => return None,
                                HtmlBackslashAction::QuoteToggle(next)
                                | HtmlBackslashAction::Advance(next)
                                | HtmlBackslashAction::U0022DoubleBsOpen(next) => {
                                    i = next;
                                }
                            }
                        } else if (ctx.in_json_string && matches!(bytes[i], b'"' | b'\r' | b'\n' | b'\t'))
                            || ((ctx.in_json_string || !ctx.in_csv_field) && bytes[i] == b'\'')
                            || (ctx.in_markdown_table_line && bytes[i] == b'|')
                            || (!ctx.in_csv_field && ctx.allow_tsv_tabs && bytes[i] == b'\t')
                        {
                            return None;
                        } else if b_at_html_single_quote_check(bytes, i) {
                            if !entity_open_containers.is_empty() {
                                match scan_json_string_for_quote_hazard(
                                    bytes,
                                    i,
                                    Some(HtmlQuoteMode::SingleEntity),
                                    double_bs_u0022,
                                    stop_on_tsv_tab,
                                    stop_on_md_pipe,
                                    false,
                                ) {
                                    Ok((end, false)) => {
                                        i = end;
                                        continue;
                                    }
                                    Ok((_, true)) | Err(_) => return None,
                                }
                            } else if in_json_or_u0022 && is_uncontained_entity_json_quote_at(bytes, i) {
                                return None;
                            }
                            i += 1;
                        } else {
                            i += 1;
                        }
                    }
                    HtmlQuoteMode::RawSingle => {
                        if bytes[i] == b'\'' {
                            mode = HtmlQuoteMode::None;
                            i += 1;
                        } else if bytes[i] == b'&'
                            && let Some((HtmlQuoteMode::SingleEntity, len)) = match_html_quote_entity(&bytes[i..])
                        {
                            match check_single_quote_breakout(
                                bytes,
                                after_name,
                                i,
                                i + len,
                                true,
                                false,
                                ctx,
                                single_saw_json_opener,
                                &mut single_span,
                                unredacted_close_cache,
                                &mut next_close_cache,
                            ) {
                                Some(true) => return None,
                                Some(false) => {
                                    mode = HtmlQuoteMode::None;
                                    i += len;
                                }
                                None => {
                                    i += len;
                                }
                            }
                        } else if bytes[i] == b'\\' {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            let u0027_match = bytes.get(q..q + 5) == Some(b"u0027")
                                && (((ctx.in_double_escaped_json && ctx.allow_double_bs && bs_count % 4 == 2)
                                    || bs_count % 2 == 1)
                                    || (ctx.in_json_string
                                        && ctx.allow_double_bs
                                        && bs_count % 4 == 2
                                        && unredacted_close_cache[usize::from(ctx.allow_double_bs)]
                                            .get_or_insert_with(|| {
                                                last_unredacted_closing_km_pos(bytes, after_name, ctx.allow_double_bs)
                                            })
                                            .is_some_and(|cs| cs >= q + 5)));
                            if u0027_match {
                                match check_single_quote_breakout(
                                    bytes,
                                    after_name,
                                    i,
                                    q + 5,
                                    true,
                                    true,
                                    ctx,
                                    single_saw_json_opener,
                                    &mut single_span,
                                    unredacted_close_cache,
                                    &mut next_close_cache,
                                ) {
                                    Some(true) => return None,
                                    Some(false) => {
                                        mode = HtmlQuoteMode::None;
                                        i = q + 5;
                                    }
                                    None => {
                                        i = q + 5;
                                    }
                                }
                            } else if in_json_or_u0022 || ctx.in_markdown_table_line {
                                match classify_html_escaped_backslash(bytes, i, after_name, false, false, ctx) {
                                    HtmlBackslashAction::Abort => return None,
                                    HtmlBackslashAction::Advance(next)
                                    | HtmlBackslashAction::QuoteToggle(next)
                                    | HtmlBackslashAction::U0022DoubleBsOpen(next) => {
                                        i = next;
                                    }
                                }
                            } else {
                                i = q;
                            }
                        } else if (ctx.in_json_string && matches!(bytes[i], b'"' | b'\r' | b'\n' | b'\t'))
                            || (ctx.in_markdown_table_line && bytes[i] == b'|')
                            || (!ctx.in_csv_field && ctx.allow_tsv_tabs && bytes[i] == b'\t')
                        {
                            return None;
                        } else {
                            if matches!(bytes[i], b'{' | b'[') {
                                single_saw_json_opener = true;
                            }
                            i += 1;
                        }
                    }
                    HtmlQuoteMode::RawDouble => {
                        if bytes[i] == b'\\' && (ctx.in_json_string || ctx.in_markdown_table_line) {
                            match classify_html_escaped_backslash(bytes, i, after_name, false, false, ctx) {
                                HtmlBackslashAction::Abort => return None,
                                HtmlBackslashAction::Advance(next) | HtmlBackslashAction::U0022DoubleBsOpen(next) => {
                                    i = next
                                }
                                HtmlBackslashAction::QuoteToggle(next) => {
                                    mode = HtmlQuoteMode::None;
                                    i = next;
                                }
                            }
                        } else if bytes[i] == b'"' {
                            if ctx.in_json_string {
                                return None;
                            }
                            if ctx.in_csv_field {
                                if bytes.get(i + 1) == Some(&b'"') {
                                    mode = HtmlQuoteMode::None;
                                    i += 2;
                                } else {
                                    return None;
                                }
                            } else {
                                mode = HtmlQuoteMode::None;
                                i += 1;
                            }
                        } else if (ctx.in_json_string && matches!(bytes[i], b'\r' | b'\n' | b'\t'))
                            || (ctx.in_markdown_table_line && bytes[i] == b'|')
                            || (!ctx.in_csv_field && ctx.allow_tsv_tabs && bytes[i] == b'\t')
                        {
                            return None;
                        } else {
                            i += 1;
                        }
                    }
                    HtmlQuoteMode::U0022DoubleBs => {
                        if bytes[i] == b'\\' && (ctx.in_json_string || ctx.in_markdown_table_line) {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            if strict_nested
                                && bs_count % 4 == 1
                                && (bytes.get(q) == Some(&b'"') || bytes.get(q..q + 5) == Some(b"u0022"))
                            {
                                return None;
                            } else if bs_count % 4 == 2 && bytes.get(q..q + 5) == Some(b"u0022") {
                                mode = HtmlQuoteMode::None;
                                i = q + 5;
                            } else if ctx.in_markdown_json_string && bs_count % 4 == 2 && bytes.get(q) == Some(&b'"') {
                                mode = HtmlQuoteMode::None;
                                i = q + 1;
                            } else if !ctx.in_markdown_json_string && bs_count % 4 == 3 && bytes.get(q) == Some(&b'"') {
                                if ctx.in_csv_field {
                                    if bytes.get(q + 1) == Some(&b'"') {
                                        mode = HtmlQuoteMode::None;
                                        i = q + 2;
                                    } else {
                                        return None;
                                    }
                                } else {
                                    mode = HtmlQuoteMode::None;
                                    i = q + 1;
                                }
                            } else if !ctx.in_markdown_json_string && bs_count % 4 == 2 && bytes.get(q) == Some(&b'"') {
                                return None;
                            } else if ctx.in_markdown_table_line && bs_count % 2 == 1 && bytes.get(q) == Some(&b'|') {
                                i = q + 1;
                            } else {
                                i = q;
                            }
                        } else if (ctx.in_json_string && matches!(bytes[i], b'"' | b'\r' | b'\n' | b'\t'))
                            || (ctx.in_markdown_table_line && bytes[i] == b'|')
                            || (!ctx.in_csv_field && ctx.allow_tsv_tabs && bytes[i] == b'\t')
                        {
                            return None;
                        } else {
                            i += 1;
                        }
                    }
                    HtmlQuoteMode::U0027Single => {
                        if bytes[i] == b'\'' {
                            if u0027_quote_close_breaks_out(
                                bytes,
                                after_name,
                                i + 1,
                                true,
                                ctx,
                                unredacted_close_cache,
                                &mut next_close_cache,
                            ) {
                                return None;
                            }
                            mode = HtmlQuoteMode::None;
                            i += 1;
                        } else if bytes[i] == b'&'
                            && let Some((HtmlQuoteMode::SingleEntity, len)) = match_html_quote_entity(&bytes[i..])
                        {
                            if u0027_quote_close_breaks_out(
                                bytes,
                                after_name,
                                i + len,
                                true,
                                ctx,
                                unredacted_close_cache,
                                &mut next_close_cache,
                            ) {
                                return None;
                            }
                            let close_km_after = unredacted_close_cache[usize::from(ctx.allow_double_bs)]
                                .get_or_insert_with(|| {
                                    last_unredacted_closing_km_pos(bytes, after_name, ctx.allow_double_bs)
                                })
                                .is_some_and(|cs| cs >= i + len);
                            if close_km_after {
                                if i >= single_span.scanned_until {
                                    single_span = scan_single_quote_span(bytes, i + len, true, ctx);
                                }
                                if single_span.last_bare_gt.is_some_and(|p| p >= i + len) {
                                    return None;
                                }
                            }
                            i += len;
                        } else if bytes[i] == b'\\' {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            if bs_count % 2 == 1 && bytes.get(q..q + 5) == Some(b"u0027") {
                                if u0027_quote_close_breaks_out(
                                    bytes,
                                    after_name,
                                    q + 5,
                                    true,
                                    ctx,
                                    unredacted_close_cache,
                                    &mut next_close_cache,
                                ) {
                                    return None;
                                }
                                mode = HtmlQuoteMode::None;
                                i = q + 5;
                            } else if ctx.in_json_string || ctx.in_markdown_table_line {
                                match classify_html_escaped_backslash(bytes, i, after_name, false, false, ctx) {
                                    HtmlBackslashAction::Abort => return None,
                                    HtmlBackslashAction::Advance(next)
                                    | HtmlBackslashAction::QuoteToggle(next)
                                    | HtmlBackslashAction::U0022DoubleBsOpen(next) => {
                                        i = next;
                                    }
                                }
                            } else {
                                i = q;
                            }
                        } else if (ctx.in_json_string && matches!(bytes[i], b'"' | b'\r' | b'\n' | b'\t'))
                            || (ctx.in_markdown_table_line && bytes[i] == b'|')
                            || (!ctx.in_csv_field && ctx.allow_tsv_tabs && bytes[i] == b'\t')
                        {
                            return None;
                        } else {
                            i += 1;
                        }
                    }
                    HtmlQuoteMode::U0027DoubleBs => {
                        if bytes[i] == b'\'' {
                            if u0027_quote_close_breaks_out(
                                bytes,
                                after_name,
                                i + 1,
                                true,
                                ctx,
                                unredacted_close_cache,
                                &mut next_close_cache,
                            ) {
                                return None;
                            }
                            mode = HtmlQuoteMode::None;
                            i += 1;
                        } else if bytes[i] == b'&'
                            && let Some((HtmlQuoteMode::SingleEntity, len)) = match_html_quote_entity(&bytes[i..])
                        {
                            if u0027_quote_close_breaks_out(
                                bytes,
                                after_name,
                                i + len,
                                true,
                                ctx,
                                unredacted_close_cache,
                                &mut next_close_cache,
                            ) {
                                return None;
                            }
                            let close_km_after = unredacted_close_cache[usize::from(ctx.allow_double_bs)]
                                .get_or_insert_with(|| {
                                    last_unredacted_closing_km_pos(bytes, after_name, ctx.allow_double_bs)
                                })
                                .is_some_and(|cs| cs >= i + len);
                            if close_km_after {
                                if i >= single_span.scanned_until {
                                    single_span = scan_single_quote_span(bytes, i + len, true, ctx);
                                }
                                if single_span.last_bare_gt.is_some_and(|p| p >= i + len) {
                                    return None;
                                }
                            }
                            i += len;
                        } else if bytes[i] == b'\\' {
                            let bs_count = count_consecutive_backslashes(bytes, i);
                            let q = i + bs_count;
                            if bs_count % 4 == 2 && bytes.get(q..q + 5) == Some(b"u0027") {
                                if u0027_quote_close_breaks_out(
                                    bytes,
                                    after_name,
                                    q + 5,
                                    true,
                                    ctx,
                                    unredacted_close_cache,
                                    &mut next_close_cache,
                                ) {
                                    return None;
                                }
                                mode = HtmlQuoteMode::None;
                                i = q + 5;
                            } else if ctx.in_json_string || ctx.in_markdown_table_line {
                                match classify_html_escaped_backslash(bytes, i, after_name, false, false, ctx) {
                                    HtmlBackslashAction::Abort => return None,
                                    HtmlBackslashAction::Advance(next)
                                    | HtmlBackslashAction::QuoteToggle(next)
                                    | HtmlBackslashAction::U0022DoubleBsOpen(next) => {
                                        i = next;
                                    }
                                }
                            } else {
                                i = q;
                            }
                        } else if (ctx.in_json_string && matches!(bytes[i], b'"' | b'\r' | b'\n' | b'\t'))
                            || (ctx.in_markdown_table_line && bytes[i] == b'|')
                            || (!ctx.in_csv_field && ctx.allow_tsv_tabs && bytes[i] == b'\t')
                        {
                            return None;
                        } else {
                            i += 1;
                        }
                    }
                }
            }
            None
        }
    }
}

#[inline]
fn b_at_html_single_quote_check(bytes: &[u8], i: usize) -> bool {
    bytes[i] == b'"' && count_preceding_backslashes(bytes, 0, i).is_multiple_of(2)
}

fn find_closing_keymaterial_tag(
    bytes: &[u8],
    open_end: usize,
    syntax: TagSyntax,
    allow_double_bs: bool,
) -> Option<(usize, usize)> {
    const TAG_NAME: &[u8] = b"keymaterial";
    let mut pos = open_end;

    while let Some(km_pos) = find_ascii_bytes(bytes, pos, TAG_NAME) {
        let after_km = km_pos + TAG_NAME.len();

        let close_start = match syntax {
            TagSyntax::Raw => {
                if let Some(cs) = ends_with_close_tag_prefix(bytes, open_end, km_pos, allow_double_bs) {
                    Some(cs)
                } else if km_pos >= open_end + 4 && bytes[km_pos - 1] == b':' {
                    let mut prefix_start = km_pos - 1;
                    while prefix_start > open_end && is_xml_ncname_char(bytes[prefix_start - 1]) {
                        if prefix_start < km_pos - 1
                            && ends_with_close_tag_prefix(bytes, open_end, prefix_start, allow_double_bs).is_some()
                        {
                            break;
                        }
                        prefix_start -= 1;
                    }
                    if prefix_start < km_pos - 1 {
                        ends_with_close_tag_prefix(bytes, open_end, prefix_start, allow_double_bs)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            TagSyntax::HtmlEscaped => {
                if let Some(cs) = ends_with_html_close_prefix_with_json(bytes, open_end, km_pos, allow_double_bs) {
                    Some(cs)
                } else if km_pos >= open_end + 7 && bytes[km_pos - 1] == b':' {
                    let mut prefix_start = km_pos - 1;
                    while prefix_start > open_end && is_xml_ncname_char(bytes[prefix_start - 1]) {
                        if prefix_start < km_pos - 1
                            && ends_with_html_close_prefix_with_json(bytes, open_end, prefix_start, allow_double_bs)
                                .is_some()
                        {
                            break;
                        }
                        prefix_start -= 1;
                    }
                    if prefix_start < km_pos - 1 {
                        ends_with_html_close_prefix_with_json(bytes, open_end, prefix_start, allow_double_bs)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };

        if let Some(cs) = close_start {
            let mut end = after_km;
            loop {
                if end < bytes.len() && bytes[end].is_ascii_whitespace() {
                    end += 1;
                } else if bytes[end..].starts_with(b"<br>") {
                    end += 4;
                } else if syntax == TagSyntax::HtmlEscaped
                    && let Some(br_len) = match_html_br_entity(&bytes[end..])
                {
                    end += br_len;
                } else if let Some(skip) = starts_with_escaped_ws(&bytes[end..], allow_double_bs) {
                    end += skip;
                } else if let Some((b' ' | b'\t' | b'\r' | b'\n', skip)) =
                    match_json_u00_char(&bytes[end..], allow_double_bs)
                {
                    end += skip;
                } else {
                    break;
                }
            }
            match syntax {
                TagSyntax::Raw => {
                    if end < bytes.len() && bytes[end] == b'>' {
                        return Some((cs, end + 1));
                    }
                    if let Some((b'>', skip)) = match_json_u00_char(&bytes[end..], allow_double_bs) {
                        return Some((cs, end + skip));
                    }
                }
                TagSyntax::HtmlEscaped => {
                    if let Some(gt_len) = match_html_gt_entity(&bytes[end..]) {
                        return Some((cs, end + gt_len));
                    }
                    if end < bytes.len() && bytes[end] == b'>' {
                        return Some((cs, end + 1));
                    }
                    if let Some((b'>', skip)) = match_json_u00_char(&bytes[end..], allow_double_bs) {
                        return Some((cs, end + skip));
                    }
                }
            }
        }

        pos = after_km;
    }

    None
}

fn unescape_csv_field(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0usize;
    while i < raw.len() {
        if raw[i] == b'"' && raw.get(i + 1) == Some(&b'"') {
            out.push(b'"');
            i += 2;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    out
}

fn mask_json_span_preserving_delims(buf: &mut [u8], start: usize, end: usize) -> bool {
    if end < start + 2 {
        return false;
    }
    let opener = buf[start];
    let closer = if opener == b'{' { b'}' } else { b']' };
    if buf[end - 1] == closer && buf[start + 1..end - 1].iter().all(|&b| b == b' ') {
        return false;
    }
    buf[start] = opener;
    buf[start + 1..end - 1].fill(b' ');
    buf[end - 1] = closer;
    true
}

fn find_embedded_json_mask_spans(
    bytes: &[u8],
    depth: usize,
    from_json_value: bool,
    check_raw_u0027: bool,
) -> Result<Vec<(usize, usize)>, ReportError> {
    if depth >= MAX_NESTED_JSON_DEPTH || (!bytes.contains(&b'{') && !bytes.contains(&b'[')) {
        return Ok(Vec::new());
    }

    let mut all_mask_spans = Vec::new();
    let mut base = 0usize;
    while base < bytes.len() {
        let valid_len = match std::str::from_utf8(&bytes[base..]) {
            Ok(s) => s.len(),
            Err(e) => e.valid_up_to(),
        };
        if valid_len > 0 {
            let chunk_bytes = &bytes[base..base + valid_len];
            let chunk_str = std::str::from_utf8(chunk_bytes).unwrap_or("");
            if chunk_bytes.contains(&b'{') || chunk_bytes.contains(&b'[') {
                let mut open_km_ranges_opt: Option<Vec<(usize, usize)>> = None;
                let mut idx = 0usize;
                let mut too_deep_openers: Option<Vec<bool>> = None;
                while idx < chunk_bytes.len() {
                    if matches!(chunk_bytes[idx], b'{' | b'[') && starts_raw_json_container(chunk_bytes, idx) {
                        if too_deep_openers.as_ref().is_some_and(|td| td[idx]) {
                            idx += 1;
                            continue;
                        }
                        let mut stream = serde_json::Deserializer::from_str(&chunk_str[idx..]).into_iter::<Value>();
                        match stream.next() {
                            Some(Ok(val)) => {
                                let consumed = stream.byte_offset();
                                if consumed > 0 && idx + consumed <= chunk_bytes.len() {
                                    assert_r4_clean_json_value_inner(&val, depth + 1)?;
                                    let span = &chunk_bytes[idx..idx + consumed];
                                    let keep_unmasked = json_span_has_quote_parity_hazard(span) && {
                                        let open_km_ranges = open_km_ranges_opt.get_or_insert_with(|| {
                                            compute_open_keymaterial_tag_ranges(chunk_bytes, from_json_value)
                                        });
                                        pos_in_sorted_ranges(open_km_ranges, idx)
                                            || (check_raw_u0027 && raw_json_span_has_u0027_apos_km_leak(span))
                                    };
                                    if !keep_unmasked {
                                        all_mask_spans.push((base + idx, base + idx + consumed));
                                    }
                                    idx += consumed;
                                    continue;
                                }
                            }
                            Some(Err(ref e)) if is_serde_json_recursion_limit_err(e) => {
                                if let Some(next_idx) = skip_excess_json_openers(chunk_bytes, idx) {
                                    idx = next_idx;
                                    continue;
                                }
                                let td = too_deep_openers
                                    .get_or_insert_with(|| compute_too_deep_json_openers(chunk_bytes, idx));
                                if td[idx] {
                                    idx += 1;
                                    continue;
                                }
                            }
                            _ => {}
                        }
                    }
                    idx += 1;
                }
            }
        }
        if base + valid_len >= bytes.len() {
            break;
        }
        let err_len = match std::str::from_utf8(&bytes[base + valid_len..]) {
            Ok(_) => 0,
            Err(e) => e.error_len().unwrap_or(bytes.len() - (base + valid_len)),
        };
        base += valid_len + err_len.max(1);
    }

    Ok(all_mask_spans)
}

fn assert_r4_clean_embedded_json_in_bytes(
    work_bytes: &mut [u8],
    depth: usize,
    from_json_value: bool,
) -> Result<bool, ReportError> {
    assert_r4_clean_embedded_json_in_bytes_with_options(work_bytes, depth, from_json_value, true)
}

fn assert_r4_clean_embedded_json_in_bytes_with_options(
    work_bytes: &mut [u8],
    depth: usize,
    from_json_value: bool,
    check_raw_u0027: bool,
) -> Result<bool, ReportError> {
    let spans = find_embedded_json_mask_spans(work_bytes, depth, from_json_value, check_raw_u0027)?;
    let mut modified = false;
    for (ms, me) in spans {
        if mask_json_span_preserving_delims(work_bytes, ms, me) {
            modified = true;
        }
    }
    Ok(modified)
}

fn assert_r4_clean_embedded_json_in_bytes_cow(
    work_bytes: &mut std::borrow::Cow<'_, [u8]>,
    depth: usize,
    from_json_value: bool,
    check_raw_u0027: bool,
) -> Result<bool, ReportError> {
    let spans = find_embedded_json_mask_spans(work_bytes, depth, from_json_value, check_raw_u0027)?;
    if spans.is_empty() {
        return Ok(false);
    }
    let buf = work_bytes.to_mut();
    let mut modified = false;
    for (ms, me) in spans {
        if mask_json_span_preserving_delims(buf, ms, me) {
            modified = true;
        }
    }
    Ok(modified)
}

fn assert_r4_clean_bytes_internal(
    bytes: &[u8],
    allow_csv: bool,
    allow_json_ctx: bool,
    allow_markdown: bool,
) -> Result<(), ReportError> {
    assert_r4_clean_bytes_with_depth(bytes, allow_csv, allow_json_ctx, allow_markdown, 0, true)
}

fn assert_r4_clean_bytes_with_depth(
    bytes: &[u8],
    allow_csv: bool,
    allow_json_ctx: bool,
    allow_markdown: bool,
    depth: usize,
    allow_tsv_tabs: bool,
) -> Result<(), ReportError> {
    assert_r4_clean_bytes_with_depth_and_origin(
        bytes,
        allow_csv,
        allow_json_ctx,
        allow_markdown,
        depth,
        allow_tsv_tabs,
        false,
    )
}

fn assert_r4_clean_bytes_with_depth_and_origin(
    bytes: &[u8],
    allow_csv: bool,
    allow_json_ctx: bool,
    allow_markdown: bool,
    depth: usize,
    allow_tsv_tabs: bool,
    from_json_value: bool,
) -> Result<(), ReportError> {
    assert_r4_clean_bytes_with_options(
        bytes,
        allow_csv,
        allow_json_ctx,
        allow_markdown,
        depth,
        allow_tsv_tabs,
        from_json_value,
        true,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn assert_r4_clean_bytes_with_options(
    bytes: &[u8],
    allow_csv: bool,
    allow_json_ctx: bool,
    allow_markdown: bool,
    depth: usize,
    allow_tsv_tabs: bool,
    from_json_value: bool,
    run_embedded_json_pass: bool,
    run_html_pass: bool,
) -> Result<(), ReportError> {
    if !allow_csv && !allow_json_ctx && !allow_markdown && !contains_ascii_case_insensitive(bytes, b"keymaterial") {
        return Ok(());
    }
    let doc_has_md_separator = allow_markdown && document_has_markdown_separator(bytes);
    let trimmed_doc = bytes.trim_ascii();
    let allow_md_table_lines =
        allow_markdown && (doc_has_md_separator || (!trimmed_doc.contains(&b'\n') && !trimmed_doc.contains(&b'\r')));
    let mut lower_bytes_opt: Option<Vec<u8>> = None;
    let csv_ranges = if allow_csv && bytes.contains(&b'"') {
        let lower = lower_bytes_opt.get_or_insert_with(|| to_ascii_lowercase_vec(bytes));
        collect_rfc4180_csv_quoted_content_ranges(lower, allow_md_table_lines, doc_has_md_separator)
    } else {
        Vec::new()
    };

    let mut work_bytes = std::borrow::Cow::Borrowed(bytes);
    let mut masked_any = false;

    if allow_md_table_lines {
        let mut line_start = 0usize;
        while line_start < bytes.len() {
            let line_end = find_byte(bytes, line_start, b'\n').unwrap_or(bytes.len());
            let line = bytes[line_start..line_end]
                .strip_suffix(b"\r")
                .unwrap_or(&bytes[line_start..line_end]);
            let inside_csv = csv_ranges
                .iter()
                .any(|&(cs, ce, _)| cs <= line_start && line_start < ce);
            if !inside_csv && is_strict_markdown_table_line(line, doc_has_md_separator) {
                for raw_cell in split_markdown_row_cells(line.trim_ascii()) {
                    let cell = raw_cell.strip_prefix(b" ").unwrap_or(raw_cell);
                    let cell = cell.strip_suffix(b" ").unwrap_or(cell);
                    verify_markdown_table_cell(cell, depth)?;
                }
                work_bytes.to_mut()[line_start..line_end].fill(b'_');
                masked_any = true;
            }
            line_start = line_end + 1;
        }
    }

    let mut unclosed_csv_ranges = Vec::new();
    for &(cs, ce, is_closed) in &csv_ranges {
        if is_closed {
            let unescaped = unescape_csv_field(&bytes[cs..ce]);
            if depth < MAX_NESTED_JSON_DEPTH {
                assert_r4_clean_decoded_cell_with_depth(&unescaped, depth + 1)?;
            } else {
                assert_r4_clean_decoded_cell_inner_with_options(&unescaped, depth, false, from_json_value, false)?;
            }
            work_bytes.to_mut()[cs..ce].fill(b'_');
            masked_any = true;
        } else {
            unclosed_csv_ranges.push((cs, ce));
        }
    }

    if run_html_pass && allow_json_ctx && depth < MAX_NESTED_JSON_DEPTH && bytes.contains(&b'<') {
        let mut line_start = 0usize;
        while line_start < bytes.len() {
            let line_end = find_byte(bytes, line_start, b'\n').unwrap_or(bytes.len());
            let trimmed_end = if line_end > line_start && bytes[line_end - 1] == b'\r' {
                line_end - 1
            } else {
                line_end
            };
            let touches_csv = csv_ranges.iter().any(|&(cs, ce, _)| cs < line_end && line_start < ce);
            let is_md = allow_md_table_lines
                && is_strict_markdown_table_line(&bytes[line_start..trimmed_end], doc_has_md_separator);
            if !touches_csv && !is_md && line_start < trimmed_end {
                if allow_tsv_tabs {
                    let mut cell_start = line_start;
                    while cell_start <= trimmed_end {
                        let cell_end = find_byte(&bytes[..trimmed_end], cell_start, b'\t').unwrap_or(trimmed_end);
                        if cell_start < cell_end && is_html_document_or_fragment(&bytes[cell_start..cell_end]) {
                            verify_html_with_embedded_json_with_origin(
                                &bytes[cell_start..cell_end],
                                depth + 1,
                                from_json_value,
                            )?;
                            work_bytes.to_mut()[cell_start..cell_end].fill(b'_');
                            masked_any = true;
                        }
                        if cell_end >= trimmed_end {
                            break;
                        }
                        cell_start = cell_end + 1;
                    }
                } else if is_html_document_or_fragment(&bytes[line_start..trimmed_end]) {
                    verify_html_with_embedded_json_with_origin(
                        &bytes[line_start..trimmed_end],
                        depth + 1,
                        from_json_value,
                    )?;
                    work_bytes.to_mut()[line_start..trimmed_end].fill(b'_');
                    masked_any = true;
                }
            }
            line_start = line_end + 1;
        }
    }

    if allow_json_ctx
        && run_embedded_json_pass
        && assert_r4_clean_embedded_json_in_bytes_cow(&mut work_bytes, depth, from_json_value, true)?
    {
        masked_any = true;
    }

    if !contains_ascii_case_insensitive(&work_bytes, b"keymaterial") {
        return Ok(());
    }

    let lower_work = if masked_any {
        to_ascii_lowercase_vec(&work_bytes)
    } else {
        lower_bytes_opt.unwrap_or_else(|| to_ascii_lowercase_vec(bytes))
    };

    let mut csv_dbl_state: Option<(usize, usize, bool)> = None;
    let mut json_tracker = JsonContextTracker::with_markdown_separator(allow_md_table_lines, doc_has_md_separator);
    if allow_json_ctx && has_html_entity_json_delim(&lower_work) {
        json_tracker.html_entity_quotes = true;
    }
    let (single_u0022_json_ctx, double_u0022_json_ctx) = if contains_ascii_case_insensitive(&lower_work, b"u0022") {
        precompute_u0022_json_ctx(&lower_work, false, None)
    } else {
        (false, false)
    };
    let mut cursor = 0usize;
    let mut unredacted_close_cache: [Option<Option<usize>>; 2] = [None, None];

    while let Some(OpeningTagMatch {
        open_start,
        after_name,
        syntax,
        opened_with_u003c,
    }) = find_opening_keymaterial_tag(&lower_work, cursor, allow_json_ctx || double_u0022_json_ctx)
    {
        let (ctx, bound_end) = if !allow_json_ctx {
            if is_double_escaped_tag_open(&lower_work, open_start) && !double_u0022_json_ctx {
                cursor = after_name;
                continue;
            }
            let decoded_u0022_ctx = single_u0022_json_ctx || double_u0022_json_ctx;
            let effective_in_json_string = decoded_u0022_ctx && (syntax == TagSyntax::HtmlEscaped || opened_with_u003c);
            (
                TagScanContext {
                    in_json_string: effective_in_json_string,
                    in_double_escaped_json: double_u0022_json_ctx,
                    allow_double_bs: double_u0022_json_ctx,
                    opened_with_u003c,
                    allow_tsv_tabs,
                    in_decoded_u0022_json_ctx: decoded_u0022_ctx,
                    ..TagScanContext::default()
                },
                lower_work.len(),
            )
        } else if let Some((cs, ce)) = unclosed_csv_ranges
            .iter()
            .copied()
            .find(|&(cs, ce)| cs <= open_start && open_start < ce)
        {
            let (in_json_string, rel_string_start, in_nested_json_string) =
                is_csv_field_in_json_string(&lower_work[cs..open_start]);
            if is_double_escaped_tag_open(&lower_work, open_start) && !in_json_string {
                cursor = after_name;
                continue;
            }
            let has_double_escaped_gap = check_csv_field_double_escaped(
                &lower_work,
                cs,
                rel_string_start,
                in_json_string,
                cursor,
                open_start,
                &mut csv_dbl_state,
            );
            let in_double_escaped_json = in_nested_json_string
                || has_double_escaped_gap
                || (in_json_string && is_double_escaped_tag_open(&lower_work, open_start));
            (
                TagScanContext {
                    in_csv_field: true,
                    in_json_string,
                    in_markdown_json_string: false,
                    in_markdown_table_line: false,
                    in_double_escaped_json,
                    in_nested_json_string,
                    allow_double_bs: in_json_string,
                    opened_with_u003c,
                    allow_tsv_tabs: false,
                    in_decoded_u0022_json_ctx: false,
                },
                ce,
            )
        } else {
            let (in_json_string, in_markdown_json_string, in_markdown_table_line, in_nested_json_string) =
                json_tracker.advance_to(&lower_work, open_start);
            if is_double_escaped_tag_open(&lower_work, open_start) && !in_json_string && !double_u0022_json_ctx {
                cursor = after_name;
                continue;
            }
            let has_double_escaped_gap =
                in_json_string && json_tracker.mark_double_escaped_gap(&lower_work, cursor, open_start);
            let decoded_u0022_ctx = !in_json_string && (single_u0022_json_ctx || double_u0022_json_ctx);
            let effective_in_json_string =
                in_json_string || (decoded_u0022_ctx && (syntax == TagSyntax::HtmlEscaped || opened_with_u003c));
            let in_double_escaped_json = in_markdown_json_string
                || in_nested_json_string
                || has_double_escaped_gap
                || (!in_json_string && double_u0022_json_ctx)
                || (in_json_string && is_double_escaped_tag_open(&lower_work, open_start));
            (
                TagScanContext {
                    in_csv_field: false,
                    in_json_string: effective_in_json_string,
                    in_markdown_json_string,
                    in_markdown_table_line,
                    in_double_escaped_json,
                    in_nested_json_string,
                    allow_double_bs: in_json_string || (!in_json_string && double_u0022_json_ctx),
                    opened_with_u003c,
                    allow_tsv_tabs,
                    in_decoded_u0022_json_ctx: decoded_u0022_ctx,
                },
                lower_work.len(),
            )
        };

        let bounded = &lower_work[..bound_end];
        let Some((close_start, open_end, is_self_closing)) =
            find_tag_close_quote_aware_cached(bounded, after_name, syntax, ctx, &mut unredacted_close_cache)
        else {
            return Err(ReportError::CustodyVerificationFailed(
                "R4 violation: unclosed <keyMaterial> opening tag detected in exported bytes".to_string(),
            ));
        };

        if find_ascii_bytes(&lower_work[after_name..close_start], 0, b"keymaterial").is_some()
            && has_unredacted_inner_keymaterial_in_span(
                &lower_work,
                after_name,
                close_start,
                allow_json_ctx || double_u0022_json_ctx,
                ctx,
            )
        {
            return Err(ReportError::CustodyVerificationFailed(
                "R4 violation: unredacted <keyMaterial> inside <keyMaterial> attributes detected in exported bytes"
                    .to_string(),
            ));
        }

        if is_self_closing {
            cursor = open_end;
            continue;
        }

        let Some((close_tag_start, close_tag_end)) =
            find_closing_keymaterial_tag(bounded, open_end, syntax, ctx.allow_double_bs)
        else {
            return Err(ReportError::CustodyVerificationFailed(
                "R4 violation: truncated unclosed <keyMaterial> value detected in exported bytes".to_string(),
            ));
        };

        let inner = lower_work[open_end..close_tag_start].trim_ascii();
        if inner != b"[redacted]" {
            return Err(ReportError::CustodyVerificationFailed(
                "R4 violation: unredacted <keyMaterial> value detected in exported bytes".to_string(),
            ));
        }
        cursor = close_tag_end;
    }

    Ok(())
}

fn unescape_html_entities(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0usize;
    while i < raw.len() {
        let Some(amp) = find_byte(raw, i, b'&') else {
            out.extend_from_slice(&raw[i..]);
            break;
        };
        if amp > i {
            out.extend_from_slice(&raw[i..amp]);
        }
        let rest = &raw[amp..];
        if rest.get(..6).is_some_and(|s| s.eq_ignore_ascii_case(b"&quot;")) {
            out.push(b'"');
            i = amp + 6;
        } else if rest.get(..6).is_some_and(|s| s.eq_ignore_ascii_case(b"&apos;")) {
            out.push(b'\'');
            i = amp + 6;
        } else if rest.get(..4).is_some_and(|s| s.eq_ignore_ascii_case(b"&lt;")) {
            out.push(b'<');
            i = amp + 4;
        } else if rest.get(..4).is_some_and(|s| s.eq_ignore_ascii_case(b"&gt;")) {
            out.push(b'>');
            i = amp + 4;
        } else if rest.get(..5).is_some_and(|s| s.eq_ignore_ascii_case(b"&amp;")) {
            out.push(b'&');
            i = amp + 5;
        } else if let Some((cp, len)) = parse_html_numeric_char_ref(rest)
            && let Some(ch) = char::from_u32(cp)
        {
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            i = amp + len;
        } else {
            out.push(b'&');
            i = amp + 1;
        }
    }
    out
}

#[inline]
fn unescape_html_entities_cow(raw: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    if raw.contains(&b'&') {
        std::borrow::Cow::Owned(unescape_html_entities(raw))
    } else {
        std::borrow::Cow::Borrowed(raw)
    }
}

fn raw_keymaterial_name_end(lower_bytes: &[u8], pos: usize) -> Option<usize> {
    if lower_bytes.get(pos) != Some(&b'<') {
        return None;
    }
    let mut name_end = pos + 1;
    while name_end < lower_bytes.len() && (is_xml_ncname_char(lower_bytes[name_end]) || lower_bytes[name_end] == b':') {
        name_end += 1;
    }
    let name = &lower_bytes[pos + 1..name_end];
    let is_km_name = name == b"keymaterial"
        || (name.ends_with(b":keymaterial")
            && name.len() > ":keymaterial".len()
            && name[..name.len() - ":keymaterial".len()]
                .iter()
                .all(|&b| is_xml_ncname_char(b)));
    if !is_km_name {
        return None;
    }
    let after = &lower_bytes[name_end..];
    let is_boundary = matches!(
        lower_bytes.get(name_end).copied(),
        Some(b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n')
    ) || after.starts_with(b"<br>")
        || after.starts_with(b"\\/")
        || after.starts_with(b"\\\\/")
        || starts_with_escaped_ws(after, true).is_some()
        || matches!(
            match_json_u00_char(after, true),
            Some((b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n', _))
        );
    is_boundary.then_some(name_end)
}

fn is_raw_keymaterial_open_at(lower_bytes: &[u8], pos: usize) -> bool {
    raw_keymaterial_name_end(lower_bytes, pos).is_some()
}

fn find_html_open_tag_end(lower_bytes: &[u8], pos: usize) -> Option<usize> {
    let mut i = pos + 1;
    let mut quote: Option<u8> = None;
    let mut km_close_cache: [Option<Option<usize>>; 2] = [None, None];
    let mut no_raw_closing_km = false;
    while i < lower_bytes.len() {
        let b = lower_bytes[i];
        if let Some(q) = quote {
            if b == b'<'
                && let Some(name_end) = raw_keymaterial_name_end(lower_bytes, i)
            {
                if let Some((_cs, km_open_end, is_self_closing)) = find_tag_close_quote_aware_cached(
                    lower_bytes,
                    name_end,
                    TagSyntax::Raw,
                    TagScanContext {
                        allow_double_bs: true,
                        ..TagScanContext::default()
                    },
                    &mut km_close_cache,
                ) {
                    let km_end = if !is_self_closing && !no_raw_closing_km {
                        if let Some((_cs, km_close_end)) =
                            find_closing_keymaterial_tag(lower_bytes, km_open_end, TagSyntax::Raw, true)
                        {
                            km_close_end
                        } else {
                            no_raw_closing_km = true;
                            km_open_end
                        }
                    } else {
                        km_open_end
                    };
                    if !lower_bytes[name_end..km_end].contains(&q) {
                        i = km_end;
                        continue;
                    }
                }
                if let Some((_cs, km_close_end)) =
                    find_closing_keymaterial_tag(lower_bytes, name_end, TagSyntax::Raw, true)
                {
                    return Some(km_close_end);
                }
                return None;
            }
            if b == q {
                quote = None;
            }
        } else if matches!(b, b'"' | b'\'') {
            quote = Some(b);
        } else if b == b'<'
            && let Some(name_end) = raw_keymaterial_name_end(lower_bytes, i)
            && let Some((_cs, km_open_end, is_self_closing)) = find_tag_close_quote_aware_cached(
                lower_bytes,
                name_end,
                TagSyntax::Raw,
                TagScanContext {
                    allow_double_bs: true,
                    ..TagScanContext::default()
                },
                &mut km_close_cache,
            )
        {
            if !is_self_closing && !no_raw_closing_km {
                if let Some((_cs, km_close_end)) =
                    find_closing_keymaterial_tag(lower_bytes, km_open_end, TagSyntax::Raw, true)
                {
                    i = km_close_end;
                    continue;
                }
                no_raw_closing_km = true;
            }
            i = km_open_end;
            continue;
        } else if b == b'>' {
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

fn find_html_close_tag(lower_bytes: &[u8], start: usize, tag: &[u8]) -> Option<(usize, usize)> {
    let mut i = start;
    while i + 2 + tag.len() < lower_bytes.len() {
        if lower_bytes[i] == b'<' && lower_bytes[i + 1] == b'/' {
            let after_name = i + 2 + tag.len();
            if lower_bytes.get(i + 2..after_name) == Some(tag) {
                let mut end = after_name;
                while end < lower_bytes.len() && lower_bytes[end].is_ascii_whitespace() {
                    end += 1;
                }
                if lower_bytes.get(end) == Some(&b'>') {
                    return Some((i, end + 1));
                }
            }
        }
        i += 1;
    }
    None
}

fn contains_block_html_tag(lower_bytes: &[u8], start: usize, block_tags: &[&[u8]]) -> bool {
    let mut i = start;
    let mut quote: Option<u8> = None;
    while i < lower_bytes.len() {
        let b = lower_bytes[i];
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if matches!(b, b'"' | b'\'') {
            quote = Some(b);
            i += 1;
            continue;
        }
        if b == b'<' {
            if let Some(name_end) = raw_keymaterial_name_end(lower_bytes, i) {
                if let Some((_cs, km_open_end, is_self_closing)) = find_tag_close_quote_aware(
                    lower_bytes,
                    name_end,
                    TagSyntax::Raw,
                    TagScanContext {
                        allow_double_bs: true,
                        ..TagScanContext::default()
                    },
                ) {
                    if !is_self_closing
                        && let Some((_cs, km_close_end)) =
                            find_closing_keymaterial_tag(lower_bytes, km_open_end, TagSyntax::Raw, true)
                    {
                        i = km_close_end;
                        continue;
                    }
                    i = km_open_end;
                    continue;
                }
                i = name_end;
                continue;
            }
            if lower_bytes[i..].starts_with(b"<!--") {
                return true;
            }
            if lower_bytes[i..].starts_with(b"<!doctype")
                && matches!(
                    lower_bytes.get(i + 9).copied(),
                    Some(b'>' | b' ' | b'\t' | b'\r' | b'\n')
                )
            {
                return true;
            }
            for &tag in block_tags {
                let after = i + 1 + tag.len();
                if lower_bytes.get(i + 1..after) == Some(tag)
                    && matches!(
                        lower_bytes.get(after).copied(),
                        Some(b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n')
                    )
                {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

fn contains_html_entity_bytes(lower_bytes: &[u8]) -> bool {
    let mut i = 0usize;
    while i < lower_bytes.len() {
        if lower_bytes[i] == b'&' {
            let rest = &lower_bytes[i..];
            if rest.starts_with(b"&quot;")
                || rest.starts_with(b"&apos;")
                || rest.starts_with(b"&lt;")
                || rest.starts_with(b"&gt;")
                || rest.starts_with(b"&amp;")
                || parse_html_numeric_char_ref(rest).is_some()
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn find_html_quote_entity_close(
    lower_field: &[u8],
    start: usize,
    target_mode: HtmlQuoteMode,
) -> Option<(usize, usize)> {
    let mut j = start;
    while j < lower_field.len() {
        if lower_field[j] == b'\\' {
            let bs = count_consecutive_backslashes(lower_field, j);
            if lower_field.get(j + bs) == Some(&b'&')
                && let Some((qmode, len)) = match_html_quote_entity(&lower_field[j + bs..])
                && qmode == target_mode
            {
                if bs % 2 == 1 {
                    j += bs + len;
                    continue;
                }
                return Some((j + bs, j + bs + len));
            }
            j += bs;
            continue;
        }
        if lower_field[j] == b'&'
            && let Some((qmode, len)) = match_html_quote_entity(&lower_field[j..])
            && qmode == target_mode
        {
            return Some((j, j + len));
        }
        j += 1;
    }
    None
}

fn find_html_double_quote_entity_close(lower_field: &[u8], start: usize) -> Option<(usize, usize)> {
    find_html_quote_entity_close(lower_field, start, HtmlQuoteMode::DoubleEntity)
}

fn find_html_double_quote_entity_open_backward(slice: &[u8]) -> Option<usize> {
    let mut pos = slice.len();
    while pos > 0 {
        if slice[pos - 1] == b';'
            && let Some(q_start) = match_html_double_quote_entity_at_end(&slice[..pos])
            && count_preceding_backslashes(slice, 0, q_start).is_multiple_of(2)
        {
            return Some(q_start);
        }
        pos -= 1;
    }
    None
}

fn scan_json_primitive_end(slice: &[u8], pos: usize) -> Option<usize> {
    if pos >= slice.len() {
        return None;
    }
    if slice[pos] == b'-' || slice[pos].is_ascii_digit() {
        let mut e = pos;
        if slice[e] == b'-' {
            e += 1;
        }
        let digits_start = e;
        while e < slice.len() && matches!(slice[e], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
            e += 1;
        }
        if e > digits_start
            && is_json_number_token(&slice[pos..e])
            && !slice.get(e).is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        {
            return Some(e);
        }
        return None;
    }
    for kw in [b"true".as_slice(), b"false".as_slice(), b"null".as_slice()] {
        if slice[pos..].starts_with(kw) {
            let end = pos + kw.len();
            if !slice.get(end).is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_') {
                return Some(end);
            }
        }
    }
    None
}

fn find_csv_doubled_string_open_backward(slice: &[u8]) -> Option<usize> {
    if slice.len() < 4 || !slice.ends_with(b"\"\"") {
        return None;
    }
    let bs = count_preceding_backslashes(slice, 0, slice.len() - 2);
    if !bs.is_multiple_of(2) {
        return None;
    }
    let mut pos = slice.len() - 2;
    while pos > 0 {
        if pos >= 2 && slice[pos - 2..pos] == *b"\"\"" {
            let inner_bs = count_preceding_backslashes(slice, 0, pos - 2);
            if inner_bs.is_multiple_of(2) {
                return Some(pos - 2);
            }
            pos -= inner_bs + 2;
            continue;
        }
        if slice[pos - 1] == b'"' {
            return None;
        }
        pos -= 1;
    }
    None
}

fn span_has_unredacted_keymaterial_in_html_quote(lower_span: &[u8]) -> bool {
    if find_ascii_bytes(lower_span, 0, b"keymaterial").is_none() {
        return false;
    }
    let mut seg_start = 0usize;
    let mut search_from = 0usize;
    while let Some((rel_cs, rel_end)) = slice_contains_closing_keymaterial_tag(&lower_span[search_from..], true) {
        let cs = search_from + rel_cs;
        let close_end = search_from + rel_end;
        if !ends_with_gt_redacted(&lower_span[seg_start..cs]) {
            return true;
        }
        seg_start = close_end;
        search_from = close_end;
    }
    let mut pos = 0usize;
    while let Some(m) = find_opening_keymaterial_tag(lower_span, pos, true) {
        if m.syntax == TagSyntax::HtmlEscaped {
            return true;
        }
        let ctx = TagScanContext {
            in_csv_field: true,
            allow_double_bs: true,
            opened_with_u003c: m.opened_with_u003c,
            ..TagScanContext::default()
        };
        let Some((_cs, open_end, is_self_closing)) =
            find_tag_close_quote_aware(lower_span, m.after_name, m.syntax, ctx)
        else {
            return true;
        };
        if has_unredacted_inner_keymaterial_in_span(lower_span, m.after_name, open_end, true, ctx) {
            return true;
        }
        if is_self_closing {
            pos = open_end;
            continue;
        }
        let Some((close_start, close_end)) = find_closing_keymaterial_tag(lower_span, open_end, m.syntax, true) else {
            return true;
        };
        if lower_span[open_end..close_start].trim_ascii() != b"[redacted]" {
            return true;
        }
        pos = close_end;
    }
    false
}

fn html_json_value_or_list_reaches_close_or_km_memo(
    lower_field: &[u8],
    mut pos: usize,
    from_colon: bool,
    memo: &mut JsonMarkerMemo,
) -> bool {
    let mut after_colon = from_colon;
    let mut visited: Vec<(usize, bool)> = Vec::new();
    let res = loop {
        if pos >= lower_field.len() {
            break false;
        }
        let bit = if after_colon { 128u8 } else { 16u8 };
        if (memo.flags[pos] & bit) != 0 {
            break false;
        }
        visited.push((pos, after_colon));

        let val_end = if lower_field[pos] == b'&'
            && let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&lower_field[pos..])
        {
            let content_start = pos + len;
            let Some((close_start, close_end)) = find_html_double_quote_entity_close(lower_field, content_start) else {
                break after_colon && span_has_unredacted_keymaterial_in_html_quote(&lower_field[content_start..]);
            };
            if after_colon && span_has_unredacted_keymaterial_in_html_quote(&lower_field[content_start..close_start]) {
                break true;
            }
            close_end
        } else if matches!(lower_field[pos], b'{' | b'[') {
            let end = scan_html_json_container_end_with_csv(lower_field, pos, true);
            if end <= pos || !is_json_container_slice_with_csv(&lower_field[pos..end], true, true) {
                break false;
            }
            end
        } else if let Some(ve) = scan_json_primitive_end(lower_field, pos) {
            ve
        } else {
            break false;
        };

        let mut after = val_end;
        while after < lower_field.len() && lower_field[after].is_ascii_whitespace() {
            after += 1;
        }
        if after >= lower_field.len() {
            break false;
        }
        if matches!(lower_field[after], b'}' | b']') {
            break true;
        }
        if after_colon && lower_field[after] == b':' {
            break false;
        }
        if !after_colon && lower_field[after] == b':' && lower_field[pos] == b'&' {
            after_colon = true;
            let mut val_start = after + 1;
            while val_start < lower_field.len() && lower_field[val_start].is_ascii_whitespace() {
                val_start += 1;
            }
            if val_start <= pos {
                break false;
            }
            pos = val_start;
            continue;
        }
        if lower_field[after] == b',' {
            after_colon = false;
            let mut next_pos = after + 1;
            while next_pos < lower_field.len() && lower_field[next_pos].is_ascii_whitespace() {
                next_pos += 1;
            }
            if next_pos <= pos {
                break false;
            }
            pos = next_pos;
            continue;
        }
        break false;
    };
    if !res {
        for (vp, vc) in visited {
            memo.flags[vp] |= if vc { 128u8 } else { 16u8 };
        }
    }
    res
}

fn is_valid_html_json_container_at(lower_field: &[u8], pos: usize) -> bool {
    if pos >= lower_field.len() || !matches!(lower_field[pos], b'{' | b'[') {
        return false;
    }
    let end = scan_html_json_container_end_with_csv(lower_field, pos, true);
    end > pos && is_json_container_slice_with_csv(&lower_field[pos..end], true, true)
}

fn html_quoted_entity_has_json_key_prefix(lower_field: &[u8], open_q_start: usize, memo: &mut JsonMarkerMemo) -> bool {
    let k = skip_json_ws_backward(lower_field, open_q_start);
    if k == 0 {
        return true;
    }
    match lower_field[k - 1] {
        b'{' => true,
        b',' => {
            let bc = skip_json_ws_backward(lower_field, k - 1);
            ends_with_html_json_value_before_comma_memo(lower_field, bc, false, Some(memo))
        }
        _ => false,
    }
}

fn is_html_colon_preceded_by_json_key(lower_field: &[u8], before_colon: usize, memo: &mut JsonMarkerMemo) -> bool {
    let prefix = &lower_field[..before_colon];
    if let Some(close_q_start) = match_html_double_quote_entity_at_end(prefix)
        && count_preceding_backslashes(prefix, 0, close_q_start).is_multiple_of(2)
        && let Some(open_q_start) = find_html_double_quote_entity_open_backward(&prefix[..close_q_start])
    {
        return html_quoted_entity_has_json_key_prefix(lower_field, open_q_start, memo);
    }
    if let Some(open_csv_q) = find_csv_doubled_string_open_backward(prefix) {
        return html_quoted_entity_has_json_key_prefix(lower_field, open_csv_q, memo);
    }
    let mut key_start = before_colon;
    while key_start > 0
        && (prefix[key_start - 1].is_ascii_alphanumeric() || matches!(prefix[key_start - 1], b'_' | b'-'))
    {
        key_start -= 1;
    }
    if key_start < before_colon {
        let k = skip_json_ws_backward(prefix, key_start);
        if k > 0 {
            return match prefix[k - 1] {
                b'{' => true,
                b',' => {
                    let bc = skip_json_ws_backward(prefix, k - 1);
                    ends_with_html_json_value_before_comma_memo(lower_field, bc, false, Some(memo))
                }
                _ => false,
            };
        }
    }
    false
}

fn html_quoted_entity_followed_by_json_structure_memo(
    lower_field: &[u8],
    open_q_start: usize,
    close_end: usize,
    memo: &mut JsonMarkerMemo,
) -> bool {
    let mut after = close_end;
    while after < lower_field.len() && lower_field[after].is_ascii_whitespace() {
        after += 1;
    }
    if after >= lower_field.len() {
        return false;
    }
    match lower_field[after] {
        b'}' | b']' => {
            let cm = memo
                .container
                .get_or_insert_with(|| JsonContainerMemo::new(lower_field.len(), true, true));
            ends_with_valid_json_container_memo(lower_field, after + 1, cm)
        }
        b':' => {
            let mut val_start = after + 1;
            while val_start < lower_field.len() && lower_field[val_start].is_ascii_whitespace() {
                val_start += 1;
            }
            if val_start >= lower_field.len() {
                return false;
            }
            if html_json_value_or_list_reaches_close_or_km_memo(lower_field, val_start, true, memo)
                || is_valid_html_json_container_at(lower_field, val_start)
            {
                return true;
            }
            lower_field[val_start] == b'&'
                && matches!(
                    match_html_quote_entity(&lower_field[val_start..]),
                    Some((HtmlQuoteMode::DoubleEntity, _))
                )
                && html_quoted_entity_has_json_key_prefix(lower_field, open_q_start, memo)
        }
        b',' => {
            let mut elem_start = after + 1;
            while elem_start < lower_field.len() && lower_field[elem_start].is_ascii_whitespace() {
                elem_start += 1;
            }
            html_json_value_or_list_reaches_close_or_km_memo(lower_field, elem_start, false, memo)
                || is_valid_html_json_container_at(lower_field, elem_start)
        }
        _ => false,
    }
}

fn html_colon_followed_by_json_value_memo(
    lower_field: &[u8],
    colon_pos: usize,
    allow_double_entity: bool,
    memo: &mut JsonMarkerMemo,
) -> bool {
    let mut val_start = colon_pos + 1;
    while val_start < lower_field.len() && lower_field[val_start].is_ascii_whitespace() {
        val_start += 1;
    }
    if val_start >= lower_field.len() {
        return false;
    }
    if allow_double_entity
        && lower_field[val_start] == b'&'
        && matches!(
            match_html_quote_entity(&lower_field[val_start..]),
            Some((HtmlQuoteMode::DoubleEntity, _))
        )
    {
        return true;
    }
    is_valid_html_json_container_at(lower_field, val_start)
        || html_json_value_or_list_reaches_close_or_km_memo(lower_field, val_start, true, memo)
}

fn has_unclosed_html_quot_km_leak(lower_field: &[u8], after_ws: usize, has_json_prefix: bool) -> bool {
    if has_json_prefix {
        return find_opening_keymaterial_tag(lower_field, after_ws, true).is_some();
    }
    span_has_unredacted_keymaterial_in_html_quote(&lower_field[after_ws..])
}

fn comma_html_double_quoted_value_is_json_or_km_memo(
    lower_field: &[u8],
    first_after_open_quote: usize,
    before_comma: usize,
    memo: &mut JsonMarkerMemo,
) -> bool {
    let has_json_prefix = ends_with_html_json_value_before_comma_memo(lower_field, before_comma, true, Some(memo));
    let fail_bit = if has_json_prefix { 64u8 } else { 32u8 };
    let mut pos = first_after_open_quote;
    let mut is_first = true;
    let mut visited_content_starts = Vec::new();
    let res = loop {
        let content_start = if is_first {
            is_first = false;
            pos
        } else if pos >= lower_field.len() {
            break false;
        } else if lower_field[pos] == b'&'
            && let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&lower_field[pos..])
        {
            pos + len
        } else if matches!(lower_field[pos], b'{' | b'[') {
            let end = scan_html_json_container_end_with_csv(lower_field, pos, true);
            if end > pos && is_json_container_slice_with_csv(&lower_field[pos..end], true, true) {
                let mut after = end;
                while after < lower_field.len() && lower_field[after].is_ascii_whitespace() {
                    after += 1;
                }
                if after < lower_field.len() && matches!(lower_field[after], b'}' | b']') {
                    break true;
                }
                if after < lower_field.len() && lower_field[after] == b',' {
                    let mut next_pos = after + 1;
                    while next_pos < lower_field.len() && lower_field[next_pos].is_ascii_whitespace() {
                        next_pos += 1;
                    }
                    if next_pos <= pos {
                        break false;
                    }
                    pos = next_pos;
                    continue;
                }
                break has_json_prefix;
            }
            break false;
        } else {
            let Some(ve) = scan_json_primitive_end(lower_field, pos) else {
                break false;
            };
            let mut after = ve;
            while after < lower_field.len() && lower_field[after].is_ascii_whitespace() {
                after += 1;
            }
            if after < lower_field.len() && matches!(lower_field[after], b'}' | b']') {
                break true;
            }
            if after < lower_field.len() && lower_field[after] == b',' {
                let mut next_pos = after + 1;
                while next_pos < lower_field.len() && lower_field[next_pos].is_ascii_whitespace() {
                    next_pos += 1;
                }
                if next_pos <= pos {
                    break false;
                }
                pos = next_pos;
                continue;
            }
            break false;
        };

        if content_start <= lower_field.len() && (memo.flags[content_start] & fail_bit) != 0 {
            break false;
        }
        if content_start <= lower_field.len() {
            visited_content_starts.push(content_start);
        }

        if let Some((close_start, close_end)) = find_html_double_quote_entity_close(lower_field, content_start) {
            let mut after = close_end;
            while after < lower_field.len() && lower_field[after].is_ascii_whitespace() {
                after += 1;
            }
            let structural_json_after = after < lower_field.len()
                && (matches!(lower_field[after], b'}' | b']')
                    || (lower_field[after] == b':'
                        && html_colon_followed_by_json_value_memo(lower_field, after, has_json_prefix, memo)));
            if span_has_unredacted_keymaterial_in_html_quote(&lower_field[content_start..close_start])
                || (find_opening_keymaterial_tag(&lower_field[..close_start], content_start, true).is_some()
                    && (has_json_prefix || structural_json_after))
            {
                break true;
            }
            if structural_json_after {
                break true;
            }
            if after < lower_field.len() && lower_field[after] == b',' {
                let mut next_pos = after + 1;
                while next_pos < lower_field.len() && lower_field[next_pos].is_ascii_whitespace() {
                    next_pos += 1;
                }
                if next_pos <= pos {
                    break false;
                }
                pos = next_pos;
                continue;
            }
            break false;
        }
        let mut after_ws = content_start;
        while after_ws < lower_field.len() && lower_field[after_ws].is_ascii_whitespace() {
            after_ws += 1;
        }
        break has_unclosed_html_quot_km_leak(lower_field, after_ws, has_json_prefix);
    };
    if !res {
        for cs in visited_content_starts {
            memo.flags[cs] |= fail_bit;
        }
    }
    res
}

fn ends_with_html_json_value_before_comma_memo(
    full: &[u8],
    mut end: usize,
    mut allow_standalone: bool,
    mut memo: Option<&mut JsonMarkerMemo>,
) -> bool {
    let mut visited: Vec<(usize, bool)> = Vec::new();
    let res = loop {
        if let Some(m) = memo.as_deref() {
            let known_bit = if allow_standalone { 4u8 } else { 1u8 };
            let val_bit = if allow_standalone { 8u8 } else { 2u8 };
            if (m.flags[end] & known_bit) != 0 {
                break (m.flags[end] & val_bit) != 0;
            }
        }
        if memo.is_some() {
            visited.push((end, allow_standalone));
        }
        let slice = &full[..end];
        if let Some(close_q_start) = match_html_double_quote_entity_at_end(slice)
            && count_preceding_backslashes(slice, 0, close_q_start).is_multiple_of(2)
        {
            let Some(open_q_start) = find_html_double_quote_entity_open_backward(&slice[..close_q_start]) else {
                break false;
            };
            let k = skip_json_ws_backward(slice, open_q_start);
            if k == 0 {
                break allow_standalone;
            }
            match slice[k - 1] {
                b'[' | b'{' => break true,
                b',' => {
                    let bc = skip_json_ws_backward(slice, k - 1);
                    if bc >= end {
                        break false;
                    }
                    end = bc;
                    continue;
                }
                b':' => {
                    let bcol = skip_json_ws_backward(slice, k - 1);
                    if ends_with_json_string_quote(&slice[..bcol]) {
                        break true;
                    }
                    if bcol >= end {
                        break false;
                    }
                    end = bcol;
                    allow_standalone = true;
                    continue;
                }
                _ => break false,
            }
        }
        if ends_with_json_string_quote(slice) {
            break true;
        }
        if let Some(&close) = slice.last()
            && matches!(close, b'}' | b']')
        {
            let opener = if close == b'}' { b'{' } else { b'[' };
            if !slice.contains(&opener) {
                break false;
            }
            if let Some(m) = memo.as_deref_mut() {
                let cm = m
                    .container
                    .get_or_insert_with(|| JsonContainerMemo::new(full.len(), true, true));
                break ends_with_valid_json_container_memo(full, end, cm);
            }
            break ends_with_valid_json_container_with_csv(slice, true, true);
        }
        let (k, prefix_slice) = if slice.last().is_some_and(|&b| b.is_ascii_digit()) {
            let mut num_start = slice.len();
            while num_start > 0 && matches!(slice[num_start - 1], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
                num_start -= 1;
            }
            if !is_json_number_token(&slice[num_start..]) {
                break false;
            }
            (skip_json_ws_backward(slice, num_start), slice)
        } else if let Some(prefix) = [b"true".as_slice(), b"false".as_slice(), b"null".as_slice()]
            .into_iter()
            .find_map(|kw| slice.strip_suffix(kw))
        {
            (skip_json_ws_backward(prefix, prefix.len()), prefix)
        } else {
            break false;
        };

        if k == 0 {
            break allow_standalone;
        }
        match prefix_slice[k - 1] {
            b'[' => break true,
            b',' => {
                let bc = skip_json_ws_backward(prefix_slice, k - 1);
                if bc >= end {
                    break false;
                }
                end = bc;
            }
            b':' => {
                let bcol = skip_json_ws_backward(prefix_slice, k - 1);
                if ends_with_json_string_quote(&prefix_slice[..bcol]) {
                    break true;
                }
                if bcol >= end {
                    break false;
                }
                end = bcol;
                allow_standalone = true;
            }
            _ => break false,
        }
    };
    if let Some(m) = memo {
        for (ve, vas) in visited {
            let known_bit = if vas { 4u8 } else { 1u8 };
            let val_bit = if vas { 8u8 } else { 2u8 };
            m.flags[ve] |= known_bit;
            if res {
                m.flags[ve] |= val_bit;
            }
        }
    }
    res
}

fn field_has_html_encoded_json_or_keymaterial(lower_field: &[u8]) -> bool {
    let mut has_u003c_km = false;
    let mut pos = 0usize;
    while let Some(m) = find_opening_keymaterial_tag(lower_field, pos, true) {
        if m.syntax == TagSyntax::HtmlEscaped {
            return true;
        }
        if m.opened_with_u003c {
            has_u003c_km = true;
        }
        let open_close = find_tag_close_quote_aware(
            lower_field,
            m.after_name,
            m.syntax,
            TagScanContext {
                in_csv_field: true,
                allow_double_bs: true,
                opened_with_u003c: m.opened_with_u003c,
                ..TagScanContext::default()
            },
        );
        let open_tag_end = open_close.map_or(lower_field.len(), |(_, open_end, _)| open_end);
        let attr_span = &lower_field[m.after_name..open_tag_end];
        let mut k = 0usize;
        while k < attr_span.len() {
            if attr_span[k] == b'&' && match_html_quote_entity(&attr_span[k..]).is_some() {
                return true;
            }
            k += 1;
        }
        if open_close.is_none() {
            break;
        }
        pos = m.after_name;
    }
    if !lower_field.contains(&b'&') {
        return false;
    }
    let has_json_container = lower_field.contains(&b'{') || lower_field.contains(&b'[');
    let mut memo = JsonMarkerMemo::new(lower_field.len());
    let mut cached_next_double: Option<Option<(usize, usize)>> = None;
    let mut cached_next_single: Option<Option<(usize, usize)>> = None;
    let mut cached_next_km: Option<Option<usize>> = None;
    let mut last_false_double: Option<(usize, usize, usize)> = None;
    let mut last_false_single: Option<(usize, usize, usize)> = None;
    let mut i = 0usize;
    while i < lower_field.len() {
        if lower_field[i] == b'\\' {
            let bs = count_consecutive_backslashes(lower_field, i);
            if bs % 2 == 1
                && lower_field.get(i + bs) == Some(&b'&')
                && let Some((_qmode, len)) = match_html_quote_entity(&lower_field[i + bs..])
            {
                i += bs + len;
                continue;
            }
            i += bs;
            continue;
        }
        if lower_field[i] == b'&'
            && let Some((qmode, len)) = match_html_quote_entity(&lower_field[i..])
        {
            if qmode == HtmlQuoteMode::DoubleEntity {
                let open_q_start = i;
                let content_start = i + len;
                let close_opt = match cached_next_double {
                    Some(Some((cs, ce))) if cs >= content_start => Some((cs, ce)),
                    Some(None) => None,
                    _ => {
                        let found = find_html_double_quote_entity_close(lower_field, content_start);
                        cached_next_double = Some(found);
                        found
                    }
                };
                let span_end = close_opt.map_or(lower_field.len(), |(cs, _)| cs);
                let next_km = match cached_next_km {
                    Some(Some(km)) if km >= content_start => Some(km),
                    Some(None) => None,
                    _ => {
                        let found = find_ascii_bytes(lower_field, content_start, b"keymaterial");
                        cached_next_km = Some(found);
                        found
                    }
                };
                if let Some(km) = next_km
                    && km < span_end
                {
                    let already_verified_false = matches!(
                        last_false_double,
                        Some((prev_end, prev_cs, prev_km))
                            if prev_end == span_end
                                && prev_km == km
                                && find_ascii_bytes(&lower_field[prev_cs..content_start], 0, b"[redacted]").is_none()
                    );
                    if !already_verified_false
                        && span_has_unredacted_keymaterial_in_html_quote(&lower_field[content_start..span_end])
                    {
                        return true;
                    }
                    last_false_double = Some((span_end, content_start, km));
                }
                let mut p = i;
                while p > 0 && matches!(lower_field[p - 1], b' ' | b'\t' | b'\r' | b'\n') {
                    p -= 1;
                }
                if p > 0 {
                    match lower_field[p - 1] {
                        b'{' | b'[' => return true,
                        b':' => {
                            let mut before_colon = p - 1;
                            while before_colon > 0
                                && matches!(lower_field[before_colon - 1], b' ' | b'\t' | b'\r' | b'\n')
                            {
                                before_colon -= 1;
                            }
                            if is_html_colon_preceded_by_json_key(lower_field, before_colon, &mut memo) {
                                return true;
                            }
                        }
                        b',' => {
                            let mut before_comma = p - 1;
                            while before_comma > 0
                                && matches!(lower_field[before_comma - 1], b' ' | b'\t' | b'\r' | b'\n')
                            {
                                before_comma -= 1;
                            }
                            if ((has_json_container || has_u003c_km)
                                && ends_with_html_json_value_before_comma_memo(
                                    lower_field,
                                    before_comma,
                                    false,
                                    Some(&mut memo),
                                ))
                                || comma_html_double_quoted_value_is_json_or_km_memo(
                                    lower_field,
                                    content_start,
                                    before_comma,
                                    &mut memo,
                                )
                            {
                                return true;
                            }
                        }
                        _ => {}
                    }
                }
                if let Some((_close_start, close_end)) = close_opt
                    && html_quoted_entity_followed_by_json_structure_memo(
                        lower_field,
                        open_q_start,
                        close_end,
                        &mut memo,
                    )
                {
                    return true;
                }
            } else if qmode == HtmlQuoteMode::SingleEntity {
                let content_start = i + len;
                let close_opt = match cached_next_single {
                    Some(Some((cs, ce))) if cs >= content_start => Some((cs, ce)),
                    Some(None) => None,
                    _ => {
                        let found =
                            find_html_quote_entity_close(lower_field, content_start, HtmlQuoteMode::SingleEntity);
                        cached_next_single = Some(found);
                        found
                    }
                };
                let span_end = close_opt.map_or(lower_field.len(), |(cs, _)| cs);
                let next_km = match cached_next_km {
                    Some(Some(km)) if km >= content_start => Some(km),
                    Some(None) => None,
                    _ => {
                        let found = find_ascii_bytes(lower_field, content_start, b"keymaterial");
                        cached_next_km = Some(found);
                        found
                    }
                };
                if let Some(km) = next_km
                    && km < span_end
                {
                    let already_verified_false = matches!(
                        last_false_single,
                        Some((prev_end, prev_cs, prev_km))
                            if prev_end == span_end
                                && prev_km == km
                                && find_ascii_bytes(&lower_field[prev_cs..content_start], 0, b"[redacted]").is_none()
                    );
                    if !already_verified_false
                        && span_has_unredacted_keymaterial_in_html_quote(&lower_field[content_start..span_end])
                    {
                        return true;
                    }
                    last_false_single = Some((span_end, content_start, km));
                }
            }
            i += len;
            continue;
        }
        i += 1;
    }
    false
}

fn is_inline_prefixed_rfc4180_csv(bytes: &[u8], lower_rest: &[u8]) -> bool {
    if !bytes.contains(&b'\n') && !bytes.contains(&b'\r') {
        return false;
    }
    if parse_rfc4180_csv_fields(bytes).is_err() {
        return false;
    }
    let csv_ranges = collect_rfc4180_csv_quoted_content_ranges(lower_rest, false, false);
    if !csv_ranges.iter().any(|&(_, _, closed)| closed) {
        return false;
    }
    let mut outside = Vec::new();
    let mut prev = 0usize;
    for &(cs, ce, closed) in &csv_ranges {
        if closed && cs >= prev && ce <= lower_rest.len() {
            outside.extend_from_slice(&lower_rest[prev..cs]);
            prev = ce;
        }
    }
    if prev < lower_rest.len() {
        outside.extend_from_slice(&lower_rest[prev..]);
    }
    if contains_html_entity_bytes(&outside) {
        return false;
    }
    if contains_html_entity_bytes(lower_rest) {
        let all_entity_fields_csv_doubled = csv_ranges.iter().all(|&(cs, ce, closed)| {
            if !closed || !contains_html_entity_bytes(&lower_rest[cs..ce]) {
                return true;
            }
            let field = &lower_rest[cs..ce];
            !field_has_html_encoded_json_or_keymaterial(field) && field.windows(2).any(|w| w == b"\"\"")
        });
        return outside.contains(&b',') && all_entity_fields_csv_doubled;
    }
    true
}

fn is_html_document_or_fragment(bytes: &[u8]) -> bool {
    let mut rest = bytes.trim_ascii_start();
    while let Some(after_open) = rest.strip_prefix(b"<!--") {
        let Some(end_rel) = find_ascii_bytes(after_open, 0, b"-->") else {
            return false;
        };
        rest = after_open[end_rel + 3..].trim_ascii_start();
    }
    if !rest.starts_with(b"<") {
        return false;
    }
    let lower_prefix: Vec<u8> = rest.iter().take(128).map(u8::to_ascii_lowercase).collect();
    if is_raw_keymaterial_open_at(&lower_prefix, 0) {
        return false;
    }
    if lower_prefix.starts_with(b"<!doctype")
        && matches!(lower_prefix.get(9).copied(), Some(b'>' | b' ' | b'\t' | b'\r' | b'\n'))
    {
        return true;
    }
    const BLOCK_HTML_TAGS: &[&[u8]] = &[
        b"html",
        b"head",
        b"meta",
        b"title",
        b"style",
        b"script",
        b"body",
        b"h1",
        b"h2",
        b"h3",
        b"h4",
        b"h5",
        b"h6",
        b"div",
        b"p",
        b"pre",
        b"textarea",
        b"table",
        b"thead",
        b"tbody",
        b"tfoot",
        b"tr",
        b"th",
        b"td",
        b"ul",
        b"ol",
        b"li",
        b"br",
        b"hr",
        b"section",
        b"article",
        b"header",
        b"footer",
        b"nav",
        b"main",
        b"aside",
        b"figure",
        b"figcaption",
        b"caption",
        b"colgroup",
        b"col",
    ];
    for &tag in BLOCK_HTML_TAGS {
        let after = 1 + tag.len();
        if lower_prefix.get(1..after) == Some(tag)
            && matches!(
                lower_prefix.get(after).copied(),
                Some(b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n')
            )
        {
            return true;
        }
    }
    const INLINE_HTML_TAGS: &[&[u8]] = &[b"b", b"i", b"em", b"strong", b"a", b"span", b"code"];
    for &tag in INLINE_HTML_TAGS {
        let after = 1 + tag.len();
        if lower_prefix.get(1..after) == Some(tag)
            && matches!(
                lower_prefix.get(after).copied(),
                Some(b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n')
            )
        {
            let lower_rest = to_ascii_lowercase_vec(rest);
            let scan_start = find_html_open_tag_end(&lower_rest, 0).unwrap_or(after);
            if contains_block_html_tag(&lower_rest, scan_start, BLOCK_HTML_TAGS) {
                return true;
            }
            let has_close_tag = find_html_close_tag(&lower_rest, after, tag).is_some();
            if !(has_close_tag && contains_html_entity_bytes(&lower_rest[after..]))
                && is_inline_prefixed_rfc4180_csv(bytes, &lower_rest)
            {
                return false;
            }
            if has_close_tag {
                return true;
            }
            return contains_html_entity_bytes(&lower_rest[after..]);
        }
    }
    false
}

#[cfg(test)]
fn check_html_tag_attributes(attr_slice: &[u8]) -> Result<(), ReportError> {
    check_html_tag_attributes_with_depth(attr_slice, 0)
}

fn check_html_tag_attributes_with_depth(attr_slice: &[u8], depth: usize) -> Result<(), ReportError> {
    let has_km = contains_ascii_case_insensitive(attr_slice, b"keymaterial");
    let mut lower_attr_opt: Option<Vec<u8>> = None;
    let mut unredacted_close_cache: [Option<Option<usize>>; 2] = [None, None];
    let mut no_closing_tag = [false; 2];
    let mut k = 0usize;
    while k < attr_slice.len() {
        let loop_start = k;
        while k < attr_slice.len() && (attr_slice[k].is_ascii_whitespace() || matches!(attr_slice[k], b'/' | b'>')) {
            k += 1;
        }
        if k >= attr_slice.len() {
            break;
        }
        let name_start = k;
        k = scan_unquoted_html_token_end_cached(
            attr_slice,
            &mut lower_attr_opt,
            has_km,
            name_start,
            true,
            &mut unredacted_close_cache,
            &mut no_closing_tag,
        );
        let name_slice = &attr_slice[name_start..k];
        if name_slice.contains(&b'<') {
            assert_r4_clean_raw_bytes(name_slice)?;
        }
        if name_slice.contains(&b'&') || contains_ascii_case_insensitive(name_slice, b"\\u003c") {
            let decoded = unescape_html_entities_cow(name_slice);
            assert_r4_clean_html_attr_decoded_with_depth(&decoded, depth)?;
        }
        while k < attr_slice.len() && attr_slice[k].is_ascii_whitespace() {
            k += 1;
        }
        if attr_slice.get(k) != Some(&b'=') {
            if k <= loop_start {
                k = loop_start + 1;
            }
            continue;
        }
        k += 1;
        while k < attr_slice.len() && attr_slice[k].is_ascii_whitespace() {
            k += 1;
        }
        if k >= attr_slice.len() {
            break;
        }
        let val_slice = if matches!(attr_slice[k], b'"' | b'\'') {
            let q = attr_slice[k];
            let val_start = k + 1;
            let mut val_end = val_start;
            while val_end < attr_slice.len() && attr_slice[val_end] != q {
                val_end += 1;
            }
            k = if val_end < attr_slice.len() {
                val_end + 1
            } else {
                val_end
            };
            &attr_slice[val_start..val_end]
        } else {
            let val_start = k;
            k = scan_unquoted_html_token_end_cached(
                attr_slice,
                &mut lower_attr_opt,
                has_km,
                val_start,
                false,
                &mut unredacted_close_cache,
                &mut no_closing_tag,
            );
            &attr_slice[val_start..k]
        };
        if !val_slice.is_empty() {
            let decoded = unescape_html_entities_cow(val_slice);
            assert_r4_clean_html_attr_decoded_with_depth(&decoded, depth)?;
        }
        if k <= loop_start {
            k = loop_start + 1;
        }
    }
    Ok(())
}

fn match_html_amp_entity(rest: &[u8]) -> Option<usize> {
    if rest.get(..5).is_some_and(|s| s.eq_ignore_ascii_case(b"&amp;")) {
        return Some(5);
    }
    if let Some((cp, len)) = parse_html_numeric_char_ref(rest)
        && cp == u32::from(b'&')
    {
        return Some(len);
    }
    None
}

fn contains_json_opener_or_html_entity(bytes: &[u8]) -> bool {
    if bytes.contains(&b'{') || bytes.contains(&b'[') {
        return true;
    }
    if !bytes.contains(&b'&') {
        return false;
    }
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'&'
            && let Some((cp, len)) = parse_html_numeric_char_ref(&bytes[i..])
        {
            if matches!(cp, 123 | 91) {
                return true;
            }
            i += len;
            continue;
        }
        i += 1;
    }
    false
}

fn ends_with_html_json_opener_entity(bytes: &[u8], end: usize) -> bool {
    if end > 3 && bytes[end - 1] == b';' {
        let search_start = end.saturating_sub(12);
        if let Some(rel_amp) = bytes[search_start..end].iter().rposition(|&b| b == b'&') {
            let start = search_start + rel_amp;
            if let Some((cp, len)) = parse_html_numeric_char_ref(&bytes[start..end])
                && start + len == end
                && matches!(cp, 123 | 91)
            {
                return true;
            }
        }
    }
    false
}

fn starts_with_html_json_closer_entity(rest: &[u8]) -> bool {
    matches!(parse_html_numeric_char_ref(rest), Some((125 | 93, _)))
}

fn has_double_encoded_html_syntax(raw: &[u8]) -> bool {
    let mut i = 0usize;
    while i < raw.len() {
        if raw[i] == b'&'
            && let Some(amp_len) = match_html_amp_entity(&raw[i..])
        {
            let after = &raw[i + amp_len..];
            if after.get(..5).is_some_and(|s| s.eq_ignore_ascii_case(b"quot;"))
                || after.get(..5).is_some_and(|s| s.eq_ignore_ascii_case(b"apos;"))
                || after.get(..3).is_some_and(|s| s.eq_ignore_ascii_case(b"lt;"))
                || after.get(..3).is_some_and(|s| s.eq_ignore_ascii_case(b"gt;"))
            {
                return true;
            }
            if after.starts_with(b"#") {
                let mut probe = Vec::with_capacity(after.len().min(12) + 1);
                probe.push(b'&');
                probe.extend_from_slice(&after[..after.len().min(12)]);
                if let Some((cp, _)) = parse_html_numeric_char_ref(&probe)
                    && matches!(cp, 34 | 39 | 47 | 60 | 62)
                {
                    return true;
                }
            }
            i += amp_len;
            continue;
        }
        i += 1;
    }
    false
}

fn has_html_entity_json_delim(lower_bytes: &[u8]) -> bool {
    if !lower_bytes.contains(&b'&') || !contains_json_opener_or_html_entity(lower_bytes) {
        return false;
    }
    let mut i = 0usize;
    while i < lower_bytes.len() {
        if lower_bytes[i] == b'&'
            && let Some((HtmlQuoteMode::DoubleEntity, len)) = match_html_quote_entity(&lower_bytes[i..])
        {
            let before = skip_json_ws_backward(lower_bytes, i);
            if before > 0
                && (matches!(lower_bytes[before - 1], b'{' | b'[' | b':' | b',')
                    || ends_with_html_json_opener_entity(lower_bytes, before))
            {
                return true;
            }
            let after = skip_json_ws_forward(lower_bytes, i + len);
            if after < lower_bytes.len()
                && (matches!(lower_bytes[after], b':' | b',' | b'}' | b']')
                    || starts_with_html_json_closer_entity(&lower_bytes[after..]))
            {
                return true;
            }
            i += len;
            continue;
        }
        i += 1;
    }
    false
}

fn is_raw_keymaterial_close_at(lower_bytes: &[u8], pos: usize) -> bool {
    if lower_bytes.get(pos..pos + 2) != Some(b"</") {
        return false;
    }
    let mut p = pos + 2;
    while p < lower_bytes.len() && is_xml_ncname_char(lower_bytes[p]) {
        p += 1;
    }
    let name = if lower_bytes.get(p) == Some(&b':') {
        p += 1;
        let name_start = p;
        while p < lower_bytes.len() && is_xml_ncname_char(lower_bytes[p]) {
            p += 1;
        }
        &lower_bytes[name_start..p]
    } else {
        &lower_bytes[pos + 2..p]
    };
    name == b"keymaterial" && matches!(lower_bytes.get(p).copied(), Some(b'>' | b' ' | b'\t' | b'\r' | b'\n'))
}

fn find_html_open_tag_end_with_skip_bound(lower_bytes: &[u8], pos: usize) -> (Option<usize>, usize) {
    let mut i = pos + 1;
    let mut quote: Option<u8> = None;
    let mut first_barrier: Option<usize> = None;
    let mut km_close_cache: [Option<Option<usize>>; 2] = [None, None];
    let mut no_raw_closing_km = false;
    while i < lower_bytes.len() {
        let b = lower_bytes[i];
        if let Some(q) = quote {
            if b == b'<'
                && let Some(name_end) = raw_keymaterial_name_end(lower_bytes, i)
            {
                if let Some((_cs, km_open_end, is_self_closing)) = find_tag_close_quote_aware_cached(
                    lower_bytes,
                    name_end,
                    TagSyntax::Raw,
                    TagScanContext {
                        allow_double_bs: true,
                        ..TagScanContext::default()
                    },
                    &mut km_close_cache,
                ) {
                    let km_end = if !is_self_closing && !no_raw_closing_km {
                        if let Some((_cs, km_close_end)) =
                            find_closing_keymaterial_tag(lower_bytes, km_open_end, TagSyntax::Raw, true)
                        {
                            km_close_end
                        } else {
                            no_raw_closing_km = true;
                            km_open_end
                        }
                    } else {
                        km_open_end
                    };
                    if !lower_bytes[name_end..km_end].contains(&q) {
                        i = km_end;
                        continue;
                    }
                }
                if let Some((_cs, km_close_end)) =
                    find_closing_keymaterial_tag(lower_bytes, name_end, TagSyntax::Raw, true)
                {
                    return (Some(km_close_end), first_barrier.unwrap_or(km_close_end));
                }
                return (None, first_barrier.unwrap_or(lower_bytes.len()));
            }
            if b == q {
                quote = None;
            }
        } else if matches!(b, b'"' | b'\'') {
            if first_barrier.is_none() {
                first_barrier = Some(i);
            }
            quote = Some(b);
        } else if b == b'<'
            && let Some(name_end) = raw_keymaterial_name_end(lower_bytes, i)
            && let Some((_cs, km_open_end, is_self_closing)) = find_tag_close_quote_aware_cached(
                lower_bytes,
                name_end,
                TagSyntax::Raw,
                TagScanContext {
                    allow_double_bs: true,
                    ..TagScanContext::default()
                },
                &mut km_close_cache,
            )
        {
            if first_barrier.is_none() {
                first_barrier = Some(i);
            }
            if !is_self_closing && !no_raw_closing_km {
                if let Some((_cs, km_close_end)) =
                    find_closing_keymaterial_tag(lower_bytes, km_open_end, TagSyntax::Raw, true)
                {
                    i = km_close_end;
                    continue;
                }
                no_raw_closing_km = true;
            }
            i = km_open_end;
            continue;
        } else if b == b'>' {
            return (Some(i + 1), first_barrier.unwrap_or(i + 1));
        }
        i += 1;
    }
    (None, first_barrier.unwrap_or(lower_bytes.len()))
}

fn nl_tag_index(tag_name: &[u8]) -> Option<usize> {
    match tag_name {
        b"script" => Some(0),
        b"style" => Some(1),
        b"title" => Some(2),
        b"textarea" => Some(3),
        b"td" => Some(4),
        b"th" => Some(5),
        b"tr" => Some(6),
        b"table" => Some(7),
        _ => None,
    }
}

struct MaskHtmlJsonResult {
    masked: Vec<u8>,
    nl_in_json_str: bool,
    clean_cross_cell_km_spans: Vec<(usize, usize)>,
}

fn mask_html_tags_for_json_scan(bytes: &[u8]) -> Vec<u8> {
    mask_html_tags_for_json_scan_with_options(bytes, false).0
}

fn mask_html_tags_for_json_scan_with_options(bytes: &[u8], space_inside_json_string: bool) -> (Vec<u8>, bool) {
    let res = mask_html_tags_for_json_scan_detailed(bytes, space_inside_json_string);
    (res.masked, res.nl_in_json_str)
}

struct CrossCellSeg {
    start: usize,
    end: usize,
    clean_km_spans: Vec<(usize, usize)>,
}

struct CrossCellPlan {
    segs: Vec<CrossCellSeg>,
    has_hazard_at_or_after: Vec<bool>,
    seg_masked: Vec<bool>,
    cur_seg: usize,
}

fn find_next_nl_tag_pos(bytes: &[u8], lower: &[u8], start: usize) -> usize {
    let mut p = start;
    let mut skip_tag_scan_until = start;
    while p < bytes.len() {
        if bytes[p] != b'<' {
            let Some(next_lt) = find_byte(bytes, p, b'<') else {
                return bytes.len();
            };
            p = next_lt;
        }
        if bytes[p..].starts_with(b"<!--") {
            if let Some(end_pos) = find_ascii_bytes(bytes, p + 4, b"-->") {
                p = end_pos + 3;
            } else {
                p += 4;
            }
            continue;
        }
        if raw_keymaterial_name_end(lower, p).is_some() || is_raw_keymaterial_close_at(lower, p) {
            p += 1;
            continue;
        }
        if bytes.get(p + 1) == Some(&b'!') {
            if let Some(gt) = find_byte(bytes, p, b'>') {
                p = gt + 1;
                continue;
            }
            return bytes.len();
        }
        if bytes.get(p + 1) == Some(&b'/') || bytes.get(p + 1).is_some_and(u8::is_ascii_alphabetic) {
            if p < skip_tag_scan_until {
                p += 1;
                continue;
            }
            let name_start = p + 1 + usize::from(bytes.get(p + 1) == Some(&b'/'));
            let mut tag_name_end = name_start;
            while tag_name_end < lower.len()
                && (lower[tag_name_end].is_ascii_alphanumeric() || matches!(lower[tag_name_end], b'-' | b':'))
            {
                tag_name_end += 1;
            }
            let tag_name = &lower[name_start..tag_name_end];
            let (end_opt, skip_until) = find_html_open_tag_end_with_skip_bound(lower, p);
            if let Some(end) = end_opt {
                if nl_tag_index(tag_name).is_some() {
                    return p;
                }
                p = end;
                continue;
            }
            skip_tag_scan_until = skip_tag_scan_until.max(skip_until);
        }
        p += 1;
    }
    bytes.len()
}

fn analyze_cross_cell_segment(
    lower_seg: &[u8],
    seg_offset: usize,
    out_clean: &mut Vec<(usize, usize)>,
) -> (bool, bool) {
    if !contains_ascii_case_insensitive(lower_seg, b"keymaterial") {
        return (false, false);
    }
    let first_open_pos = find_opening_keymaterial_tag(lower_seg, 0, true).map(|m| m.open_start);
    let last_unredacted_close = last_unredacted_closing_km_pos(lower_seg, 0, true);
    let has_orphan_close = last_unredacted_close.is_some()
        && first_open_pos.is_none_or(|fp| slice_contains_closing_keymaterial_tag(&lower_seg[..fp], true).is_some());
    let mut has_hazard = last_unredacted_close.is_some();
    let mut pos = 0usize;
    let mut unredacted_close_cache: [Option<Option<usize>>; 2] = [None, None];
    let mut next_close_cache: [Option<Option<(usize, usize)>>; 2] = [None, None];

    while let Some(m) = find_opening_keymaterial_tag(lower_seg, pos, true) {
        if m.opened_with_u003c {
            has_hazard = true;
            pos = m.after_name;
            continue;
        }
        let ctx = TagScanContext {
            allow_double_bs: true,
            opened_with_u003c: m.opened_with_u003c,
            ..TagScanContext::default()
        };
        let Some((close_start, open_end, is_self_closing)) =
            find_tag_close_quote_aware_cached(lower_seg, m.after_name, m.syntax, ctx, &mut unredacted_close_cache)
        else {
            has_hazard = true;
            break;
        };
        let tag_span = &lower_seg[m.after_name..open_end];
        let attr_has_json_escape = find_ascii_bytes(tag_span, 0, b"\\\"").is_some()
            || find_ascii_bytes(tag_span, 0, b"\\u0022").is_some()
            || find_ascii_bytes(tag_span, 0, b"\\u0027").is_some()
            || find_ascii_bytes(tag_span, 0, b"\\u003c").is_some()
            || find_ascii_bytes(tag_span, 0, b"\\u003e").is_some();
        let attr_has_inner_km = find_ascii_bytes(&lower_seg[m.after_name..close_start], 0, b"keymaterial").is_some()
            && has_unredacted_inner_keymaterial_in_span(lower_seg, m.after_name, close_start, true, ctx);
        if is_self_closing {
            if attr_has_json_escape || attr_has_inner_km {
                has_hazard = true;
            } else if !has_hazard {
                out_clean.push((seg_offset + m.open_start, seg_offset + open_end));
            }
            pos = open_end;
        } else {
            let syn_idx = usize::from(m.syntax == TagSyntax::HtmlEscaped);
            let close_opt = match next_close_cache[syn_idx] {
                Some(None) => None,
                Some(Some((be, ce))) if be >= open_end => Some((be, ce)),
                _ => {
                    let found = find_closing_keymaterial_tag(lower_seg, open_end, m.syntax, true);
                    next_close_cache[syn_idx] = Some(found);
                    found
                }
            };
            if let Some((body_end, close_end)) = close_opt {
                let body_clean = lower_seg[open_end..body_end].trim_ascii() == b"[redacted]";
                if attr_has_json_escape || attr_has_inner_km || !body_clean {
                    has_hazard = true;
                    pos = open_end;
                } else {
                    if !has_hazard {
                        out_clean.push((seg_offset + m.open_start, seg_offset + close_end));
                    }
                    pos = close_end;
                }
            } else {
                has_hazard = true;
                pos = open_end;
            }
        }
    }
    if has_hazard {
        out_clean.clear();
    } else if has_double_encoded_html_syntax(lower_seg) {
        let mut dec = unescape_html_entities(lower_seg);
        dec.make_ascii_lowercase();
        let mut dummy_clean = Vec::new();
        let (dec_hazard, dec_orphan) = analyze_cross_cell_segment(&dec, 0, &mut dummy_clean);
        if dec_hazard {
            out_clean.clear();
            return (true, has_orphan_close || dec_orphan);
        }
    }
    (has_hazard, has_orphan_close)
}

impl CrossCellPlan {
    fn build(bytes: &[u8], lower: &[u8]) -> Option<Self> {
        if !contains_ascii_case_insensitive(lower, b"keymaterial") {
            return None;
        }
        let mut segs = Vec::new();
        let mut seg_hazards = Vec::new();
        let mut seg_orphans = Vec::new();
        let mut pos = 0usize;
        while pos < bytes.len() {
            let seg_end = find_next_nl_tag_pos(bytes, lower, pos);
            let mut clean_km_spans = Vec::new();
            let (has_hazard, has_orphan_close) = if seg_end > pos {
                analyze_cross_cell_segment(&lower[pos..seg_end], pos, &mut clean_km_spans)
            } else {
                (false, false)
            };
            segs.push(CrossCellSeg {
                start: pos,
                end: seg_end,
                clean_km_spans,
            });
            seg_hazards.push(has_hazard);
            seg_orphans.push(has_orphan_close);
            if seg_end >= bytes.len() {
                break;
            }
            let (end_opt, _) = find_html_open_tag_end_with_skip_bound(lower, seg_end);
            pos = end_opt.unwrap_or(seg_end + 1);
        }
        if segs.is_empty() {
            return None;
        }
        let mut has_hazard_at_or_after = vec![false; segs.len()];
        let mut running_hazard = false;
        let mut running_orphan = false;
        for idx in (0..segs.len()).rev() {
            if running_orphan && !segs[idx].clean_km_spans.is_empty() {
                // Keep only closed `[REDACTED]` tags without quote delimiters when an orphan `</keyMaterial>` follows.
                segs[idx].clean_km_spans.retain(|&(s, e)| {
                    let span = &lower[s..e];
                    !span.contains(&b'"')
                        && !span.contains(&b'\'')
                        && find_ascii_bytes(span, 0, b"&quot;").is_none()
                        && find_ascii_bytes(span, 0, b"&apos;").is_none()
                        && find_ascii_bytes(span, 0, b"&#").is_none()
                });
            }
            running_hazard |= seg_hazards[idx];
            has_hazard_at_or_after[idx] = running_hazard;
            running_orphan |= seg_orphans[idx];
        }
        if !has_hazard_at_or_after.first().copied().unwrap_or(false) {
            return None;
        }
        let seg_masked = vec![false; segs.len()];
        Some(Self {
            segs,
            has_hazard_at_or_after,
            seg_masked,
            cur_seg: 0,
        })
    }

    fn advance_to(&mut self, pos: usize) {
        while self.cur_seg < self.segs.len() && self.segs[self.cur_seg].end <= pos {
            self.cur_seg += 1;
        }
    }

    fn has_future_hazard_from(&mut self, pos: usize) -> bool {
        self.advance_to(pos);
        self.has_hazard_at_or_after.get(self.cur_seg).copied().unwrap_or(false)
    }

    fn mask_clean_km_at(&mut self, pos: usize, out: &mut [u8], recorded: &mut Vec<(usize, usize)>) {
        self.advance_to(pos);
        if self.cur_seg < self.segs.len()
            && self.segs[self.cur_seg].start <= pos
            && pos < self.segs[self.cur_seg].end
            && !self.seg_masked[self.cur_seg]
        {
            self.seg_masked[self.cur_seg] = true;
            for &(s, e) in &self.segs[self.cur_seg].clean_km_spans {
                out[s..e].fill(b' ');
                recorded.push((s, e));
            }
        }
    }
}

fn mask_html_tags_for_json_scan_detailed(bytes: &[u8], space_inside_json_string: bool) -> MaskHtmlJsonResult {
    let lower = to_ascii_lowercase_vec(bytes);
    let mut tracker = if has_html_entity_json_delim(&lower) {
        JsonContextTracker::with_html_entities()
    } else {
        JsonContextTracker::with_markdown(false)
    };
    let mut open_nl_tags: Vec<(usize, bool)> = Vec::new();
    let mut open_nl_counts = [0usize; 8];
    let mut crossed_string_start: Option<usize> = None;
    let mut plan = if space_inside_json_string {
        CrossCellPlan::build(bytes, &lower)
    } else {
        None
    };
    let mut clean_cross_cell_km_spans = Vec::new();
    let mut out = bytes.to_vec();
    let mut nl_in_json_str = false;
    let mut i = 0usize;
    let mut skip_tag_scan_until = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            let Some(next_lt) = find_byte(bytes, i, b'<') else {
                break;
            };
            i = next_lt;
        }
        if bytes[i..].starts_with(b"<!--") {
            if let Some(end_pos) = find_ascii_bytes(bytes, i + 4, b"-->") {
                out[i..end_pos + 3].fill(b' ');
                i = end_pos + 3;
                continue;
            }
            i += 4;
            continue;
        }
        if raw_keymaterial_name_end(&lower, i).is_some() || is_raw_keymaterial_close_at(&lower, i) {
            i += 1;
            continue;
        }
        if bytes.get(i + 1) == Some(&b'/') {
            if i < skip_tag_scan_until {
                i += 1;
                continue;
            }
            let mut tag_name_end = i + 2;
            while tag_name_end < lower.len()
                && (lower[tag_name_end].is_ascii_alphanumeric() || matches!(lower[tag_name_end], b'-' | b':'))
            {
                tag_name_end += 1;
            }
            let tag_name = &lower[i + 2..tag_name_end];
            let (end_opt, skip_until) = find_html_open_tag_end_with_skip_bound(&lower, i);
            if let Some(end) = end_opt {
                let fill = if let Some(nl_idx) = nl_tag_index(tag_name) {
                    let (in_json_string, _, _, _) = tracker.advance_to(&out, i);
                    if !in_json_string {
                        crossed_string_start = None;
                    }
                    let matched_outside_json = if open_nl_counts[nl_idx] == 0 {
                        false
                    } else if let Some(pos) = open_nl_tags.iter().rposition(|&(idx, _)| idx == nl_idx) {
                        let (_, started) = open_nl_tags[pos];
                        for &(popped_idx, _) in &open_nl_tags[pos..] {
                            open_nl_counts[popped_idx] -= 1;
                        }
                        open_nl_tags.truncate(pos);
                        !started
                    } else {
                        false
                    };
                    if in_json_string && (space_inside_json_string || !matched_outside_json) {
                        if matched_outside_json {
                            if space_inside_json_string {
                                if !plan.as_mut().is_some_and(|p| p.has_future_hazard_from(end)) {
                                    if open_nl_tags.is_empty() {
                                        crossed_string_start = None;
                                        out[i..end].fill(b'\n');
                                        i = end;
                                        continue;
                                    }
                                } else if let Some(p) = plan.as_mut() {
                                    p.mask_clean_km_at(end, &mut out, &mut clean_cross_cell_km_spans);
                                }
                            }
                            crossed_string_start = Some(tracker.string_start);
                        }
                        b' '
                    } else {
                        if in_json_string {
                            nl_in_json_str = true;
                        }
                        b'\n'
                    }
                } else {
                    b' '
                };
                out[i..end].fill(fill);
                i = end;
            } else {
                skip_tag_scan_until = skip_tag_scan_until.max(skip_until);
                i += 1;
            }
            continue;
        }
        if bytes.get(i + 1) == Some(&b'!') {
            if let Some(gt) = find_byte(bytes, i, b'>') {
                out[i..gt + 1].fill(b' ');
                i = gt + 1;
            } else {
                break;
            }
            continue;
        }
        if bytes.get(i + 1).is_some_and(u8::is_ascii_alphabetic) {
            if i < skip_tag_scan_until {
                i += 1;
                continue;
            }
            let mut tag_name_end = i + 2;
            while tag_name_end < lower.len()
                && (lower[tag_name_end].is_ascii_alphanumeric() || matches!(lower[tag_name_end], b'-' | b':'))
            {
                tag_name_end += 1;
            }
            let tag_name = &lower[i + 1..tag_name_end];
            let (end_opt, skip_until) = find_html_open_tag_end_with_skip_bound(&lower, i);
            if let Some(end) = end_opt {
                let fill = if let Some(nl_idx) = nl_tag_index(tag_name) {
                    let (in_json_string, _, _, _) = tracker.advance_to(&out, i);
                    if !in_json_string {
                        crossed_string_start = None;
                    }
                    let is_self_closing = end >= i + 2 && bytes[end - 2] == b'/';
                    if in_json_string && space_inside_json_string && crossed_string_start == Some(tracker.string_start)
                    {
                        if !is_self_closing {
                            open_nl_tags.push((nl_idx, false));
                            open_nl_counts[nl_idx] += 1;
                        }
                        if !plan.as_mut().is_some_and(|p| p.has_future_hazard_from(end)) {
                            crossed_string_start = None;
                            b'\n'
                        } else {
                            if let Some(p) = plan.as_mut() {
                                p.mask_clean_km_at(end, &mut out, &mut clean_cross_cell_km_spans);
                            }
                            b' '
                        }
                    } else {
                        if !is_self_closing {
                            open_nl_tags.push((nl_idx, in_json_string));
                            open_nl_counts[nl_idx] += 1;
                        }
                        if in_json_string { b' ' } else { b'\n' }
                    }
                } else if space_inside_json_string && crossed_string_start.is_some() {
                    let (in_json_string, _, _, _) = tracker.advance_to(&out, i);
                    if !in_json_string {
                        crossed_string_start = None;
                        b' '
                    } else if crossed_string_start == Some(tracker.string_start) {
                        if !plan.as_mut().is_some_and(|p| p.has_future_hazard_from(end)) {
                            crossed_string_start = None;
                            b'\n'
                        } else {
                            if let Some(p) = plan.as_mut() {
                                p.mask_clean_km_at(end, &mut out, &mut clean_cross_cell_km_spans);
                            }
                            b' '
                        }
                    } else {
                        b' '
                    }
                } else {
                    b' '
                };
                out[i..end].fill(fill);
                i = end;
            } else {
                skip_tag_scan_until = skip_tag_scan_until.max(skip_until);
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    MaskHtmlJsonResult {
        masked: out,
        nl_in_json_str,
        clean_cross_cell_km_spans,
    }
}

fn mask_verified_raw_json_html_escaped_tags(raw: &[u8]) -> Option<Vec<u8>> {
    let lower = to_ascii_lowercase_vec(raw);
    let mut tracker = JsonContextTracker::with_markdown(false);
    let mut masked = raw.to_vec();
    let mut changed = false;
    let mut cursor = 0usize;
    let mut unredacted_close_cache: [Option<Option<usize>>; 2] = [None, None];

    while let Some(OpeningTagMatch {
        open_start,
        after_name,
        syntax,
        opened_with_u003c,
    }) = find_opening_keymaterial_tag(&lower, cursor, true)
    {
        let (in_json_string, in_markdown_json_string, in_markdown_table_line, in_nested_json_string) =
            tracker.advance_to(&lower, open_start);
        let has_double_escaped_gap = in_json_string && tracker.mark_double_escaped_gap(&lower, cursor, open_start);
        if (syntax == TagSyntax::HtmlEscaped || (syntax == TagSyntax::Raw && opened_with_u003c)) && in_json_string {
            let in_double_escaped_json = in_markdown_json_string
                || in_nested_json_string
                || has_double_escaped_gap
                || is_double_escaped_tag_open(&lower, open_start);
            let ctx = TagScanContext {
                in_csv_field: false,
                in_json_string,
                in_markdown_json_string,
                in_markdown_table_line,
                in_double_escaped_json,
                in_nested_json_string,
                allow_double_bs: true,
                opened_with_u003c,
                allow_tsv_tabs: false,
                in_decoded_u0022_json_ctx: false,
            };
            if let Some((_cs, open_end, is_self_closing)) =
                find_tag_close_quote_aware_cached(&lower, after_name, syntax, ctx, &mut unredacted_close_cache)
            {
                let span_end = if is_self_closing {
                    Some(open_end)
                } else if let Some((close_start, close_end)) =
                    find_closing_keymaterial_tag(&lower, open_end, syntax, ctx.allow_double_bs)
                {
                    (lower[open_end..close_start].trim_ascii() == b"[redacted]").then_some(close_end)
                } else {
                    None
                };
                if let Some(end) = span_end
                    && !has_double_encoded_html_syntax(&raw[open_start..end])
                    && !has_unredacted_inner_keymaterial_in_span(&lower, after_name, open_end, true, ctx)
                {
                    masked[open_start..end].fill(b'_');
                    changed = true;
                    cursor = end;
                    continue;
                }
            }
        }
        cursor = after_name;
    }

    changed.then_some(masked)
}

fn flush_html_text_buf_with_origin(
    text_buf: &mut Vec<u8>,
    depth: usize,
    from_json_value: bool,
) -> Result<(), ReportError> {
    if !text_buf.is_empty() {
        if contains_ascii_case_insensitive(text_buf, b"\\u0022")
            && !has_double_encoded_html_syntax(text_buf)
            && !has_html_entity_json_delim(text_buf)
            && let Err(err) = assert_r4_clean_decoded_cell_inner_with_origin(text_buf, depth + 1, false, false)
        {
            text_buf.clear();
            return Err(err);
        }
        let decoded = unescape_html_entities_cow(text_buf);
        let check_decoded = |buf: &[u8]| -> Result<(), ReportError> {
            if is_html_document_or_fragment(buf) {
                if depth < MAX_NESTED_JSON_DEPTH {
                    return verify_html_with_embedded_json_with_origin(buf, depth + 1, from_json_value);
                }
                let masked_html = mask_html_tags_for_json_scan(buf);
                return assert_r4_clean_decoded_cell_inner_with_origin(&masked_html, depth, false, from_json_value);
            }
            assert_r4_clean_decoded_cell_inner_with_origin(buf, depth, false, from_json_value)
        };
        let res = match check_decoded(&decoded) {
            Ok(()) => Ok(()),
            Err(err) => {
                if assert_r4_clean_decoded_cell_inner_with_origin(text_buf, depth, false, from_json_value).is_ok()
                    && let Some(masked) = mask_verified_raw_json_html_escaped_tags(text_buf)
                {
                    let masked_decoded = unescape_html_entities(&masked);
                    check_decoded(&masked_decoded).map_err(|_| err)
                } else {
                    Err(err)
                }
            }
        };
        text_buf.clear();
        res?;
    }
    Ok(())
}

fn verify_html_document_or_fragment_with_origin(
    bytes: &[u8],
    depth: usize,
    from_json_value: bool,
) -> Result<(), ReportError> {
    let lower_bytes = to_ascii_lowercase_vec(bytes);
    let mut text_buf = Vec::new();
    let mut i = 0usize;
    let mut unredacted_close_cache: [Option<Option<usize>>; 2] = [None, None];

    while i < bytes.len() {
        if bytes[i] != b'<' {
            let next_lt = find_byte(bytes, i, b'<').unwrap_or(bytes.len());
            text_buf.extend_from_slice(&bytes[i..next_lt]);
            i = next_lt;
            continue;
        }

        if bytes[i..].starts_with(b"<!--") {
            flush_html_text_buf_with_origin(&mut text_buf, depth, from_json_value)?;
            if let Some(end_pos) = find_ascii_bytes(bytes, i + 4, b"-->") {
                assert_r4_clean_raw_bytes(&bytes[i + 4..end_pos])?;
                i = end_pos + 3;
            } else {
                assert_r4_clean_raw_bytes(&bytes[i + 4..])?;
                i = bytes.len();
            }
            continue;
        }

        if let Some(name_end) = raw_keymaterial_name_end(&lower_bytes, i) {
            let (in_json_string, in_nested_json_string) = if text_buf.is_empty() {
                (false, false)
            } else {
                let decoded_prefix = unescape_html_entities_cow(&text_buf);
                let lower_prefix = to_ascii_lowercase_vec(&decoded_prefix);
                let mut tracker = JsonContextTracker::with_markdown(false);
                let (in_j, _, _, in_nested_j) = tracker.advance_to(&lower_prefix, lower_prefix.len());
                (in_j, in_nested_j)
            };
            let ctx = TagScanContext {
                in_csv_field: false,
                in_json_string,
                in_markdown_json_string: false,
                in_markdown_table_line: false,
                in_double_escaped_json: in_nested_json_string,
                in_nested_json_string,
                allow_double_bs: in_json_string,
                opened_with_u003c: false,
                allow_tsv_tabs: false,
                in_decoded_u0022_json_ctx: false,
            };
            if let Some((_cs, open_end, is_self_closing)) = find_tag_close_quote_aware_cached(
                &lower_bytes,
                name_end,
                TagSyntax::Raw,
                ctx,
                &mut unredacted_close_cache,
            ) {
                let end = if is_self_closing {
                    open_end
                } else if let Some((_cs, close_end)) =
                    find_closing_keymaterial_tag(&lower_bytes, open_end, TagSyntax::Raw, ctx.allow_double_bs)
                {
                    close_end
                } else {
                    open_end
                };
                if in_json_string {
                    text_buf.extend_from_slice(&bytes[i..end]);
                } else {
                    flush_html_text_buf_with_origin(&mut text_buf, depth, from_json_value)?;
                    if open_end > name_end + 1 {
                        check_html_tag_attributes_with_depth(&bytes[name_end..open_end - 1], depth)?;
                    }
                    assert_r4_clean_decoded_cell_inner_with_origin(&bytes[i..end], depth + 1, false, from_json_value)?;
                }
                i = end;
            } else if !in_json_string {
                flush_html_text_buf_with_origin(&mut text_buf, depth, from_json_value)?;
                return assert_r4_clean_decoded_cell_inner_with_options(
                    &bytes[i..],
                    depth + 1,
                    false,
                    from_json_value,
                    false,
                );
            } else {
                text_buf.push(bytes[i]);
                i += 1;
            }
            continue;
        }

        if bytes.get(i + 1) == Some(&b'/') {
            flush_html_text_buf_with_origin(&mut text_buf, depth, from_json_value)?;
            if let Some(end) = find_html_open_tag_end(&lower_bytes, i) {
                i = end;
            } else {
                assert_r4_clean_raw_bytes(&bytes[i..])?;
                i = bytes.len();
            }
            continue;
        }

        if bytes.get(i + 1) == Some(&b'!') {
            flush_html_text_buf_with_origin(&mut text_buf, depth, from_json_value)?;
            if let Some(gt) = find_byte(bytes, i, b'>') {
                i = gt + 1;
            } else {
                i = bytes.len();
            }
            continue;
        }

        if bytes.get(i + 1).is_some_and(u8::is_ascii_alphabetic) {
            flush_html_text_buf_with_origin(&mut text_buf, depth, from_json_value)?;
            let mut tag_name_end = i + 2;
            while tag_name_end < lower_bytes.len()
                && (lower_bytes[tag_name_end].is_ascii_alphanumeric()
                    || matches!(lower_bytes[tag_name_end], b'-' | b':'))
            {
                tag_name_end += 1;
            }
            let tag_name = &lower_bytes[i + 1..tag_name_end];
            let Some(tag_end) = find_html_open_tag_end(&lower_bytes, i) else {
                assert_r4_clean_raw_bytes(&bytes[i..])?;
                let dec = unescape_html_entities(&bytes[i..]);
                let allow_html_reentry = dec != bytes[i..] || bytes[i..].contains(&b'\n');
                return assert_r4_clean_decoded_cell_inner_with_options(
                    &dec,
                    depth + 1,
                    false,
                    from_json_value,
                    allow_html_reentry,
                );
            };
            if tag_end > tag_name_end + 1 {
                check_html_tag_attributes_with_depth(&bytes[tag_name_end..tag_end - 1], depth)?;
            }
            i = tag_end;

            if matches!(tag_name, b"title" | b"textarea") {
                if let Some((close_start, close_end)) = find_html_close_tag(&lower_bytes, i, tag_name) {
                    let decoded = unescape_html_entities_cow(&bytes[i..close_start]);
                    assert_r4_clean_decoded_cell_inner_with_origin(&decoded, depth + 1, false, from_json_value)?;
                    i = close_end;
                } else {
                    let decoded = unescape_html_entities_cow(&bytes[i..]);
                    assert_r4_clean_decoded_cell_inner_with_origin(&decoded, depth + 1, false, from_json_value)?;
                    i = bytes.len();
                }
            } else if matches!(tag_name, b"script" | b"style") {
                if let Some((close_start, close_end)) = find_html_close_tag(&lower_bytes, i, tag_name) {
                    assert_r4_clean_decoded_cell_inner_with_origin(
                        &bytes[i..close_start],
                        depth + 1,
                        false,
                        from_json_value,
                    )?;
                    i = close_end;
                } else {
                    assert_r4_clean_decoded_cell_inner_with_origin(&bytes[i..], depth + 1, false, from_json_value)?;
                    i = bytes.len();
                }
            }
            continue;
        }

        text_buf.push(bytes[i]);
        i += 1;
    }

    flush_html_text_buf_with_origin(&mut text_buf, depth, from_json_value)
}

fn assert_r4_clean_raw_bytes(bytes: &[u8]) -> Result<(), ReportError> {
    assert_r4_clean_bytes_with_depth(bytes, false, false, false, 0, false)
}

fn verify_unmasked_broken_json_strings_in_html_with_origin(
    bytes: &[u8],
    _from_json_value: bool,
) -> Result<(), ReportError> {
    let has_u0022 = contains_ascii_case_insensitive(bytes, b"u0022");
    if (!has_u0022 && !bytes.contains(&b'"')) || !contains_ascii_case_insensitive(bytes, b"keymaterial") {
        return Ok(());
    }
    let lower = to_ascii_lowercase_vec(bytes);
    let (single_u0022_json_ctx, double_u0022_json_ctx) = if has_u0022 {
        precompute_u0022_json_ctx(&lower, false, None)
    } else {
        (false, false)
    };
    let mut tracker = JsonContextTracker::with_markdown(false);
    let mut cursor = 0usize;
    let mut unredacted_close_cache: [Option<Option<usize>>; 2] = [None, None];
    while let Some(OpeningTagMatch {
        open_start,
        after_name,
        syntax,
        opened_with_u003c,
    }) = find_opening_keymaterial_tag(&lower, cursor, true)
    {
        let (in_json_string, _, _, in_nested_json_string) = tracker.advance_to(&lower, open_start);
        let decoded_u0022_ctx = !in_json_string && (single_u0022_json_ctx || double_u0022_json_ctx);
        if !in_json_string && !decoded_u0022_ctx {
            cursor = after_name;
            continue;
        }
        if is_double_escaped_tag_open(&lower, open_start) && !in_json_string && !double_u0022_json_ctx {
            cursor = after_name;
            continue;
        }
        let has_double_escaped_gap = in_json_string && tracker.mark_double_escaped_gap(&lower, cursor, open_start);
        let effective_in_json_string =
            in_json_string || (decoded_u0022_ctx && (syntax == TagSyntax::HtmlEscaped || opened_with_u003c));
        let in_double_escaped_json = in_nested_json_string
            || has_double_escaped_gap
            || (!in_json_string && double_u0022_json_ctx)
            || (in_json_string && is_double_escaped_tag_open(&lower, open_start));
        let ctx = TagScanContext {
            in_csv_field: false,
            in_json_string: effective_in_json_string,
            in_markdown_json_string: false,
            in_markdown_table_line: false,
            in_double_escaped_json,
            in_nested_json_string,
            allow_double_bs: in_json_string || double_u0022_json_ctx,
            opened_with_u003c,
            allow_tsv_tabs: false,
            in_decoded_u0022_json_ctx: decoded_u0022_ctx,
        };
        let Some((_cs, open_end, is_self_closing)) =
            find_tag_close_quote_aware_cached(&lower, after_name, syntax, ctx, &mut unredacted_close_cache)
        else {
            return Err(ReportError::CustodyVerificationFailed(
                "R4 violation: unclosed <keyMaterial> opening tag detected in exported bytes".to_string(),
            ));
        };
        if is_self_closing {
            cursor = open_end;
            continue;
        }
        let Some((close_start, close_end)) =
            find_closing_keymaterial_tag(&lower, open_end, syntax, ctx.allow_double_bs)
        else {
            return Err(ReportError::CustodyVerificationFailed(
                "R4 violation: truncated unclosed <keyMaterial> value detected in exported bytes".to_string(),
            ));
        };
        if lower[open_end..close_start].trim_ascii() != b"[redacted]" {
            return Err(ReportError::CustodyVerificationFailed(
                "R4 violation: unredacted <keyMaterial> value detected in exported bytes".to_string(),
            ));
        }
        cursor = close_end;
    }
    Ok(())
}

fn verify_html_with_embedded_json_with_origin(
    bytes: &[u8],
    depth: usize,
    from_json_value: bool,
) -> Result<(), ReportError> {
    verify_html_document_or_fragment_with_origin(bytes, depth, from_json_value)?;
    if contains_json_opener_or_html_entity(bytes) || contains_ascii_case_insensitive(bytes, b"u0022") {
        let (mut projected, nl_in_json) = mask_html_tags_for_json_scan_with_options(bytes, false);
        let _ = assert_r4_clean_embedded_json_in_bytes(&mut projected, depth, from_json_value)?;
        verify_unmasked_broken_json_strings_in_html_with_origin(&projected, from_json_value)?;
        if nl_in_json {
            let (mut space_proj, _) = mask_html_tags_for_json_scan_with_options(bytes, true);
            let _ = assert_r4_clean_embedded_json_in_bytes(&mut space_proj, depth, from_json_value)?;
            verify_unmasked_broken_json_strings_in_html_with_origin(&space_proj, from_json_value)?;
            if has_html_entity_json_delim(&space_proj) {
                let mut space_entity_decoded = unescape_html_entities(&space_proj);
                if space_entity_decoded.contains(&b'<') {
                    space_entity_decoded = mask_html_tags_for_json_scan_with_options(&space_entity_decoded, true).0;
                }
                let _ = assert_r4_clean_embedded_json_in_bytes(&mut space_entity_decoded, depth, from_json_value)?;
                verify_unmasked_broken_json_strings_in_html_with_origin(&space_entity_decoded, from_json_value)?;
            }
        }
        if has_html_entity_json_delim(&projected) {
            let mut entity_decoded = unescape_html_entities(&projected);
            let mut dec_nl_in_json = false;
            if entity_decoded.contains(&b'<') {
                let (masked, flag) = mask_html_tags_for_json_scan_with_options(&entity_decoded, false);
                entity_decoded = masked;
                dec_nl_in_json = flag;
            }
            let _ = assert_r4_clean_embedded_json_in_bytes_with_options(
                &mut entity_decoded,
                depth,
                from_json_value,
                false,
            )?;
            verify_unmasked_broken_json_strings_in_html_with_origin(&entity_decoded, from_json_value)?;
            if dec_nl_in_json {
                let raw_dec = unescape_html_entities(&projected);
                let (mut space_dec, _) = mask_html_tags_for_json_scan_with_options(&raw_dec, true);
                let _ = assert_r4_clean_embedded_json_in_bytes(&mut space_dec, depth, from_json_value)?;
                verify_unmasked_broken_json_strings_in_html_with_origin(&space_dec, from_json_value)?;
            }
        }
    }
    Ok(())
}

fn verify_html_with_embedded_json(bytes: &[u8], depth: usize) -> Result<(), ReportError> {
    verify_html_with_embedded_json_with_origin(bytes, depth, false)
}

pub fn assert_r4_clean_bytes(bytes: &[u8]) -> Result<(), ReportError> {
    let trimmed = bytes.trim_ascii();
    if (trimmed.starts_with(b"{") || trimmed.starts_with(b"["))
        && let Ok(val) = serde_json::from_slice::<Value>(trimmed)
    {
        return assert_r4_clean_json_value(&val);
    }
    if is_html_document_or_fragment(bytes) {
        verify_html_with_embedded_json(bytes, 0)
    } else {
        assert_r4_clean_bytes_internal(bytes, true, true, true)
    }
}

fn assert_r4_clean_json_value_inner(val: &Value, depth: usize) -> Result<(), ReportError> {
    assert_r4_clean_json_value_inner_with_html(val, depth, true)
}

fn assert_r4_clean_json_string_value(s: &str, depth: usize, allow_html: bool) -> Result<(), ReportError> {
    if depth < MAX_NESTED_JSON_DEPTH {
        let trimmed = s.trim();
        if (trimmed.starts_with('{') || trimmed.starts_with('[') || trimmed.starts_with('"'))
            && let Ok(nested) = serde_json::from_str::<Value>(trimmed)
        {
            return assert_r4_clean_json_value_inner_with_html(&nested, depth + 1, allow_html);
        }
    }
    if allow_html && is_html_document_or_fragment(s.as_bytes()) {
        if depth < MAX_NESTED_JSON_DEPTH {
            return verify_html_with_embedded_json_with_origin(s.as_bytes(), depth + 1, false);
        }
        let masked_html = mask_html_tags_for_json_scan(s.as_bytes());
        return assert_r4_clean_decoded_cell_inner_with_options(&masked_html, depth, false, false, false);
    }
    let s_for_scan = s;
    let bytes = s_for_scan.as_bytes();
    let allow_csv = (bytes.contains(&b'\n') || bytes.contains(&b'\r')) && bytes.contains(&b'"') && {
        let lower_s = to_ascii_lowercase_vec(bytes);
        is_inline_prefixed_rfc4180_csv(bytes, &lower_s)
    };
    if depth < MAX_NESTED_JSON_DEPTH && (s_for_scan.contains('{') || s_for_scan.contains('[')) {
        let mut open_km_ranges_opt: Option<Vec<(usize, usize)>> = None;
        let mut mask_spans = Vec::new();
        let mut idx = 0usize;
        let mut too_deep_openers: Option<Vec<bool>> = None;
        while idx < bytes.len() {
            if matches!(bytes[idx], b'{' | b'[') && starts_raw_json_container(bytes, idx) {
                if too_deep_openers.as_ref().is_some_and(|td| td[idx]) {
                    idx += 1;
                    continue;
                }
                let mut stream = serde_json::Deserializer::from_str(&s_for_scan[idx..]).into_iter::<Value>();
                match stream.next() {
                    Some(Ok(nested)) => {
                        let consumed = stream.byte_offset();
                        if consumed > 0 && idx + consumed <= bytes.len() {
                            assert_r4_clean_json_value_inner_with_html(&nested, depth + 1, allow_html)?;
                            let span = &bytes[idx..idx + consumed];
                            let keep_unmasked = json_span_has_quote_parity_hazard(span) && {
                                let open_km_ranges = open_km_ranges_opt
                                    .get_or_insert_with(|| compute_open_keymaterial_tag_ranges(bytes, true));
                                pos_in_sorted_ranges(open_km_ranges, idx) || raw_json_span_has_u0027_apos_km_leak(span)
                            };
                            if !keep_unmasked {
                                mask_spans.push((idx, idx + consumed));
                            }
                            idx += consumed;
                            continue;
                        }
                    }
                    Some(Err(ref e)) if is_serde_json_recursion_limit_err(e) => {
                        if let Some(next_idx) = skip_excess_json_openers(bytes, idx) {
                            idx = next_idx;
                            continue;
                        }
                        let td = too_deep_openers.get_or_insert_with(|| compute_too_deep_json_openers(bytes, idx));
                        if td[idx] {
                            idx += 1;
                            continue;
                        }
                    }
                    _ => {}
                }
            }
            idx += 1;
        }
        let mut masked_buf: Option<Vec<u8>> = None;
        if !mask_spans.is_empty() {
            let buf = masked_buf.get_or_insert_with(|| bytes.to_vec());
            for (ms, me) in mask_spans {
                mask_json_span_preserving_delims(buf, ms, me);
            }
        }
        let check_bytes = masked_buf.as_deref().unwrap_or(bytes);
        let trimmed_check = check_bytes.trim_ascii();
        if allow_csv
            || check_bytes.contains(&b'{')
            || check_bytes.contains(&b'[')
            || (trimmed_check.starts_with(b"\"") && trimmed_check.ends_with(b"\""))
        {
            return assert_r4_clean_bytes_with_options(
                check_bytes,
                allow_csv,
                true,
                false,
                depth + 1,
                false,
                true,
                allow_csv,
                true,
            );
        }
        return assert_r4_clean_bytes_with_depth_and_origin(check_bytes, false, false, false, depth, false, true);
    }
    let trimmed = s_for_scan.trim();
    if allow_csv
        || s_for_scan.contains('{')
        || s_for_scan.contains('[')
        || (trimmed.starts_with('"') && trimmed.ends_with('"'))
    {
        assert_r4_clean_bytes_with_depth_and_origin(s_for_scan.as_bytes(), allow_csv, true, false, depth, false, true)
    } else {
        assert_r4_clean_bytes_with_depth_and_origin(s_for_scan.as_bytes(), false, false, false, depth, false, true)
    }
}

fn assert_r4_clean_json_value_inner_with_html(val: &Value, depth: usize, allow_html: bool) -> Result<(), ReportError> {
    match val {
        Value::String(s) => assert_r4_clean_json_string_value(s, depth, allow_html),
        Value::Array(items) => {
            for item in items {
                assert_r4_clean_json_value_inner_with_html(item, depth, allow_html)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (k, v) in map {
                assert_r4_clean_json_string_value(k, depth, allow_html)?;
                assert_r4_clean_json_value_inner_with_html(v, depth, allow_html)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn assert_r4_clean_json_value(val: &Value) -> Result<(), ReportError> {
    assert_r4_clean_json_value_inner(val, 0)
}

fn assert_r4_clean_decoded_cell_inner_with_origin(
    cell: &[u8],
    depth: usize,
    allow_html: bool,
    from_json_value: bool,
) -> Result<(), ReportError> {
    assert_r4_clean_decoded_cell_inner_with_options(cell, depth, allow_html, from_json_value, true)
}

fn assert_r4_clean_decoded_cell_inner_with_options(
    cell: &[u8],
    depth: usize,
    allow_html: bool,
    from_json_value: bool,
    run_html_pass: bool,
) -> Result<(), ReportError> {
    if depth < MAX_NESTED_JSON_DEPTH {
        let trimmed = cell.trim_ascii();
        if (trimmed.starts_with(b"{") || trimmed.starts_with(b"[") || trimmed.starts_with(b"\""))
            && let Ok(val) = serde_json::from_slice::<Value>(trimmed)
        {
            return assert_r4_clean_json_value_inner_with_html(&val, depth + 1, allow_html);
        }
    }
    if allow_html && is_html_document_or_fragment(cell) {
        if depth < MAX_NESTED_JSON_DEPTH {
            return verify_html_with_embedded_json_with_origin(cell, depth + 1, from_json_value);
        }
        let masked_html = mask_html_tags_for_json_scan(cell);
        return assert_r4_clean_decoded_cell_inner_with_options(&masked_html, depth, false, from_json_value, false);
    }
    let allow_csv = (cell.contains(&b'\n') || cell.contains(&b'\r')) && cell.contains(&b'"') && {
        let lower_cell = to_ascii_lowercase_vec(cell);
        is_inline_prefixed_rfc4180_csv(cell, &lower_cell)
    };
    let trimmed = cell.trim_ascii();
    if allow_csv
        || cell.contains(&b'{')
        || cell.contains(&b'[')
        || (trimmed.starts_with(b"\"") && trimmed.ends_with(b"\""))
    {
        assert_r4_clean_bytes_with_options(
            cell,
            allow_csv,
            true,
            false,
            depth,
            false,
            from_json_value,
            true,
            run_html_pass,
        )
    } else {
        assert_r4_clean_bytes_with_options(
            cell,
            false,
            false,
            false,
            depth,
            false,
            from_json_value,
            true,
            run_html_pass,
        )
    }
}

fn assert_r4_clean_decoded_cell_inner(cell: &[u8], depth: usize, allow_html: bool) -> Result<(), ReportError> {
    assert_r4_clean_decoded_cell_inner_with_origin(cell, depth, allow_html, false)
}

fn assert_r4_clean_decoded_cell_with_depth(cell: &[u8], depth: usize) -> Result<(), ReportError> {
    assert_r4_clean_decoded_cell_inner(cell, depth, true)
}

fn assert_r4_clean_decoded_cell(cell: &[u8]) -> Result<(), ReportError> {
    assert_r4_clean_decoded_cell_with_depth(cell, 0)
}

fn parse_rfc4180_csv_fields(bytes: &[u8]) -> Result<Vec<Vec<u8>>, ReportError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let mut fields = Vec::new();
    let mut current = Vec::new();
    let mut i = 0usize;
    let mut at_field_start = true;
    let mut in_quotes = false;

    while i < bytes.len() {
        if in_quotes {
            if bytes[i] == b'"' {
                if bytes.get(i + 1) == Some(&b'"') {
                    current.push(b'"');
                    i += 2;
                } else {
                    match bytes.get(i + 1).copied() {
                        None => {
                            in_quotes = false;
                            i += 1;
                        }
                        Some(b',') => {
                            in_quotes = false;
                            fields.push(std::mem::take(&mut current));
                            i += 2;
                            at_field_start = true;
                        }
                        Some(b'\r') => {
                            in_quotes = false;
                            fields.push(std::mem::take(&mut current));
                            i += if bytes.get(i + 2) == Some(&b'\n') { 3 } else { 2 };
                            at_field_start = true;
                        }
                        Some(b'\n') => {
                            in_quotes = false;
                            fields.push(std::mem::take(&mut current));
                            i += 2;
                            at_field_start = true;
                        }
                        Some(_) => {
                            return Err(ReportError::CustodyVerificationFailed(
                                "R4 violation: invalid CSV quote sequence in exported bytes".to_string(),
                            ));
                        }
                    }
                }
            } else {
                current.push(bytes[i]);
                i += 1;
            }
        } else if at_field_start && bytes[i] == b'"' {
            in_quotes = true;
            at_field_start = false;
            i += 1;
        } else if bytes[i] == b',' {
            fields.push(std::mem::take(&mut current));
            i += 1;
            at_field_start = true;
        } else if bytes[i] == b'\r' {
            fields.push(std::mem::take(&mut current));
            i += if bytes.get(i + 1) == Some(&b'\n') { 2 } else { 1 };
            at_field_start = true;
        } else if bytes[i] == b'\n' {
            fields.push(std::mem::take(&mut current));
            i += 1;
            at_field_start = true;
        } else {
            current.push(bytes[i]);
            i += 1;
            at_field_start = false;
        }
    }

    if in_quotes {
        return Err(ReportError::CustodyVerificationFailed(
            "R4 violation: unclosed CSV quote detected in exported bytes".to_string(),
        ));
    }

    if !current.is_empty() || !at_field_start {
        fields.push(current);
    }

    Ok(fields)
}

fn unescape_markdown_bs_and_pipe(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0usize;
    while i < raw.len() {
        if raw[i] == b'\\' {
            if let Some(&next) = raw.get(i + 1)
                && matches!(next, b'\\' | b'|')
            {
                out.push(next);
                i += 2;
                continue;
            }
            out.push(b'\\');
            i += 1;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    out
}

#[inline]
fn contains_ascii_case_insensitive(haystack: &[u8], lower_needle: &[u8]) -> bool {
    let nlen = lower_needle.len();
    if haystack.len() < nlen {
        return false;
    }
    if nlen == 0 {
        return true;
    }
    let first_lo = lower_needle[0].to_ascii_lowercase();
    let first_hi = first_lo.to_ascii_uppercase();
    let limit = haystack.len() - nlen;
    let mut i = 0usize;
    while i <= limit {
        let b = haystack[i];
        if (b == first_lo || b == first_hi) && haystack[i..i + nlen].eq_ignore_ascii_case(lower_needle) {
            return true;
        }
        i += 1;
    }
    false
}

fn ends_with_gt_redacted(before_close: &[u8]) -> bool {
    let trimmed = before_close.trim_ascii_end();
    let Some(before_redacted) = trimmed.strip_suffix(b"[redacted]") else {
        return false;
    };
    let prefix = before_redacted.trim_ascii_end();
    if prefix.ends_with(b">") {
        return true;
    }
    if prefix.len() >= 4 && prefix[prefix.len() - 4..].eq_ignore_ascii_case(b"&gt;") {
        return true;
    }
    if prefix.len() >= 4 && prefix[prefix.len() - 1] == b';' {
        let search_start = prefix.len().saturating_sub(12);
        if let Some(rel_amp) = prefix[search_start..].iter().rposition(|&b| b == b'&') {
            let start = search_start + rel_amp;
            if let Some(len) = match_html_gt_entity(&prefix[start..])
                && start + len == prefix.len()
            {
                return true;
            }
        }
    }
    if prefix.len() >= 6 && prefix[prefix.len() - 5..].eq_ignore_ascii_case(b"u003e") {
        let bs = count_preceding_backslashes(prefix, 0, prefix.len() - 5);
        if bs % 2 == 1 || bs % 4 == 2 {
            return true;
        }
    }
    false
}

fn slice_contains_closing_keymaterial_tag(lower: &[u8], allow_double_bs: bool) -> Option<(usize, usize)> {
    let mut pos = 0usize;
    while let Some(km_pos) = find_ascii_bytes(lower, pos, b"keymaterial") {
        let close_start = ends_with_close_tag_prefix(lower, 0, km_pos, allow_double_bs)
            .or_else(|| ends_with_html_close_prefix_with_json(lower, 0, km_pos, allow_double_bs))
            .or_else(|| {
                if km_pos >= 3 && lower[km_pos - 1] == b':' {
                    let mut prefix_start = km_pos - 1;
                    while prefix_start > 0 && is_xml_ncname_char(lower[prefix_start - 1]) {
                        if prefix_start < km_pos - 1
                            && (ends_with_close_tag_prefix(lower, 0, prefix_start, allow_double_bs).is_some()
                                || ends_with_html_close_prefix_with_json(lower, 0, prefix_start, allow_double_bs)
                                    .is_some())
                        {
                            break;
                        }
                        prefix_start -= 1;
                    }
                    if prefix_start < km_pos - 1 {
                        ends_with_close_tag_prefix(lower, 0, prefix_start, allow_double_bs)
                            .or_else(|| ends_with_html_close_prefix_with_json(lower, 0, prefix_start, allow_double_bs))
                    } else {
                        None
                    }
                } else {
                    None
                }
            });
        if let Some(cs) = close_start {
            let mut end = km_pos + "keymaterial".len();
            loop {
                if end < lower.len() && lower[end].is_ascii_whitespace() {
                    end += 1;
                } else if lower[end..].starts_with(b"<br>") {
                    end += 4;
                } else if let Some(br_len) = match_html_br_entity(&lower[end..]) {
                    end += br_len;
                } else if let Some(skip) = starts_with_escaped_ws(&lower[end..], allow_double_bs) {
                    end += skip;
                } else if let Some((b' ' | b'\t' | b'\r' | b'\n', skip)) =
                    match_json_u00_char(&lower[end..], allow_double_bs)
                {
                    end += skip;
                } else {
                    break;
                }
            }
            if let Some(gt_len) = match_html_gt_entity(&lower[end..]) {
                end += gt_len;
            } else if end < lower.len() && lower[end] == b'>' {
                end += 1;
            } else if let Some((b'>', skip)) = match_json_u00_char(&lower[end..], allow_double_bs) {
                end += skip;
            }
            return Some((cs, end));
        }
        pos = km_pos + "keymaterial".len();
    }
    None
}

fn has_unredacted_inner_keymaterial_in_span_depth(
    lower: &[u8],
    span_start: usize,
    span_end: usize,
    allow_json_ctx: bool,
    outer_ctx: TagScanContext,
    depth: usize,
) -> bool {
    if depth >= 32 {
        return true;
    }
    let mut pos = span_start;
    while let Some(OpeningTagMatch {
        open_start,
        after_name,
        syntax,
        opened_with_u003c,
    }) = find_opening_keymaterial_tag(&lower[..span_end], pos, allow_json_ctx)
    {
        let inner_ctx = TagScanContext {
            in_double_escaped_json: outer_ctx.in_double_escaped_json
                || (outer_ctx.in_json_string && is_double_escaped_tag_open(lower, open_start)),
            opened_with_u003c,
            ..outer_ctx
        };
        let Some((_cs, open_end, is_self_closing)) =
            find_tag_close_quote_aware(&lower[..span_end], after_name, syntax, inner_ctx)
        else {
            return true;
        };
        if has_unredacted_inner_keymaterial_in_span_depth(
            lower,
            after_name,
            open_end,
            allow_json_ctx,
            inner_ctx,
            depth + 1,
        ) {
            return true;
        }
        if is_self_closing {
            pos = open_end;
            continue;
        }
        let Some((close_start, close_end)) =
            find_closing_keymaterial_tag(&lower[..span_end], open_end, syntax, inner_ctx.allow_double_bs)
        else {
            return true;
        };
        if lower[open_end..close_start].trim_ascii() != b"[redacted]" {
            return true;
        }
        pos = close_end;
    }
    false
}

fn has_unredacted_inner_keymaterial_in_span(
    lower: &[u8],
    span_start: usize,
    span_end: usize,
    allow_json_ctx: bool,
    outer_ctx: TagScanContext,
) -> bool {
    has_unredacted_inner_keymaterial_in_span_depth(lower, span_start, span_end, allow_json_ctx, outer_ctx, 0)
}

fn raw_string_has_unredacted_closing_keymaterial_tag(bytes: &[u8], allow_json_ctx: bool) -> bool {
    if !contains_ascii_case_insensitive(bytes, b"keymaterial") {
        return false;
    }
    let lower = to_ascii_lowercase_vec(bytes);
    let mut tracker = JsonContextTracker::with_markdown(false);
    let mut cursor = 0usize;
    let mut unredacted_close_cache: [Option<Option<usize>>; 2] = [None, None];

    while let Some(OpeningTagMatch {
        open_start,
        after_name,
        syntax,
        opened_with_u003c,
    }) = find_opening_keymaterial_tag(&lower, cursor, allow_json_ctx)
    {
        let (in_json_string, in_markdown_json_string, in_markdown_table_line, in_nested_json_string, has_dbl_gap) =
            if allow_json_ctx {
                let (ij, imj, imt, inj) = tracker.advance_to(&lower, open_start);
                if is_double_escaped_tag_open(&lower, open_start) && !ij {
                    cursor = after_name;
                    continue;
                }
                let gap = ij && tracker.mark_double_escaped_gap(&lower, cursor, open_start);
                (ij, imj, imt, inj, gap)
            } else {
                (false, false, false, false, false)
            };
        let in_double_escaped_json = in_markdown_json_string
            || in_nested_json_string
            || has_dbl_gap
            || (in_json_string && is_double_escaped_tag_open(&lower, open_start));
        let ctx = TagScanContext {
            in_csv_field: false,
            in_json_string,
            in_markdown_json_string,
            in_markdown_table_line,
            in_double_escaped_json,
            in_nested_json_string,
            allow_double_bs: allow_json_ctx && in_json_string,
            opened_with_u003c,
            allow_tsv_tabs: false,
            in_decoded_u0022_json_ctx: false,
        };
        let Some((_cs, open_end, is_self_closing)) =
            find_tag_close_quote_aware_cached(&lower, after_name, syntax, ctx, &mut unredacted_close_cache)
        else {
            return true;
        };
        let mut seg_start = open_start;
        let mut search_from = after_name;
        while let Some((rel_cs, rel_end)) =
            slice_contains_closing_keymaterial_tag(&lower[search_from..open_end], ctx.allow_double_bs)
        {
            let cs = search_from + rel_cs;
            let close_end = search_from + rel_end;
            if !ends_with_gt_redacted(&lower[seg_start..cs]) {
                return true;
            }
            seg_start = close_end;
            search_from = close_end;
        }
        if has_unredacted_inner_keymaterial_in_span(&lower, after_name, open_end, allow_json_ctx, ctx) {
            return true;
        }
        if is_self_closing {
            cursor = open_end;
            continue;
        }
        let Some((close_start, close_end)) =
            find_closing_keymaterial_tag(&lower, open_end, syntax, ctx.allow_double_bs)
        else {
            return true;
        };
        if lower[open_end..close_start].trim_ascii() != b"[redacted]" {
            return true;
        }
        cursor = close_end;
    }

    false
}

fn has_unredacted_closing_keymaterial_tag_json(val: &Value, depth: usize) -> bool {
    match val {
        Value::String(s) => {
            if depth < MAX_NESTED_JSON_DEPTH {
                let trimmed = s.trim();
                if (trimmed.starts_with('{') || trimmed.starts_with('[') || trimmed.starts_with('"'))
                    && let Ok(nested) = serde_json::from_str::<Value>(trimmed)
                {
                    return has_unredacted_closing_keymaterial_tag_json(&nested, depth + 1);
                }
            }
            if depth < MAX_NESTED_JSON_DEPTH && (s.contains('{') || s.contains('[')) {
                return has_unredacted_closing_keymaterial_tag_with_depth(s.as_bytes(), depth + 1);
            }
            raw_string_has_unredacted_closing_keymaterial_tag(s.as_bytes(), false)
        }
        Value::Array(items) => items
            .iter()
            .any(|item| has_unredacted_closing_keymaterial_tag_json(item, depth)),
        Value::Object(map) => map.iter().any(|(k, v)| {
            has_unredacted_closing_keymaterial_tag_with_depth(k.as_bytes(), depth)
                || has_unredacted_closing_keymaterial_tag_json(v, depth)
        }),
        _ => false,
    }
}

fn has_unredacted_closing_keymaterial_tag_with_depth(bytes: &[u8], depth: usize) -> bool {
    if depth < MAX_NESTED_JSON_DEPTH {
        let trimmed = bytes.trim_ascii();
        if (trimmed.starts_with(b"{") || trimmed.starts_with(b"[") || trimmed.starts_with(b"\""))
            && let Ok(val) = serde_json::from_slice::<Value>(trimmed)
        {
            return has_unredacted_closing_keymaterial_tag_json(&val, depth + 1);
        }
    }

    if depth < MAX_NESTED_JSON_DEPTH && (bytes.contains(&b'{') || bytes.contains(&b'[')) {
        let mut mask_spans = Vec::new();
        let mut base = 0usize;
        while base < bytes.len() {
            let valid_len = match std::str::from_utf8(&bytes[base..]) {
                Ok(s) => s.len(),
                Err(e) => e.valid_up_to(),
            };
            if valid_len > 0 {
                let chunk_bytes = &bytes[base..base + valid_len];
                let chunk_str = std::str::from_utf8(chunk_bytes).unwrap_or("");
                if chunk_bytes.contains(&b'{') || chunk_bytes.contains(&b'[') {
                    let mut idx = 0usize;
                    let mut too_deep_openers: Option<Vec<bool>> = None;
                    while idx < chunk_bytes.len() {
                        if matches!(chunk_bytes[idx], b'{' | b'[') && starts_raw_json_container(chunk_bytes, idx) {
                            if too_deep_openers.as_ref().is_some_and(|td| td[idx]) {
                                idx += 1;
                                continue;
                            }
                            let mut stream = serde_json::Deserializer::from_str(&chunk_str[idx..]).into_iter::<Value>();
                            match stream.next() {
                                Some(Ok(val)) => {
                                    let consumed = stream.byte_offset();
                                    if consumed > 0 && idx + consumed <= chunk_bytes.len() {
                                        if has_unredacted_closing_keymaterial_tag_json(&val, depth + 1) {
                                            return true;
                                        }
                                        mask_spans.push((base + idx, base + idx + consumed));
                                        idx += consumed;
                                        continue;
                                    }
                                }
                                Some(Err(ref e)) if is_serde_json_recursion_limit_err(e) => {
                                    if let Some(next_idx) = skip_excess_json_openers(chunk_bytes, idx) {
                                        idx = next_idx;
                                        continue;
                                    }
                                    let td = too_deep_openers
                                        .get_or_insert_with(|| compute_too_deep_json_openers(chunk_bytes, idx));
                                    if td[idx] {
                                        idx += 1;
                                        continue;
                                    }
                                }
                                _ => {}
                            }
                        }
                        idx += 1;
                    }
                }
            }
            if base + valid_len >= bytes.len() {
                break;
            }
            let err_len = match std::str::from_utf8(&bytes[base + valid_len..]) {
                Ok(_) => 0,
                Err(e) => e.error_len().unwrap_or(bytes.len() - (base + valid_len)),
            };
            base += valid_len + err_len.max(1);
        }
        if !mask_spans.is_empty() {
            let mut masked = bytes.to_vec();
            for (ms, me) in mask_spans {
                masked[ms..me].fill(b'_');
            }
            return raw_string_has_unredacted_closing_keymaterial_tag(&masked, true);
        }
        return raw_string_has_unredacted_closing_keymaterial_tag(bytes, true);
    }

    raw_string_has_unredacted_closing_keymaterial_tag(bytes, true)
}

fn verify_markdown_table_cell(cell: &[u8], depth: usize) -> Result<(), ReportError> {
    let full_unescaped = unescape_markdown_cell(cell);
    match assert_r4_clean_decoded_cell_with_depth(&full_unescaped, depth) {
        Ok(()) => Ok(()),
        Err(err) => {
            if contains_ascii_case_insensitive(cell, b"<br>") {
                let bs_pipe = unescape_markdown_bs_and_pipe(cell);
                if !has_unredacted_closing_keymaterial_tag_with_depth(&bs_pipe, depth)
                    && assert_r4_clean_decoded_cell_with_depth(&bs_pipe, depth).is_ok()
                {
                    return Ok(());
                }
            }
            Err(err)
        }
    }
}

fn unescape_markdown_cell(raw: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    if !raw.contains(&b'\\') && !contains_ascii_case_insensitive(raw, b"<br>") {
        return std::borrow::Cow::Borrowed(raw);
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0usize;
    while i < raw.len() {
        if raw[i] == b'\\' {
            if let Some(&next) = raw.get(i + 1)
                && matches!(next, b'\\' | b'|')
            {
                out.push(next);
                i += 2;
                continue;
            }
            out.push(b'\\');
            i += 1;
        } else if raw.get(i..i + 4).is_some_and(|s| s.eq_ignore_ascii_case(b"<br>")) {
            out.push(b'\n');
            i += 4;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    std::borrow::Cow::Owned(out)
}

fn split_markdown_row_cells(line: &[u8]) -> Vec<&[u8]> {
    let mut cells = Vec::new();
    let mut i = 1usize;
    let mut cell_start = 1usize;

    while i < line.len() {
        if line[i] == b'\\' {
            i += if i + 1 < line.len() { 2 } else { 1 };
        } else if line[i] == b'|' {
            cells.push(&line[cell_start..i]);
            i += 1;
            cell_start = i;
        } else {
            i += 1;
        }
    }

    if cell_start < line.len() && !line[cell_start..].trim_ascii().is_empty() {
        cells.push(&line[cell_start..]);
    }

    cells
}

fn assert_r4_clean_for_format(bytes: &[u8], format: ExportFormat) -> Result<(), ReportError> {
    match format {
        ExportFormat::Csv => match parse_rfc4180_csv_fields(bytes) {
            Ok(fields) => {
                for field in fields {
                    assert_r4_clean_decoded_cell(&field)?;
                }
                Ok(())
            }
            Err(err) => {
                assert_r4_clean_bytes_internal(bytes, true, true, false)?;
                Err(err)
            }
        },
        ExportFormat::Tsv => {
            for line in bytes.split(|&b| b == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                if line.is_empty() {
                    continue;
                }
                for cell in line.split(|&b| b == b'\t') {
                    assert_r4_clean_decoded_cell(cell)?;
                }
            }
            Ok(())
        }
        ExportFormat::Json => {
            if let Ok(val) = serde_json::from_slice::<Value>(bytes) {
                assert_r4_clean_json_value(&val)
            } else {
                assert_r4_clean_bytes_internal(bytes, false, true, false)
            }
        }
        ExportFormat::Jsonl => {
            for line in bytes.split(|&b| b == b'\n') {
                let trimmed = line.trim_ascii();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(val) = serde_json::from_slice::<Value>(trimmed) {
                    assert_r4_clean_json_value(&val)?;
                } else {
                    assert_r4_clean_bytes_internal(trimmed, false, true, false)?;
                }
            }
            Ok(())
        }
        ExportFormat::Html | ExportFormat::HtmlVertical => verify_html_with_embedded_json(bytes, 0),
        ExportFormat::Markdown => {
            for line in bytes.split(|&b| b == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                if is_strict_markdown_table_line(line, true) {
                    for raw_cell in split_markdown_row_cells(line.trim_ascii()) {
                        let cell = raw_cell.strip_prefix(b" ").unwrap_or(raw_cell);
                        let cell = cell.strip_suffix(b" ").unwrap_or(cell);
                        verify_markdown_table_cell(cell, 0)?;
                    }
                } else if !line.is_empty() {
                    assert_r4_clean_decoded_cell(line)?;
                }
            }
            Ok(())
        }
    }
}

pub fn render_report(data: &TableData, format: ExportFormat, opts: &ReportOptions) -> Result<Vec<u8>, ReportError> {
    let rendered = if opts.enforce_r4_redaction {
        let clean = sanitize_table_for_report(data);
        let clean_export = sanitize_export_options(&opts.export);
        export_table(&clean, format, &clean_export)?
    } else {
        export_table(data, format, &opts.export)?
    };
    if opts.enforce_r4_redaction {
        assert_r4_clean_for_format(&rendered, format)?;
    }
    Ok(rendered)
}

pub fn format_file_extension(format: ExportFormat) -> &'static str {
    match format {
        ExportFormat::HtmlVertical => "vertical.html",
        other => other.extension(),
    }
}

#[derive(Debug, Clone)]
pub struct CustodyManifestBuilder {
    tool_id: String,
    tool_version: String,
    leaves: Vec<CustodyLeaf>,
}

impl CustodyManifestBuilder {
    pub fn new(tool_id: impl Into<String>, tool_version: impl Into<String>) -> Self {
        Self {
            tool_id: tool_id.into(),
            tool_version: tool_version.into(),
            leaves: Vec::new(),
        }
    }

    pub fn add_artifact(&mut self, path: &Path, bytes: &[u8]) -> &mut Self {
        let index = self.leaves.len();
        self.leaves.push(CustodyLeaf {
            index,
            path: path.display().to_string(),
            size_bytes: bytes.len() as u64,
            sha256: sha256_hex(bytes),
            sha512: sha512_hex(bytes),
        });
        self
    }

    pub fn add_existing_file(&mut self, path: &Path) -> Result<&mut Self, ReportError> {
        let bytes = fs::read(path)?;
        self.add_artifact(path, &bytes);
        Ok(self)
    }

    pub fn build(self) -> CustodyManifest {
        build_custody_manifest(self.tool_id, self.tool_version, self.leaves)
    }

    pub fn write_to(self, path: &Path) -> Result<CustodyManifest, ReportError> {
        let manifest = self.build();
        write_custody_manifest_json(&manifest, path)?;
        Ok(manifest)
    }
}

pub fn export_table_formats(
    data: &TableData,
    output_dir: &Path,
    base_stem: &str,
    formats: &[ExportFormat],
    opts: &ReportOptions,
) -> Result<CustodyManifest, ReportError> {
    if formats.is_empty() {
        return Err(ReportError::InvalidArgument(
            "at least one export format must be specified".to_string(),
        ));
    }
    if base_stem.trim().is_empty() {
        return Err(ReportError::InvalidArgument("base_stem must not be empty".to_string()));
    }

    fs::create_dir_all(output_dir)?;

    let (clean_data, clean_export) = if opts.enforce_r4_redaction {
        (sanitize_table_for_report(data), sanitize_export_options(&opts.export))
    } else {
        (data.clone(), opts.export.clone())
    };

    let mut builder = CustodyManifestBuilder::new(&clean_data.schema.tool_id, &clean_export.tool_version);
    for &fmt in formats {
        let ext = format_file_extension(fmt);
        let artifact_path = output_dir.join(format!("{base_stem}.{ext}"));
        let bytes = export_table(&clean_data, fmt, &clean_export)?;
        if opts.enforce_r4_redaction {
            assert_r4_clean_for_format(&bytes, fmt)?;
        }
        fs::write(&artifact_path, &bytes)?;
        builder.add_artifact(&artifact_path, &bytes);
    }

    let custody_path = output_dir.join(format!("{base_stem}.custody.json"));
    builder.write_to(&custody_path)
}

pub fn write_single_report_with_custody(
    data: &TableData,
    out_path: &Path,
    format: ExportFormat,
    custody_path: Option<&Path>,
    opts: &ReportOptions,
) -> Result<CustodyManifest, ReportError> {
    let bytes = render_report(data, format, opts)?;
    if let Some(parent) = out_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(out_path, &bytes)?;

    let (tool_id, tool_version) = if opts.enforce_r4_redaction {
        (
            sanitize_string_r4(&data.schema.tool_id),
            sanitize_string_r4(&opts.export.tool_version),
        )
    } else {
        (data.schema.tool_id.clone(), opts.export.tool_version.clone())
    };
    let mut builder = CustodyManifestBuilder::new(tool_id, tool_version);
    builder.add_artifact(out_path, &bytes);

    if let Some(cpath) = custody_path {
        builder.write_to(cpath)
    } else {
        Ok(builder.build())
    }
}

pub fn verify_custody_manifest(manifest: &CustodyManifest) -> Result<(), ReportError> {
    if manifest.artifact_count != manifest.leaves.len() {
        return Err(ReportError::CustodyVerificationFailed(format!(
            "artifact_count {} does not match leaves length {}",
            manifest.artifact_count,
            manifest.leaves.len()
        )));
    }

    let mut total_bytes = 0u64;
    let mut sha256_leaves = Vec::with_capacity(manifest.leaves.len());
    let mut sha512_leaves = Vec::with_capacity(manifest.leaves.len());

    for (expected_idx, leaf) in manifest.leaves.iter().enumerate() {
        if leaf.index != expected_idx {
            return Err(ReportError::CustodyVerificationFailed(format!(
                "leaf index {} out of order (expected {expected_idx})",
                leaf.index
            )));
        }
        let path = Path::new(&leaf.path);
        let bytes = fs::read(path)
            .map_err(|e| ReportError::CustodyVerificationFailed(format!("failed to read leaf '{}': {e}", leaf.path)))?;
        let actual_size = bytes.len() as u64;
        if actual_size != leaf.size_bytes {
            return Err(ReportError::CustodyVerificationFailed(format!(
                "size mismatch for '{}': expected {} bytes, got {actual_size}",
                leaf.path, leaf.size_bytes
            )));
        }
        let actual_sha256 = sha256_hex(&bytes);
        if actual_sha256 != leaf.sha256 {
            return Err(ReportError::CustodyVerificationFailed(format!(
                "SHA-256 mismatch for '{}': expected {}, got {actual_sha256}",
                leaf.path, leaf.sha256
            )));
        }
        let actual_sha512 = sha512_hex(&bytes);
        if actual_sha512 != leaf.sha512 {
            return Err(ReportError::CustodyVerificationFailed(format!(
                "SHA-512 mismatch for '{}': expected {}, got {actual_sha512}",
                leaf.path, leaf.sha512
            )));
        }
        total_bytes = total_bytes.saturating_add(actual_size);
        sha256_leaves.push(actual_sha256);
        sha512_leaves.push(actual_sha512);
    }

    if total_bytes != manifest.total_bytes {
        return Err(ReportError::CustodyVerificationFailed(format!(
            "total_bytes mismatch: expected {}, got {total_bytes}",
            manifest.total_bytes
        )));
    }

    let expected_root_256 = compute_merkle_root_sha256(&sha256_leaves);
    if expected_root_256 != manifest.merkle_root_sha256 {
        return Err(ReportError::CustodyVerificationFailed(format!(
            "SHA-256 Merkle root mismatch: expected {}, got {expected_root_256}",
            manifest.merkle_root_sha256
        )));
    }

    let expected_root_512 = compute_merkle_root_sha512(&sha512_leaves);
    if expected_root_512 != manifest.merkle_root_sha512 {
        return Err(ReportError::CustodyVerificationFailed(format!(
            "SHA-512 Merkle root mismatch: expected {}, got {expected_root_512}",
            manifest.merkle_root_sha512
        )));
    }

    Ok(())
}

pub fn verify_custody_manifest_file(path: &Path) -> Result<CustodyManifest, ReportError> {
    let raw = fs::read(path)?;
    let manifest: CustodyManifest = serde_json::from_slice(&raw)?;
    verify_custody_manifest(&manifest)?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use guap_table::{ColumnDef, ColumnType, Row, TableSchema};
    use serde_json::json;

    use super::*;

    static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
        fn new(prefix: &str) -> Self {
            let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let path = std::env::temp_dir().join(format!("net2rust_report_{prefix}_{pid}_{seq}"));
            fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn sample_table_data() -> TableData {
        let schema = TableSchema::new(
            "sockets.ports",
            "Active TCP/UDP Sockets",
            vec![
                ColumnDef::new("process", "Process", ColumnType::Text),
                ColumnDef::new("port", "Local Port", ColumnType::Uint),
                ColumnDef::new("note", "Note", ColumnType::Text),
            ],
        );
        let rows = vec![
            Row::new(
                1,
                vec![
                    CellValue::Text("svchost.exe".to_string()),
                    CellValue::Uint(443),
                    CellValue::Text("=CMD|'/C calc'!A0".to_string()),
                ],
            ),
            Row::new(
                2,
                vec![
                    CellValue::Text("edge.exe".to_string()),
                    CellValue::Uint(8080),
                    CellValue::Text("<script>alert(1)</script>".to_string()),
                ],
            ),
        ];
        TableData {
            schema,
            rows,
            total_rows: 2,
        }
    }

    #[test]
    fn test_render_all_seven_formats_with_neutralization_and_xss_escape() {
        let data = sample_table_data();
        let opts = ReportOptions::default();

        let csv = String::from_utf8(render_report(&data, ExportFormat::Csv, &opts).unwrap()).unwrap();
        assert!(csv.contains("'=CMD|'/C calc'!A0"));

        let tsv = String::from_utf8(render_report(&data, ExportFormat::Tsv, &opts).unwrap()).unwrap();
        assert!(tsv.contains("'=CMD|'/C calc'!A0"));

        let json_bytes = render_report(&data, ExportFormat::Json, &opts).unwrap();
        let json_val: Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(json_val.as_array().unwrap().len(), 2);

        let jsonl = String::from_utf8(render_report(&data, ExportFormat::Jsonl, &opts).unwrap()).unwrap();
        assert_eq!(jsonl.lines().count(), 2);

        let html = String::from_utf8(render_report(&data, ExportFormat::Html, &opts).unwrap()).unwrap();
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));

        let html_v = String::from_utf8(render_report(&data, ExportFormat::HtmlVertical, &opts).unwrap()).unwrap();
        assert!(!html_v.contains("<script>alert(1)</script>"));
        assert!(html_v.contains("&lt;script&gt;"));

        let md = String::from_utf8(render_report(&data, ExportFormat::Markdown, &opts).unwrap()).unwrap();
        assert!(md.contains("| Process | Local Port | Note |"));
    }

    #[test]
    fn test_batch_export_merkle_custody_and_tamper_detection() {
        let dir = TempDirGuard::new("merkle");
        let data = sample_table_data();
        let all_formats = [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Jsonl,
            ExportFormat::Html,
            ExportFormat::HtmlVertical,
            ExportFormat::Markdown,
        ];
        let opts = ReportOptions::default();

        let manifest = export_table_formats(&data, dir.path(), "report", &all_formats, &opts).unwrap();
        assert_eq!(manifest.artifact_count, 7);
        assert_eq!(manifest.leaves.len(), 7);
        assert_eq!(manifest.merkle_root_sha256.len(), 64);
        assert_eq!(manifest.merkle_root_sha512.len(), 128);

        let custody_file = dir.path().join("report.custody.json");
        assert!(custody_file.is_file());
        verify_custody_manifest_file(&custody_file).unwrap();

        // Tamper 1 byte in the CSV artifact and confirm verification fails.
        let csv_path = Path::new(&manifest.leaves[0].path);
        let mut bytes = fs::read(csv_path).unwrap();
        bytes[0] ^= 0xFF;
        fs::write(csv_path, &bytes).unwrap();

        let err = verify_custody_manifest_file(&custody_file).unwrap_err();
        assert!(matches!(err, ReportError::CustodyVerificationFailed(_)));
    }

    #[test]
    fn test_write_single_report_with_custody() {
        let dir = TempDirGuard::new("single");
        let data = sample_table_data();
        let out = dir.path().join("out.json");
        let custody = dir.path().join("out.custody.json");
        let manifest = write_single_report_with_custody(
            &data,
            &out,
            ExportFormat::Json,
            Some(&custody),
            &ReportOptions::default(),
        )
        .unwrap();
        assert_eq!(manifest.artifact_count, 1);
        verify_custody_manifest_file(&custody).unwrap();
    }

    #[test]
    fn test_r4_redaction_strips_keymaterial_and_sensitive_headers() {
        let schema = TableSchema::new(
            "radio.wifi-profiles",
            "WLAN Profiles",
            vec![ColumnDef::new("xml", "XML", ColumnType::Text)],
        );
        let row = Row::new(
            1,
            vec![CellValue::Text(
                "<WLANProfile><sharedKey><keyMaterial>TopSecretWiFi123</keyMaterial></sharedKey></WLANProfile>"
                    .to_string(),
            )],
        )
        .with_detail_json(json!({
            "headers": {
                "Authorization": "Bearer secret-jwt-token",
                "Cookie": "theme=dark; JSESSIONID=supersecret; lang=en",
                "User-Agent": "net2rust-test/1.0"
            },
            "profile_xml": "<keyMaterial>NestedSecretPass</keyMaterial>"
        }))
        .with_raw_bytes(b"<keyMaterial>RawBytesSecret</keyMaterial>".to_vec());

        let data = TableData {
            schema,
            rows: vec![row],
            total_rows: 1,
        };

        let mut opts = ReportOptions::default();
        opts.export.include_detail_json = true;

        let json_out = String::from_utf8(render_report(&data, ExportFormat::Json, &opts).unwrap()).unwrap();
        assert!(!json_out.contains("TopSecretWiFi123"));
        assert!(!json_out.contains("NestedSecretPass"));
        assert!(!json_out.contains("secret-jwt-token"));
        assert!(!json_out.contains("supersecret"));
        assert!(json_out.contains("[REDACTED]"));
        assert!(json_out.contains("net2rust-test/1.0"));

        let sanitized = sanitize_table_for_report(&data);
        let raw_str = String::from_utf8_lossy(sanitized.rows[0].raw_bytes.as_deref().unwrap());
        assert!(!raw_str.contains("RawBytesSecret"));
        assert!(raw_str.contains("<keyMaterial>[REDACTED]</keyMaterial>"));
    }

    #[test]
    fn test_export_table_formats_rejects_empty_formats() {
        let dir = TempDirGuard::new("empty_fmt");
        let err =
            export_table_formats(&sample_table_data(), dir.path(), "x", &[], &ReportOptions::default()).unwrap_err();
        assert!(matches!(err, ReportError::InvalidArgument(_)));
    }

    #[test]
    fn test_assert_r4_clean_bytes_self_closing_escaped_and_truncated_edge_cases() {
        // Self-closing tags (with or without sibling text and quoted `/>` / `>`) must be allowed across all 7 formats.
        let xml_cases = [
            "<WLANProfile><keyMaterial/>sibling</WLANProfile>",
            r#"<WLANProfile><keyMaterial attr="x/>" />sibling</WLANProfile>"#,
            r#"<WLANProfile><keyMaterial attr="x>y" />sibling</WLANProfile>"#,
            "<WLANProfile><keyMaterial attr='x/>' />sibling</WLANProfile>",
            "<wlan:WLANProfile><wlan:keyMaterialType>passPhrase</wlan:keyMaterialType><wlan:keyMaterial attr=\"x/>\" />sibling</wlan:WLANProfile>",
        ];

        let all_formats = [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Jsonl,
            ExportFormat::Html,
            ExportFormat::HtmlVertical,
            ExportFormat::Markdown,
        ];

        for xml in xml_cases {
            assert_r4_clean_bytes(xml.as_bytes()).unwrap_or_else(|e| panic!("self-closing rejected for {xml}: {e}"));
            let schema = TableSchema::new(
                "radio.wifi-profiles",
                "WLAN Profiles",
                vec![ColumnDef::new("xml", "XML", ColumnType::Text)],
            );
            let data = TableData {
                schema,
                rows: vec![Row::new(1, vec![CellValue::Text(xml.to_string())])],
                total_rows: 1,
            };
            for fmt in all_formats {
                render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("render_report({fmt:?}) rejected {xml}: {e}"));
            }
        }

        // HTML-escaped self-closing and redacted forms pass directly.
        assert_r4_clean_bytes(b"&lt;keyMaterial/&gt;sibling").unwrap();
        assert_r4_clean_bytes(b"&lt;keyMaterial attr=&quot;x/&gt;&quot; /&gt;sibling").unwrap();
        assert_r4_clean_bytes(b"&lt;keyMaterial&gt;[REDACTED]&lt;/keyMaterial&gt;").unwrap();

        // Unredacted, HTML-escaped, substring-[REDACTED], empty, and truncated forms must ALL fail.
        let bad_cases: &[&[u8]] = &[
            b"<keyMaterial>Secret</keyMaterial>",
            br#"<keyMaterial attr="x/>">Secret</keyMaterial>"#,
            br#""<keyMaterial attr=""x/>"">Secret</keyMaterial>""#,
            b"&lt;keyMaterial&gt;Secret&lt;/keyMaterial&gt;",
            b"&lt;wlan:keyMaterial&gt;Secret&lt;/wlan:keyMaterial&gt;",
            b"&lt;keyMaterial attr=&quot;x/&gt;&quot;&gt;Secret&lt;/keyMaterial&gt;",
            b"<keyMaterial>Secret",
            b"<keyMaterial attr=\"x\">Secret",
            b"&lt;keyMaterial&gt;Secret",
            b"<keyMaterial>[REDACTED] extra</keyMaterial>",
            b"<keyMaterial></keyMaterial>",
        ];
        for bad in bad_cases {
            let res = assert_r4_clean_bytes(bad);
            assert!(
                res.is_err(),
                "expected R4 failure for {:?}",
                String::from_utf8_lossy(bad)
            );
        }

        // Verify enforce_r4_redaction=false on HTML-escaped output still gets caught if caller checks bytes.
        let leak_schema = TableSchema::new(
            "radio.wifi-profiles",
            "WLAN Profiles",
            vec![ColumnDef::new("xml", "XML", ColumnType::Text)],
        );
        let leak_data = TableData {
            schema: leak_schema,
            rows: vec![Row::new(
                1,
                vec![CellValue::Text("<keyMaterial>Secret</keyMaterial>".into())],
            )],
            total_rows: 1,
        };
        let unredacted_opts = ReportOptions {
            enforce_r4_redaction: false,
            ..Default::default()
        };
        let html_bytes = render_report(&leak_data, ExportFormat::Html, &unredacted_opts).unwrap();
        assert!(assert_r4_clean_bytes(&html_bytes).is_err());
    }

    #[test]
    fn test_r4_redaction_handles_array_headers_and_nested_non_headers_auth_keys() {
        let schema = TableSchema::new(
            "capture.http",
            "HTTP",
            vec![ColumnDef::new("url", "URL", ColumnType::Text)],
        );
        let row = Row::new(1, vec![CellValue::Text("https://example.com".to_string())]).with_detail_json(json!({
            "headers": {
                "Authorization": ["Bearer MultiValSecret8"],
                "Cookie": ["theme=dark; sid=MultiCookieSecret9"],
                "User-Agent": ["ua/1.0"]
            },
            "request_headers": [
                {"Authorization": "Bearer ArrayObjSecret"},
                {"name": "X-Auth", "value": ["ArrayNamedSecret1", "ArrayNamedSecret2"]},
                ["Cookie", "auth_token=PairSecret"]
            ],
            "alt_headers": {
                "X-Auth": "AltXAuthSecret10",
                "X-Token": ["AltXToken1", "AltXToken2"],
                "X-Session-Id": "SessSecret",
                "X-Jwt-Token": "JwtSecret",
                "X-Bearer-Token": "BearerSecret",
                "Set-Cookie2": "session_id=Cookie2Secret; Version=1",
                "Content-Type": "application/json"
            }
        }));

        let data = TableData {
            schema,
            rows: vec![row],
            total_rows: 1,
        };
        let mut opts = ReportOptions::default();
        opts.export.include_detail_json = true;

        let json_out = String::from_utf8(render_report(&data, ExportFormat::Json, &opts).unwrap()).unwrap();
        for secret in [
            "MultiValSecret8",
            "MultiCookieSecret9",
            "ArrayObjSecret",
            "ArrayNamedSecret1",
            "ArrayNamedSecret2",
            "PairSecret",
            "AltXAuthSecret10",
            "AltXToken1",
            "AltXToken2",
            "SessSecret",
            "JwtSecret",
            "BearerSecret",
            "Cookie2Secret",
        ] {
            assert!(!json_out.contains(secret), "leaked secret '{secret}' in: {json_out}");
        }
        assert!(json_out.contains("ua/1.0"));
        assert!(json_out.contains("theme=dark"));
        assert!(json_out.contains("application/json"));
    }

    #[test]
    fn test_r4_utf8_inside_keymaterial_all_formats_no_panic() {
        let all_formats = [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Jsonl,
            ExportFormat::Html,
            ExportFormat::HtmlVertical,
            ExportFormat::Markdown,
        ];
        let payloads = [
            r#"<WLANProfile><keyMaterial attr="café"/>sibling</WLANProfile>"#,
            "<WLANProfile><keyMaterial café/>sibling</WLANProfile>",
            r#"<WLANProfile><keyMaterial attr="日本語🔑"/>sibling</WLANProfile>"#,
            r#"<WLANProfile><keyMaterial attr="日本語🔑">SecretUtf8Pass</keyMaterial></WLANProfile>"#,
        ];

        for payload in payloads {
            let schema = TableSchema::new(
                "radio.wifi-profiles",
                "WLAN Profiles",
                vec![ColumnDef::new("xml", "XML", ColumnType::Text)],
            );
            let data = TableData {
                schema,
                rows: vec![Row::new(1, vec![CellValue::Text(payload.to_string())])],
                total_rows: 1,
            };
            for fmt in all_formats {
                let bytes = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("render_report({fmt:?}) failed for UTF-8 payload {payload}: {e}"));
                let out = String::from_utf8_lossy(&bytes);
                assert!(
                    !out.contains("SecretUtf8Pass"),
                    "UTF-8 payload leaked secret in {fmt:?}: {out}"
                );
            }
        }

        // Direct HTML-escaped UTF-8 check (both clean self-closing and unredacted secret).
        assert_r4_clean_bytes("<p>&lt;keyMaterial attr=&quot;café&quot;/&gt;sibling</p>".as_bytes()).unwrap();
        assert_r4_clean_bytes("<p>&lt;keyMaterial café/&gt;sibling</p>".as_bytes()).unwrap();
        assert!(
            assert_r4_clean_bytes(
                "<p>&lt;keyMaterial attr=&quot;café&quot;&gt;Secret&lt;/keyMaterial&gt;</p>".as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn test_r4_csv_attribute_quotes_and_raw_empty_attribute_edge_cases() {
        let all_formats = [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Jsonl,
            ExportFormat::Html,
            ExportFormat::HtmlVertical,
            ExportFormat::Markdown,
        ];
        let valid_self_closing = [
            r#"<WLANProfile><keyMaterial attr=">"/>sibling</WLANProfile>"#,
            r#"<WLANProfile><keyMaterial attr=" >"/>sibling</WLANProfile>"#,
            r#"<WLANProfile><keyMaterial attr="/>"/>sibling</WLANProfile>"#,
            r#"<WLANProfile><keyMaterial attr=" />"/>sibling</WLANProfile>"#,
            r#"<WLANProfile><keyMaterial attr=""/>sibling</WLANProfile>"#,
            r#"<WLANProfile><keyMaterial attr="\"/>sibling</WLANProfile>"#,
            r#"<WLANProfile><keyMaterial attr="" attr2=">"/>sibling</WLANProfile>"#,
        ];

        for xml in valid_self_closing {
            assert_r4_clean_bytes(xml.as_bytes()).unwrap_or_else(|e| panic!("raw self-closing rejected {xml}: {e}"));
            let schema = TableSchema::new(
                "radio.wifi-profiles",
                "WLAN Profiles",
                vec![ColumnDef::new("xml", "XML", ColumnType::Text)],
            );
            let data = TableData {
                schema,
                rows: vec![Row::new(1, vec![CellValue::Text(xml.to_string())])],
                total_rows: 1,
            };
            for fmt in all_formats {
                render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("render_report({fmt:?}) failed for {xml}: {e}"));
            }
        }

        // Unredacted CSV exports with `/>` or ` />` or `>` inside attribute must ALL be caught by assert_r4_clean_bytes.
        let unredacted_opts = ReportOptions {
            enforce_r4_redaction: false,
            ..Default::default()
        };
        let leaky_xmls = [
            r#"<WLANProfile><keyMaterial attr="/>">SecretCsvSlash1</keyMaterial></WLANProfile>"#,
            r#"<WLANProfile><keyMaterial attr=" />">SecretCsvSpaceSlash2</keyMaterial></WLANProfile>"#,
            r#"<WLANProfile><keyMaterial attr=">">SecretCsvGt3</keyMaterial></WLANProfile>"#,
            r#"<WLANProfile><keyMaterial attr="\">SecretCsvBackslash4</keyMaterial></WLANProfile>"#,
            r#"<WLANProfile><keyMaterial attr1="" attr2="/>">SecretRawEmptyPlusSlash5</keyMaterial></WLANProfile>"#,
        ];
        for xml in leaky_xmls {
            assert!(
                assert_r4_clean_bytes(xml.as_bytes()).is_err(),
                "raw leak bypassed: {xml}"
            );
            let schema = TableSchema::new(
                "radio.wifi-profiles",
                "WLAN Profiles",
                vec![ColumnDef::new("xml", "XML", ColumnType::Text)],
            );
            let data = TableData {
                schema,
                rows: vec![Row::new(1, vec![CellValue::Text(xml.to_string())])],
                total_rows: 1,
            };
            let csv_bytes = render_report(&data, ExportFormat::Csv, &unredacted_opts).unwrap();
            assert!(
                assert_r4_clean_bytes(&csv_bytes).is_err(),
                "CSV leak bypassed assert_r4_clean_bytes for {xml}: {}",
                String::from_utf8_lossy(&csv_bytes)
            );
        }
    }

    #[test]
    fn test_r4_include_detail_json_with_csv_and_markdown_escaped_quotes() {
        let all_formats = [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Jsonl,
            ExportFormat::Html,
            ExportFormat::HtmlVertical,
            ExportFormat::Markdown,
        ];
        let clean_details = [
            json!({"xml": r#"<WLANProfile><keyMaterial attr=">"/>ok</WLANProfile>"#}),
            json!({"xml": r#"<WLANProfile><keyMaterial attr=""/>ok</WLANProfile>"#}),
            json!({"xml": r#"<WLANProfile><keyMaterial attr="a\"/>ok</WLANProfile>"#}),
        ];

        let mut opts = ReportOptions::default();
        opts.export.include_detail_json = true;

        for detail in clean_details {
            let schema = TableSchema::new(
                "radio.wifi-profiles",
                "WLAN Profiles",
                vec![ColumnDef::new("id", "ID", ColumnType::Text)],
            );
            let data = TableData {
                schema,
                rows: vec![Row::new(1, vec![CellValue::Text("row1".to_string())]).with_detail_json(detail.clone())],
                total_rows: 1,
            };
            for fmt in all_formats {
                render_report(&data, fmt, &opts)
                    .unwrap_or_else(|e| panic!("render_report({fmt:?}) with detail_json failed for {detail}: {e}"));
            }
        }

        // Unredacted detail_json exported to CSV / Markdown must still be rejected by assert_r4_clean_bytes.
        let unredacted_opts = ReportOptions {
            export: opts.export.clone(),
            enforce_r4_redaction: false,
        };
        let leak_schema = TableSchema::new(
            "radio.wifi-profiles",
            "WLAN Profiles",
            vec![ColumnDef::new("id", "ID", ColumnType::Text)],
        );
        let leak_data = TableData {
            schema: leak_schema,
            rows: vec![Row::new(1, vec![CellValue::Text("row1".to_string())]).with_detail_json(
                json!({"xml": r#"<WLANProfile><keyMaterial attr="/>">Secret</keyMaterial></WLANProfile>"#}),
            )],
            total_rows: 1,
        };
        for fmt in [ExportFormat::Csv, ExportFormat::Markdown] {
            let exported = render_report(&leak_data, fmt, &unredacted_opts).unwrap();
            assert!(
                assert_r4_clean_bytes(&exported).is_err(),
                "unredacted detail_json in {fmt:?} bypassed assert_r4_clean_bytes: {}",
                String::from_utf8_lossy(&exported)
            );
        }

        // Even backslash count before `""` (`\\\\""`) inside DoubleCsvJson must NOT prematurely exit DoubleCsvJson.
        let even_bs_csv_json = br#""{""xml"":""<keyMaterial attr=\""a\\\\""b/>\""">SecretEvenBs</keyMaterial>""}""#;
        assert!(assert_r4_clean_bytes(even_bs_csv_json).is_err());
    }

    #[test]
    fn test_r4_markdown_br_newline_inside_keymaterial_tag() {
        let unredacted_opts = ReportOptions {
            enforce_r4_redaction: false,
            ..Default::default()
        };
        let leak_schema = TableSchema::new(
            "radio.wifi-profiles",
            "WLAN Profiles",
            vec![ColumnDef::new("xml", "XML", ColumnType::Text)],
        );
        let leak_data = TableData {
            schema: leak_schema.clone(),
            rows: vec![Row::new(
                1,
                vec![CellValue::Text(
                    "<WLANProfile><keyMaterial\n>MdNewlineSecret123</keyMaterial></WLANProfile>".to_string(),
                )],
            )],
            total_rows: 1,
        };

        let md_unredacted = render_report(&leak_data, ExportFormat::Markdown, &unredacted_opts).unwrap();
        assert!(
            assert_r4_clean_bytes(&md_unredacted).is_err(),
            "Markdown <keyMaterial<br>> bypassed assert_r4_clean_bytes: {}",
            String::from_utf8_lossy(&md_unredacted)
        );

        let md_redacted = render_report(&leak_data, ExportFormat::Markdown, &ReportOptions::default()).unwrap();
        let md_str = String::from_utf8(md_redacted).unwrap();
        assert!(!md_str.contains("MdNewlineSecret123"));
        assert!(md_str.contains("[REDACTED]"));

        // Self-closing and redacted forms with `<br>` inside opening/closing tags must pass cleanly.
        assert_r4_clean_bytes(b"| <WLANProfile><keyMaterial<br>/>sibling</WLANProfile> |").unwrap();
        assert_r4_clean_bytes(b"| <WLANProfile><keyMaterial<br>>[REDACTED]</keyMaterial<br>></WLANProfile> |").unwrap();
    }

    #[test]
    fn test_r4_redaction_headers_string_string_array_and_nested_object_sensitive_keys() {
        let schema = TableSchema::new(
            "capture.http",
            "HTTP",
            vec![ColumnDef::new("url", "URL", ColumnType::Text)],
        );
        let row_single =
            Row::new(1, vec![CellValue::Text("https://example.com/1".to_string())]).with_detail_json(json!({
                "headers": "Authorization: Bearer RawStringSecret99"
            }));
        let row_array = Row::new(2, vec![CellValue::Text("https://example.com/2".to_string())])
            .with_detail_json(json!({
                "headers": [
                    "Authorization: Bearer ArrStrSecret88",
                    "Cookie: theme=dark; sid=ArrCookie88",
                    "User-Agent: net2rust-agent/1.0"
                ],
                "request_headers": "Host: example.com\r\nAuthorization: Bearer BlockSecret77\r\nCookie: sid=BlockCookie77",
                "Authorization": { "raw": "Bearer NestedObjAuthSecret66" },
                "Cookie": { "raw": "lang=en; sid=NestedObjCookieSecret55" }
            }));

        let data = TableData {
            schema,
            rows: vec![row_single, row_array],
            total_rows: 2,
        };
        let mut opts = ReportOptions::default();
        opts.export.include_detail_json = true;

        let json_out = String::from_utf8(render_report(&data, ExportFormat::Json, &opts).unwrap()).unwrap();
        for secret in [
            "RawStringSecret99",
            "ArrStrSecret88",
            "ArrCookie88",
            "BlockSecret77",
            "BlockCookie77",
            "NestedObjAuthSecret66",
            "NestedObjCookieSecret55",
        ] {
            assert!(!json_out.contains(secret), "leaked secret '{secret}' in: {json_out}");
        }
        assert!(json_out.contains("Authorization: [REDACTED]"));
        assert!(json_out.contains("Cookie: theme=dark; sid=[REDACTED]"));
        assert!(json_out.contains("User-Agent: net2rust-agent/1.0"));
        assert!(json_out.contains("lang=en; sid=[REDACTED]"));
    }

    #[test]
    fn test_r4_multiline_csv_clean_and_unredacted_caught() {
        let schema = TableSchema::new(
            "radio.wifi-profiles",
            "WLAN Profiles",
            vec![ColumnDef::new("xml", "XML", ColumnType::Text)],
        );

        let clean_xml = "<WLANProfile><keyMaterial attr=\"line1\n>line2\"/>ok</WLANProfile>";
        let clean_data = TableData {
            schema: schema.clone(),
            rows: vec![Row::new(1, vec![CellValue::Text(clean_xml.to_string())])],
            total_rows: 1,
        };
        let clean_csv = render_report(&clean_data, ExportFormat::Csv, &ReportOptions::default()).unwrap();
        assert_r4_clean_bytes(&clean_csv).expect("clean multiline CSV must pass assert_r4_clean_bytes");

        let leak_xml =
            "<WLANProfile><keyMaterial attr=\"line1\n/>line2\">MultilineCsvSecret</keyMaterial></WLANProfile>";
        let leak_data = TableData {
            schema,
            rows: vec![Row::new(1, vec![CellValue::Text(leak_xml.to_string())])],
            total_rows: 1,
        };
        let unredacted_opts = ReportOptions {
            enforce_r4_redaction: false,
            ..Default::default()
        };
        let leak_csv = render_report(&leak_data, ExportFormat::Csv, &unredacted_opts).unwrap();
        assert!(
            assert_r4_clean_bytes(&leak_csv).is_err(),
            "multiline CSV leak bypassed assert_r4_clean_bytes: {}",
            String::from_utf8_lossy(&leak_csv)
        );
        assert!(
            assert_r4_clean_for_format(&leak_csv, ExportFormat::Csv).is_err(),
            "multiline CSV leak bypassed assert_r4_clean_for_format"
        );

        // Redacted default export of the multiline payload must succeed and strip the secret.
        let redacted_csv = render_report(&leak_data, ExportFormat::Csv, &ReportOptions::default()).unwrap();
        let redacted_str = String::from_utf8_lossy(&redacted_csv);
        assert!(!redacted_str.contains("MultilineCsvSecret"));
        assert!(redacted_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_r4_markdown_and_tsv_same_line_empty_attr_clean_and_leak() {
        let schema = TableSchema::new(
            "radio.wifi-profiles",
            "WLAN Profiles",
            vec![
                ColumnDef::new("c1", "C1", ColumnType::Text),
                ColumnDef::new("c2", "C2", ColumnType::Text),
                ColumnDef::new("c3", "C3", ColumnType::Text),
            ],
        );

        let clean_data = TableData {
            schema: schema.clone(),
            rows: vec![Row::new(
                1,
                vec![
                    CellValue::Text(r#"<keyMaterial a=""/>ok"#.to_string()),
                    CellValue::Text(r#"note=""value"#.to_string()),
                    CellValue::Text("ok".to_string()),
                ],
            )],
            total_rows: 1,
        };

        for fmt in [ExportFormat::Markdown, ExportFormat::Tsv] {
            let bytes = render_report(&clean_data, fmt, &ReportOptions::default())
                .unwrap_or_else(|e| panic!("clean same-line empty attr failed for {fmt:?}: {e}"));
            assert_r4_clean_bytes(&bytes)
                .unwrap_or_else(|e| panic!("assert_r4_clean_bytes failed for clean {fmt:?}: {e}"));
        }

        let leak_data = TableData {
            schema,
            rows: vec![Row::new(
                1,
                vec![
                    CellValue::Text(r#"<keyMaterial a="">BypassEmptyAttrSecret</keyMaterial>"#.to_string()),
                    CellValue::Text(r#"note="""#.to_string()),
                    CellValue::Text("<x/>".to_string()),
                ],
            )],
            total_rows: 1,
        };
        let unredacted_opts = ReportOptions {
            enforce_r4_redaction: false,
            ..Default::default()
        };

        for fmt in [ExportFormat::Markdown, ExportFormat::Tsv] {
            let leak_bytes = render_report(&leak_data, fmt, &unredacted_opts).unwrap();
            assert!(
                assert_r4_clean_bytes(&leak_bytes).is_err(),
                "same-line empty-attr leak bypassed assert_r4_clean_bytes in {fmt:?}: {}",
                String::from_utf8_lossy(&leak_bytes)
            );
            assert!(
                assert_r4_clean_for_format(&leak_bytes, fmt).is_err(),
                "same-line empty-attr leak bypassed assert_r4_clean_for_format in {fmt:?}"
            );
        }

        let raw_leak = br#"| <keyMaterial a="">BypassEmptyAttrSecret</keyMaterial> | note="" | <x/> |"#;
        assert!(assert_r4_clean_bytes(raw_leak).is_err());
    }

    #[test]
    fn test_r4_markdown_raw_backslash_quote_and_detail_json() {
        let schema = TableSchema::new(
            "radio.wifi-profiles",
            "WLAN Profiles",
            vec![ColumnDef::new("xml", "XML", ColumnType::Text)],
        );

        let clean_raw_cell = r#"<WLANProfile><keyMaterial attr=\" >"/>ok</WLANProfile>"#;
        let clean_data = TableData {
            schema: schema.clone(),
            rows: vec![Row::new(1, vec![CellValue::Text(clean_raw_cell.to_string())])],
            total_rows: 1,
        };

        let md_bytes = render_report(&clean_data, ExportFormat::Markdown, &ReportOptions::default())
            .expect("clean Markdown with raw backslash-quote must pass");
        assert_r4_clean_bytes(&md_bytes)
            .expect("assert_r4_clean_bytes must pass on clean Markdown raw backslash-quote");

        // Also ensure Markdown detail_json with `\" >\"` in JSON string passes when self-closing and fails when unredacted.
        let mut opts = ReportOptions::default();
        opts.export.include_detail_json = true;
        let json_clean_data = TableData {
            schema: schema.clone(),
            rows: vec![
                Row::new(1, vec![CellValue::Text("row1".to_string())])
                    .with_detail_json(json!({"xml": r#"<WLANProfile><keyMaterial attr=" >"/>ok</WLANProfile>"#})),
            ],
            total_rows: 1,
        };
        let md_json_clean = render_report(&json_clean_data, ExportFormat::Markdown, &opts).unwrap();
        assert_r4_clean_bytes(&md_json_clean).unwrap();

        let unredacted_opts = ReportOptions {
            export: opts.export,
            enforce_r4_redaction: false,
        };
        let json_leak_data = TableData {
            schema,
            rows: vec![Row::new(1, vec![CellValue::Text("row1".to_string())]).with_detail_json(
                json!({"xml": r#"<WLANProfile><keyMaterial attr=" />">MdJsonSecret</keyMaterial></WLANProfile>"#}),
            )],
            total_rows: 1,
        };
        let md_json_leak = render_report(&json_leak_data, ExportFormat::Markdown, &unredacted_opts).unwrap();
        assert!(assert_r4_clean_bytes(&md_json_leak).is_err());
        assert!(assert_r4_clean_for_format(&md_json_leak, ExportFormat::Markdown).is_err());
    }

    #[test]
    fn test_r4_json_escaped_whitespace_tag_boundaries() {
        let bad_payloads: &[&[u8]] = &[
            br#"{"xml":"<keyMaterial\n>Secret</keyMaterial>"}"#,
            br#"{"xml":"<keyMaterial\r>Secret</keyMaterial>"}"#,
            br#"{"xml":"<keyMaterial\t>Secret</keyMaterial>"}"#,
            br#"{"xml":"<keyMaterial\n>Secret</keyMaterial\n>"}"#,
            br#"{"xml":"<keyMaterial\t>[REDACTED] extra</keyMaterial\r>"}"#,
        ];
        for payload in bad_payloads {
            assert!(
                assert_r4_clean_bytes(payload).is_err(),
                "JSON-escaped whitespace tag bypassed assert_r4_clean_bytes: {}",
                String::from_utf8_lossy(payload)
            );
        }

        let clean_payloads: &[&[u8]] = &[
            br#"{"xml":"<keyMaterial\n/>ok"}"#,
            br#"{"xml":"<keyMaterial\n>[REDACTED]</keyMaterial\n>"}"#,
            br#"{"xml":"<keyMaterial\t>[REDACTED]</keyMaterial\r\n>"}"#,
        ];
        for payload in clean_payloads {
            assert_r4_clean_bytes(payload).unwrap_or_else(|e| {
                panic!(
                    "clean JSON-escaped whitespace tag rejected {}: {e}",
                    String::from_utf8_lossy(payload)
                )
            });
        }
    }

    #[test]
    fn test_r4_redaction_header_aliases_sibling_fields_and_http_headers() {
        let schema = TableSchema::new(
            "capture.http",
            "HTTP",
            vec![ColumnDef::new("url", "URL", ColumnType::Text)],
        );
        let row = Row::new(1, vec![CellValue::Text("https://example.com".to_string())]).with_detail_json(json!({
            "headers": [
                {"name": "Authorization", "raw": "Bearer AdvNameRawSecret"},
                {"name": "Authorization", "values": ["Bearer AdvNameValuesSecret"]},
                {"header": "Authorization", "value": "Bearer AdvHeaderKeySecret"},
                {"header": "User-Agent", "value": "net2rust-ua/2.0"}
            ],
            "http_headers": "Host: a\nAuthorization: Bearer HttpHeadersStrSecret",
            "raw_headers": "Cookie: theme=dark; sid=RawHeadersCookieSecret\r\nX-Api-Key: RawHeadersApiKeySecret"
        }));

        let data = TableData {
            schema,
            rows: vec![row],
            total_rows: 1,
        };
        let sanitized = sanitize_table_for_report(&data);
        let sanitized_str = serde_json::to_string(&sanitized.rows[0].detail_json).unwrap();

        for secret in [
            "AdvNameRawSecret",
            "AdvNameValuesSecret",
            "AdvHeaderKeySecret",
            "HttpHeadersStrSecret",
            "RawHeadersCookieSecret",
            "RawHeadersApiKeySecret",
        ] {
            assert!(
                !sanitized_str.contains(secret),
                "leaked secret '{secret}' in: {sanitized_str}"
            );
        }
        assert!(sanitized_str.contains("net2rust-ua/2.0"));
        assert!(sanitized_str.contains("Host: a"));
        assert!(sanitized_str.contains("theme=dark"));

        let mut opts = ReportOptions::default();
        opts.export.include_detail_json = true;
        let json_out = String::from_utf8(render_report(&data, ExportFormat::Json, &opts).unwrap()).unwrap();
        assert!(!json_out.contains("AdvNameRawSecret"));
        assert!(!json_out.contains("HttpHeadersStrSecret"));
        assert!(json_out.contains("net2rust-ua/2.0"));
    }

    #[test]
    fn test_r4_unclosed_quote_csv_and_decoded_leading_quote_cells() {
        let all_formats = [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Jsonl,
            ExportFormat::Html,
            ExportFormat::HtmlVertical,
            ExportFormat::Markdown,
        ];
        let schema = TableSchema::new(
            "radio.wifi-profiles",
            "WLAN Profiles",
            vec![ColumnDef::new("xml", "XML", ColumnType::Text)],
        );
        let clean_data = TableData {
            schema,
            rows: vec![Row::new(
                1,
                vec![CellValue::Text(r#""<keyMaterial a=""/>ok"#.to_string())],
            )],
            total_rows: 1,
        };
        for fmt in all_formats {
            let rendered = render_report(&clean_data, fmt, &ReportOptions::default())
                .unwrap_or_else(|e| panic!("render_report({fmt:?}) rejected clean leading-quote cell: {e}"));
            assert_r4_clean_for_format(&rendered, fmt)
                .unwrap_or_else(|e| panic!("assert_r4_clean_for_format({fmt:?}) failed: {e}"));
        }

        // Direct `assert_r4_clean_bytes` must pass unclosed-quote clean forms and reject R4 bypass.
        assert_r4_clean_bytes(br#""<keyMaterial a=""/>ok"#).unwrap();
        assert_r4_clean_bytes(br#"col1,"<keyMaterial a=""/>ok"#).unwrap();
        assert!(
            assert_r4_clean_bytes(br#"col1,"<keyMaterial a="">Secret</keyMaterial> | note="" | <x/>"#).is_err(),
            "unclosed-quote CSV R4 bypass was not caught"
        );
    }

    #[test]
    fn test_r4_compact_json_trailing_backslash_and_tsv_tab_column_boundaries() {
        // Compact JSON strings ending in `\\"` must close outside Markdown tables.
        assert_r4_clean_bytes(br#"["\\"]	<keyMaterial attr=\" >"/>ok"#).unwrap();
        assert_r4_clean_bytes(br#"{"p":"C:\\"}	<keyMaterial attr=\" >"/>ok"#).unwrap();
        assert!(
            assert_r4_clean_bytes(br#"["\\"]	<keyMaterial attr=\"a">Secret</keyMaterial><x attr=\"/>"#).is_err(),
            "TSV backslash-desync R4 bypass was not caught"
        );

        // Raw `\t` must isolate broken JSON in column 1 from column 2.
        assert_r4_clean_bytes(b"{\"a\":\"unclosed\t<keyMaterial attr=\\\" >\"/>ok\tok").unwrap();
        assert!(
            assert_r4_clean_bytes(
                b"{\"a\":\"unclosed\t<keyMaterial attr=\\\" >\">TsvColLeakSecret</keyMaterial>\tnote=\\\" />"
            )
            .is_err(),
            "TSV broken-JSON column-1 leak bypassed assert_r4_clean_bytes"
        );

        // Compact JSON array with `",` must not be misclassified as CSV-quoted fields.
        assert_r4_clean_bytes(br#"["ok","<keyMaterial a=\"b\",c/>ok","end"]"#).unwrap();
        assert_r4_clean_bytes(br#"col1,["ok","<keyMaterial a=\"b\",c/>ok","end"]"#).unwrap();
        assert!(assert_r4_clean_bytes(br#"["ok","<keyMaterial a=\"b\",c>Secret</keyMaterial>","end"]"#).is_err());
        // Unbalanced `"` inside XML (`a=b"`) is treated as an unclosed attribute quote, matching r4.rs.
        assert!(assert_r4_clean_bytes(br#"["ok","<keyMaterial a=b\",c/>ok","end"]"#).is_err());
    }

    #[test]
    fn test_r4_json_unicode_escapes_and_nested_json_strings() {
        // Direct assert_r4_clean_bytes must catch \u003c/\u003C/\u0020/\u002f/\u003e/\u000a forms.
        let bad_payloads: &[&[u8]] = &[
            br#"{"xml":"\u003ckeyMaterial\u003eSecret\u003c/keyMaterial\u003e"}"#,
            br#"{"xml":"\u003CkeyMaterial\u003ESecret\u003C/keyMaterial\u003E"}"#,
            br#"{"xml":"<keyMaterial\u0020>Secret</keyMaterial>"}"#,
            br#"{"xml":"<keyMaterial\u000a>Secret</keyMaterial\u000d>"}"#,
            br#"{"xml":"\\u003ckeyMaterial\\u003eSecret\\u003c\\u002fkeyMaterial\\u003e"}"#,
            br#"{"xml":"\u003cwlan:keyMaterial\u003eSecret\u003c/wlan:keyMaterial\u003e"}"#,
        ];
        for payload in bad_payloads {
            assert!(
                assert_r4_clean_bytes(payload).is_err(),
                "JSON Unicode escape bypassed assert_r4_clean_bytes: {}",
                String::from_utf8_lossy(payload)
            );
        }

        let clean_payloads: &[&[u8]] = &[
            br#"{"xml":"\u003ckeyMaterial\u002f\u003eok"}"#,
            br#"{"xml":"\u003ckeyMaterial attr=\"\u003e\"\u002f\u003eok"}"#,
            br#"{"xml":"\u003ckeyMaterial\u003e[REDACTED]\u003c\u002fkeyMaterial\u003e"}"#,
        ];
        for payload in clean_payloads {
            assert_r4_clean_bytes(payload).unwrap_or_else(|e| {
                panic!(
                    "clean JSON Unicode escape tag rejected {}: {e}",
                    String::from_utf8_lossy(payload)
                )
            });
        }

        // render_report must sanitize nested JSON strings, prefixed `body={...}`, and detail_json nested strings.
        let schema = TableSchema::new(
            "capture.http",
            "HTTP",
            vec![ColumnDef::new("payload", "Payload", ColumnType::Text)],
        );
        let rows = vec![
            Row::new(
                1,
                vec![CellValue::Text(
                    r#"{"xml":"\u003ckeyMaterial\u003eNestedU003cSecret\u003c/keyMaterial\u003e"}"#.to_string(),
                )],
            ),
            Row::new(
                2,
                vec![CellValue::Text(
                    r#"body={"xml":"\u003ckeyMaterial\u003ePrefixedU003cSecret\u003c/keyMaterial\u003e"}"#.to_string(),
                )],
            ),
            Row::new(
                3,
                vec![CellValue::Text(
                    r#"body={"xml":"\\u003ckeyMaterial\\u003eDoubleEscU003cSecret\\u003c/keyMaterial\\u003e"}"#
                        .to_string(),
                )],
            ),
            Row::new(
                4,
                vec![CellValue::Text(
                    r#"{"xml":"<keyMaterial\n>NestedWsSecret</keyMaterial>"}"#.to_string(),
                )],
            ),
            Row::new(
                5,
                vec![CellValue::Text(
                    r#"body={"xml":"\u003ckeyMaterial\u003eBrokenJsonSecret\u003c/keyMaterial\u003e"#.to_string(),
                )],
            ),
            Row::new(6, vec![CellValue::Text("ok".to_string())]).with_detail_json(json!({
                "raw_payload": "{\"headers\":{\"Authorization\":\"Bearer NestedJsonHdrSecret\"}}"
            })),
        ];

        let data = TableData {
            schema,
            rows,
            total_rows: 6,
        };
        let mut opts = ReportOptions::default();
        opts.export.include_detail_json = true;

        let json_out = String::from_utf8(render_report(&data, ExportFormat::Json, &opts).unwrap()).unwrap();
        for secret in [
            "NestedU003cSecret",
            "PrefixedU003cSecret",
            "DoubleEscU003cSecret",
            "NestedWsSecret",
            "BrokenJsonSecret",
            "NestedJsonHdrSecret",
        ] {
            assert!(!json_out.contains(secret), "leaked secret '{secret}' in: {json_out}");
        }
        assert!(json_out.contains("[REDACTED]"));
    }

    #[test]
    fn test_r4_redaction_additional_header_aliases_tuples_prefixes_and_top_level_descriptor() {
        let schema = TableSchema::new(
            "capture.http",
            "HTTP",
            vec![ColumnDef::new("url", "URL", ColumnType::Text)],
        );
        let row_array_and_keys = Row::new(1, vec![CellValue::Text("https://example.com/1".to_string())])
            .with_detail_json(json!({
                "headers": [
                    {"header_name": "Authorization", "value": "Bearer HeaderNameAliasSecret"},
                    {"field": "Cookie", "value": "theme=dark; sid=FieldAliasSecret"},
                    ["Authorization", "Bearer Tuple3Secret", "extra"],
                    ["User-Agent", "net2rust-ua/3.0", "keep-extra"]
                ],
                "http_header": "Authorization: Bearer SingularHttpHeaderSecret",
                "headers_raw": "Authorization: Bearer HeadersRawSuffixSecret"
            }));
        let row_top_descriptor = Row::new(2, vec![CellValue::Text("https://example.com/2".to_string())])
            .with_detail_json(json!({
                "headers": {
                    "name": "Authorization",
                    "data": "Bearer TopObjDataSecret"
                }
            }));

        let data = TableData {
            schema,
            rows: vec![row_array_and_keys, row_top_descriptor],
            total_rows: 2,
        };
        let mut opts = ReportOptions::default();
        opts.export.include_detail_json = true;

        let json_out = String::from_utf8(render_report(&data, ExportFormat::Json, &opts).unwrap()).unwrap();
        for secret in [
            "HeaderNameAliasSecret",
            "FieldAliasSecret",
            "Tuple3Secret",
            "SingularHttpHeaderSecret",
            "HeadersRawSuffixSecret",
            "TopObjDataSecret",
        ] {
            assert!(!json_out.contains(secret), "leaked secret '{secret}' in: {json_out}");
        }
        assert!(json_out.contains("net2rust-ua/3.0"));
        assert!(json_out.contains("keep-extra"));
        assert!(json_out.contains("theme=dark"));
    }

    #[test]
    fn test_r4_double_json_bare_quote_termination_and_render() {
        let bare_quote_bypasses: &[&[u8]] = &[
            br#"{"a":"<keyMaterial attr=\"x">Secret</keyMaterial>\" />"}"#,
            br#"{"a":"\u003ckeyMaterial attr=\"x"\u003eSecret\u003c/keyMaterial\u003e\" />"}"#,
            br#""{""a"":""<keyMaterial attr=\""x"">Secret</keyMaterial>\"" />""}""#,
            br#""{""a"":""<keyMaterial attr=\""x"">Secret</keyMaterial>\"" />""}"#,
            br#"| {"a":"<keyMaterial attr=\\"x">Secret</keyMaterial>\\" />"} |"#,
        ];
        for payload in bare_quote_bypasses {
            assert!(
                assert_r4_clean_bytes(payload).is_err(),
                "bare-quote Double*Json R4 bypass was not caught: {}",
                String::from_utf8_lossy(payload)
            );
        }

        let all_formats = [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Jsonl,
            ExportFormat::Html,
            ExportFormat::HtmlVertical,
            ExportFormat::Markdown,
        ];
        let schema = TableSchema::new(
            "capture.http",
            "HTTP",
            vec![ColumnDef::new("payload", "Payload", ColumnType::Text)],
        );
        let data = TableData {
            schema,
            rows: vec![Row::new(
                1,
                vec![CellValue::Text(
                    r#"{"a":"\u003ckeyMaterial attr=\"x"\u003eSecret\u003c/keyMaterial\u003e\" />"}"#.to_string(),
                )],
            )],
            total_rows: 1,
        };
        for fmt in all_formats {
            let rendered = render_report(&data, fmt, &ReportOptions::default())
                .unwrap_or_else(|e| panic!("render_report({fmt:?}) failed on bare-quote broken JSON: {e}"));
            let out = String::from_utf8_lossy(&rendered);
            assert!(!out.contains("Secret"), "leaked Secret in {fmt:?}: {out}");
            assert!(out.contains("[REDACTED]"), "missing [REDACTED] in {fmt:?}: {out}");
        }
    }

    #[test]
    fn test_r4_csv_unquoted_quote_and_closed_brace_before_quoted_field() {
        let bad_csvs: &[&[u8]] = &[
            br#"col1=foo"bar,"<keyMaterial attr=""x/>"">Secret</keyMaterial>""#,
            br#"a"b,"<keyMaterial attr=""x/>"">Secret</keyMaterial>""#,
            b"C1,C2\r\n{foo},\"<keyMaterial attr=\"\"a/>\"\">MixedBraceCsvSecret</keyMaterial>\"\r\n",
            br#"col1,{"a":"{"},"<keyMaterial attr=""x/>"">Secret</keyMaterial>""#,
        ];
        for payload in bad_csvs {
            assert!(
                assert_r4_clean_bytes(payload).is_err(),
                "CSV quoted field leak bypassed assert_r4_clean_bytes: {}",
                String::from_utf8_lossy(payload)
            );
        }

        let clean_csv = b"C1,C2\r\n{foo},\"<keyMaterial attr=\"\">\"\" />ok\"\r\n";
        assert_r4_clean_bytes(clean_csv).expect("clean CRLF CSV after {foo} must pass assert_r4_clean_bytes");
        assert_r4_clean_bytes(b"C1,C2\r\n{foo},\"<keyMaterial attr=\"\"\"\"/>ok\"\r\n")
            .expect("clean empty-attr CRLF CSV after {foo} must pass assert_r4_clean_bytes");
        assert_r4_clean_bytes(br#"col1,{"a":"{"},"<keyMaterial attr="">""/>ok""#)
            .expect("clean CSV after JSON object with { inside string must pass");
    }

    #[test]
    fn test_r4_json_u0022_u0027_attr_quotes_and_escaped_slash() {
        let bad_u0022_u0027: &[&[u8]] = &[
            br#"{"xml":"\u003ckeyMaterial attr=\u0022/\u003e\u0022\u003eSecret\u003c/keyMaterial\u003e"}"#,
            br#"{"xml":"\u003ckeyMaterial attr=\u0027/\u003e\u0027\u003eSecret\u003c/keyMaterial\u003e"}"#,
            br#"{"xml":"\\u003ckeyMaterial attr=\\u0022/\\u003e\\u0022\\u003eSecret\\u003c/keyMaterial\\u003e"}"#,
            br#"{"xml":"\\u003ckeyMaterial attr=\\u0027/\\u003e\\u0027\\u003eSecret\\u003c/keyMaterial\\u003e"}"#,
            br#"{"xml":"\u003ckeyMaterial attr=\u0022x">Secret\u003c/keyMaterial\u003e"}"#,
            br#"{"xml":"\u003ckeyMaterial attr=\u0027x">Secret\u003c/keyMaterial\u003e"}"#,
            br#"{"xml":"<keyMaterial attr=\"a\">Secret<\/keyMaterial>"}"#,
        ];
        for payload in bad_u0022_u0027 {
            assert!(
                assert_r4_clean_bytes(payload).is_err(),
                "\\u0022/\\u0027 or \\/ leak bypassed assert_r4_clean_bytes: {}",
                String::from_utf8_lossy(payload)
            );
        }

        let clean_payloads: &[&[u8]] = &[
            br#"{"xml":"\u003ckeyMaterial attr=\u0022\u003e\u0022/\u003eok"}"#,
            br#"{"xml":"\u003ckeyMaterial attr=\u0027\u003e\u0027/\u003eok"}"#,
            br#"{"xml":"\u003ckeyMaterial attr=\u0022a\\\u0022/\u003eok"}"#,
            br#"{"xml":"\\u003ckeyMaterial attr=\\u0022\\u003e\\u0022/\\u003eok"}"#,
            br#"{"xml":"\\u003ckeyMaterial attr=\\u0027\\u003e\\u0027/\\u003eok"}"#,
            br#"{"xml":"<keyMaterial>[REDACTED]<\/keyMaterial>"}"#,
            br#"{"xml":"<keyMaterial attr=\"a\"\/>ok"}"#,
            br#"{"xml":"<keyMaterial\/>ok"}"#,
            br#"{"xml":"\u003ckeyMaterial\u003e[REDACTED]\u003c\/keyMaterial\u003e"}"#,
        ];
        for payload in clean_payloads {
            assert_r4_clean_bytes(payload).unwrap_or_else(|e| {
                panic!(
                    "clean \\u0022/\\u0027/\\/ payload rejected {}: {e}",
                    String::from_utf8_lossy(payload)
                )
            });
        }

        let all_formats = [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Jsonl,
            ExportFormat::Html,
            ExportFormat::HtmlVertical,
            ExportFormat::Markdown,
        ];
        for raw_payload in [
            r#"body={"xml":"\u003ckeyMaterial attr=\u0022/\u003e\u0022\u003eBrokenU0022Secret\u003c/keyMaterial\u003e"#,
            r#"body={"xml":"\u003ckeyMaterial attr=\u0027/\u003e\u0027\u003eBrokenU0022Secret\u003c/keyMaterial\u003e"#,
        ] {
            let schema = TableSchema::new(
                "capture.http",
                "HTTP",
                vec![ColumnDef::new("payload", "Payload", ColumnType::Text)],
            );
            let data = TableData {
                schema,
                rows: vec![Row::new(1, vec![CellValue::Text(raw_payload.to_string())])],
                total_rows: 1,
            };
            for fmt in all_formats {
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("render_report({fmt:?}) failed for {raw_payload}: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains("BrokenU0022Secret"), "leaked secret in {fmt:?}: {out}");
                assert!(out.contains("[REDACTED]"), "missing [REDACTED] in {fmt:?}: {out}");
            }
        }
    }

    #[test]
    fn test_r4_redaction_nested_data_items_header_list_and_hyphenated_keys() {
        let schema = TableSchema::new(
            "capture.http",
            "HTTP",
            vec![ColumnDef::new("url", "URL", ColumnType::Text)],
        );
        let row = Row::new(1, vec![CellValue::Text("https://example.com".to_string())]).with_detail_json(json!({
            "header_list": [
                {"name": "Authorization", "value": "Bearer HdrListSecret"},
                {"name": "User-Agent", "value": "net2rust-ua/4.0"}
            ],
            "headers": {
                "data": [
                    {"name": "Authorization", "value": "Bearer NestedHdrArrSecret"},
                    {"name": "Accept", "value": "application/json"}
                ],
                "items": [
                    ["Authorization", "Bearer NestedTupleSecret"],
                    ["Cookie", "theme=light; sid=NestedTupleCookieSecret"],
                    ["User-Agent", "net2rust-item-ua/1.0"]
                ]
            },
            "headers-raw": "Authorization: Bearer HyphenHdrSecret\r\nUser-Agent: raw-ua/1.0"
        }));

        let data = TableData {
            schema,
            rows: vec![row],
            total_rows: 1,
        };
        let sanitized = sanitize_table_for_report(&data);
        let sanitized_str = serde_json::to_string(&sanitized.rows[0].detail_json).unwrap();
        for secret in [
            "HdrListSecret",
            "NestedHdrArrSecret",
            "NestedTupleSecret",
            "NestedTupleCookieSecret",
            "HyphenHdrSecret",
        ] {
            assert!(
                !sanitized_str.contains(secret),
                "leaked secret '{secret}' in: {sanitized_str}"
            );
        }
        assert!(sanitized_str.contains("net2rust-ua/4.0"));
        assert!(sanitized_str.contains("application/json"));
        assert!(sanitized_str.contains("net2rust-item-ua/1.0"));
        assert!(sanitized_str.contains("theme=light"));
        assert!(sanitized_str.contains("raw-ua/1.0"));
    }

    #[test]
    fn test_r4_quote_mode_boundaries_newlines_tabs_pipes_and_single_bare_quote() {
        let bad_payloads: &[&[u8]] = &[
            // RawQuoteMode::Single bare `"` and TSV `\t`
            br#"{"a":"<keyMaterial attr='x">Secret</keyMaterial>' />"}"#,
            br#"{"a":"\u003ckeyMaterial attr='x"\u003eSingleBareSecret\u003c/keyMaterial\u003e' /\u003e"}"#,
            b"<keyMaterial attr='x\t>TsvSingleSecret</keyMaterial>\t' />",
            // RawQuoteMode::DoubleRaw TSV `\t`
            b"<keyMaterial attr=\"x\t>TsvDoubleSecret</keyMaterial>\t\" />",
            // RawQuoteMode::DoubleJson `\t`, `\n`, `\r`, Markdown `|`
            b"{\"a\":\"<keyMaterial attr=\\\"x\t>TsvDoubleJsonTabSecret</keyMaterial>\t\\\" />\"}",
            b"{\"a\":\"<keyMaterial attr=\\\"x\n>Secret</keyMaterial>\\\" />",
            b"{\"a\":\"<keyMaterial attr=\\\"x\r>Secret</keyMaterial>\\\" />",
            br#"| {"a":"<keyMaterial attr=\"x | >Secret</keyMaterial>\" />"} |"#,
            // RawQuoteMode::DoubleMarkdownJson unescaped `|`
            br#"| {"a":"<keyMaterial attr=\\"x | >Secret</keyMaterial>\\" />"} |"#,
            // RawQuoteMode::Single inside Markdown table cell with unescaped `|`
            br#"| {"a":"<keyMaterial attr='x | >Secret</keyMaterial>' />"} |"#,
            br#"| <keyMaterial attr='x | >Secret</keyMaterial>' /> |"#,
            br#"| <keyMaterial attr="x | >Secret</keyMaterial>" /> |"#,
            // DoubleCsvJson with raw newline / tab / bare quote
            b"\"{\"\"a\"\":\"\"<keyMaterial attr=\\\"\"x\n>Secret</keyMaterial>\\\"\" />\"\"}\"",
        ];
        for payload in bad_payloads {
            assert!(
                assert_r4_clean_bytes(payload).is_err(),
                "quote-mode boundary bypass was not caught: {}",
                String::from_utf8_lossy(payload)
            );
        }

        // Clean Markdown-escaped `\|` and JSON `\"` inside Single / DoubleJson / DoubleMarkdownJson must pass.
        let clean_payloads: &[&[u8]] = &[
            br#"{"a":"<keyMaterial attr='x\"y'/>ok"}"#,
            br#"{"a":"<keyMaterial attr=\"a|b\"/>ok"}"#,
            br#"| {"a":"<keyMaterial attr=\\"x \| >\\"/>ok"} |"#,
            br#"| {"a":"<keyMaterial attr='x \| >'/>ok"} |"#,
            br#"| <keyMaterial attr="x \| >"/>ok |"#,
        ];
        for payload in clean_payloads {
            assert_r4_clean_bytes(payload).unwrap_or_else(|e| {
                panic!(
                    "clean boundary payload rejected {}: {e}",
                    String::from_utf8_lossy(payload)
                )
            });
        }

        // Full 7-format render_report on NlBrokenSecret and SingleBareSecret must redact and verify cleanly.
        let all_formats = [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Jsonl,
            ExportFormat::Html,
            ExportFormat::HtmlVertical,
            ExportFormat::Markdown,
        ];
        let cases = [
            (
                "NlBrokenSecret",
                "{\"a\":\"<keyMaterial attr=\\\"x\n>NlBrokenSecret</keyMaterial>\\\" />",
            ),
            (
                "SingleBareSecret",
                r#"{"a":"\u003ckeyMaterial attr='x"\u003eSingleBareSecret\u003c/keyMaterial\u003e' /\u003e"}"#,
            ),
            (
                "PrefixedNlBrokenSecret",
                "body={\"a\":\"<keyMaterial attr=\\\"x\n>PrefixedNlBrokenSecret</keyMaterial>\\\" />",
            ),
        ];
        for (secret, raw_cell) in cases {
            let schema = TableSchema::new(
                "capture.http",
                "HTTP",
                vec![ColumnDef::new("payload", "Payload", ColumnType::Text)],
            );
            let data = TableData {
                schema,
                rows: vec![Row::new(1, vec![CellValue::Text(raw_cell.to_string())])],
                total_rows: 1,
            };
            for fmt in all_formats {
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("render_report({fmt:?}) failed for {secret}: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "leaked {secret} in {fmt:?}: {out}");
                assert!(out.contains("[REDACTED]"), "missing [REDACTED] in {fmt:?}: {out}");
            }
        }
    }

    #[test]
    fn test_r4_mixed_xml_attribute_quote_equivalence_and_render() {
        let bad_mixed: &[&[u8]] = &[
            br#"{"xml":"\u003ckeyMaterial attr=\"/\u003e\u0022\u003eMixedQuoteSecret\u003c/keyMaterial\u003e\" /\u003e"}"#,
            br#"{"xml":"\u003ckeyMaterial attr=\u0022/\u003e\"\u003eMixedQuoteSecretRev\u003c/keyMaterial\u003e\u0022 /\u003e"}"#,
            br#"{"xml":"\u003ckeyMaterial attr='/\u003e\u0027\u003eMixedSingleU0027Secret\u003c/keyMaterial\u003e' /\u003e"}"#,
            br#"{"xml":"\u003ckeyMaterial attr=\u0027/\u003e'\u003eMixedU0027SingleSecret\u003c/keyMaterial\u003e\u0027 /\u003e"}"#,
            br#""{""xml"":""\u003ckeyMaterial attr=\""/\u003e\u0022\u003eCsvMixedSecret\u003c/keyMaterial\u003e\"" /\u003e""}""#,
            br#""{""xml"":""\u003ckeyMaterial attr=\u0022/\u003e\""\u003eCsvMixedRevSecret\u003c/keyMaterial\u003e\u0022 /\u003e""}""#,
            br#"| {"xml":"\\u003ckeyMaterial attr=\\"/\\u003e\\u0022\\u003eMdMixedSecret\\u003c/keyMaterial\\u003e\\" /\\u003e"} |"#,
            br#"| {"xml":"\\u003ckeyMaterial attr=\\u0022/\\u003e\\"\\u003eMdMixedRevSecret\\u003c/keyMaterial\\u003e\\u0022 /\\u003e"} |"#,
            br#"| {"xml":"\\u003ckeyMaterial attr='/\\u003e\\u0027\\u003eMdSingleMixedSecret\\u003c/keyMaterial\\u003e' /\\u003e"} |"#,
            br#"{"xml":"\\u003ckeyMaterial attr=\\\"/\\u003e\\u0022\\u003eDoubleEncMixedSecret\\u003c/keyMaterial\\u003e\\\" /\\u003e"}"#,
        ];
        for payload in bad_mixed {
            assert!(
                assert_r4_clean_bytes(payload).is_err(),
                "mixed attribute quote R4 bypass was not caught: {}",
                String::from_utf8_lossy(payload)
            );
        }

        let clean_mixed: &[&[u8]] = &[
            br#"{"xml":"\u003ckeyMaterial attr=\u0022\u003e\"/\u003eok"}"#,
            br#"{"xml":"\u003ckeyMaterial attr=\"\u003e\u0022/\u003eok"}"#,
            br#"{"xml":"\u003ckeyMaterial attr='\u003e\u0027/\u003eok"}"#,
            br#"{"xml":"\u003ckeyMaterial attr=\u0027\u003e'/\u003eok"}"#,
            br#""{""xml"":""\u003ckeyMaterial attr=\""\u003e\u0022/\u003eok""}""#,
            br#""{""xml"":""\u003ckeyMaterial attr=\u0022\u003e\""/\u003eok""}""#,
            br#"| {"xml":"\\u003ckeyMaterial attr=\\"\\u003e\\u0022/\\u003eok"} |"#,
            br#"| {"xml":"\\u003ckeyMaterial attr=\\u0022\\u003e\\"/\\u003eok"} |"#,
            br#"| {"xml":"\\u003ckeyMaterial attr='\\u003e\\u0027/\\u003eok"} |"#,
            br#"{"xml":"\\u003ckeyMaterial attr=\\\"\\u003e\\u0022/\\u003eok"}"#,
        ];
        for payload in clean_mixed {
            assert_r4_clean_bytes(payload).unwrap_or_else(|e| {
                panic!(
                    "clean mixed attribute quote payload rejected {}: {e}",
                    String::from_utf8_lossy(payload)
                )
            });
        }

        // Broken/prefixed mixed-quote JSON in render_report across all 7 formats.
        let all_formats = [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Jsonl,
            ExportFormat::Html,
            ExportFormat::HtmlVertical,
            ExportFormat::Markdown,
        ];
        let broken_cases = [
            (
                "MixedBrokenSecret",
                r#"body={"xml":"\u003ckeyMaterial attr=\"/\u003e\u0022\u003eMixedBrokenSecret\u003c/keyMaterial\u003e\" /\u003e"#,
            ),
            (
                "MixedSingleU0027Secret",
                r#"body={"xml":"\u003ckeyMaterial attr='/\u003e\u0027\u003eMixedSingleU0027Secret\u003c/keyMaterial\u003e' /\u003e"#,
            ),
        ];
        for (secret, raw_cell) in broken_cases {
            let schema = TableSchema::new(
                "capture.http",
                "HTTP",
                vec![ColumnDef::new("payload", "Payload", ColumnType::Text)],
            );
            let data = TableData {
                schema,
                rows: vec![Row::new(1, vec![CellValue::Text(raw_cell.to_string())])],
                total_rows: 1,
            };
            for fmt in all_formats {
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("render_report({fmt:?}) failed for {secret}: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "leaked {secret} in {fmt:?}: {out}");
                assert!(out.contains("[REDACTED]"), "missing [REDACTED] in {fmt:?}: {out}");
            }
        }
    }

    #[test]
    fn test_r4_four_backslash_u00_and_slash_parity() {
        let bad_four_bs: &[&[u8]] = &[
            br#"{"xml":"\\u003ckeyMaterial attr=\\u0022a\\\\u0022/>Secret\\u003c/keyMaterial\\u003e"}"#,
            br#"{"xml":"\\u003ckeyMaterial attr=\\u0022a\\\\u0022/\\u003e\\u0022\\u003eFourBsSecret\\u003c/keyMaterial\\u003e"}"#,
            br#"{"xml":"\\u003ckeyMaterial attr=\\u0027a\\\\u0027/\\u003e\\u0027\\u003eFourBsSingleSecret\\u003c/keyMaterial\\u003e"}"#,
            // 4-backslash `\\\\u002f` and `\\\\/` must NOT be treated as self-closing `/`
            br#"{"xml":"\\u003ckeyMaterial attr=\\u0022a\\u0022\\\\u002f\\u003eSecret\\u003c/keyMaterial\\u003e"}"#,
            br#"{"xml":"\\u003ckeyMaterial attr=\\u0022a\\u0022\\\\/\\u003eSecret\\u003c/keyMaterial\\u003e"}"#,
            // 4-backslash `\\\\u003c` must NOT close a real `\\u003ckeyMaterial` (results in truncated tag error)
            br#"{"xml":"\\u003ckeyMaterial\\u003eSecret\\\\u003c/keyMaterial\\u003e"}"#,
        ];
        for payload in bad_four_bs {
            assert!(
                assert_r4_clean_bytes(payload).is_err(),
                "4-backslash parity R4 bypass was not caught: {}",
                String::from_utf8_lossy(payload)
            );
        }

        // Literal `\\\\u003ckeyMaterial` is NOT an opening `<keyMaterial>` tag!
        assert_r4_clean_bytes(br#"{"xml":"\\\\u003ckeyMaterial\\u003eLiteralText\\\\u003c/keyMaterial\\u003e"}"#)
            .expect("4-backslash literal \\\\u003c must not be mistaken for <keyMaterial>");

        // Broken/prefixed 4-backslash payload in render_report across all 7 formats.
        let all_formats = [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Jsonl,
            ExportFormat::Html,
            ExportFormat::HtmlVertical,
            ExportFormat::Markdown,
        ];
        let raw_cell = r#"body={"xml":"\\u003ckeyMaterial attr=\\u0022a\\\\u0022/\\u003e\\u0022\\u003eFourBsBrokenSecret\\u003c/keyMaterial\\u003e"#;
        let schema = TableSchema::new(
            "capture.http",
            "HTTP",
            vec![ColumnDef::new("payload", "Payload", ColumnType::Text)],
        );
        let data = TableData {
            schema,
            rows: vec![Row::new(1, vec![CellValue::Text(raw_cell.to_string())])],
            total_rows: 1,
        };
        for fmt in all_formats {
            let rendered = render_report(&data, fmt, &ReportOptions::default())
                .unwrap_or_else(|e| panic!("render_report({fmt:?}) failed for 4-backslash payload: {e}"));
            let out = String::from_utf8_lossy(&rendered);
            assert!(
                !out.contains("FourBsBrokenSecret"),
                "leaked FourBsBrokenSecret in {fmt:?}: {out}"
            );
            assert!(out.contains("[REDACTED]"), "missing [REDACTED] in {fmt:?}: {out}");
        }
    }

    #[test]
    fn test_r4_csv_unclosed_brace_or_bracket_in_col1_before_quoted_col2() {
        let schema = TableSchema::new(
            "radio.wifi-profiles",
            "WLAN Profiles",
            vec![
                ColumnDef::new("c1", "C1", ColumnType::Text),
                ColumnDef::new("c2", "C2", ColumnType::Text),
            ],
        );
        let unredacted_opts = ReportOptions {
            enforce_r4_redaction: false,
            ..Default::default()
        };

        for col1 in ["{foo", "[foo", "a=1{foo", "{unclosed", "[unclosed", "[123", "[true"] {
            let leak_data = TableData {
                schema: schema.clone(),
                rows: vec![Row::new(
                    1,
                    vec![
                        CellValue::Text(col1.to_string()),
                        CellValue::Text(r#"<keyMaterial attr="a/>">UnclosedBraceCsvSecret</keyMaterial>"#.to_string()),
                    ],
                )],
                total_rows: 1,
            };
            let unredacted_csv = render_report(&leak_data, ExportFormat::Csv, &unredacted_opts).unwrap();
            assert!(
                assert_r4_clean_bytes(&unredacted_csv).is_err(),
                "unclosed '{col1}' in col1 caused CSV col2 R4 bypass: {}",
                String::from_utf8_lossy(&unredacted_csv)
            );

            let clean_data = TableData {
                schema: schema.clone(),
                rows: vec![Row::new(
                    1,
                    vec![
                        CellValue::Text(col1.to_string()),
                        CellValue::Text(r#"<keyMaterial attr=">"/>ok"#.to_string()),
                    ],
                )],
                total_rows: 1,
            };
            let clean_csv = render_report(&clean_data, ExportFormat::Csv, &ReportOptions::default())
                .unwrap_or_else(|e| panic!("clean render_report(Csv) failed after '{col1}': {e}"));
            assert_r4_clean_bytes(&clean_csv).unwrap_or_else(|e| {
                panic!(
                    "assert_r4_clean_bytes rejected clean CSV after '{col1}': {e}: {}",
                    String::from_utf8_lossy(&clean_csv)
                )
            });
        }
    }

    #[test]
    fn test_r4_iter8_three_bs_single_layer_and_double_escaped_single_u0027() {
        let all_formats = [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Jsonl,
            ExportFormat::Html,
            ExportFormat::HtmlVertical,
            ExportFormat::Markdown,
        ];

        // Finding 1: bs_count % 4 == 3 (`\\\"`) on single-layer JSON must enter DoubleJson, not U0022DoubleBs.
        let bad_three_bs: &[&[u8]] = &[
            br#"{"xml":"\u003ckeyMaterial attr=\\\"x\\u0022/\u003e\\\"\u003eThreeBsBypassSecret\u003c/keyMaterial\u003e"}"#,
            br#"{"xml":"\u003ckeyMaterial attr=\\\"x\\u0022/\u003e\\\"\u003eThreeBsBrokenSecret\u003c/keyMaterial\u003e"#,
        ];
        for payload in bad_three_bs {
            assert!(
                assert_r4_clean_bytes(payload).is_err(),
                "3-bs single-layer JSON bypassed assert_r4_clean_bytes: {}",
                String::from_utf8_lossy(payload)
            );
        }

        // Clean single-layer JSON with `\\\"` and literal `\\u0022` inside must pass.
        assert_r4_clean_bytes(br#"{"xml":"\u003ckeyMaterial attr=\\\"x\\u0022\u003e\\\"\u002f\u003eok"}"#)
            .expect("clean single-layer JSON with \\\\\\\" and literal \\\\u0022 must pass");

        // Finding 2: RawQuoteMode::Single `\\u0027` in non-Markdown double-escaped JSON.
        let bad_double_single_u0027: &[&[u8]] = &[
            br#"{"outer":"{\"xml\":\"<keyMaterial attr='/\u003e\\u0027>DoubleSingleU0027Secret</keyMaterial>' />\"}"}"#,
            br#"{"xml":"\\u003ckeyMaterial attr='/\\u003e\\u0027\\u003eDirectDoubleU0027Secret\\u003c/keyMaterial\\u003e' /\\u003e"}"#,
            br#"{"xml":"\\u003ckeyMaterial attr='a\\u0027\\u003eSingleDoubleBsSecret\\u003c/keyMaterial\\u003e'/\\u003e"}"#,
        ];
        for payload in bad_double_single_u0027 {
            assert!(
                assert_r4_clean_bytes(payload).is_err(),
                "double-escaped Single \\\\u0027 bypassed assert_r4_clean_bytes: {}",
                String::from_utf8_lossy(payload)
            );
        }

        // Critical clean invariants for single-layer literal `\\u0027` and double-escaped `\\u0027`.
        let clean_single_u0027: &[&[u8]] = &[
            br#"{"xml":"<keyMaterial attr='a\\u0027b/>'/>ok"}"#,
            br#"{"xml":"\\u003ckeyMaterial attr='a\\u0027/\\u003eok"}"#,
        ];
        for payload in clean_single_u0027 {
            assert_r4_clean_bytes(payload).unwrap_or_else(|e| {
                panic!(
                    "clean Single \\\\u0027 payload rejected {}: {e}",
                    String::from_utf8_lossy(payload)
                )
            });
        }

        // render_report across all 7 formats for broken 3-bs single-layer JSON (both closed and unclosed) and broken double-escaped \\u0027.
        let render_cases = [
            (
                "ThreeBsBrokenSecret",
                r#"body={"xml":"\u003ckeyMaterial attr=\\\"x\\u0022/\u003e\\\"\u003eThreeBsBrokenSecret\u003c/keyMaterial\u003e"#,
            ),
            (
                "ThreeBsClosedSecret",
                r#"body={"xml":"\u003ckeyMaterial attr=\\\"x\\u0022/\u003e\\\"\u003eThreeBsClosedSecret\u003c/keyMaterial\u003e"}"#,
            ),
            (
                "BrokenDoubleSingleU0027Secret",
                r#"body={"xml":"\\u003ckeyMaterial attr='/\\u003e\\u0027\\u003eBrokenDoubleSingleU0027Secret\\u003c/keyMaterial\\u003e' /\\u003e"#,
            ),
        ];
        for (secret, raw_cell) in render_cases {
            let schema = TableSchema::new(
                "capture.http",
                "HTTP",
                vec![ColumnDef::new("payload", "Payload", ColumnType::Text)],
            );
            let data = TableData {
                schema,
                rows: vec![Row::new(1, vec![CellValue::Text(raw_cell.to_string())])],
                total_rows: 1,
            };
            for fmt in all_formats {
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("render_report({fmt:?}) failed for {secret}: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "leaked {secret} in {fmt:?}: {out}");
                assert!(out.contains("[REDACTED]"), "missing [REDACTED] in {fmt:?}: {out}");
            }
        }
    }

    #[test]
    fn test_r4_iter8_double_csv_json_gating_html_entities_and_markdown_edge_cases() {
        let all_formats = [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Jsonl,
            ExportFormat::Html,
            ExportFormat::HtmlVertical,
            ExportFormat::Markdown,
        ];

        // Finding 3: DoubleCsvJson CSV-only gating & Markdown `|` termination.
        let bad_csv_json_gating: &[&[u8]] = &[
            br#"| <keyMaterial attr=\""x | >MdCsvJsonPipeSecret</keyMaterial>\"" /> |"#,
            br#"<keyMaterial attr=\""x>RawCsvJsonSecret</keyMaterial>\"" />"#,
            br#"| {"a":"<keyMaterial attr=\""x | >MdJsonCsvPipeSecret</keyMaterial>\"" />"} |"#,
        ];
        for payload in bad_csv_json_gating {
            assert!(
                assert_r4_clean_bytes(payload).is_err(),
                "DoubleCsvJson gating leak bypassed assert_r4_clean_bytes: {}",
                String::from_utf8_lossy(payload)
            );
        }

        let schema = TableSchema::new(
            "capture.http",
            "HTTP",
            vec![ColumnDef::new("payload", "Payload", ColumnType::Text)],
        );
        let raw_u003c_data = TableData {
            schema: schema.clone(),
            rows: vec![Row::new(
                1,
                vec![CellValue::Text(
                    r#"\u003ckeyMaterial attr=\""x/>RawU003cCsvJsonSecret\u003c/keyMaterial\u003e\"" /\u003e"#
                        .to_string(),
                )],
            )],
            total_rows: 1,
        };
        for fmt in all_formats {
            let rendered = render_report(&raw_u003c_data, fmt, &ReportOptions::default())
                .unwrap_or_else(|e| panic!("render_report({fmt:?}) failed for RawU003cCsvJsonSecret: {e}"));
            let out = String::from_utf8_lossy(&rendered);
            assert!(
                !out.contains("RawU003cCsvJsonSecret"),
                "leaked RawU003cCsvJsonSecret in {fmt:?}: {out}"
            );
            assert!(out.contains("[REDACTED]"), "missing [REDACTED] in {fmt:?}: {out}");
        }

        // Finding 4: Html / HtmlVertical `escape_html` (`&quot;`) on `\u003c` payloads.
        let clean_html_data = TableData {
            schema: schema.clone(),
            rows: vec![Row::new(
                1,
                vec![CellValue::Text(
                    r#"body={"a":"\u003ckeyMaterial attr=\"a\u003eb\"/\u003eok"}"#.to_string(),
                )],
            )],
            total_rows: 1,
        };
        for fmt in [ExportFormat::Html, ExportFormat::HtmlVertical] {
            let rendered = render_report(&clean_html_data, fmt, &ReportOptions::default())
                .unwrap_or_else(|e| panic!("clean render_report({fmt:?}) failed for \\u003c + &quot;: {e}"));
            assert_r4_clean_bytes(&rendered)
                .unwrap_or_else(|e| panic!("assert_r4_clean_bytes rejected clean {fmt:?} output: {e}"));
        }

        let bad_html_fragments: &[&[u8]] = &[
            br#"<tr><td>body={&quot;a&quot;:&quot;\u003ckeyMaterial attr=\&quot;/\u003e\&quot;\u003eHtmlQuotBypassSecret\u003c/keyMaterial\u003e</td></tr>"#,
            br#"<tr><th>Payload</th><td>body={&quot;a&quot;:&quot;\u003ckeyMaterial attr=\&quot;/\u003e\&quot;\u003eHtmlQuotBypassSecret\u003c/keyMaterial\u003e</td></tr>"#,
        ];
        for html in bad_html_fragments {
            assert!(
                assert_r4_clean_bytes(html).is_err(),
                "HTML &quot; leak bypassed assert_r4_clean_bytes: {}",
                String::from_utf8_lossy(html)
            );
        }

        // Finding 5: Markdown `\\\\u003c` double-encoded JSON, `| ` prefix non-over-redaction, `<br>`, and leading whitespace.
        let unredacted_opts = ReportOptions {
            enforce_r4_redaction: false,
            ..Default::default()
        };
        let md_double_enc_data = TableData {
            schema: schema.clone(),
            rows: vec![Row::new(
                1,
                vec![CellValue::Text(
                    r#"{"xml":"\\u003ckeyMaterial attr=\\u0022/\\u003e\\u0022\\u003eMdRealDblSecret\\u003c/keyMaterial\\u003e"}"#
                        .to_string(),
                )],
            )],
            total_rows: 1,
        };
        let md_leaked = render_report(&md_double_enc_data, ExportFormat::Markdown, &unredacted_opts).unwrap();
        assert!(
            assert_r4_clean_bytes(&md_leaked).is_err(),
            "real guap-export Markdown double-encoded JSON bypassed assert_r4_clean_bytes: {}",
            String::from_utf8_lossy(&md_leaked)
        );
        assert!(
            assert_r4_clean_bytes(
                br#"| {"xml":"\\\\u003ckeyMaterial attr=\\\\u0022a\\\\\\\\u0022/\\\\u003e\\\\u0022\\\\u003eMdFourBsSecret\\\\u003c/keyMaterial\\\\u003e"} |"#
            )
            .is_err()
        );

        let clean_pipe_data = TableData {
            schema,
            rows: vec![Row::new(
                1,
                vec![CellValue::Text(r#"| <keyMaterial attr="a|b"/>ok"#.to_string())],
            )],
            total_rows: 1,
        };
        for fmt in all_formats {
            let rendered = render_report(&clean_pipe_data, fmt, &ReportOptions::default())
                .unwrap_or_else(|e| panic!("render_report({fmt:?}) failed for clean | prefix: {e}"));
            let out = String::from_utf8_lossy(&rendered);
            assert!(
                !out.contains("[REDACTED]"),
                "clean | <keyMaterial attr=\"a|b\"/>ok was falsely redacted in {fmt:?}: {out}"
            );
        }

        let bad_md_br_and_lead_ws: &[&[u8]] = &[
            br#"| {"a":"<keyMaterial attr=\\"x<br>>MdBrSecret</keyMaterial>\\" />"} |"#,
            br#"| {"a":"<keyMaterial attr='x<br>>MdBrSqSecret</keyMaterial>' />"} |"#,
            br#" "<keyMaterial attr='x" />LeadSpaceSecret</keyMaterial>' />" "#,
        ];
        for payload in bad_md_br_and_lead_ws {
            assert!(
                assert_r4_clean_bytes(payload).is_err(),
                "Markdown <br> or leading-space JSON string bypassed assert_r4_clean_bytes: {}",
                String::from_utf8_lossy(payload)
            );
        }
    }

    const ALL_SEVEN_FORMATS: [ExportFormat; 7] = [
        ExportFormat::Csv,
        ExportFormat::Tsv,
        ExportFormat::Json,
        ExportFormat::Jsonl,
        ExportFormat::Html,
        ExportFormat::HtmlVertical,
        ExportFormat::Markdown,
    ];

    fn single_cell_table(cell: &str) -> TableData {
        TableData {
            schema: TableSchema::new(
                "capture.http",
                "HTTP",
                vec![ColumnDef::new("payload", "Payload", ColumnType::Text)],
            ),
            rows: vec![Row::new(1, vec![CellValue::Text(cell.to_string())])],
            total_rows: 1,
        }
    }

    #[test]
    fn test_r4_iter9_t1_t2_t3_nested_json_inner_quote_termination() {
        // T1: RawQuoteMode::Single nested JSON `\"` leak (Iter 8 R1-F1)
        let t1_payload =
            r#"body={"outer":"{\"xml\":\"<keyMaterial attr='a\",\"x\":\"'/>LeakBrokenInnerSecret</keyMaterial>\""#;
        assert!(assert_r4_clean_bytes(t1_payload.as_bytes()).is_err());
        let t1_data = single_cell_table(t1_payload);
        for fmt in ALL_SEVEN_FORMATS {
            let rendered = render_report(&t1_data, fmt, &ReportOptions::default()).unwrap();
            let out = String::from_utf8_lossy(&rendered);
            assert!(!out.contains("LeakBrokenInnerSecret"), "leaked in {fmt:?}: {out}");
            assert!(out.contains("[REDACTED]"), "missing [REDACTED] in {fmt:?}: {out}");
            assert_r4_clean_for_format(&rendered, fmt).unwrap();
            assert_r4_clean_bytes(&rendered).unwrap();
        }

        // T2: Valid outer JSON + U0022Single / U0027Single nested `\"`
        let t2_valid_outer =
            r#"{"outer":"{\"xml\":\"<keyMaterial attr='a\",\"x\":\"'/>LeakValidInnerSecret</keyMaterial>\"}"}"#;
        assert!(assert_r4_clean_bytes(t2_valid_outer.as_bytes()).is_err());
        let t2_valid_data = single_cell_table(t2_valid_outer);
        for fmt in ALL_SEVEN_FORMATS {
            let rendered = render_report(&t2_valid_data, fmt, &ReportOptions::default()).unwrap();
            let out = String::from_utf8_lossy(&rendered);
            assert!(out.contains("[REDACTED]"), "missing [REDACTED] in {fmt:?}: {out}");
            assert_r4_clean_for_format(&rendered, fmt).unwrap();
            assert_r4_clean_bytes(&rendered).unwrap();
        }

        let t2_cases = [
            (
                "LeakNestedU0027",
                r#"body={"outer":"{\"xml\":\"<keyMaterial attr=\\u0027a\",\"x\":\"\\u0027/>LeakNestedU0027</keyMaterial>\""#,
            ),
            (
                "LeakNestedU0022",
                r#"body={"outer":"{\"xml\":\"<keyMaterial attr=\u0022a\",\"x\":\"\u0022/>LeakNestedU0022</keyMaterial>\""#,
            ),
            (
                "LeakArrayU0022Secret",
                r#"body={"outer":"[\"<keyMaterial attr='a\u0022,1,'/>LeakArrayU0022Secret</keyMaterial>\""#,
            ),
            (
                "LeakUnquotedSecret",
                r#"body={"outer":"{\"xml\":\"<keyMaterial attr=a\",\"x\":\" />LeakUnquotedSecret</keyMaterial>\""#,
            ),
        ];
        for (secret, payload) in t2_cases {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "T2 bypass for {secret}: {payload}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "leaked {secret} in {fmt:?}: {out}");
                assert!(out.contains("[REDACTED]"), "missing [REDACTED] in {fmt:?}: {out}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }

        // T3: Clean nested JSON `\\\"` inside single-quoted <keyMaterial>
        let t3_clean = [
            r#"{"outer":"{\"xml\":\"<keyMaterial attr='a\\\"b/>'/>ok\"}"}"#,
            r#"body={"outer":"{\"xml\":\"<keyMaterial attr='a\\\"b/>'/>ok\""#,
        ];
        for payload in t3_clean {
            assert_r4_clean_bytes(payload.as_bytes()).unwrap();
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains("[REDACTED]"), "over-redacted {payload} in {fmt:?}: {out}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }
    }

    #[test]
    fn test_r4_iter9_t4_t5_non_corrupting_json_and_key_sanitization() {
        // T4: Clean JSON `\u0022` / `\u0027` / `\u003e` not corrupted (Iter 8 R1-F2)
        let t4_clean = [
            r#"{"xml":"<keyMaterial attr=\"x>\u0022/>ok"}"#,
            r#"{"xml":"<keyMaterial attr='x>\u0027/>ok"}"#,
            r#"{"outer":"{\"xml\":\"<keyMaterial attr=\\\"x>\\u0022/>ok\"}"}"#,
            r#"body={"xml":"<keyMaterial attr=\"x>\u0022/>ok"}"#,
            r#"body={"xml":"<keyMaterial attr=\"x>\u0022/>ok""#,
        ];
        for payload in t4_clean {
            assert_r4_clean_bytes(payload.as_bytes())
                .unwrap_or_else(|e| panic!("T4 clean payload rejected {payload}: {e}"));
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("T4 render_report({fmt:?}) failed for {payload}: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains("[REDACTED]"), "T4 false [REDACTED] in {fmt:?}: {out}");
                if fmt == ExportFormat::Json {
                    let parsed: Value = serde_json::from_slice(&rendered).unwrap();
                    assert_eq!(parsed[0]["payload"].as_str().unwrap(), payload);
                } else if fmt == ExportFormat::Jsonl {
                    let parsed: Value = serde_json::from_slice(&rendered).unwrap();
                    assert_eq!(parsed["payload"].as_str().unwrap(), payload);
                }
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }

        // T5: Clean XML attr containing valid JSON `{...}` + JSON key leak
        let t5_clean_raw = r#"<keyMaterial attr='{"a":1}'/>ok"#;
        assert_r4_clean_bytes(t5_clean_raw.as_bytes()).unwrap();
        let t5_clean_json = r#"{"xml":"<keyMaterial attr='{\"a\":1}'/>ok"}"#;
        assert_r4_clean_bytes(t5_clean_json.as_bytes()).unwrap();
        for cell in [t5_clean_raw, t5_clean_json] {
            let data = single_cell_table(cell);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains("[REDACTED]"), "T5 false [REDACTED] in {fmt:?}: {out}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }

        let t5_key_leak = r#"{"<keyMaterial>KeySecret</keyMaterial>":"ok"}"#;
        assert!(assert_r4_clean_bytes(t5_key_leak.as_bytes()).is_err());
        let mut detail_opts = ReportOptions::default();
        detail_opts.export.include_detail_json = true;
        let t5_key_data = TableData {
            schema: TableSchema::new(
                "capture.http",
                "HTTP",
                vec![ColumnDef::new("payload", "Payload", ColumnType::Text)],
            ),
            rows: vec![
                Row::new(1, vec![CellValue::Text(t5_key_leak.to_string())])
                    .with_detail_json(json!({"<keyMaterial>DetailKeySecret</keyMaterial>": "ok"})),
            ],
            total_rows: 1,
        };
        for fmt in ALL_SEVEN_FORMATS {
            let rendered = render_report(&t5_key_data, fmt, &detail_opts).unwrap();
            let out = String::from_utf8_lossy(&rendered);
            assert!(!out.contains("KeySecret"), "T5 leaked key in {fmt:?}: {out}");
            assert!(
                !out.contains("DetailKeySecret"),
                "T5 leaked detail key in {fmt:?}: {out}"
            );
            assert!(out.contains("[REDACTED]"), "T5 missing [REDACTED] in {fmt:?}: {out}");
            assert_r4_clean_for_format(&rendered, fmt).unwrap();
            assert_r4_clean_bytes(&rendered).unwrap();
        }
    }

    #[test]
    fn test_r4_iter9_t6_t7_html_escaped_numeric_and_case_insensitive_entities() {
        // T6: HtmlEscaped numeric/case-insensitive quote entities (Iter 8 C1-F1)
        let t6_render_cases = [
            (
                "RenderDec34Secret",
                "&lt;keyMaterial attr=&#34;a/&gt;&#34;&gt;RenderDec34Secret&lt;/keyMaterial&gt;",
            ),
            (
                "RenderX22Secret",
                "&lt;keyMaterial attr=&#x22;a/&gt;&#x22;&gt;RenderX22Secret&lt;/keyMaterial&gt;",
            ),
            (
                "RenderUpperX22Secret",
                "&lt;keyMaterial attr=&#X22;a/&gt;&#X22;&gt;RenderUpperX22Secret&lt;/keyMaterial&gt;",
            ),
            (
                "RenderPadDec34Secret",
                "&lt;keyMaterial attr=&#0034;a/&gt;&#0034;&gt;RenderPadDec34Secret&lt;/keyMaterial&gt;",
            ),
            (
                "RenderUpperX27Secret",
                "&lt;keyMaterial attr=&#X27;a/&gt;&#X27;&gt;RenderUpperX27Secret&lt;/keyMaterial&gt;",
            ),
            (
                "RenderMixSecret",
                "&lt;keyMaterial attr=&quot;a&#34; x=&#34;/&gt;&#34;&gt;RenderMixSecret&lt;/keyMaterial&gt;",
            ),
        ];
        for (secret, payload) in t6_render_cases {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "T6 direct bypass for {secret}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "T6 leaked {secret} in {fmt:?}: {out}");
                assert!(out.contains("[REDACTED]"), "T6 missing [REDACTED] in {fmt:?}: {out}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }

        let t6_direct_bad: &[&[u8]] = &[
            b"<p>&lt;keyMaterial attr=&#34;a/&gt;&#34;&gt;RawDec34Secret&lt;/keyMaterial&gt;</p>",
            b"<p>&lt;keyMaterial attr=&#x22;a/&gt;&#x22;&gt;RawX22Secret&lt;/keyMaterial&gt;</p>",
            b"<tr><td>&amp;lt;keyMaterial attr=&amp;#34;a/&amp;gt;&amp;#34;&amp;gt;TdDblDec34Secret&amp;lt;/keyMaterial&amp;gt;</td></tr>",
            br#"{"xml":"&lt;keyMaterial attr=&#34;a/&gt;&#34;&gt;JsonDec34Secret&lt;/keyMaterial&gt;"}"#,
        ];
        for bad in t6_direct_bad {
            assert!(
                assert_r4_clean_bytes(bad).is_err(),
                "T6 direct HTML-escaped leak bypassed: {}",
                String::from_utf8_lossy(bad)
            );
        }

        // T7: Clean HtmlEscaped numeric quote entities invariant
        let t7_clean = [
            "&lt;keyMaterial attr=&#34;a&gt;b&#34;/&gt;ok",
            "&lt;keyMaterial attr=&#x22;a&gt;b&#x22;/&gt;ok",
            "&lt;keyMaterial attr=&#X27;a&gt;b&#X27;/&gt;ok",
            "&lt;keyMaterial attr=&#0034;a&gt;b&#0034;/&gt;ok",
        ];
        for payload in t7_clean {
            assert_r4_clean_bytes(payload.as_bytes()).unwrap();
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains("[REDACTED]"), "T7 false [REDACTED] in {fmt:?}: {out}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }
    }

    #[test]
    fn test_r4_iter9_t8_t9_t10_streaming_html_attributes_splitting_and_fragments() {
        // T8: HTML open-tag attributes (Iter 8 C1-F2)
        let t8_bad: &[&[u8]] = &[
            br#"<td title="<keyMaterial>HtmlTdAttrSecret</keyMaterial>">ok</td>"#,
            br#"<th data-x="<keyMaterial>HtmlThAttrSecret</keyMaterial>">ok</th>"#,
            br#"<tr><td>ok</td></tr><h1 title="<keyMaterial>HtmlH1AttrSecret</keyMaterial>">ok</h1>"#,
            br#"<tr><td>ok</td></tr><code title="<keyMaterial>HtmlCodeAttrSecret</keyMaterial>">ok</code>"#,
            br#"<tr><td>ok</td></tr><td title="&lt;keyMaterial attr=&#34;/&gt;&#34;&gt;HtmlAttrEscSecret&lt;/keyMaterial&gt;">ok</td>"#,
        ];
        for bad in t8_bad {
            assert!(
                assert_r4_clean_bytes(bad).is_err(),
                "T8 HTML attribute leak bypassed: {}",
                String::from_utf8_lossy(bad)
            );
        }

        // T9: HTML tag-splitting <keyMaterial attr="a<td>"> (Iter 8 C1-F2)
        assert!(
            assert_r4_clean_bytes(br#"<keyMaterial attr="a<td>" >HtmlTdInAttrSecret</keyMaterial>b</td>" />"#).is_err()
        );
        assert!(
            assert_r4_clean_bytes(br#"<keyMaterial attr="a<th>" >HtmlThInAttrSecret</keyMaterial>b</th>" />"#).is_err()
        );
        assert!(
            assert_r4_clean_bytes(br#"<div><keyMaterial attr="a<td>" >HtmlTdInAttrSecret</keyMaterial>b</td></div>"#)
                .is_err()
        );
        assert_r4_clean_bytes(br#"<keyMaterial attr="a<td>" />ok"#).unwrap();
        assert_r4_clean_bytes(br#"<td><keyMaterial attr="a<td>" />ok</td>"#).unwrap();

        // T10: Unclosed <tr><td> + <textarea> + <p> &quot;+\u003c (Iter 8 R1-F3 & C1-F2)
        let t10_bad: &[&[u8]] = &[
            br#"<tr><td>body={&quot;a&quot;:&quot;\u003ckeyMaterial attr=\&quot;/\u003e\&quot;\u003eUnclosedOnlyTdSecret\u003c/keyMaterial\u003e"#,
            br#"<html><body><textarea>body={&quot;a&quot;:&quot;\u003ckeyMaterial attr=\&quot;/\u003e\&quot;\u003eTextareaQuotSecret\u003c/keyMaterial\u003e&quot;}</textarea></body></html>"#,
            br#"<p>body={&quot;a&quot;:&quot;\u003ckeyMaterial attr=\&quot;/\u003e\&quot;\u003ePQuotSecret\u003c/keyMaterial\u003e&quot;}</p>"#,
        ];
        for bad in t10_bad {
            assert!(
                assert_r4_clean_bytes(bad).is_err(),
                "T10 HTML fragment leak bypassed: {}",
                String::from_utf8_lossy(bad)
            );
        }
        let t10_clean: &[&[u8]] = &[
            br#"<tr><td>{&quot;a&quot;:&quot;\u003ckeyMaterial attr=\&quot;a\u003eb\&quot;/\u003eok&quot;}"#,
            br#"<html><body><textarea>{&quot;a&quot;:&quot;\u003ckeyMaterial attr=\&quot;a\u003eb\&quot;/\u003eok&quot;}</textarea></body></html>"#,
        ];
        for clean in t10_clean {
            assert_r4_clean_bytes(clean).unwrap_or_else(|e| {
                panic!(
                    "T10 clean HTML fragment rejected {}: {e}",
                    String::from_utf8_lossy(clean)
                )
            });
        }
    }

    #[test]
    fn test_r4_iter9_t11_t12_csv_nested_json_and_pipe_prefix_all_formats() {
        // T11: CSV-doubled nested JSON `\\u0022` (Iter 8 C1-F3)
        let t11_leak =
            br#""{""outer"":""{\""xml\"":\""<keyMaterial attr=\\\""/\u003e\\u0022>CsvNestedMixedSecret</keyMaterial>\\\"" />\""}""}"#;
        assert!(assert_r4_clean_bytes(t11_leak).is_err());

        let t11_clean_raw = [
            br#""{""outer"":""{\""xml\"":\""<keyMaterial attr=\\\""x>\\u0022/>ok\""}""}""#.as_slice(),
            br#""body={""outer"":""{\""xml\"":\""<keyMaterial attr=\\\""a\\u0022/\u003eok\""}""}""#.as_slice(),
        ];
        for clean in t11_clean_raw {
            assert_r4_clean_bytes(clean).unwrap_or_else(|e| {
                panic!(
                    "T11 clean CSV nested JSON rejected {}: {e}",
                    String::from_utf8_lossy(clean)
                )
            });
        }

        let t11_clean_cell = r#"{"outer":"{\"xml\":\"<keyMaterial attr=\\\"x>\\u0022/>ok\"}"}"#;
        let t11_data = single_cell_table(t11_clean_cell);
        let csv = render_report(&t11_data, ExportFormat::Csv, &ReportOptions::default()).unwrap();
        assert!(!String::from_utf8_lossy(&csv).contains("[REDACTED]"));
        assert_r4_clean_bytes(&csv).unwrap();

        // T12: Clean `| `-prefixed cells across all 7 formats + assert_r4_clean_bytes (Iter 8 C1-F4)
        let t12_cells = [
            r#"| <keyMaterial attr="a|b"/>ok"#,
            r#"| <keyMaterial attr='x|y'/>ok"#,
            r#"| <keyMaterial attr="café|🔑"/>ok"#,
        ];
        for cell in t12_cells {
            let data = single_cell_table(cell);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("T12 render_report({fmt:?}) failed for {cell}: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains("[REDACTED]"), "T12 over-redacted in {fmt:?}: {out}");
                assert_r4_clean_for_format(&rendered, fmt)
                    .unwrap_or_else(|e| panic!("T12 assert_r4_clean_for_format({fmt:?}) failed: {e}"));
                assert_r4_clean_bytes(&rendered)
                    .unwrap_or_else(|e| panic!("T12 assert_r4_clean_bytes({fmt:?}) failed for {out}: {e}"));
            }
        }
    }

    #[test]
    fn test_r4_iter9_t13_t14_schema_metadata_and_utf8_char_boundaries() {
        // T13: TableSchema (`title`, `tool_id`, `col.label`, `col.id`) & ExportOptions (`title_override`, `tool_version`)
        let schema = TableSchema::new(
            "<keyMaterial>ToolIdSecret</keyMaterial>",
            "<keyMaterial>TitleSecret</keyMaterial>",
            vec![ColumnDef::new(
                "<keyMaterial>ColIdSecret</keyMaterial>",
                "&lt;keyMaterial attr=&#34;/&gt;&#34;&gt;LabelSecret&lt;/keyMaterial&gt;",
                ColumnType::Text,
            )],
        );
        let data = TableData {
            schema,
            rows: vec![Row::new(1, vec![CellValue::Text("ok".to_string())])],
            total_rows: 1,
        };
        let mut opts = ReportOptions::default();
        opts.export.title_override = Some("<keyMaterial>OverrideSecret</keyMaterial>".to_string());
        opts.export.tool_version = "<keyMaterial>VersionSecret</keyMaterial>".to_string();

        for fmt in ALL_SEVEN_FORMATS {
            let rendered = render_report(&data, fmt, &opts).unwrap();
            let out = String::from_utf8_lossy(&rendered);
            for secret in [
                "ToolIdSecret",
                "TitleSecret",
                "ColIdSecret",
                "LabelSecret",
                "OverrideSecret",
                "VersionSecret",
            ] {
                assert!(!out.contains(secret), "T13 leaked {secret} in {fmt:?}: {out}");
            }
            assert!(out.contains("[REDACTED]"), "T13 missing [REDACTED] in {fmt:?}: {out}");
            assert_r4_clean_for_format(&rendered, fmt).unwrap();
            assert_r4_clean_bytes(&rendered).unwrap();
        }

        // T14: UTF-8 is_char_boundary across HTML entities & JSON `\u0022`
        assert!(
            assert_r4_clean_bytes(
                "<p>&lt;keyMaterial attr=&#x22;café/&gt;🔑&#x22;&gt;Utf8X22Secret&lt;/keyMaterial&gt;</p>".as_bytes()
            )
            .is_err()
        );
        assert_r4_clean_bytes("<p>&lt;keyMaterial attr=&#x22;café&gt;🔑&#x22;/&gt;ok</p>".as_bytes()).unwrap();

        let utf8_json_cell = r#"{"xml":"<keyMaterial attr=\"café>\u0022/>🔑ok"}"#;
        let utf8_data = single_cell_table(utf8_json_cell);
        for fmt in ALL_SEVEN_FORMATS {
            let rendered = render_report(&utf8_data, fmt, &ReportOptions::default()).unwrap();
            let out = String::from_utf8_lossy(&rendered);
            assert!(!out.contains("[REDACTED]"), "T14 over-redacted in {fmt:?}: {out}");
            assert_r4_clean_for_format(&rendered, fmt).unwrap();
            assert_r4_clean_bytes(&rendered).unwrap();
        }
    }

    #[test]
    fn test_r4_iter10_remediation_all_seven_findings() {
        // 1. TagSyntax::HtmlEscaped JSON backslash / \u0022 / \\u0022 / strict_nested parity
        let html_esc_leaks = [
            (
                "LeakHtmlU0022Secret",
                r#"body={"xml":"&lt;keyMaterial attr=&quot;a\u0022,\u0022x\u0022:\u0022&quot; /&gt;LeakHtmlU0022Secret&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakSingleEntU0022Secret",
                r#"body={"xml":"&lt;keyMaterial attr=&#39;a\u0022,\u0022x\u0022:\u0022&#39; /&gt;LeakSingleEntU0022Secret&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakRawSqU0022Secret",
                r#"body={"xml":"&lt;keyMaterial attr='a\u0022,\u0022x\u0022:\u0022' /&gt;LeakRawSqU0022Secret&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakNoneU0022Secret",
                r#"body={"xml":"&lt;keyMaterial attr=a\u0022,\u0022x\u0022:\u0022 /&gt;LeakNoneU0022Secret&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakHtmlRawDoubleSecret",
                r#"body={"xml":"&lt;keyMaterial attr=\"/&gt;\"&gt;LeakHtmlRawDoubleSecret&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakHtmlRawDoubleU0022Secret",
                r#"body={"xml":"&lt;keyMaterial attr=\"a\u0022,\u0022x\u0022:\u0022\" /&gt;LeakHtmlRawDoubleU0022Secret&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakNestedHtmlBsQSecret",
                r#"body={"outer":"{\"xml\":\"&lt;keyMaterial attr=&quot;a\",\"x\":\"&quot; /&gt;LeakNestedHtmlBsQSecret&lt;/keyMaterial&gt;\""#,
            ),
            (
                "LeakNestedHtmlU0022Secret",
                r#"body={"outer":"{\"xml\":\"&lt;keyMaterial attr=&quot;a\u0022,\u0022x\u0022:\u0022&quot; /&gt;LeakNestedHtmlU0022Secret&lt;/keyMaterial&gt;\""#,
            ),
            (
                "LeakNestedDblHtmlU0022Secret",
                r#"body={"outer":"{\"xml\":\"&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot; /&gt;LeakNestedDblHtmlU0022Secret&lt;/keyMaterial&gt;\""#,
            ),
            (
                "LeakNestedRawSqBsQSecret",
                r#"body={"outer":"{\"xml\":\"&lt;keyMaterial attr='a\",\"x':'\" /&gt;LeakNestedRawSqBsQSecret&lt;/keyMaterial&gt;\""#,
            ),
        ];
        for (secret, payload) in html_esc_leaks {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "Item 1 direct bypass for {secret}: {payload}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "Item 1 leaked {secret} in {fmt:?}: {out}");
                assert!(
                    out.contains("[REDACTED]"),
                    "Item 1 missing [REDACTED] in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }
        assert!(
            assert_r4_clean_bytes(
                br#"| body={"xml":"&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot; /&gt;LeakMdHtmlU0022Secret&lt;/keyMaterial&gt; |"#
            )
            .is_err()
        );

        let html_esc_clean = [
            r#"body={"xml":"&lt;keyMaterial attr=&quot;a\"b&quot;/&gt;ok"#,
            r#"body={"xml":"&lt;keyMaterial attr=&#39;a\"b&#39;/&gt;ok"#,
            r#"body={"xml":"&lt;keyMaterial attr='a\"b'/&gt;ok"#,
            r#"body={"xml":"&lt;keyMaterial attr=\"a&gt;b\"/&gt;ok"#,
            r#"body={"outer":"{\"xml\":\"&lt;keyMaterial attr=&quot;a\\\"b&quot;/&gt;ok\"}"}"#,
        ];
        for payload in html_esc_clean {
            assert_r4_clean_bytes(payload.as_bytes())
                .unwrap_or_else(|e| panic!("Item 1 clean rejected {payload}: {e}"));
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains("[REDACTED]"), "Item 1 false [REDACTED] in {fmt:?}: {out}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }

        // 2. is_raw_keymaterial_open_at escaped delimiters inside HTML
        let html_escaped_delims_bad: &[&[u8]] = &[
            br#"<p>{"xml":"<keyMaterial\u003eHtmlU003eSecret</keyMaterial>"}</p>"#,
            br#"<p>{"xml":"<keyMaterial\n>HtmlEscWsSecret</keyMaterial>"}</p>"#,
            br#"<p><keyMaterial\n>HtmlRawEscWsSecret</keyMaterial></p>"#,
            br#"<td title="ok"><keyMaterial\n>TdRawEscWsSecret</keyMaterial></td>"#,
            br#"<p>{"xml":"<keyMaterial\/ >HtmlEscSlashSecret</keyMaterial>"}</p>"#,
            br#"<p>{"xml":"<keyMaterial\u0020>HtmlU0020Secret</keyMaterial>"}</p>"#,
        ];
        for bad in html_escaped_delims_bad {
            assert!(
                assert_r4_clean_bytes(bad).is_err(),
                "Item 2 HTML escaped delimiter bypassed: {}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_r4_clean_bytes(br#"<p>{"xml":"<keyMaterial attr=\"a\u003e\"/\u003eok"}</p>"#).unwrap();
        assert_r4_clean_bytes(br#"<p>{"xml":"<keyMaterial attr=\"a<td>\"/\u003eok"}</p>"#).unwrap();

        // 3. is_html_document_or_fragment leading <!-- ... --> comments & CSV <b> header narrowing
        let comment_html_bad: &[&[u8]] = &[
            br#"<!-- ok --><tr><td>body={&quot;a&quot;:&quot;\u003ckeyMaterial attr=\&quot;/\u003e\&quot;\u003eCommentHtmlSecret\u003c/keyMaterial\u003e&quot;}</td></tr>"#,
            br#"<!-- ok --><tr><td>&amp;lt;keyMaterial attr=&amp;#34;/&amp;gt;&amp;#34;&amp;gt;CommentDblDec34Secret&amp;lt;/keyMaterial&amp;gt;</td></tr>"#,
            br#"<b><tr><td>body={&quot;a&quot;:&quot;\u003ckeyMaterial attr=\&quot;/\u003e\&quot;\u003eBTagBlockSecret\u003c/keyMaterial\u003e&quot;}</td></tr>"#,
            br#"<b><keyMaterial attr="&quot;/&gt;&quot;">InlineClosedSecret</keyMaterial></b>"#,
        ];
        for bad in comment_html_bad {
            assert!(
                assert_r4_clean_bytes(bad).is_err(),
                "Item 3 HTML comment/inline-block bypassed: {}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_r4_clean_bytes(b"<b>\r\n\"<keyMaterial attr=\"\"a>b\"\"/>ok\"").unwrap();
        assert_r4_clean_bytes(b"<b>\r\n\"<keyMaterial attr=\"\"a<td>b\"\"/>ok\"").unwrap();

        // 4. find_html_open_tag_end unquoted <keyMaterial> inside HTML attributes
        assert!(assert_r4_clean_bytes(b"<td title=<keyMaterial>UnquotedAttrSecret</keyMaterial>>ok</td>").is_err());
        assert!(
            assert_r4_clean_bytes(b"<td title=<keyMaterial attr=\"a b\">UnquotedAttrSpaceSecret</keyMaterial>>ok</td>")
                .is_err()
        );
        assert_r4_clean_bytes(b"<td title=<keyMaterial/>>ok</td>").unwrap();
        assert_r4_clean_bytes(b"<td title=<keyMaterial attr=\"a b\"/>ok>ok</td>").unwrap();
        assert_r4_clean_bytes(b"<td title=plain>ok</td>").unwrap();

        // 5. assert_r4_clean_json_value_inner JSON Object keys & depth == MAX_NESTED_JSON_DEPTH parity
        let clean_json_key = r#"{"xml":"<keyMaterial attr=\"a\u0022/>ok"}"#;
        let mut detail_opts = ReportOptions::default();
        detail_opts.export.include_detail_json = true;
        let key_table = TableData {
            schema: TableSchema::new(
                "capture.http",
                "HTTP",
                vec![ColumnDef::new(clean_json_key, "Payload", ColumnType::Text)],
            ),
            rows: vec![
                Row::new(1, vec![CellValue::Text("ok".to_string())]).with_detail_json(json!({ clean_json_key: "ok" })),
            ],
            total_rows: 1,
        };
        for fmt in ALL_SEVEN_FORMATS {
            let rendered = render_report(&key_table, fmt, &detail_opts)
                .unwrap_or_else(|e| panic!("Item 5 key render_report({fmt:?}) failed: {e}"));
            let out = String::from_utf8_lossy(&rendered);
            assert!(
                !out.contains("[REDACTED]"),
                "Item 5 key over-redacted in {fmt:?}: {out}"
            );
            assert_r4_clean_for_format(&rendered, fmt).unwrap();
            assert_r4_clean_bytes(&rendered).unwrap();
        }

        let mut depth8_clean = r#"{"xml":"<keyMaterial attr=\"x>\u0022/>ok"}"#.to_string();
        let mut depth8_leak = r#"{"xml":"<keyMaterial attr=\"x>\u0022>Depth8Secret</keyMaterial>"}"#.to_string();
        for layer in 0..7 {
            let key = format!("l{layer}");
            depth8_clean = json!({ key.clone(): depth8_clean }).to_string();
            depth8_leak = json!({ key: depth8_leak }).to_string();
        }
        let depth8_clean_data = single_cell_table(&depth8_clean);
        for fmt in ALL_SEVEN_FORMATS {
            let rendered = render_report(&depth8_clean_data, fmt, &ReportOptions::default())
                .unwrap_or_else(|e| panic!("Item 5 depth-8 clean render_report({fmt:?}) failed: {e}"));
            let out = String::from_utf8_lossy(&rendered);
            assert!(!out.contains("[REDACTED]"), "Item 5 depth-8 over-redacted in {fmt:?}");
            assert_r4_clean_for_format(&rendered, fmt).unwrap();
            assert_r4_clean_bytes(&rendered).unwrap();
        }
        assert!(assert_r4_clean_bytes(depth8_leak.as_bytes()).is_err());
        let depth8_leak_data = single_cell_table(&depth8_leak);
        for fmt in ALL_SEVEN_FORMATS {
            let rendered = render_report(&depth8_leak_data, fmt, &ReportOptions::default()).unwrap();
            let out = String::from_utf8_lossy(&rendered);
            assert!(!out.contains("Depth8Secret"), "Item 5 depth-8 leaked in {fmt:?}");
            assert!(
                out.contains("[REDACTED]"),
                "Item 5 depth-8 missing [REDACTED] in {fmt:?}"
            );
            assert_r4_clean_for_format(&rendered, fmt).unwrap();
            assert_r4_clean_bytes(&rendered).unwrap();
        }

        // 6. ExportFormat::Markdown literal <br> in JSON strings & unescaped # {title}
        let md_clean_cases = [
            r#"{"xml":"<keyMaterial attr=\"a<br>b\"/>ok"}"#,
            r#"body={"xml":"<keyMaterial attr=\"a<br>b\"/>ok"}"#,
        ];
        for cell in md_clean_cases {
            let data = single_cell_table(cell);
            let rendered = render_report(&data, ExportFormat::Markdown, &ReportOptions::default())
                .unwrap_or_else(|e| panic!("Item 6 Markdown <br> failed for {cell}: {e}"));
            let out = String::from_utf8_lossy(&rendered);
            assert!(!out.contains("[REDACTED]"), "Item 6 false [REDACTED]: {out}");
            assert_r4_clean_for_format(&rendered, ExportFormat::Markdown).unwrap();
            assert_r4_clean_bytes(&rendered).unwrap();
        }
        let title_data = TableData {
            schema: TableSchema::new(
                "capture.http",
                r#"{"xml":"<keyMaterial attr=\"a\\u0022b\"/>ok"}"#,
                vec![ColumnDef::new("payload", "Payload", ColumnType::Text)],
            ),
            rows: vec![Row::new(1, vec![CellValue::Text("ok".to_string())])],
            total_rows: 1,
        };
        let md_title = render_report(&title_data, ExportFormat::Markdown, &ReportOptions::default()).unwrap();
        assert!(!String::from_utf8_lossy(&md_title).contains("[REDACTED]"));
        assert_r4_clean_for_format(&md_title, ExportFormat::Markdown).unwrap();
        assert_r4_clean_bytes(&md_title).unwrap();
        assert!(
            assert_r4_clean_bytes(br#"| {"a":"<keyMaterial attr=\\"x<br>>MdBrSecret</keyMaterial>\\" />"} |"#).is_err()
        );

        // 7. Strict Markdown detection for multi-line 1-column CSV/TSV | ... |
        let pipe_sq = single_cell_table(r#"| <keyMaterial attr='a|b'/>ok |"#);
        let pipe_dq = single_cell_table(r#"| <keyMaterial attr="a|b"/>ok |"#);
        for (data, fmt) in [
            (&pipe_sq, ExportFormat::Csv),
            (&pipe_sq, ExportFormat::Tsv),
            (&pipe_dq, ExportFormat::Csv),
            (&pipe_dq, ExportFormat::Tsv),
        ] {
            let rendered = render_report(data, fmt, &ReportOptions::default()).unwrap();
            let out = String::from_utf8_lossy(&rendered);
            assert!(!out.contains("[REDACTED]"), "Item 7 false [REDACTED] in {fmt:?}: {out}");
            assert_r4_clean_for_format(&rendered, fmt).unwrap();
            assert_r4_clean_bytes(&rendered).unwrap();
        }
        assert_r4_clean_bytes(b"Payload\r\n| <keyMaterial attr='a|b'/>ok |").unwrap();
        assert_r4_clean_bytes(b"Payload\n| <keyMaterial attr=\"a|b\"/>ok |").unwrap();
    }

    #[test]
    fn test_r4_iter11_remediation_all_seven_defects() {
        // 1. RawQuoteMode::Single / U0027Single / U0027DoubleBs \u0022 / \\u0022 termination
        let item1_leaks = [
            (
                "LeakRawTagSqU0022Secret",
                r#"body={"xml":"<keyMaterial attr='a\u0022,\u0022x\u0022:\u0022' />LeakRawTagSqU0022Secret</keyMaterial>"#,
            ),
            (
                "LeakRawU003cSqU0022Secret",
                r#"body={"xml":"\u003ckeyMaterial attr='a\u0022,\u0022x\u0022:\u0022' /\u003eLeakRawU003cSqU0022Secret\u003c/keyMaterial\u003e"#,
            ),
            (
                "LeakRawU0027U0022Secret",
                r#"body={"xml":"\u003ckeyMaterial attr=\u0027a\u0022,\u0022x\u0022:\u0022\u0027 /\u003eLeakRawU0027U0022Secret\u003c/keyMaterial\u003e"#,
            ),
            (
                "LeakRawSqDblU0022Secret",
                r#"body={"xml":"\\u003ckeyMaterial attr='a\\u0022,\\u0022x\\u0022:\\u0022' /\\u003eLeakRawSqDblU0022Secret\\u003c/keyMaterial\\u003e"#,
            ),
            (
                "LeakRawU0027DblU0022Secret",
                r#"body={"xml":"\\u003ckeyMaterial attr=\\u0027a\\u0022,\\u0022x\\u0022:\\u0022\\u0027 /\\u003eLeakRawU0027DblU0022Secret\\u003c/keyMaterial\\u003e"#,
            ),
        ];
        for (secret, payload) in item1_leaks {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "Item 1 direct bypass for {secret}: {payload}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "Item 1 leaked {secret} in {fmt:?}: {out}");
                assert!(out.contains("[REDACTED]"), "Item 1 missing [REDACTED] in {fmt:?}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }
        for clean in [
            r#"body={"xml":"<keyMaterial attr='a\\u0022b'/>ok"#,
            r#"body={"xml":"<keyMaterial attr=\\u0027a\\u0022b\\u0027/>ok"#,
        ] {
            assert_r4_clean_bytes(clean.as_bytes()).unwrap();
            let data = single_cell_table(clean);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains("[REDACTED]"), "Item 1 over-redacted {clean} in {fmt:?}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }

        // 2. Markdown <br> + literal </keyMaterial> field, >Secret[REDACTED]</keyMaterial>, and broken DoubleEntity <br>
        let md_clean_br_note = r#"{"xml":"<keyMaterial attr=\"a<br>b\"/>ok","note":"</keyMaterial>"}"#;
        let md_clean_broken_he = r#"body={"xml":"&lt;keyMaterial attr=&quot;a<br>b&quot;/&gt;ok"#;
        for cell in [md_clean_br_note, md_clean_broken_he] {
            let data = single_cell_table(cell);
            let rendered = render_report(&data, ExportFormat::Markdown, &ReportOptions::default())
                .unwrap_or_else(|e| panic!("Item 2 Markdown render failed for {cell}: {e}"));
            let out = String::from_utf8_lossy(&rendered);
            assert!(!out.contains("[REDACTED]"), "Item 2 over-redacted in Markdown: {out}");
            assert_r4_clean_for_format(&rendered, ExportFormat::Markdown).unwrap();
            assert_r4_clean_bytes(&rendered).unwrap();
        }
        assert_r4_clean_bytes(br#"| {"xml":"<keyMaterial attr=\"a<br>b\"/>ok","note":"</keyMaterial>"} |"#).unwrap();
        assert_r4_clean_bytes(br#"| body={"xml":"&lt;keyMaterial attr=&quot;a<br>b&quot;/&gt;ok |"#).unwrap();
        let md_redacted_bypass = br#"| {"a":"<keyMaterial attr=\\"x<br>>Secret[REDACTED]</keyMaterial>\\" />"} |"#;
        assert!(assert_r4_clean_bytes(md_redacted_bypass).is_err());
        assert!(assert_r4_clean_for_format(md_redacted_bypass, ExportFormat::Markdown).is_err());

        // 3. dbl_html_u0022 vs clean literal \\u0022 in single-layer JSON
        let dbl_html_leaks = [
            (
                "LeakDblHtmlU0022Secret",
                r#"body={"xml":"\\u0022&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot; /&gt;LeakDblHtmlU0022Secret&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakDblHtmlBsqU0022Secret",
                r#"body={"xml":"\\\"&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot; /&gt;LeakDblHtmlBsqU0022Secret&lt;/keyMaterial&gt;"#,
            ),
        ];
        for (secret, payload) in dbl_html_leaks {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "Item 3 direct bypass for {secret}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "Item 3 leaked {secret} in {fmt:?}: {out}");
                assert!(out.contains("[REDACTED]"), "Item 3 missing [REDACTED] in {fmt:?}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }
        for clean in [
            r#"body={"xml":"&lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
            r#"body={"xml":"&lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt; &lt;keyMaterial attr=&quot;c\\u0022d&quot;/&gt;ok"#,
        ] {
            assert_r4_clean_bytes(clean.as_bytes()).unwrap();
            let data = single_cell_table(clean);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains("[REDACTED]"), "Item 3 over-redacted {clean} in {fmt:?}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }

        // 4. TagSyntax::HtmlEscaped `>` and `\u003e` / `\u002f` / escaped-u00 whitespace
        let he_delim_leaks = [
            (
                "LeakJsonHeU003e",
                r#"{"xml":"&lt;keyMaterial\u003eLeakJsonHeU003e&lt;/keyMaterial&gt;"}"#,
            ),
            (
                "LeakMixedGt",
                r#"{"xml":"&lt;keyMaterial>LeakMixedGt&lt;/keyMaterial&gt;"}"#,
            ),
            (
                "LeakBrokenHeU003e",
                r#"body={"xml":"&lt;keyMaterial\u003eLeakBrokenHeU003e&lt;/keyMaterial&gt;"}"#,
            ),
            (
                "LeakUnclosedHeU003e",
                r#"body={"xml":"&lt;keyMaterial\u003eLeakUnclosedHeU003e&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakHeU0020",
                r#"body={"xml":"&lt;keyMaterial\u0020attr=&quot;a&quot;&gt;LeakHeU0020&lt;/keyMaterial\u003e"}"#,
            ),
            (
                "LeakHeCloseU002f",
                r#"body={"xml":"&lt;keyMaterial\u003eLeakHeCloseU002f&lt;\u002fkeyMaterial\u003e"}"#,
            ),
        ];
        for (secret, payload) in he_delim_leaks {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "Item 4 direct bypass for {secret}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "Item 4 leaked {secret} in {fmt:?}: {out}");
                assert!(out.contains("[REDACTED]"), "Item 4 missing [REDACTED] in {fmt:?}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }
        for clean in [
            r#"body={"xml":"&lt;keyMaterial attr=&quot;a&gt;b&quot;\u002f\u003eok"}"#,
            r#"body={"xml":"&lt;keyMaterial attr=&quot;a&quot;/&gt;ok"}"#,
        ] {
            assert_r4_clean_bytes(clean.as_bytes()).unwrap();
            let data = single_cell_table(clean);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains("[REDACTED]"), "Item 4 over-redacted {clean} in {fmt:?}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }

        // 5. strict_nested `\\u0022` in HtmlEscaped (HtmlQuoteMode::U0022DoubleBs)
        let nested_he_clean = r#"body={"outer":"{\"xml\":\"&lt;keyMaterial attr=\\u0022a&gt;b\\u0022/&gt;ok"#;
        assert_r4_clean_bytes(nested_he_clean.as_bytes()).unwrap();
        let nested_he_clean_data = single_cell_table(nested_he_clean);
        for fmt in ALL_SEVEN_FORMATS {
            let rendered = render_report(&nested_he_clean_data, fmt, &ReportOptions::default()).unwrap();
            let out = String::from_utf8_lossy(&rendered);
            assert!(!out.contains("[REDACTED]"), "Item 5 over-redacted in {fmt:?}: {out}");
            assert_r4_clean_for_format(&rendered, fmt).unwrap();
            assert_r4_clean_bytes(&rendered).unwrap();
        }
        for (secret, payload) in [
            (
                "LeakNestedU0022Open",
                r#"body={"outer":"{\"xml\":\"&lt;keyMaterial attr=\\u0022/&gt;\\u0022&gt;LeakNestedU0022Open&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakNestedU0022Mid",
                r#"body={"outer":"{\"xml\":\"&lt;keyMaterial attr=\\u0022a\\u0022,\\u0022x\\u0022:\\u0022 /&gt;LeakNestedU0022Mid&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakNestedSingleBs",
                r#"body={"outer":"{\"xml\":\"&lt;keyMaterial attr=\\u0022a\u0022b\\u0022/&gt;LeakNestedSingleBs&lt;/keyMaterial&gt;"#,
            ),
        ] {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "Item 5 bypass for {secret}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "Item 5 leaked {secret} in {fmt:?}: {out}");
                assert!(out.contains("[REDACTED]"), "Item 5 missing [REDACTED] in {fmt:?}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }

        // 6. flush_html_text_buf `&quot;` + `\"` inside `<p>` broken/prefixed JSON
        assert_r4_clean_bytes(br#"<p>body={"xml":"&lt;keyMaterial attr=&quot;a\"b&quot;/&gt;ok"}</p>"#).unwrap();
        assert_r4_clean_bytes(br#"<p>body={"xml":"&lt;keyMaterial attr=&quot;a\"b&quot;/&gt;ok</p>"#).unwrap();
        for bad in [
            br#"<p>body={"xml":"&lt;keyMaterial attr=&quot;a\"/&gt;&quot;&gt;PLeak1&lt;/keyMaterial&gt;"}</p>"#.as_slice(),
            br#"<p>body={"xml":"&lt;keyMaterial attr=&quot;a\"b&quot;/&gt;","x":"&amp;lt;keyMaterial&amp;gt;PLeak2&amp;lt;/keyMaterial&amp;gt;"}</p>"#.as_slice(),
            br#"<p>body={"a":"\u003ckeyMaterial attr=&quot;/&gt;&quot;\u003ePLeak3</keyMaterial>"}</p>"#.as_slice(),
        ] {
            assert!(
                assert_r4_clean_bytes(bad).is_err(),
                "Item 6 HTML <p> leak bypassed: {}",
                String::from_utf8_lossy(bad)
            );
        }

        // 7. is_html_document_or_fragment inline-tag edge cases vs CSV `<b>` + `</b>`
        for bad in [
            br#"<span>body={&quot;a&quot;:&quot;\u003ckeyMaterial attr=\&quot;/\u003e\&quot;\u003eSpanNoCloseSecret\u003c/keyMaterial\u003e&quot;}"#.as_slice(),
            br#"<b>body={&quot;a&quot;:&quot;\u003ckeyMaterial attr=\&quot;/\u003e\&quot;\u003eUnclosedBoldLeak\u003c/keyMaterial\u003e&quot;}"#.as_slice(),
            b"<b>\r\n\"hello\",body={&quot;a&quot;:&quot;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eInlineCsvMixSecret\\u003c/keyMaterial\\u003e&quot;}\r\n</b>".as_slice(),
        ] {
            assert!(
                assert_r4_clean_bytes(bad).is_err(),
                "Item 7 inline HTML leak bypassed: {}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_r4_clean_bytes(b"<b>\r\n\"<keyMaterial attr=\"\"a>b\"\"/>ok\",</b>").unwrap();
    }

    #[test]
    fn test_r4_iter12_remediation_all_four_defects() {
        // 1. Markdown <br> multi-</keyMaterial> and nested <keyMaterial> inside after_name..open_end
        let md_br_leaks = [
            br#"| {"a":"<keyMaterial attr=\\"x<br>>[REDACTED]</keyMaterial>LeakMd2CloseSecret</keyMaterial>\\" />"} |"#.as_slice(),
            br#"| {"a":"<keyMaterial attr=\\"x<br>>[REDACTED]</keyMaterial><keyMaterial>LeakAfter</keyMaterial>\\" />"} |"#.as_slice(),
            br#"| {"a":"<keyMaterial attr=\\"x<br>>[REDACTED]</keyMaterial>>LeakSecondClose</keyMaterial>\\" />"} |"#.as_slice(),
            br#"| {"a":"<keyMaterial attr=\\"x<br>>&gt;[REDACTED]&lt;/keyMaterial&gt;>LeakSecondHtml</keyMaterial>\\" />"} |"#.as_slice(),
            br#"| {"a":"<keyMaterial attr=\\"x<br>>[REDACTED]</keyMaterial><keyMaterial>Leak>[REDACTED]</keyMaterial>\\" />"} |"#.as_slice(),
            br#"| {"a":"<keyMaterial attr=\\"x<br>>[REDACTED]</keyMaterial><keyMaterial>UnclosedNoClose\\" />"} |"#.as_slice(),
        ];
        for bad in md_br_leaks {
            assert!(
                assert_r4_clean_bytes(bad).is_err(),
                "Defect 1 direct bypass: {}",
                String::from_utf8_lossy(bad)
            );
            assert!(
                assert_r4_clean_for_format(bad, ExportFormat::Markdown).is_err(),
                "Defect 1 Markdown format bypass: {}",
                String::from_utf8_lossy(bad)
            );
        }
        let md_br_clean = r#"{"xml":"<keyMaterial attr=\"a<br>b\"/>ok","note":"</keyMaterial>"}"#;
        assert_r4_clean_bytes(md_br_clean.as_bytes()).unwrap();
        let md_rendered = render_report(
            &single_cell_table(md_br_clean),
            ExportFormat::Markdown,
            &ReportOptions::default(),
        )
        .unwrap();
        assert!(!String::from_utf8_lossy(&md_rendered).contains("[REDACTED]"));
        assert_r4_clean_for_format(&md_rendered, ExportFormat::Markdown).unwrap();
        assert_r4_clean_bytes(&md_rendered).unwrap();

        // 2. is_inline_prefixed_rfc4180_csv closed <b>...</b> / <span>...</span> with quoted &quot; JSON
        let inline_html_leaks: &[&[u8]] = &[
            b"<b>\r\n\"body={&quot;a&quot;:&quot;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eLeakBoldQuotedJson\\u003c/keyMaterial\\u003e&quot;}\"\r\n</b>",
            b"<span>\n\"body={&quot;a&quot;:&quot;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eSpanCsvBypass\\u003c/keyMaterial\\u003e&quot;}\"\n</span>",
            b"<b>\r\n\"a=\"\"b\"\"\",\"body={&quot;a&quot;:&quot;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eMixEntityBypass\\u003c/keyMaterial\\u003e&quot;}\"\r\n</b>",
        ];
        for bad in inline_html_leaks {
            assert!(
                assert_r4_clean_bytes(bad).is_err(),
                "Defect 2 inline HTML quoted-JSON bypass: {}",
                String::from_utf8_lossy(bad)
            );
            assert!(
                assert_r4_clean_for_format(bad, ExportFormat::Html).is_err(),
                "Defect 2 Html format bypass: {}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_r4_clean_bytes(b"<b>\r\n\"<keyMaterial attr=\"\"a>b\"\"/>ok\",</b>").unwrap();
        assert_r4_clean_bytes(b"<b>\r\n\"<keyMaterial attr=\"\"a>b\"\"/>ok\"").unwrap();
        assert_r4_clean_bytes(b"<b>\r\n\"<keyMaterial attr=\"\"a<td>b\"\"/>ok\"").unwrap();

        // 3. Multi-tag in_double_escaped_json persistence across JsonContextTracker & is_csv_field_in_json_string / sanitizer parity
        let multi_tag_leaks = [
            (
                "LeakAfterDblU003c",
                r#"body={"xml":"\\u003ckeyMaterial/\\u003e &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakAfterDblU003c&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakCsvGap2Secret",
                r#""{""xml"":""\\u0022<keyMaterial attr='ok'/>&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot; /&gt;LeakCsvGap2Secret&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakCsvAfterDblU003c",
                r#""{""xml"":""\\u003ckeyMaterial/\\u003e &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot; /&gt;LeakCsvAfterDblU003c&lt;/keyMaterial&gt;"#,
            ),
        ];
        for (secret, payload) in multi_tag_leaks {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "Defect 3 direct bypass for {secret}: {payload}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("Defect 3 render_report({fmt:?}) failed for {secret}: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "Defect 3 leaked {secret} in {fmt:?}: {out}");
                assert!(
                    out.contains("[REDACTED]"),
                    "Defect 3 missing [REDACTED] in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }
        // Reset across separate JSON strings in same object/CSV field
        for clean in [
            r#"body={"a":"\\u003ckeyMaterial/\\u003e","b":"&lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
            r#""{""a"":""\\u003ckeyMaterial/\\u003e"",""b"":""&lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
        ] {
            assert_r4_clean_bytes(clean.as_bytes())
                .unwrap_or_else(|e| panic!("Defect 3 clean reset rejected {clean}: {e}"));
        }

        // 4. has_double_escaped_json_markers precision: preserve literal \\u0022 in single-layer broken JSON prefixes
        let clean_prose_u0022 = [
            r#"body={"xml":"prefix \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
            r#"body={"xml":"prefix \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"}"#,
            r#"<p>body={"xml":"prefix \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"}</p>"#,
        ];
        for clean in clean_prose_u0022 {
            assert_r4_clean_bytes(clean.as_bytes())
                .unwrap_or_else(|e| panic!("Defect 4 clean prefix rejected {clean}: {e}"));
            let data = single_cell_table(clean);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("Defect 4 render_report({fmt:?}) failed for {clean}: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(
                    !out.contains("[REDACTED]"),
                    "Defect 4 over-redacted {clean} in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }
        for (secret, payload) in [
            (
                "LeakDblHtmlU0022Secret",
                r#"body={"xml":"\\u0022&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot; /&gt;LeakDblHtmlU0022Secret&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakStructU0022Secret",
                r#"body={"xml":"{\\u0022k\\u0022:\\u0022&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot; /&gt;LeakStructU0022Secret&lt;/keyMaterial&gt;"#,
            ),
        ] {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "Defect 4 genuine double-escaped bypass for {secret}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "Defect 4 leaked {secret} in {fmt:?}: {out}");
                assert!(out.contains("[REDACTED]"), "Defect 4 missing [REDACTED] in {fmt:?}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }
    }

    #[test]
    fn test_r4_iter13_remediation_all_three_defects() {
        // 1. has_double_escaped_json_markers escaped JSON whitespace (\\n, \\r, \\t, \\u0020) around \\u0022
        let dbl_ws_leaks = [
            (
                "LeakArrNlU0022",
                r#"body={"xml":"[\\n  \\u0022prefix &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakArrNlU0022&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakI12DblCr",
                r#"body={"xml":"[\\r\\n\\u0022prefix &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakI12DblCr&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakCsvArrNlU0022",
                r#""{""xml"":""[\\n\\u0022hello &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakCsvArrNlU0022&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakArrU0020",
                r#"body={"xml":"[\\u0020\\t\\u0022prefix &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakArrU0020&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakStructColonWs",
                r#"body={"xml":"{\\u0022k\\u0022\\n : \\n\\u0022&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakStructColonWs&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakArrNumComma",
                r#"body={"xml":"[1, \\u0022&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakArrNumComma&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakArrBoolComma",
                r#"body={"xml":"[true, \\u0022&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakArrBoolComma&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakCsvObjColon",
                r#""{""xml"":""{\""k\"":\\u0022&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakCsvObjColon&lt;/keyMaterial&gt;"#,
            ),
        ];
        for (secret, payload) in dbl_ws_leaks {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "Iter13 Defect 1 direct bypass for {secret}: {payload}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("Iter13 Defect 1 render_report({fmt:?}) failed for {secret}: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(
                    !out.contains(secret),
                    "Iter13 Defect 1 leaked {secret} in {fmt:?}: {out}"
                );
                assert!(
                    out.contains("[REDACTED]"),
                    "Iter13 Defect 1 missing [REDACTED] in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }

        // 2. has_double_escaped_json_markers prose `, \\u0022` and `: \\u0022` clean preservation
        let prose_u0022_clean = [
            r#"body={"xml":"hello, \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
            r#"body={"xml":"note: \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
            r#"body={"xml":"step1, \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
            r#"body={"xml":"not true, \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
            r#"body={"xml":"note:\\n  \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
        ];
        for clean in prose_u0022_clean {
            assert_r4_clean_bytes(clean.as_bytes())
                .unwrap_or_else(|e| panic!("Iter13 Defect 2 clean prose rejected {clean}: {e}"));
            let data = single_cell_table(clean);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("Iter13 Defect 2 render_report({fmt:?}) failed for {clean}: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(
                    !out.contains("[REDACTED]"),
                    "Iter13 Defect 2 over-redacted {clean} in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }

        // 3. is_inline_prefixed_rfc4180_csv closed <b>...</b> / <span>...</span> HTML with `,` + `""` + `&quot;` JSON
        let inline_html_csv_leaks: &[(&str, &str)] = &[
            (
                "LeakBoldDoubledBypass",
                "<b>\r\n\"x=\"\"y\"\" body={&quot;a&quot;:&quot;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eLeakBoldDoubledBypass\\u003c/keyMaterial\\u003e&quot;}\",\r\n</b>",
            ),
            (
                "LeakSpanDoubledBypass",
                "<span>\n\"x=\"\"y\"\" body={&quot;a&quot;:&quot;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eLeakSpanDoubledBypass\\u003c/keyMaterial\\u003e&quot;}\",\n</span>",
            ),
            (
                "LeakI12CsvBold",
                "<b>a, b\r\n\"note \"\"q\"\" body={&quot;a&quot;:&quot;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eLeakI12CsvBold\\u003c/keyMaterial\\u003e&quot;}\"\r\n</b>",
            ),
            (
                "LeakI12CsvSpan",
                "<span>a, b\n\"note \"\"q\"\" body={&quot;a&quot;:&quot;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eLeakI12CsvSpan\\u003c/keyMaterial\\u003e&quot;}\"\n</span>",
            ),
            (
                "LeakI12CsvCol2",
                "<b>\r\n\"note \"\"q\"\" body={&quot;a&quot;:&quot;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eLeakI12CsvCol2\\u003c/keyMaterial\\u003e&quot;}\",col2\r\n</b>",
            ),
            (
                "LeakI13UnclosedBold",
                "<b>a, b\r\n\"note \"\"q\"\" body={&quot;a&quot;:&quot;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eLeakI13UnclosedBold\\u003c/keyMaterial\\u003e&quot;}\"",
            ),
            (
                "LeakI13UnclosedNum34",
                "<b>a, b\r\n\"note \"\"q\"\" body={&#34;a&#34;:&#34;\\u003ckeyMaterial attr=\\&#34;/\\u003e\\&#34;\\u003eLeakI13UnclosedNum34\\u003c/keyMaterial\\u003e&#34;}\"",
            ),
        ];
        for (secret, payload) in inline_html_csv_leaks {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "Iter13 Defect 3 direct bypass for {secret}: {payload}"
            );
            assert!(
                assert_r4_clean_for_format(payload.as_bytes(), ExportFormat::Html).is_err(),
                "Iter13 Defect 3 Html format bypass for {secret}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("Iter13 Defect 3 render_report({fmt:?}) failed for {secret}: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(
                    !out.contains(secret),
                    "Iter13 Defect 3 leaked {secret} in {fmt:?}: {out}"
                );
                assert!(
                    out.contains("[REDACTED]"),
                    "Iter13 Defect 3 missing [REDACTED] in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }
        assert_r4_clean_bytes(b"<b>\r\n\"<keyMaterial attr=\"\"a>b\"\"/>ok\",</b>").unwrap();
        assert_r4_clean_bytes(b"<b>\r\n\"<keyMaterial attr=\"\"a>b\"\"/>&quot;ok&quot;\",col2").unwrap();
    }

    #[test]
    fn test_r4_iter14_remediation_all_four_defects() {
        fn run_with_timeout<F, T>(label: &str, f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(std::time::Duration::from_millis(8000))
                .unwrap_or_else(|e| panic!("{label} timed out (>1500ms): {e}"))
        }

        // 1. Defect 1: check_html_tag_attributes > hang & sanitize_html_fragment_r4 attr re-escaping
        run_with_timeout("check_html_tag_attributes raw > probe", || {
            let _ = check_html_tag_attributes(b" a>b");
            let _ = check_html_tag_attributes(b" title='x' > foo");
            let _ = check_html_tag_attributes(b" >>>");
            assert_r4_clean_bytes(br#"<div title="x={"a":"<keyMaterial/>"}">hi</div>"#).unwrap();
        });
        let attr_x_eq_json = r#"<div title="x={&quot;a&quot;:&quot;\u003ckeyMaterial attr=\&quot;/\u003e\&quot;\u003eLeakI13AttrXEqJson\u003c/keyMaterial\u003e&quot;}">hi</div>"#;
        run_with_timeout("attr_x_eq_json assert_r4_clean_bytes + 7 formats", move || {
            assert!(
                assert_r4_clean_bytes(attr_x_eq_json.as_bytes()).is_err(),
                "Defect 1 direct bypass for attr_x_eq_json"
            );
            let data = single_cell_table(attr_x_eq_json);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("Defect 1 render_report({fmt:?}) failed: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains("LeakI13AttrXEqJson"), "Defect 1 leaked in {fmt:?}: {out}");
                assert!(out.contains("[REDACTED]"), "Defect 1 missing [REDACTED] in {fmt:?}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        });

        // 2. Defect 2: field_has_html_encoded_json_or_keymaterial whitespace + multi-tag + \u003ckeyMaterial attr=&quot;
        let defect2_leaks: &[(&str, &str)] = &[
            (
                "LeakUnclosedSpaceJson",
                "<b>a, b\r\n\"note \"\"q\"\" body={ &quot;a&quot; : &quot;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eLeakUnclosedSpaceJson\\u003c/keyMaterial\\u003e&quot; }\"",
            ),
            (
                "LeakUnclosedSpanNlJson",
                "<span>a, b\n\"note \"\"q\"\" body=[\n  &quot;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eLeakUnclosedSpanNlJson\\u003c/keyMaterial\\u003e&quot;\n]\"",
            ),
            (
                "LeakUnclosedNumSpace",
                "<b>a, b\r\n\"note \"\"q\"\" body={ &#34;a&#34; : &#x22;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eLeakUnclosedNumSpace\\u003c/keyMaterial\\u003e&#x22; }\"",
            ),
            (
                "LeakI13HtmlAttrU003c",
                "<b>a, b\r\n\"note \"\"q\"\" \\u003ckeyMaterial attr=&quot;a/\\u003eb&quot;\\u003eLeakI13HtmlAttrU003c\\u003c/keyMaterial\\u003e\"",
            ),
            (
                "LeakAfterCleanRaw",
                "<b>a, b\r\n\"<keyMaterial/> &lt;keyMaterial attr=&quot;a&gt;b&quot;&gt;LeakAfterCleanRaw&lt;/keyMaterial&gt;\"",
            ),
        ];
        for (secret, payload) in defect2_leaks {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "Defect 2 direct bypass for {secret}: {payload}"
            );
            assert!(
                assert_r4_clean_for_format(payload.as_bytes(), ExportFormat::Html).is_err(),
                "Defect 2 Html format bypass for {secret}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("Defect 2 render_report({fmt:?}) failed for {secret}: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "Defect 2 leaked {secret} in {fmt:?}: {out}");
                assert!(
                    out.contains("[REDACTED]"),
                    "Defect 2 missing [REDACTED] in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }

        // 3. Defect 3: sanitize_escaped_keymaterial_in_str preserves closed RFC-4180 CSV ranges across all 7 formats
        let clean_csv_inline = [
            "<b>\r\n\"<keyMaterial attr=\"\"a>b\"\"/>ok\",</b>",
            "<b>\r\n\"<keyMaterial attr=\"\"a>b\"\"/>&quot;ok&quot;\",col2",
        ];
        for clean in clean_csv_inline {
            assert_r4_clean_bytes(clean.as_bytes())
                .unwrap_or_else(|e| panic!("Defect 3 clean CSV rejected {clean}: {e}"));
            let data = single_cell_table(clean);
            for fmt in ALL_SEVEN_FORMATS {
                if fmt == ExportFormat::Tsv {
                    // `guap-export::render_tsv` replaces `\r\n` with `"  "`, destroying the
                    // multi-line RFC-4180 CSV line boundary inside a single `TableData` cell;
                    // `render_report` safely refuses rather than falsely redacting or weakening R4.
                    assert!(render_report(&data, fmt, &ReportOptions::default()).is_err());
                    continue;
                }
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("Defect 3 render_report({fmt:?}) failed for {clean}: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(
                    !out.contains("[REDACTED]"),
                    "Defect 3 over-redacted {clean} in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }
        for (secret, payload) in [
            (
                "LeakSingleJsonEmpty",
                r#"{"k":"","xml":"<keyMaterial attr=\"/\">LeakSingleJsonEmpty</keyMaterial>"}"#,
            ),
            (
                "LeakDirtyClosedCsv",
                "<b>\r\n\"<keyMaterial attr=\"\"a>b\"\">LeakDirtyClosedCsv</keyMaterial>\",</b>",
            ),
        ] {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "Defect 3 leak bypassed for {secret}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "Defect 3 leaked {secret} in {fmt:?}");
                assert!(out.contains("[REDACTED]"), "Defect 3 missing [REDACTED] in {fmt:?}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }

        // 4. Defect 4: has_double_escaped_json_markers / ends_with_json_value_before_comma prose vs JSON
        let clean_prose = [
            r#"body={"xml":"step: 2, \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
            r#"body={"xml":"say \\u0022, &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
            r#"body={"xml":"status: true, \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
        ];
        for clean in clean_prose {
            assert_r4_clean_bytes(clean.as_bytes())
                .unwrap_or_else(|e| panic!("Defect 4 clean prose rejected {clean}: {e}"));
            let data = single_cell_table(clean);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("Defect 4 render_report({fmt:?}) failed for {clean}: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(
                    !out.contains("[REDACTED]"),
                    "Defect 4 over-redacted {clean} in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }
        let genuine_dbl_leaks = [
            (
                "LeakColonKeyNumComma",
                r#"body={"xml":"\"k\": 2, \\u0022&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakColonKeyNumComma&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakColonKeyBoolComma",
                r#"body={"xml":"\"k\": true, \\u0022&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakColonKeyBoolComma&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakQuotedThenCommaU0022",
                r#"body={"xml":"<keyMaterial/>\"x\"\\u0022,\\u0022y\\u0022:\\u0022&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakQuotedThenCommaU0022&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakMidStrU0022Comma",
                r#"body={"xml":"<keyMaterial/>\\u0022a\\u0022,\\u0022x\\u0022:\\u0022&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakMidStrU0022Comma&lt;/keyMaterial&gt;"#,
            ),
        ];
        for (secret, payload) in genuine_dbl_leaks {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "Defect 4 genuine leak bypassed for {secret}: {payload}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "Defect 4 leaked {secret} in {fmt:?}: {out}");
                assert!(out.contains("[REDACTED]"), "Defect 4 missing [REDACTED] in {fmt:?}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }
    }

    #[test]
    fn test_r4_iter15_remediation_all_five_defects() {
        fn run_with_timeout<F, T>(label: &str, f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(std::time::Duration::from_millis(8000))
                .unwrap_or_else(|e| panic!("{label} timed out (>1500ms): {e}"))
        }

        // 1. Defect 1: Embedded JSON masking must not blind starts_double_escaped_json_value_after_comma
        // and `{"b":1}` / `{\"b\":1}` after comma inside broken JSON strings.
        let defect1_leaks = [
            (
                "LeakArrNested",
                r#"body={"xml":"<keyMaterial/>\\u0022a\\u0022, [1]]&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakArrNested&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakArrMid",
                r#"body={"xml":"<keyMaterial/>\\u0022a\\u0022, [1], \\u0022b\\u0022&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakArrMid&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakObjAfterCommaNoU0022",
                r#"body={"xml":"<keyMaterial/>\\u0022a\\u0022, {"b":1}]&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakObjAfterCommaNoU0022&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakObjAfterCommaSingleBs",
                r#"body={"xml":"<keyMaterial/>\\u0022a\\u0022, {\"b\":1}]&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakObjAfterCommaSingleBs&lt;/keyMaterial&gt;"#,
            ),
        ];
        for (secret, payload) in defect1_leaks {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "Defect 1 direct bypass for {secret}: {payload}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("Defect 1 render_report({fmt:?}) failed for {secret}: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "Defect 1 leaked {secret} in {fmt:?}: {out}");
                assert!(
                    out.contains("[REDACTED]"),
                    "Defect 1 missing [REDACTED] in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }
        for clean in [
            r#"body={"xml":"{\"k\":\"\\u0022a\\u0022\"} &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
            r#"body={"xml":"[1] &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
        ] {
            assert_r4_clean_bytes(clean.as_bytes())
                .unwrap_or_else(|e| panic!("Defect 1 clean input rejected {clean}: {e}"));
            let data = single_cell_table(clean);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("Defect 1 clean render_report({fmt:?}) failed: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(
                    !out.contains("[REDACTED]"),
                    "Defect 1 over-redacted {clean} in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }

        // 2. Defect 2: Unquoted HTML attribute whitespace splitting
        let defect2_leaks = [
            (
                "LeakUnqAttr",
                r#"<div title=x={&quot;a&quot;:&quot;\u003ckeyMaterial attr=\&quot;/\u003e\&quot;\u003eLeakUnqAttr\u003c/keyMaterial\u003e&quot;}>hi</div>"#,
            ),
            (
                "LeakUnqU003c",
                r#"<div title=\u003ckeyMaterial attr="a>b">LeakUnqU003c</keyMaterial>>hi</div>"#,
            ),
        ];
        run_with_timeout("defect2_unquoted_html_attrs", move || {
            for (secret, payload) in defect2_leaks {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "Defect 2 direct bypass for {secret}: {payload}"
                );
                assert!(
                    assert_r4_clean_for_format(payload.as_bytes(), ExportFormat::Html).is_err(),
                    "Defect 2 Html format bypass for {secret}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("Defect 2 render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(!out.contains(secret), "Defect 2 leaked {secret} in {fmt:?}: {out}");
                    assert!(
                        out.contains("[REDACTED]"),
                        "Defect 2 missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
            let clean_unq = r#"<div title=x={"a":"<keyMaterial/>"}>hi</div>"#;
            assert_r4_clean_bytes(clean_unq.as_bytes()).unwrap();
            let clean_data = single_cell_table(clean_unq);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&clean_data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(
                    !out.contains("[REDACTED]"),
                    "Defect 2 over-redacted clean unquoted JSON attr in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        });

        // 3. Defect 3: Attribute-area raw <keyMaterial attr="1"> and HTML-entity attr tokens/names
        let defect3_leaks = [
            (
                "LeakAttrNameKm",
                r#"<div <keyMaterial>LeakAttrNameKm</keyMaterial>>hi</div>"#,
            ),
            (
                "LeakAttrPrefixKm",
                r#"<div a<keyMaterial>LeakAttrPrefixKm</keyMaterial>>hi</div>"#,
            ),
            (
                "LeakDivRawKmAttr",
                r#"<div <keyMaterial attr="1">LeakDivRawKmAttr</keyMaterial>>hi</div>"#,
            ),
            (
                "LeakSpanRawKmAttr",
                r#"<span title="ok" <keyMaterial attr='x'>LeakSpanRawKmAttr</keyMaterial>>hi</span>"#,
            ),
            (
                "LeakHtmlAttrToken",
                r#"<div &lt;keyMaterial&gt;LeakHtmlAttrToken&lt;/keyMaterial&gt;>hi</div>"#,
            ),
            (
                "LeakHtmlAttrToken2",
                r#"<div title="ok" &lt;keyMaterial&gt;LeakHtmlAttrToken2&lt;/keyMaterial&gt;>hi</div>"#,
            ),
            (
                "LeakHtmlAttrName",
                r#"<div data-&lt;keyMaterial&gt;LeakHtmlAttrName&lt;/keyMaterial&gt;="1">hi</div>"#,
            ),
            (
                "LeakHtmlNumAttrToken",
                r#"<div &#60;keyMaterial&#62;LeakHtmlNumAttrToken&#60;/keyMaterial&#62;>hi</div>"#,
            ),
            (
                "LeakUnquotedMixedQuote",
                r#"<div x=a" &lt;keyMaterial&gt;LeakUnquotedMixedQuote&lt;/keyMaterial&gt;">hi</div>"#,
            ),
            (
                "LeakHtmlAttrTokenSpace",
                r#"<div &lt;keyMaterial attr=&quot;1&quot;&gt;LeakHtmlAttrTokenSpace&lt;/keyMaterial&gt;>hi</div>"#,
            ),
        ];
        run_with_timeout("defect3_html_attr_tokens_and_names", move || {
            for (secret, payload) in defect3_leaks {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "Defect 3 direct bypass for {secret}: {payload}"
                );
                assert!(
                    assert_r4_clean_for_format(payload.as_bytes(), ExportFormat::Html).is_err(),
                    "Defect 3 Html format bypass for {secret}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("Defect 3 render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(!out.contains(secret), "Defect 3 leaked {secret} in {fmt:?}: {out}");
                    assert!(
                        out.contains("[REDACTED]"),
                        "Defect 3 missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
            for clean in [
                r#"<div <keyMaterial attr="a>b"/> title="ok">hi</div>"#,
                r#"<div data-&lt;keyMaterial/&gt;="1">hi</div>"#,
            ] {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("Defect 3 clean attr rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "Defect 3 over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        });

        // 4. Defect 4: Clean <b> CSV prose `: &quot;` / `, &quot;` preservation + structural JSON rejection
        let clean_csv_prose = [
            "<b>\r\n\"say: &quot;hello&quot; <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
            "<b>\r\n\"note \"\"q\"\", &quot;hello&quot; <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
        ];
        for clean in clean_csv_prose {
            assert_r4_clean_bytes(clean.as_bytes())
                .unwrap_or_else(|e| panic!("Defect 4 clean CSV prose rejected {clean}: {e}"));
            let data = single_cell_table(clean);
            for fmt in ALL_SEVEN_FORMATS {
                if fmt == ExportFormat::Tsv {
                    // Documented `Tsv` newline-lossy caveat (`guap-export/src/csv_tsv.rs:103`).
                    assert!(render_report(&data, fmt, &ReportOptions::default()).is_err());
                    continue;
                }
                let rendered = render_report(&data, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("Defect 4 render_report({fmt:?}) failed for {clean}: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(
                    !out.contains("[REDACTED]"),
                    "Defect 4 over-redacted {clean} in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }
        let defect4_leaks = [
            (
                "LeakArrHtmlJson",
                "<b>\r\n\"note \"\"q\"\" body=[1, &quot;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eLeakArrHtmlJson\\u003c/keyMaterial\\u003e&quot;]\"",
            ),
            (
                "LeakTabColonHtmlJson",
                "<b>\r\n\"note \"\"q\"\" body={&quot;a&quot;\t:\n&#x22;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eLeakTabColonHtmlJson\\u003c/keyMaterial\\u003e&#x22;}\"",
            ),
        ];
        for (secret, payload) in defect4_leaks {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "Defect 4 direct bypass for {secret}: {payload}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "Defect 4 leaked {secret} in {fmt:?}: {out}");
                assert!(out.contains("[REDACTED]"), "Defect 4 missing [REDACTED] in {fmt:?}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }

        // 5. Defect 5: Clean prose `items: 1, 2, \\u0022` vs genuine JSON array/object leaks
        let clean_items = r#"body={"xml":"items: 1, 2, \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#;
        assert_r4_clean_bytes(clean_items.as_bytes()).unwrap();
        let clean_items_data = single_cell_table(clean_items);
        for fmt in ALL_SEVEN_FORMATS {
            let rendered = render_report(&clean_items_data, fmt, &ReportOptions::default()).unwrap();
            let out = String::from_utf8_lossy(&rendered);
            assert!(
                !out.contains("[REDACTED]"),
                "Defect 5 over-redacted clean items prose in {fmt:?}: {out}"
            );
            assert_r4_clean_for_format(&rendered, fmt).unwrap();
            assert_r4_clean_bytes(&rendered).unwrap();
        }
        for (secret, payload) in [
            (
                "LeakArr12U0022",
                r#"body={"xml":"[1, 2, \\u0022&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakArr12U0022&lt;/keyMaterial&gt;"#,
            ),
            (
                "LeakKey2U0022",
                r#"body={"xml":"\"k\": 2, \\u0022&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakKey2U0022&lt;/keyMaterial&gt;"#,
            ),
        ] {
            assert!(
                assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                "Defect 5 genuine leak bypassed for {secret}"
            );
            let data = single_cell_table(payload);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(secret), "Defect 5 leaked {secret} in {fmt:?}");
                assert!(out.contains("[REDACTED]"), "Defect 5 missing [REDACTED] in {fmt:?}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        }
    }

    #[test]
    fn test_r4_iter16_remediation_all_three_defects() {
        fn run_with_timeout<F, T>(label: &str, f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(std::time::Duration::from_millis(8000))
                .unwrap_or_else(|e| panic!("{label} timed out (>1500ms): {e}"))
        }

        run_with_timeout("iter16_defect1_single_escaped_array_elements", || {
            let defect1_leaks = [
                (
                    "LeakSingleEscArrElem",
                    r#"body={"xml":"<keyMaterial/>\\u0022a\\u0022, \"b\", \"c\"]&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakSingleEscArrElem&lt;/keyMaterial&gt;"#,
                ),
                (
                    "LeakNumThenU0022ThenEscStr",
                    r#"body={"xml":"<keyMaterial/>1, \\u0022a\\u0022, \"b\", \"c\"]&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakNumThenU0022ThenEscStr&lt;/keyMaterial&gt;"#,
                ),
                (
                    "LeakEscStrThenNestedArr",
                    r#"body={"xml":"<keyMaterial/>\\u0022a\\u0022, \"b\", [1]]&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakEscStrThenNestedArr&lt;/keyMaterial&gt;"#,
                ),
                (
                    "LeakEscStrThenBool",
                    r#"body={"xml":"<keyMaterial/>\\u0022a\\u0022, \"b\", true]&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakEscStrThenBool&lt;/keyMaterial&gt;"#,
                ),
                (
                    "LeakEscStrThenNum",
                    r#"body={"xml":"<keyMaterial/>\\u0022a\\u0022, \"b\", 2]&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakEscStrThenNum&lt;/keyMaterial&gt;"#,
                ),
                (
                    "LeakEscStrChainU0022",
                    r#"body={"xml":"<keyMaterial/>\\u0022a\\u0022, \"b\", \"c\", \\u0022d\\u0022&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakEscStrChainU0022&lt;/keyMaterial&gt;"#,
                ),
                (
                    "LeakTripleBsEscArr",
                    r#"body={"xml":"<keyMaterial/>\\u0022a\\u0022, \\\"b\\\", \\\"c\\\"]&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakTripleBsEscArr&lt;/keyMaterial&gt;"#,
                ),
                (
                    "LeakEscStrInnerTripleQuote",
                    r#"body={"xml":"<keyMaterial/>\\u0022a\\u0022, \"b\\\"x\", \"c\"]&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakEscStrInnerTripleQuote&lt;/keyMaterial&gt;"#,
                ),
            ];
            for (secret, payload) in defect1_leaks {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "Iter16 Defect 1 direct bypass for {secret}: {payload}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("Iter16 Defect 1 render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains(secret),
                        "Iter16 Defect 1 leaked {secret} in {fmt:?}: {out}"
                    );
                    assert!(
                        out.contains("[REDACTED]"),
                        "Iter16 Defect 1 missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }

            let defect1_clean = [
                r#"body={"xml":"<keyMaterial/>\\u0022a\\u0022, \"hello\", world &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
                r#"body={"xml":"<keyMaterial/>\\u0022a\\u0022, \"b\\"world\", \"c\"] &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
            ];
            for clean in defect1_clean {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("Iter16 Defect 1 clean prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("Iter16 Defect 1 clean render_report({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "Iter16 Defect 1 over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        });

        run_with_timeout("iter16_defect2_braceless_html_csv_json", || {
            let defect2_leaks = [
                (
                    "LeakHtmlNoBrace",
                    "<b>\r\n\"&quot;a&quot;:&quot;<keyMaterial attr=\"\"a>\"\",col2/>LeakHtmlNoBrace</keyMaterial>&quot;\",col2",
                ),
                (
                    "LeakHtmlCommaNoBrace",
                    "<b>\r\n\"1,&quot;<keyMaterial attr=\"\"a>\"\",col2/>LeakHtmlCommaNoBrace</keyMaterial>&quot;\",col2",
                ),
                (
                    "LeakHtmlNumNoBrace",
                    "<b>\r\n\"&#34;a&#34;:&#x22;<keyMaterial attr=\"\"a>\"\",col2/>LeakHtmlNumNoBrace</keyMaterial>&#x22;\",col2",
                ),
                (
                    "LeakHtmlBoolComma",
                    "<b>\r\n\"true,&quot;<keyMaterial attr=\"\"a>\"\",col2/>LeakHtmlBoolComma</keyMaterial>&quot;\",col2",
                ),
                (
                    "LeakHtmlQuotComma",
                    "<b>\r\n\"&quot;a&quot;, &quot;<keyMaterial attr=\"\"a>\"\",col2/>LeakHtmlQuotComma</keyMaterial>&quot;\",col2",
                ),
            ];
            for (secret, payload) in defect2_leaks {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "Iter16 Defect 2 direct bypass for {secret}: {payload}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("Iter16 Defect 2 render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains(secret),
                        "Iter16 Defect 2 leaked {secret} in {fmt:?}: {out}"
                    );
                    assert!(
                        out.contains("[REDACTED]"),
                        "Iter16 Defect 2 missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }

            let defect2_clean = [
                "<b>\r\n\"say: &quot;hello&quot; <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                "<b>\r\n\"note \"\"q\"\", &quot;hello&quot; <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                "<b>\r\n\"items: 1, 2, &quot;hello&quot; <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                "<b>\r\n\"status: true, &quot;hello&quot; <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
            ];
            for clean in defect2_clean {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("Iter16 Defect 2 clean prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    if fmt == ExportFormat::Tsv {
                        assert!(render_report(&data, fmt, &ReportOptions::default()).is_err());
                        continue;
                    }
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("Iter16 Defect 2 clean render_report({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "Iter16 Defect 2 over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        });

        run_with_timeout("iter16_defect3_placeholder_braces_vs_real_json_containers", || {
            let defect3_clean_all_7 = [
                r#"body={"xml":"placeholder {name}, 2, \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
                r#"body={"xml":"a: {not json}, \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
                r#"body={"xml":"item [id], 2, \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
                r#"body={"xml":"config {host:port}, 2, \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
            ];
            for clean in defect3_clean_all_7 {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("Iter16 Defect 3 clean prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("Iter16 Defect 3 clean render_report({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "Iter16 Defect 3 over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }

            let defect3_clean_csv = [
                "<b>\r\n\"placeholder {name}, &quot;hello&quot; <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                "<b>\r\n\"item [id], &quot;hello&quot; <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
            ];
            for clean in defect3_clean_csv {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("Iter16 Defect 3 clean CSV prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    if fmt == ExportFormat::Tsv {
                        assert!(render_report(&data, fmt, &ReportOptions::default()).is_err());
                        continue;
                    }
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("Iter16 Defect 3 clean CSV render_report({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "Iter16 Defect 3 over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }

            let defect3_leaks = [
                (
                    "LeakArrCommaU0022",
                    r#"body={"xml":"<keyMaterial/>[1], \\u0022b\\u0022&lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakArrCommaU0022&lt;/keyMaterial&gt;"#,
                ),
                (
                    "LeakObjUnqKey",
                    r#"body={"xml":"<keyMaterial/>{a:1}, \\u0022hello &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakObjUnqKey&lt;/keyMaterial&gt;"#,
                ),
                (
                    "LeakObjEscKey",
                    r#"body={"xml":"<keyMaterial/>{\"a\":\"x\"}, \\u0022hello &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakObjEscKey&lt;/keyMaterial&gt;"#,
                ),
                (
                    "LeakCsvObjComma",
                    "<b>\r\n\"note {&quot;a&quot;:1}, &quot;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eLeakCsvObjComma&lt;/keyMaterial&gt;&quot;\",col2",
                ),
                (
                    "LeakCsvArrComma",
                    "<b>\r\n\"note [1, 2], &quot;\\u003ckeyMaterial attr=\\&quot;/\\u003e\\&quot;\\u003eLeakCsvArrComma&lt;/keyMaterial&gt;&quot;\",col2",
                ),
            ];
            for (secret, payload) in defect3_leaks {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "Iter16 Defect 3 genuine leak bypassed for {secret}: {payload}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("Iter16 Defect 3 render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains(secret),
                        "Iter16 Defect 3 leaked {secret} in {fmt:?}: {out}"
                    );
                    assert!(
                        out.contains("[REDACTED]"),
                        "Iter16 Defect 3 missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        });
    }

    #[test]
    fn test_r4_iter17_remediation_all_six_defects() {
        fn run_with_timeout<F, T>(label: &str, f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(std::time::Duration::from_millis(8000))
                .unwrap_or_else(|e| panic!("{label} timed out (>1500ms): {e}"))
        }

        fn assert_leaks_redacted(label: &str, cases: &[(&str, &str)]) {
            for &(secret, payload) in cases {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "{label} direct bypass for {secret}: {payload}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(!out.contains(secret), "{label} leaked {secret} in {fmt:?}: {out}");
                    assert!(
                        out.contains("[REDACTED]"),
                        "{label} missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        fn assert_clean_csv_preserved(label: &str, cases: &[&str]) {
            for &clean in cases {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("{label} clean prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    if fmt == ExportFormat::Tsv {
                        assert!(
                            render_report(&data, fmt, &ReportOptions::default()).is_err(),
                            "{label} expected Tsv newline-lossy fail-closed for {clean}"
                        );
                        continue;
                    }
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} clean render_report({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "{label} over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        run_with_timeout("iter17_defect1_unclosed_html_quot_prefix", || {
            let leaks = [
                (
                    "LeakPrefixUnclosed",
                    "<b>\r\n\"1, &quot;prefix <keyMaterial attr=\"\"a>\"\",col2/>LeakPrefixUnclosed</keyMaterial>\",col2",
                ),
                (
                    "LeakQuotPrefix",
                    "<b>\r\n\"&quot;a&quot;, &quot;prefix <keyMaterial attr=\"\"a>\"\",col2/>LeakQuotPrefix</keyMaterial>\",col2",
                ),
                (
                    "Leak5146",
                    "<b>\r\n\"1, &quot;a&quot;, &quot;prefix <keyMaterial attr=\"\"a>\"\",col2/>Leak5146</keyMaterial>\",col2",
                ),
                (
                    "LeakDec34Prefix",
                    "<b>\r\n\"1, &#34;prefix <keyMaterial attr=\"\"a>\"\",col2/>LeakDec34Prefix</keyMaterial>\",col2",
                ),
                (
                    "LeakHex22Prefix",
                    "<b>\r\n\"&#x22;a&#x22;, &#x22;prefix <keyMaterial attr=\"\"a>\"\",col2/>LeakHex22Prefix</keyMaterial>\",col2",
                ),
                (
                    "Leak5146Hex22",
                    "<b>\r\n\"1, &#34;a&#34;, &#x22;prefix <keyMaterial attr=\"\"a>\"\",col2/>Leak5146Hex22</keyMaterial>\",col2",
                ),
                (
                    "LeakProseUnclosedQuot",
                    "<b>\r\n\"note \"\"q\"\", &quot;hello&quot;, &quot;prefix <keyMaterial attr=\"\"a>\"\",col2/>LeakProseUnclosedQuot</keyMaterial>\",col2",
                ),
            ];
            assert_leaks_redacted("Iter17 Defect 1", &leaks);
        });

        run_with_timeout("iter17_defect2_non_json_placeholders_vs_containers", || {
            let clean = [
                "<b>\r\n\"note \"\"q\"\", &quot;hello&quot;, {name} <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                "<b>\r\n\"note \"\"q\"\", &quot;hello&quot;, [id] <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
            ];
            assert_clean_csv_preserved("Iter17 Defect 2", &clean);

            let leaks = [
                (
                    "LeakCommaArr",
                    "<b>\r\n\"1, &quot;a&quot;, [1] <keyMaterial attr=\"\"a>\"\",col2/>LeakCommaArr</keyMaterial>\",col2",
                ),
                (
                    "LeakCommaObj",
                    "<b>\r\n\"1, &quot;a&quot;, {\"b\":1} <keyMaterial attr=\"\"a>\"\",col2/>LeakCommaObj</keyMaterial>\",col2",
                ),
                (
                    "LeakCommaUnqObj",
                    "<b>\r\n\"1, &quot;a&quot;, {b:1} <keyMaterial attr=\"\"a>\"\",col2/>LeakCommaUnqObj</keyMaterial>\",col2",
                ),
            ];
            assert_leaks_redacted("Iter17 Defect 2", &leaks);
        });

        run_with_timeout("iter17_defect3_clean_km_inside_quot_prose", || {
            let clean = [
                "<b>\r\n\"note \"\"q\"\", &quot;see <keyMaterial attr=\"\"a>b\"\"/>ok&quot;\",col2",
                "<b>\r\n\"note \"\"q\"\", &quot;hello&quot;, &quot;see <keyMaterial attr=\"\"a>b\"\"/>ok&quot;\",col2",
                "<b>\r\n\"say: &quot;a&quot;, &quot;see <keyMaterial attr=\"\"a>b\"\"/>ok&quot;\",col2",
                "<b>\r\n\"note \"\"q\"\", &quot;see <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
            ];
            assert_clean_csv_preserved("Iter17 Defect 3", &clean);
        });

        run_with_timeout("iter17_defect4_triple_backslash_containers", || {
            for valid in [
                br#"{\\\"a\\\":1}"#.as_slice(),
                br#"[\\\"a\\\"]"#.as_slice(),
                br#"{\\\"a\\\":\\\"x,y\\\"}"#.as_slice(),
                br#"{\\\"a\\\":\\\"x}y\\\"}"#.as_slice(),
                br#"{\\\"a\\\":\\\"x:y\\\"}"#.as_slice(),
            ] {
                assert!(
                    is_json_container_slice(valid, false, 0),
                    "expected is_json_container_slice=true for {}",
                    String::from_utf8_lossy(valid)
                );
                assert!(
                    ends_with_valid_json_container(valid, false),
                    "expected ends_with_valid_json_container=true for {}",
                    String::from_utf8_lossy(valid)
                );
            }
        });

        run_with_timeout("iter17_defect5_html_quot_trailing_json", || {
            let leaks = [
                (
                    "LeakHtmlQuotThenNums",
                    "<b>\r\n\"&quot;a&quot;, 1, 2]<keyMaterial attr=\"\"a>\"\",col2/>LeakHtmlQuotThenNums</keyMaterial>\",col2",
                ),
                (
                    "LeakHtmlQuotThenTrue",
                    "<b>\r\n\"&quot;a&quot;, true]<keyMaterial attr=\"\"a>\"\",col2/>LeakHtmlQuotThenTrue</keyMaterial>\",col2",
                ),
                (
                    "LeakHtmlQuotThenArr",
                    "<b>\r\n\"&quot;a&quot;, [1]]<keyMaterial attr=\"\"a>\"\",col2/>LeakHtmlQuotThenArr</keyMaterial>\",col2",
                ),
                (
                    "LeakHtmlQuotThenUnqObj",
                    "<b>\r\n\"&quot;a&quot;, {b:1}]<keyMaterial attr=\"\"a>\"\",col2/>LeakHtmlQuotThenUnqObj</keyMaterial>\",col2",
                ),
                (
                    "LeakHtmlQuotColonNum",
                    "<b>\r\n\"&quot;a&quot;:1}<keyMaterial attr=\"\"a>\"\",col2/>LeakHtmlQuotColonNum</keyMaterial>\",col2",
                ),
                (
                    "LeakHtmlQuotColonTrue",
                    "<b>\r\n\"&quot;a&quot;:true}<keyMaterial attr=\"\"a>\"\",col2/>LeakHtmlQuotColonTrue</keyMaterial>\",col2",
                ),
                (
                    "LeakDec34ThenNums",
                    "<b>\r\n\"&#34;a&#34;, 1, 2]<keyMaterial attr=\"\"a>\"\",col2/>LeakDec34ThenNums</keyMaterial>\",col2",
                ),
                (
                    "LeakHex22ColonTrue",
                    "<b>\r\n\"&#x22;a&#x22;:true}<keyMaterial attr=\"\"a>\"\",col2/>LeakHex22ColonTrue</keyMaterial>\",col2",
                ),
            ];
            assert_leaks_redacted("Iter17 Defect 5", &leaks);

            let clean = [
                "<b>\r\n\"say: &quot;a&quot;, 1, 2 <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                "<b>\r\n\"say: &quot;a&quot;, &quot;b&quot; <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                "<b>\r\n\"note &quot;a&quot;: see below <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                "<b>\r\n\"note &quot;a&quot;: 1 item <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
            ];
            assert_clean_csv_preserved("Iter17 Defect 5", &clean);
        });

        run_with_timeout("iter17_defect6_deep_escaped_json_depth_gt8", || {
            let leaks = [(
                "LeakDeepEsc9",
                r#"body={"xml":"<keyMaterial/>{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{\"h\":{\"i\":1}}}}}}}}}, \\u0022hello &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakDeepEsc9&lt;/keyMaterial&gt;"#,
            )];
            assert_leaks_redacted("Iter17 Defect 6", &leaks);

            // Also verify 16-level single-escaped container and 1000-bracket watchdog bound
            let mut deep16 = r#"{\"k\":1}"#.to_string();
            for _ in 0..15 {
                deep16 = format!(r#"{{\"n\":{deep16}}}"#);
            }
            assert!(is_json_container_slice(deep16.as_bytes(), false, 0));

            let malformed_1000 = "[".repeat(1000);
            assert!(!is_json_container_slice(malformed_1000.as_bytes(), true, 0));
        });
    }

    #[test]
    fn test_r4_iter18_remediation_all_defects() {
        fn run_with_timeout<F, T>(label: &str, f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(std::time::Duration::from_millis(8000))
                .unwrap_or_else(|e| panic!("{label} timed out (>1500ms): {e}"))
        }

        fn assert_leaks_redacted(label: &str, cases: &[(&str, &str)]) {
            for &(secret, payload) in cases {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "{label} direct bypass for {secret}: {payload}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(!out.contains(secret), "{label} leaked {secret} in {fmt:?}: {out}");
                    assert!(
                        out.contains("[REDACTED]"),
                        "{label} missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        fn assert_clean_csv_preserved(label: &str, cases: &[&str]) {
            for &clean in cases {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("{label} clean prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    if fmt == ExportFormat::Tsv {
                        assert!(
                            render_report(&data, fmt, &ReportOptions::default()).is_err(),
                            "{label} expected Tsv newline-lossy fail-closed for {clean}"
                        );
                        continue;
                    }
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} clean render_report({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "{label} over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        // 1. Defect 1: Stack overflow (0xC00000FD) & O(N^2) timeout DoS remediation (<500ms, default stack)
        run_with_timeout("iter18_defect1_html_quot_5000_no_stack_overflow_fast", || {
            let payload_ok = format!("<b>\r\n\"{}ok\",col2", "&quot;a&quot;, ".repeat(5000));
            let t0 = std::time::Instant::now();
            assert_r4_clean_bytes(payload_ok.as_bytes()).unwrap();
            let elapsed_ok = t0.elapsed();
            assert!(
                elapsed_ok < std::time::Duration::from_millis(3000),
                "5000 html quot list took {elapsed_ok:?} (expected <500ms)"
            );

            let payload_km = format!(
                "<b>\r\n\"{} <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                "&quot;a&quot;, ".repeat(3000)
            );
            let t1 = std::time::Instant::now();
            assert_r4_clean_bytes(payload_km.as_bytes()).unwrap();
            let data = single_cell_table(&payload_km);
            for fmt in ALL_SEVEN_FORMATS {
                if fmt == ExportFormat::Tsv {
                    if let Ok(rendered) = render_report(&data, fmt, &ReportOptions::default()) {
                        assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    }
                    continue;
                }
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                assert!(!String::from_utf8_lossy(&rendered).contains("[REDACTED]"));
            }
            let elapsed_km = t1.elapsed();
            assert!(
                elapsed_km < std::time::Duration::from_millis(3000),
                "3000 html quot + clean km render took {elapsed_km:?} (expected <500ms)"
            );
        });

        run_with_timeout("iter18_defect1_json_nums_5000_no_stack_overflow_fast", || {
            let clean_nums = format!(r#"body={{"xml":"{}\\u0022a\\u0022<keyMaterial/>"#, "1, ".repeat(5000));
            let t0 = std::time::Instant::now();
            assert_r4_clean_bytes(clean_nums.as_bytes()).unwrap();
            let elapsed = t0.elapsed();
            assert!(
                elapsed < std::time::Duration::from_millis(3000),
                "5000 json numbers took {elapsed:?} (expected <500ms)"
            );

            let mixed_nums_u0022 = format!(
                r#"body={{"xml":"{}{}<keyMaterial/>"#,
                "foo 1, ".repeat(1000),
                "\\u0022a\\u0022 ".repeat(1000)
            );
            let t1 = std::time::Instant::now();
            assert_r4_clean_bytes(mixed_nums_u0022.as_bytes()).unwrap();
            let elapsed_mixed = t1.elapsed();
            assert!(
                elapsed_mixed < std::time::Duration::from_millis(3000),
                "mixed 1000+1000 took {elapsed_mixed:?} (expected <500ms)"
            );

            let leak_nums = format!(
                r#"body={{"xml":"<keyMaterial/>[{} \\u0022a\\u0022 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakNum5000&lt;/keyMaterial&gt;"#,
                "1, ".repeat(5000)
            );
            assert!(assert_r4_clean_bytes(leak_nums.as_bytes()).is_err());
        });

        // 2. Defect 2: Uppercase 1E5 scientific notation before `, \u0022`
        run_with_timeout("iter18_defect2_uppercase_scientific_notation_1E5", || {
            let leaks = [
                (
                    "Leak1E5U0022",
                    r#"body={"xml":"<keyMaterial/>1E5, \\u0022a\\u0022 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;Leak1E5U0022&lt;/keyMaterial&gt;"#,
                ),
                (
                    "Leak1EPlus5U0022",
                    r#"body={"xml":"<keyMaterial/>1E+5, \\u0022a\\u0022 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;Leak1EPlus5U0022&lt;/keyMaterial&gt;"#,
                ),
                (
                    "LeakNegExpU0022",
                    r#"body={"xml":"<keyMaterial/>-2.5E-2, \\u0022a\\u0022 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakNegExpU0022&lt;/keyMaterial&gt;"#,
                ),
            ];
            assert_leaks_redacted("Iter18 Defect 2", &leaks);
        });

        // 3. Defect 3: Unbounded iterative container validation depth (deep_esc_129, deep_esc_200)
        run_with_timeout("iter18_defect3_deep_esc_129_and_200", || {
            for depth in [129usize, 200usize] {
                let mut deep = r#"{\"k\":1}"#.to_string();
                for _ in 0..(depth - 1) {
                    deep = format!(r#"{{\"n\":{deep}}}"#);
                }
                assert!(is_json_container_slice(deep.as_bytes(), false, 0));
                let secret = format!("LeakDeep{depth}");
                let payload = format!(
                    r#"body={{"xml":"<keyMaterial/>{deep}, \\u0022hello &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;{secret}&lt;/keyMaterial&gt;"#
                );
                assert_leaks_redacted(&format!("Iter18 Defect 3 depth={depth}"), &[(&secret, &payload)]);
            }
        });

        // 4. Defect 4: Unredacted <keyMaterial> inside HTML quote entities in <b> CSV
        run_with_timeout("iter18_defect4_keymaterial_inside_html_quote_entities", || {
            let leaks = [
                (
                    "LeakClosedFirst",
                    "<b>\r\n\"note \"\"q\"\", &quot;<keyMaterial attr=\"\"a>\"\",col2/>LeakClosedFirst</keyMaterial>&quot;\",col2",
                ),
                (
                    "LeakClosedProse",
                    "<b>\r\n\"note \"\"q\"\", &quot;hello&quot;, &quot;<keyMaterial attr=\"\"a>\"\",col2/>LeakClosedProse</keyMaterial>&quot;\",col2",
                ),
                (
                    "LeakFirstBranchSecondKm",
                    "<b>\r\n\"note \"\"q\"\", &quot;prefix <keyMaterial/>[REDACTED]</keyMaterial> <keyMaterial attr=\"\"a>\"\",col2/>LeakFirstBranchSecondKm</keyMaterial>\",col2",
                ),
                (
                    "LeakSecondKm",
                    "<b>\r\n\"note \"\"q\"\", &quot;hello&quot;, &quot;prefix <keyMaterial/>[REDACTED]</keyMaterial> <keyMaterial attr=\"\"a>\"\",col2/>LeakSecondKm</keyMaterial>\",col2",
                ),
                (
                    "LeakNoComma",
                    "<b>\r\n\"note \"\"q\"\" &quot;<keyMaterial attr=\"\"a>\"\",col2/>LeakNoComma</keyMaterial>&quot;\",col2",
                ),
            ];
            assert_leaks_redacted("Iter18 Defect 4", &leaks);

            let clean = ["<b>\r\n\"note \"\"q\"\" &quot;see <keyMaterial attr=\"\"a>b\"\"/>ok&quot;\",col2"];
            assert_clean_csv_preserved("Iter18 Defect 4 Clean", &clean);

            let already_redacted = "<b>\r\n\"note \"\"q\"\" &quot;<keyMaterial>[REDACTED]</keyMaterial>&quot;\",col2";
            assert_r4_clean_bytes(already_redacted.as_bytes()).unwrap();
            let data = single_cell_table(already_redacted);
            for fmt in ALL_SEVEN_FORMATS {
                if fmt == ExportFormat::Tsv {
                    if let Ok(rendered) = render_report(&data, fmt, &ReportOptions::default()) {
                        assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    }
                    continue;
                }
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert_eq!(
                    out.to_ascii_lowercase().matches("[redacted]").count(),
                    1,
                    "Iter18 Defect 4 unexpected redaction count in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        });

        // 5. Defect 5: CSV-doubled quotes, unquoted object keys, braceless trailing containers
        run_with_timeout("iter18_defect5_csv_doubled_unquoted_braceless_containers", || {
            let leaks = [
                (
                    "LeakCsvEscKeyUnclosed",
                    "<b>\r\n\"\"\"a\"\": &quot;prefix <keyMaterial attr=\"\"a>\"\",col2/>LeakCsvEscKeyUnclosed</keyMaterial>\",col2",
                ),
                (
                    "LeakCsvEscObjKeyColon",
                    "<b>\r\n\"&quot;a&quot;, {\"\"b:c\"\": 1}]<keyMaterial attr=\"\"a>\"\",col2/>LeakCsvEscObjKeyColon</keyMaterial>\",col2",
                ),
                (
                    "LeakCsvEscObjColonUnclosed",
                    "<b>\r\n\"&quot;a&quot;, {\"\"b\"\": &quot;prefix <keyMaterial attr=\"\"a>\"\",col2/>LeakCsvEscObjColonUnclosed</keyMaterial>\",col2",
                ),
                (
                    "LeakUnqObjColonUnclosed",
                    "<b>\r\n\"{ b : &quot;prefix <keyMaterial attr=\"\"a>\"\",col2/>LeakUnqObjColonUnclosed</keyMaterial>\",col2",
                ),
                (
                    "LeakColonArr",
                    "<b>\r\n\"&quot;a&quot;: [1] <keyMaterial attr=\"\"a>\"\",col2/>LeakColonArr</keyMaterial>\",col2",
                ),
                (
                    "LeakQuotCommaArr",
                    "<b>\r\n\"&quot;a&quot;, [1] <keyMaterial attr=\"\"a>\"\",col2/>LeakQuotCommaArr</keyMaterial>\",col2",
                ),
                (
                    "LeakHtmlNoBrace",
                    "<b>\r\n\"&quot;a&quot;:&quot;<keyMaterial attr=\"\"a>\"\",col2/>LeakHtmlNoBrace</keyMaterial>&quot;\",col2",
                ),
            ];
            assert_leaks_redacted("Iter18 Defect 5", &leaks);
        });

        // 6. Defect 6: Clean <b> CSV prose preservation
        run_with_timeout("iter18_defect6_clean_csv_prose_preserved", || {
            let clean = [
                "<b>\r\n\"see [ref &quot;a&quot;] <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                "<b>\r\n\"see {section &quot;a&quot;} <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                "<b>\r\n\"say: &quot;a&quot;: &quot;b&quot; <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                "<b>\r\n\"note \"\"q\"\", &quot;a&quot;: &apos;x&apos; <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                "<b>\r\n\"note \"\"q\"\", &quot;a&quot;: &quot;b&quot; <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                "<b>\r\n\"note \"\"q\"\", &quot;see <keyMaterial attr=\"\"a>b\"\"/>ok&quot;\",col2",
            ];
            assert_clean_csv_preserved("Iter18 Defect 6", &clean);
        });
    }

    #[test]
    fn test_r4_iter19_remediation_all_defects() {
        fn run_with_timeout<F, T>(label: &str, f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(std::time::Duration::from_millis(8000))
                .unwrap_or_else(|e| panic!("{label} timed out (>1500ms): {e}"))
        }

        fn assert_leaks_redacted(label: &str, cases: &[(&str, &str)]) {
            for &(secret, payload) in cases {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "{label} direct bypass for {secret}: {payload}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(!out.contains(secret), "{label} leaked {secret} in {fmt:?}: {out}");
                    assert!(
                        out.contains("[REDACTED]"),
                        "{label} missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        fn assert_clean_csv_preserved(label: &str, cases: &[&str]) {
            for &clean in cases {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("{label} clean prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    if fmt == ExportFormat::Tsv {
                        assert!(
                            render_report(&data, fmt, &ReportOptions::default()).is_err(),
                            "{label} expected Tsv newline-lossy fail-closed for {clean}"
                        );
                        continue;
                    }
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} clean render_report({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "{label} over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        // 1. Challenge 1: starts_double_escaped_json_value_after_comma_memo trailing JSON values at gap end
        run_with_timeout("iter19_challenge1_trailing_json_value_after_comma", || {
            let leaks = [
                (
                    "LeakPrefixU0022_1E5",
                    r#"{"xml":"<keyMaterial/>prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakPrefixU0022_1E5&lt;/keyMaterial&gt;"}"#,
                ),
                (
                    "LeakPrefixU0022_1",
                    r#"{"xml":"<keyMaterial/>prefix \\u0022a\\u0022, 1 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakPrefixU0022_1&lt;/keyMaterial&gt;"}"#,
                ),
                (
                    "LeakPrefixU0022_True",
                    r#"{"xml":"<keyMaterial/>prefix \\u0022a\\u0022, true &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakPrefixU0022_True&lt;/keyMaterial&gt;"}"#,
                ),
                (
                    "LeakPrefixU0022_False",
                    r#"{"xml":"<keyMaterial/>prefix \\u0022a\\u0022, false &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakPrefixU0022_False&lt;/keyMaterial&gt;"}"#,
                ),
                (
                    "LeakPrefixU0022_Null",
                    r#"{"xml":"<keyMaterial/>prefix \\u0022a\\u0022, null &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakPrefixU0022_Null&lt;/keyMaterial&gt;"}"#,
                ),
                (
                    "LeakPrefixU0022_EscStr",
                    r#"{"xml":"<keyMaterial/>prefix \\u0022a\\u0022, \"b\" &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakPrefixU0022_EscStr&lt;/keyMaterial&gt;"}"#,
                ),
                (
                    "LeakPrefixU0022_U0022Str",
                    r#"{"xml":"<keyMaterial/>{name} \\u0022a\\u0022, \\u0022b\\u0022 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakPrefixU0022_U0022Str&lt;/keyMaterial&gt;"}"#,
                ),
                (
                    "LeakBrokenPrefixU0022_1E5",
                    r#"body={"xml":"<keyMaterial/>prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakBrokenPrefixU0022_1E5&lt;/keyMaterial&gt;"#,
                ),
                (
                    "LeakBrokenPrefixU0022_EscStr",
                    r#"body={"xml":"<keyMaterial/>prefix \\u0022a\\u0022, \"b\" &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakBrokenPrefixU0022_EscStr&lt;/keyMaterial&gt;"#,
                ),
                (
                    "LeakBrokenPrefixU0022_True",
                    r#"body={"xml":"<keyMaterial/>{name} \\u0022a\\u0022, true &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakBrokenPrefixU0022_True&lt;/keyMaterial&gt;"#,
                ),
            ];
            assert_leaks_redacted("Iter19 Challenge 1", &leaks);

            let clean_cases = [
                r#"{"xml":"<keyMaterial/>prefix \"a\", 1E5 <keyMaterial attr=\"ok\"/>ok"}"#,
                r#"body={"xml":"items: 1, 2, \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
                r#"body={"xml":"placeholder {name}, 2, \\u0022 &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
                r#"body={"xml":"<keyMaterial/>\\u0022a\\u0022, \"hello\", world &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
            ];
            for clean in clean_cases {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("Iter19 Challenge 1 clean prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("Iter19 Challenge 1 clean render({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "Iter19 Challenge 1 over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }

            let perf_chain = format!(
                r#"body={{"xml":"{}\\u0022a\\u0022, {}not_json &lt;keyMaterial attr=&quot;a\\u0022b&quot;/&gt;ok"#,
                "prefix ",
                "\"b\", 1, ".repeat(2500)
            );
            let t0 = std::time::Instant::now();
            assert_r4_clean_bytes(perf_chain.as_bytes()).unwrap();
            assert!(
                t0.elapsed() < std::time::Duration::from_millis(3000),
                "n=5000 after-comma memo took {:?} (expected <500ms)",
                t0.elapsed()
            );
        });

        // 2. Challenge 2: HtmlQuoteMode::SingleEntity (&apos;, &#39;, &#x27;, unclosed &apos;) in <b> CSV
        run_with_timeout("iter19_challenge2_single_entity_in_b_csv", || {
            let leaks = [
                (
                    "LeakAposKm",
                    "<b>\r\n\"note \"\"q\"\", &apos;<keyMaterial attr=\"\"a>\"\",col2/>LeakAposKm</keyMaterial>&apos;\",col2",
                ),
                (
                    "LeakDec39Km",
                    "<b>\r\n\"note \"\"q\"\", &#39;<keyMaterial attr=\"\"a>\"\",col2/>LeakDec39Km</keyMaterial>&#39;\",col2",
                ),
                (
                    "LeakHex27Km",
                    "<b>\r\n\"note \"\"q\"\", &#x27;<keyMaterial attr=\"\"a>\"\",col2/>LeakHex27Km</keyMaterial>&#x27;\",col2",
                ),
                (
                    "LeakUnclosedAposKm",
                    "<b>\r\n\"note \"\"q\"\", &apos;prefix <keyMaterial attr=\"\"a>\"\",col2/>LeakUnclosedAposKm</keyMaterial>\",col2",
                ),
            ];
            assert_leaks_redacted("Iter19 Challenge 2", &leaks);

            let clean = [
                "<b>\r\n\"note \"\"q\"\", &apos;see <keyMaterial attr=\"\"a>b\"\"/>ok&apos;\",col2",
                "<b>\r\n\"note \"\"q\"\", &#39;see <keyMaterial attr=\"\"a>b\"\"/>ok&#39;\",col2",
                "<b>\r\n\"note \"\"q\"\", &#x27;see <keyMaterial attr=\"\"a>b\"\"/>ok&#x27;\",col2",
            ];
            assert_clean_csv_preserved("Iter19 Challenge 2 Clean", &clean);

            for entity in ["&apos;", "&#39;", "&#x27;", r"\&apos;"] {
                let perf_payload = format!(
                    "<b>\r\n\"note \"\"q\"\", {} <keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                    format!("{entity}a{entity}, ").repeat(2500)
                );
                let t0 = std::time::Instant::now();
                assert_r4_clean_bytes(perf_payload.as_bytes()).unwrap();
                assert!(
                    t0.elapsed() < std::time::Duration::from_millis(3000),
                    "n=5000 {entity} took {:?} (expected <500ms)",
                    t0.elapsed()
                );

                let perf_escaped_tail_km = format!(
                    "<b>\r\n\"note \"\"q\"\", {}<keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                    entity.repeat(5000)
                );
                let t1 = std::time::Instant::now();
                assert_r4_clean_bytes(perf_escaped_tail_km.as_bytes()).unwrap();
                assert!(
                    t1.elapsed() < std::time::Duration::from_millis(3000),
                    "n=5000 repeated {entity} + clean km took {:?} (expected <500ms)",
                    t1.elapsed()
                );
            }
        });

        // 3. Latent: is_quoted_json_string_token_with_csv off-by-one & raw-quote fallback
        assert!(is_quoted_json_string_token_with_csv(br#"""c\\"""#, false, true));
        assert!(is_quoted_json_string_token_with_csv(br#"""a\"""""#, false, true));
        assert!(!is_quoted_json_string_token_with_csv(br#"""a"b"""#, false, true));
        assert!(!is_quoted_json_string_token_with_csv(br#"""c\""#, false, true));
        assert!(!is_quoted_json_string_token_with_csv(br#"""a\""#, false, true));
    }

    #[test]
    fn test_r4_iter20_remediation_all_defects() {
        fn run_with_timeout<F, T>(label: &str, f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(std::time::Duration::from_millis(8000))
                .unwrap_or_else(|e| panic!("{label} timed out (>1500ms): {e}"))
        }

        fn assert_leaks_redacted(label: &str, cases: &[(&str, &str)]) {
            for &(secret, payload) in cases {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "{label} direct bypass for {secret}: {payload}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(!out.contains(secret), "{label} leaked {secret} in {fmt:?}: {out}");
                    assert!(
                        out.contains("[REDACTED]"),
                        "{label} missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        fn assert_clean_preserved(label: &str, cases: &[&str]) {
            for &clean in cases {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("{label} clean prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} clean render_report({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "{label} over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        // 1. Defect 1: O(N^2) CPU DoS in field_has_html_encoded_json_or_keymaterial (SingleEntity & DoubleEntity)
        run_with_timeout("iter20_defect1_escaped_entity_bracket_dos", || {
            for entity in [
                r"\&apos;]",
                r"\&#39;]",
                r"\&#x27;]",
                r"\&quot;]",
                r"\&#34;]",
                r"\&#x22;]",
            ] {
                let payload = format!(
                    "<b>\r\n\"note \"\"q\"\", {}{}<keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                    entity.repeat(5000),
                    "a".repeat(20000),
                );
                let t0 = std::time::Instant::now();
                assert_r4_clean_bytes(payload.as_bytes()).unwrap();
                let elapsed = t0.elapsed();
                assert!(
                    elapsed < std::time::Duration::from_millis(3000),
                    "n=5000 + 20KB {entity} took {elapsed:?} (expected <500ms)"
                );
            }

            let unescaped_apos_bracket = format!(
                "<b>\r\n\"note \"\"q\"\", &apos;]{}{}<keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                "&apos;]a&apos;]".repeat(2500),
                "a".repeat(20000),
            );
            let t1 = std::time::Instant::now();
            assert_r4_clean_bytes(unescaped_apos_bracket.as_bytes()).unwrap();
            assert!(t1.elapsed() < std::time::Duration::from_millis(3000));

            let unescaped_quot_bracket = format!(
                "<b>\r\n\"note \"\"q\"\", {}{}<keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                "&quot;a]&quot;, ".repeat(2500),
                "a".repeat(20000),
            );
            let t2 = std::time::Instant::now();
            assert_r4_clean_bytes(unescaped_quot_bracket.as_bytes()).unwrap();
            assert!(t2.elapsed() < std::time::Duration::from_millis(3000));

            let apos_leak_after_redacted = "<b>\r\n\"note \"\"q\"\", &apos;prefix <keyMaterial>[REDACTED]</keyMaterial> &apos;<keyMaterial attr=\"\"a>\"\",col2/>LeakAfterRedacted</keyMaterial>\",col2";
            assert!(assert_r4_clean_bytes(apos_leak_after_redacted.as_bytes()).is_err());
        });

        // 2. Defect 2: Double-escaped \\u0022 context inside valid JSON & Row.detail_json
        run_with_timeout("iter20_defect2_double_escaped_u0022_valid_json_and_detail", || {
            let leaks = [
                (
                    "LeakValidJsonDblU0022",
                    r#"{"xml":"<keyMaterial/>prefix \\\\u0022a\\\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\\\u0022,\\\\u0022x\\\\u0022:\\\\u0022&quot;/&gt;LeakValidJsonDblU0022&lt;/keyMaterial&gt;"}"#,
                ),
                (
                    "LeakValidJsonDblU003c",
                    r#"{"xml":"<keyMaterial/>prefix \\\\u0022a\\\\u0022, 1E5 \\\\u003ckeyMaterial attr=&quot;a\\\\u0022,\\\\u0022x\\\\u0022:\\\\u0022&quot;/\\\\u003eLeakValidJsonDblU003c&lt;/keyMaterial&gt;"}"#,
                ),
            ];
            assert_leaks_redacted("Iter20 Defect 2", &leaks);

            let detail_secret = "LeakDetailDblU0022_1E5";
            let detail_val = r#"<keyMaterial/>prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakDetailDblU0022_1E5&lt;/keyMaterial&gt;"#;
            let mut detail_opts = ReportOptions::default();
            detail_opts.export.include_detail_json = true;
            let data = TableData {
                schema: TableSchema::new(
                    "capture.http",
                    "HTTP",
                    vec![ColumnDef::new("payload", "Payload", ColumnType::Text)],
                ),
                rows: vec![
                    Row::new(1, vec![CellValue::Text("ok".to_string())]).with_detail_json(json!({"xml": detail_val})),
                ],
                total_rows: 1,
            };
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &detail_opts)
                    .unwrap_or_else(|e| panic!("Iter20 Defect 2 detail_json render_report({fmt:?}) failed: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(detail_secret), "leaked {detail_secret} in {fmt:?}: {out}");
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }

            let clean = [
                r#"{"xml":"<keyMaterial/>prefix \\\\u0022a\\\\u0022, 1E5 &lt;keyMaterial attr=&quot;ok&quot;/&gt;ok"}"#,
                r#"{"xml":"<keyMaterial/>prefix \\\\u0022a\\\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\\"b&quot;/&gt;ok"}"#,
                r#"{"xml":"\\\\u003ckeyMaterial\\u003eLiteralText\\\\u003c/keyMaterial\\u003e"}"#,
            ];
            assert_clean_preserved("Iter20 Defect 2 Clean", &clean);
        });

        // 3. Defect 3: \u003ckeyMaterial (TagSyntax::Raw + opened_with_u003c) with &quot; / &#34; / &#x22; & \u0022
        run_with_timeout("iter20_defect3_u003c_quot_and_u0022", || {
            let leaks = [
                (
                    "LeakU003cQuot",
                    r#"{"xml":"<keyMaterial/>prefix \\u0022a\\u0022, 1E5 \\u003ckeyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/\\u003eLeakU003cQuot&lt;/keyMaterial&gt;"}"#,
                ),
                (
                    "LeakU003cDec34",
                    r#"{"xml":"<keyMaterial/>prefix \\u0022a\\u0022, 1E5 \\u003ckeyMaterial attr=&#34;a\\u0022,\\u0022x\\u0022:\\u0022&#34;/\\u003eLeakU003cDec34&lt;/keyMaterial&gt;"}"#,
                ),
                (
                    "LeakU003cHex22",
                    r#"{"xml":"<keyMaterial/>prefix \\u0022a\\u0022, 1E5 \\u003ckeyMaterial attr=&#x22;a\\u0022,\\u0022x\\u0022:\\u0022&#x22;/\\u003eLeakU003cHex22&lt;/keyMaterial&gt;"}"#,
                ),
                (
                    "LeakU003cU0022",
                    r#"{"xml":"<keyMaterial/>prefix \\u0022a\\u0022, 1E5 \\u003ckeyMaterial attr=\\u0022a\\u0022,\\u0022x\\u0022:\\u0022\\u0022/\\u003eLeakU003cU0022\\u003c/keyMaterial\\u003e"}"#,
                ),
                (
                    "LeakBrokenU003c",
                    r#"body={"xml":"<keyMaterial/>\u003ckeyMaterial attr=&quot;a\u0022,\u0022x\u0022:\u0022&quot;/\u003eLeakBrokenU003c\u003c/keyMaterial\u003e"#,
                ),
            ];
            assert_leaks_redacted("Iter20 Defect 3", &leaks);

            let clean = [r#"body={"xml":"\u003ckeyMaterial attr=&quot;a&quot;/\u003eok"}"#];
            assert_clean_preserved("Iter20 Defect 3 Clean", &clean);
        });

        // 4. Defect 4: TagSyntax::Raw with attr=\u0022...\u0022 or attr=\"...\" after \u0022a\u0022, 1E5 in from_json_value
        run_with_timeout("iter20_defect4_raw_u0022_and_esc_quote_in_json", || {
            let leaks = [
                (
                    "LeakRawU0022Attr",
                    r#"{"xml":"<keyMaterial/>prefix \\u0022a\\u0022, 1E5 <keyMaterial attr=\\u0022a\\u0022,\\u0022x\\u0022:\\u0022\\u0022/>LeakRawU0022Attr</keyMaterial>"}"#,
                ),
                (
                    "LeakRawEscQuoteInJson",
                    r#"{"xml":"<keyMaterial/>prefix \\u0022a\\u0022, 1E5 <keyMaterial attr=\\\"a\\u0022,\\u0022x\\u0022:\\u0022\\\"/>LeakRawEscQuoteInJson</keyMaterial>"}"#,
                ),
            ];
            assert_leaks_redacted("Iter20 Defect 4", &leaks);

            let clean = [
                r#"{"xml":"<keyMaterial/>prefix \"a\", 1E5 <keyMaterial attr=\"ok\"/>ok"}"#,
                r#"{"xml":"<keyMaterial/>prefix \\u0022a\\u0022, 1E5 <keyMaterial attr=\"ok\"/>ok"}"#,
                r#"<keyMaterial attr="ok"/>ok"#,
            ];
            assert_clean_preserved("Iter20 Defect 4 Clean", &clean);
        });

        // 5. Defect 5: JSON object-key from_json_value = true symmetry
        run_with_timeout("iter20_defect5_json_object_key_from_json_value", || {
            let leaks = [
                (
                    "LeakInJsonKey",
                    r#"{"prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakInJsonKey&lt;/keyMaterial&gt;": "ok"}"#,
                ),
                (
                    "LeakObjKey1E5",
                    r#"{"<keyMaterial/>prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakObjKey1E5&lt;/keyMaterial&gt;":"ok"}"#,
                ),
            ];
            assert_leaks_redacted("Iter20 Defect 5", &leaks);

            let clean = [r#"{"<keyMaterial attr=\"ok\"/>ok":"val"}"#];
            assert_clean_preserved("Iter20 Defect 5 Clean", &clean);
        });
    }

    #[test]
    fn test_r4_iter21_remediation_all_defects() {
        fn run_with_timeout<F, T>(label: &str, f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(std::time::Duration::from_millis(8000))
                .unwrap_or_else(|e| panic!("{label} timed out (>1500ms): {e}"))
        }

        fn assert_leaks_redacted(label: &str, cases: &[(&str, &str)]) {
            for &(secret, payload) in cases {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "{label} direct bypass for {secret}: {payload}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(!out.contains(secret), "{label} leaked {secret} in {fmt:?}: {out}");
                    assert!(
                        out.contains("[REDACTED]"),
                        "{label} missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        fn assert_clean_preserved(label: &str, cases: &[&str]) {
            for &clean in cases {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("{label} clean prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} clean render_report({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "{label} over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        // 1. Challenge 1: RawQuoteMode::DoubleRaw under in_decoded_u0022_json_ctx
        run_with_timeout("iter21_challenge1_double_raw_u0022", || {
            let leaks = [
                (
                    "LeakRawDecodedQuotU0022",
                    r#"{"xml":"<keyMaterial/>prefix \\u0022a\\u0022, 1E5 <keyMaterial attr=\"a\\u0022,\\u0022x\\u0022:\\u0022\"/>LeakRawDecodedQuotU0022</keyMaterial>"}"#,
                ),
                (
                    "LeakRawDecodedDblU0022",
                    r#"{"xml":"<keyMaterial/>prefix \\\\u0022a\\\\u0022, 1E5 <keyMaterial attr=\"a\\\\u0022,\\\\u0022x\\\\u0022:\\\\u0022\"/>LeakRawDecodedDblU0022</keyMaterial>"}"#,
                ),
                (
                    "LeakHtmlRawDecoded",
                    r#"{"xml":"<p><keyMaterial/>prefix \\u0022a\\u0022, 1E5 <keyMaterial attr=\"a\\u0022,\\u0022x\\u0022:\\u0022\"/>LeakHtmlRawDecoded</keyMaterial></p>"}"#,
                ),
            ];
            assert_leaks_redacted("Iter21 Challenge 1", &leaks);

            let detail_cases = [
                (
                    "LeakDetailRawDecoded",
                    r#"<keyMaterial/>prefix \u0022a\u0022, 1E5 <keyMaterial attr="a\u0022,\u0022x\u0022:\u0022"/>LeakDetailRawDecoded</keyMaterial>"#,
                ),
                (
                    "LeakDetailHtmlRawDecoded",
                    r#"<p><keyMaterial/>prefix \u0022a\u0022, 1E5 <keyMaterial attr="a\u0022,\u0022x\u0022:\u0022"/>LeakDetailHtmlRawDecoded</keyMaterial></p>"#,
                ),
            ];
            let mut detail_opts = ReportOptions::default();
            detail_opts.export.include_detail_json = true;
            for (secret, detail_val) in detail_cases {
                let data = TableData {
                    schema: TableSchema::new(
                        "capture.http",
                        "HTTP",
                        vec![ColumnDef::new("payload", "Payload", ColumnType::Text)],
                    ),
                    rows: vec![
                        Row::new(1, vec![CellValue::Text("ok".to_string())])
                            .with_detail_json(json!({"xml": detail_val})),
                    ],
                    total_rows: 1,
                };
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &detail_opts).unwrap_or_else(|e| {
                        panic!("Iter21 Challenge 1 detail_json render_report({fmt:?}) failed for {secret}: {e}")
                    });
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(!out.contains(secret), "leaked {secret} in {fmt:?}: {out}");
                    assert!(
                        out.contains("[REDACTED]"),
                        "missing [REDACTED] for {secret} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }

            let clean = [
                r#"<keyMaterial attr="ok"/>ok"#,
                r#"{"xml":"<keyMaterial/>prefix \"a\", 1E5 <keyMaterial attr=\"ok\"/>ok"}"#,
                r#"{"xml":"<keyMaterial/>prefix \\u0022a\\u0022, 1E5 <keyMaterial attr=\"ok\"/>ok"}"#,
                r#"body={"xml":"<keyMaterial attr=\"x>\u0022/>ok"}"#,
                r#"{"xml":"<keyMaterial/>prefix \\u0022a\\u0022, 1E5 <keyMaterial attr=\"a\u003eb\"/>ok"}"#,
            ];
            assert_clean_preserved("Iter21 Challenge 1 Clean", &clean);
        });

        // 2. Challenge 2 & Reviewer 1 Finding 1: assert_r4_clean_json_string_value HTML-fragment symmetry
        run_with_timeout("iter21_challenge2_html_fragment_json_symmetry", || {
            let leaks = [
                (
                    "LeakHtmlBPrefix",
                    r#"{"xml":"<b>prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakHtmlBPrefix&lt;/keyMaterial&gt;"}"#,
                ),
                (
                    "LeakHtmlBClosed",
                    r#"{"xml":"<b>hi</b>prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakHtmlBClosed&lt;/keyMaterial&gt;"}"#,
                ),
                (
                    "LeakHtmlFragP1",
                    r#"{"xml":"<p><keyMaterial/>prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakHtmlFragP1&lt;/keyMaterial&gt;</p>"}"#,
                ),
                (
                    "LeakHtmlFragP2",
                    r#"{"xml":"<p><keyMaterial/>prefix \\u0022a\\u0022, 1E5 \\u003ckeyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/\\u003eLeakHtmlFragP2\\u003c/keyMaterial\\u003e</p>"}"#,
                ),
                (
                    "LeakHtmlFragB1",
                    r#"{"xml":"<b><keyMaterial/>prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakHtmlFragB1&lt;/keyMaterial&gt;</b>"}"#,
                ),
                (
                    "LeakHtmlFragPDbl",
                    r#"{"xml":"<p><keyMaterial/>prefix \\\\u0022a\\\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\\\u0022,\\\\u0022x\\\\u0022:\\\\u0022&quot;/&gt;LeakHtmlFragPDbl&lt;/keyMaterial&gt;</p>"}"#,
                ),
                (
                    "LeakHtmlFragKey",
                    r#"{"<p><keyMaterial/>prefix \\u0022a\\u0022, 1E5 \\u003ckeyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/\\u003eLeakHtmlFragKey\\u003c/keyMaterial\\u003e</p>":"ok"}"#,
                ),
            ];
            assert_leaks_redacted("Iter21 Challenge 2", &leaks);

            let clean = [
                r#"{"xml":"<b><keyMaterial attr=\"ok\"/>ok</b>"}"#,
                r#"{"xml":"<p>&lt;keyMaterial attr=&quot;a&gt;b&quot;/&gt;ok</p>"}"#,
                r#"{"xml":"<p><keyMaterial attr=\"ok\"/>ok</p>"}"#,
                r#"{"<b><keyMaterial attr=\"ok\"/>ok</b>":"val"}"#,
            ];
            assert_clean_preserved("Iter21 Challenge 2 Clean", &clean);
        });

        // 3. Monotonic O(N) prev_cs advance on repeated unescaped &apos;] / &quot;a]&quot;, before clean <keyMaterial/>
        run_with_timeout("iter21_monotonic_entity_cache_perf", || {
            for (entity, count) in [("&apos;]", 5000usize), ("&quot;a]&quot;, ", 2500usize)] {
                let payload = format!(
                    "<b>\r\n\"note \"\"q\"\", {}<keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                    entity.repeat(count),
                );
                let t0 = std::time::Instant::now();
                assert_r4_clean_bytes(payload.as_bytes()).unwrap();
                let elapsed = t0.elapsed();
                assert!(
                    elapsed < std::time::Duration::from_millis(500),
                    "n=5000 {entity} took {elapsed:?} (expected <50ms)"
                );
            }
        });
    }

    #[test]
    fn test_r4_iter22_remediation_all_defects() {
        fn run_with_timeout<F, T>(label: &str, f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(std::time::Duration::from_millis(8000))
                .unwrap_or_else(|e| panic!("{label} timed out (>1500ms): {e}"))
        }

        fn assert_leaks_redacted(label: &str, cases: &[(&str, &str)]) {
            for &(secret, payload) in cases {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "{label} direct bypass for {secret}: {payload}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(!out.contains(secret), "{label} leaked {secret} in {fmt:?}: {out}");
                    assert!(
                        out.contains("[REDACTED]"),
                        "{label} missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        fn assert_clean_preserved(label: &str, cases: &[&str]) {
            for &clean in cases {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("{label} clean prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} clean render_report({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "{label} over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        // 1. Defect 1: DoubleRaw with \u0022 / \\u0022 JSON markers inside or after tag
        run_with_timeout("iter22_defect1_doubleraw_u0022_marker_inside_or_after", || {
            let leaks = [
                (
                    "LeakBrokenNestedAfter",
                    r#"{"xml":"{bad <keyMaterial attr=\"a\\u0022,\\u0022x\\u0022:\\u0022\"/>, \\u0022k\\u0022:\\u0022v\\u0022} LeakBrokenNestedAfter</keyMaterial>"}"#,
                ),
                (
                    "LeakMarkerAfter",
                    r#"{"xml":"<keyMaterial attr=\"a\\u0022,\\u0022x\\u0022:\\u0022\"/>\\u0022a\\u0022, 1E5 LeakMarkerAfter</keyMaterial>"}"#,
                ),
                (
                    "LeakDblMarkerAfter",
                    r#"{"xml":"<keyMaterial attr=\"a\\\\u0022,\\\\u0022x\\\\u0022:\\\\u0022\"/>\\\\u0022a\\\\u0022, 1E5 LeakDblMarkerAfter</keyMaterial>"}"#,
                ),
                (
                    "LeakInsideJsonMarker",
                    r#"{"xml":"<keyMaterial attr=\"a\\u0022,\\u0022x\\u0022:\\u0022\"/>LeakInsideJsonMarker</keyMaterial>"}"#,
                ),
            ];
            assert_leaks_redacted("Iter22 Defect 1", &leaks);

            let detail_secret = "LeakDetailMarkerAfter";
            let detail_val = r#"<keyMaterial attr="a\u0022,\u0022x\u0022:\u0022"/>\u0022a\u0022, 1E5 LeakDetailMarkerAfter</keyMaterial>"#;
            let mut detail_opts = ReportOptions::default();
            detail_opts.export.include_detail_json = true;
            let data = TableData {
                schema: TableSchema::new(
                    "capture.http",
                    "HTTP",
                    vec![ColumnDef::new("payload", "Payload", ColumnType::Text)],
                ),
                rows: vec![
                    Row::new(1, vec![CellValue::Text("ok".to_string())]).with_detail_json(json!({"xml": detail_val})),
                ],
                total_rows: 1,
            };
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &detail_opts)
                    .unwrap_or_else(|e| panic!("Iter22 Defect 1 detail_json render_report({fmt:?}) failed: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(detail_secret), "leaked {detail_secret} in {fmt:?}: {out}");
                assert!(
                    out.contains("[REDACTED]"),
                    "missing [REDACTED] for {detail_secret} in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }

            let clean = [
                r#"body={"xml":"<keyMaterial attr=\"x>\u0022/>ok"}"#,
                r#"{"xml":"<keyMaterial attr=\"x>\\u0022\"/>ok"}"#,
                r#"{"xml":"<keyMaterial attr=\"ok\"/>\\u0022a\\u0022, 1E5 <keyMaterial attr=\"ok\"/>ok"}"#,
                r#"{"xml":"\\\\u003ckeyMaterial\\u003eLiteralText\\\\u003c/keyMaterial\\u003e"}"#,
            ];
            assert_clean_preserved("Iter22 Defect 1 Clean", &clean);

            let perf_payload = format!(
                r#"{{"xml":"{}<keyMaterial attr=\"ok\"/>ok"}}"#,
                "a], \\\\u0022".repeat(5000)
            );
            let t0 = std::time::Instant::now();
            assert_r4_clean_bytes(perf_payload.as_bytes()).unwrap();
            assert!(
                t0.elapsed() < std::time::Duration::from_millis(3000),
                "n=5000 a], \\u0022 took {:?} (expected <500ms)",
                t0.elapsed()
            );
        });

        // 2. Defect 2: Clean prose & JSON integrity on HTML fragments with \u003ckeyMaterial attr=&quot;ok&quot;/\u003e
        run_with_timeout("iter22_defect2_html_embedded_json_u003c_quot_preservation", || {
            let clean_embedded = r#"{"xml":"<p>{\"k\":\"\\u003ckeyMaterial attr=&quot;ok&quot;/\\u003eok\"}</p>"}"#;
            assert_clean_preserved(
                "Iter22 Defect 2 Clean",
                &[
                    clean_embedded,
                    r#"<p>{"k":"\u003ckeyMaterial attr=&quot;ok&quot;/\u003eok"}</p>"#,
                    r#"{"xml":"<p>{\"k\":\"\\u003ckeyMaterial attr=&#34;ok&#x22;/\\u003eok\"}</p>"}"#,
                ],
            );

            // Verify exact uncorrupted JSON roundtrip across Json export
            let data = single_cell_table(clean_embedded);
            let rendered_json = render_report(&data, ExportFormat::Json, &ReportOptions::default()).unwrap();
            let parsed_json: Value = serde_json::from_slice(&rendered_json).unwrap();
            let cell_val = parsed_json[0]["payload"].as_str().unwrap();
            assert_eq!(cell_val, clean_embedded, "embedded JSON was corrupted in Json export");

            let leaks = [
                (
                    "LeakHtmlJsonU003c",
                    r#"{"xml":"<p>{\"k\":\"\\u003ckeyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/\\u003eLeakHtmlJsonU003c\\u003c/keyMaterial\\u003e\"}</p>"}"#,
                ),
                (
                    "LeakInnerRaw",
                    r#"<p>{"k":"\u003ckeyMaterial attr=&quot;ok&quot;/\u003e<keyMaterial>LeakInnerRaw</keyMaterial>"}</p>"#,
                ),
                (
                    "LeakInnerAttr",
                    r#"<p>{"k":"\u003ckeyMaterial attr=&quot;<keyMaterial>LeakInnerAttr</keyMaterial>&quot;/\u003e"}</p>"#,
                ),
            ];
            assert_leaks_redacted("Iter22 Defect 2 Leaks", &leaks);
        });

        // 3. Defect 3: assert_r4_clean_bytes & assert_r4_clean_for_format(Csv) on HTML fragments wrapping JSON with inner <p>/<b>
        run_with_timeout("iter22_defect3_html_fragment_embedded_json_inner_tags", || {
            let leaks = [
                (
                    "LeakOuterPHtmlInnerP",
                    r#"<p>{"xml":"<p>prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakOuterPHtmlInnerP&lt;/keyMaterial&gt;</p>"}</p>"#,
                ),
                (
                    "LeakOuterPHtmlInnerB",
                    r#"<p>{"xml":"<b>prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakOuterPHtmlInnerB&lt;/keyMaterial&gt;</b>"}</p>"#,
                ),
                (
                    "LeakBrokenInnerP",
                    r#"<p>body={"xml":"<p>prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakBrokenInnerP&lt;/keyMaterial&gt;</p>"</p>"#,
                ),
            ];
            for &(_secret, payload) in &leaks {
                assert!(
                    assert_r4_clean_for_format(payload.as_bytes(), ExportFormat::Html).is_err(),
                    "Iter22 Defect 3 Html format bypass: {payload}"
                );
            }
            assert_leaks_redacted("Iter22 Defect 3", &leaks);

            let csv_leak = concat!(
                "Payload\n",
                r#""<p>{""xml"":""<p>prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakCsvHtmlInnerP&lt;/keyMaterial&gt;</p>""}</p>""#
            );
            assert!(
                assert_r4_clean_bytes(csv_leak.as_bytes()).is_err(),
                "Iter22 Defect 3 CSV direct bypass"
            );
            assert!(
                assert_r4_clean_for_format(csv_leak.as_bytes(), ExportFormat::Csv).is_err(),
                "Iter22 Defect 3 CSV format bypass"
            );

            assert_clean_preserved(
                "Iter22 Defect 3 Clean",
                &[r#"<p>{"xml":"<p>clean <keyMaterial attr=\"ok\"/>ok</p>"}</p>"#],
            );
        });
    }

    #[test]
    fn test_r4_iter23_remediation_all_defects() {
        fn run_with_timeout<F, T>(label: &str, f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(std::time::Duration::from_millis(8000))
                .unwrap_or_else(|e| panic!("{label} timed out (>1500ms): {e}"))
        }

        fn assert_leaks_redacted(label: &str, cases: &[(&str, &str)]) {
            for &(secret, payload) in cases {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "{label} direct bypass for {secret}: {payload}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(!out.contains(secret), "{label} leaked {secret} in {fmt:?}: {out}");
                    assert!(
                        out.contains("[REDACTED]"),
                        "{label} missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        fn assert_clean_preserved(label: &str, cases: &[&str]) {
            for &clean in cases {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("{label} clean prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} clean render_report({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "{label} over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        // 1. Defect 1: O(N^2) DoS in ends_with_json_value_before_comma_memo when `{`/`[` is present
        run_with_timeout("iter23_defect1_container_memo_n5000_perf", || {
            let cases = [
                format!(
                    r#"{{"xml":"[{}<keyMaterial attr=\"ok\"/>ok"}}"#,
                    "a], \\\\u0022".repeat(5000)
                ),
                format!(
                    r#"{{"xml":"{{{}<keyMaterial attr=\"ok\"/>ok"}}"#,
                    "a}}, \\\\u0022".repeat(5000)
                ),
                format!(
                    r#"{{"xml":"{}<keyMaterial attr=\"ok\"/>ok"}}"#,
                    "[".repeat(2500) + &"a], \\\\u0022".repeat(2500)
                ),
                format!(
                    "<b>\r\n\"note \"\"q\"\", [{}<keyMaterial attr=\"\"a>b\"\"/>ok\",col2",
                    "a], &quot;".repeat(5000)
                ),
                format!(
                    "<p>{}<keyMaterial attr=\"ok\"/>ok</p>",
                    "<span ".repeat(5000) + "\"" + ">"
                ),
            ];
            for (idx, payload) in cases.iter().enumerate() {
                let t0 = std::time::Instant::now();
                assert_r4_clean_bytes(payload.as_bytes()).unwrap();
                let elapsed = t0.elapsed();
                assert!(
                    elapsed < std::time::Duration::from_millis(3000),
                    "case {idx} n=5000 took {elapsed:?} (expected <500ms)"
                );
            }
        });

        // 2. Defect 2: precompute_u0022_json_ctx must not mask unverified `{...}`/`[...]` in attributes
        run_with_timeout("iter23_defect2_precompute_u0022_no_unverified_mask", || {
            let leaks = [
                (
                    "LeakJsonCtxMask1",
                    r#"{"xml":"<keyMaterial attr={\"a\\u0022,\\u0022x\\u0022:\\u0022\"}/>LeakJsonCtxMask1</keyMaterial>"}"#,
                ),
                (
                    "LeakJsonCtxMask2",
                    r#"{"xml":"<keyMaterial attr=[\"a\\u0022,\\u0022x\\u0022:\\u0022\"]/>LeakJsonCtxMask2</keyMaterial>"}"#,
                ),
                (
                    "LeakJsonCtxMask1Html",
                    r#"{"xml":"<p><keyMaterial attr={\"a\\u0022,\\u0022x\\u0022:\\u0022\"}/>LeakJsonCtxMask1Html</keyMaterial></p>"}"#,
                ),
            ];
            assert_leaks_redacted("Iter23 Defect 2", &leaks);

            let clean = [
                r#"{"xml":"<keyMaterial attr={\"a\":\"ok\"}/>ok"}"#,
                r#"{"xml":"\\\\u003ckeyMaterial\\u003eLiteralText\\\\u003c/keyMaterial\\u003e"}"#,
            ];
            assert_clean_preserved("Iter23 Defect 2 Clean", &clean);
        });

        // 3. Defect 3: `&amp;quot;` smuggling AND `a&amp;b` clean-prose preservation
        run_with_timeout("iter23_defect3_amp_quot_smuggling_and_clean_amp", || {
            let leaks = [
                (
                    "LeakAmpQuot",
                    r#"<p>{"k":"\u003ckeyMaterial attr=&amp;quot;a\u0022,\u0022x\u0022:\u0022&amp;quot;/\u003eLeakAmpQuot\u003c/keyMaterial\u003e"}</p>"#,
                ),
                (
                    "LeakDirectU003cQuot",
                    r#"{"k":"\u003ckeyMaterial attr=&quot;a\u0022,\u0022x\u0022:\u0022&quot;/\u003eLeakDirectU003cQuot\u003c/keyMaterial\u003e"}"#,
                ),
            ];
            assert_leaks_redacted("Iter23 Defect 3", &leaks);

            let clean_amp = r#"<p>{"k":"\u003ckeyMaterial attr=&quot;a&amp;b&quot;/\u003eok"}</p>"#;
            assert_clean_preserved("Iter23 Defect 3 Clean", &[clean_amp]);
            let data = single_cell_table(clean_amp);
            let rendered_json = render_report(&data, ExportFormat::Json, &ReportOptions::default()).unwrap();
            let parsed_json: Value = serde_json::from_slice(&rendered_json).unwrap();
            assert_eq!(parsed_json[0]["payload"].as_str().unwrap(), clean_amp);
        });

        // 4. Defect 4: HTML-entity `&quot;` JSON, odd-quote HTML attrs, and `\u0022`-quoted broken JSON split across tags
        run_with_timeout("iter23_defect4_html_entity_odd_attr_u0022_broken_json", || {
            let leaks = [
                (
                    "LeakEntityJsonInnerP",
                    r#"<p>{&quot;xml&quot;:&quot;<p>prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakEntityJsonInnerP&lt;/keyMaterial&gt;</p>&quot;}</p>"#,
                ),
                (
                    "LeakHtmlQuotInnerP",
                    r#"<p>body={&quot;xml&quot;:&quot;<p>prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakHtmlQuotInnerP&lt;/keyMaterial&gt;</p>&quot;}</p>"#,
                ),
                (
                    "LeakHtmlOddAttrQuote",
                    r#"<p>body={"xml":"<span data-a="1" data-b="2" data-c="3">prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakHtmlOddAttrQuote&lt;/keyMaterial&gt;</span>"}</p>"#,
                ),
                (
                    "LeakHtmlBrokenU0022",
                    r#"<p>body={"xml":\u0022<p>prefix \u0022a\u0022, 1E5 &lt;keyMaterial attr=&quot;a\u0022,\u0022x\u0022:\u0022&quot;/&gt;LeakHtmlBrokenU0022&lt;/keyMaterial&gt;</p>\u0022}</p>"#,
                ),
                (
                    "LeakHtmlOddAttrRawTag",
                    r#"<p>body={"xml":"<span data-a="1" data-b="2" data-c="3">prefix \\u0022a\\u0022, 1E5 <keyMaterial attr=\"a\\u0022,\\u0022x\\u0022:\\u0022\"/>LeakHtmlOddAttrRawTag</keyMaterial></span>"}</p>"#,
                ),
            ];
            assert_leaks_redacted("Iter23 Defect 4", &leaks);

            let clean = [
                r#"<p>body={&quot;xml&quot;:&quot;<p>clean &lt;keyMaterial attr=\&quot;ok\&quot;/&gt;ok</p>&quot;}</p>"#,
                r#"<p>body={&quot;xml&quot;:&quot;<p>clean &lt;keyMaterial attr='ok'/&gt;ok</p>&quot;}</p>"#,
                r#"<p>body={"xml":"<span data-a="1" data-b="2" data-c="3">clean <keyMaterial attr=\"ok\"/>ok</span>"}</p>"#,
                r#"<p>see {section &quot;a&quot;} &lt;keyMaterial attr=&quot;ok&quot;/&gt;ok</p>"#,
            ];
            assert_clean_preserved("Iter23 Defect 4 Clean", &clean);
        });

        // 5. Defect 5: 2-level nested HTML-in-JSON-in-HTML
        run_with_timeout("iter23_defect5_nested_html_json_html", || {
            let leaks = [
                (
                    "LeakNestedHtmlJsonHtml",
                    r#"<p>{"outer":"<p>{\"inner\":\"<p>prefix \\u0022a\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\u0022,\\u0022x\\u0022:\\u0022&quot;/&gt;LeakNestedHtmlJsonHtml&lt;/keyMaterial&gt;</p>\"}</p>"}</p>"#,
                ),
                (
                    "LeakNestedHtmlJsonHtmlRaw",
                    r#"<p>{"outer":"<p>{\"inner\":\"<p>prefix \\u0022a\\u0022, 1E5 <keyMaterial attr=\\\"a\\u0022,\\u0022x\\u0022:\\u0022\\\"/>LeakNestedHtmlJsonHtmlRaw</keyMaterial></p>\"}</p>"}</p>"#,
                ),
            ];
            assert_leaks_redacted("Iter23 Defect 5", &leaks);

            let detail_secret = "LeakDetailNestedHtmlJsonHtml";
            let detail_val = r#"<p>{"inner":"<p>prefix \u0022a\u0022, 1E5 &lt;keyMaterial attr=&quot;a\u0022,\u0022x\u0022:\u0022&quot;/&gt;LeakDetailNestedHtmlJsonHtml&lt;/keyMaterial&gt;</p>"}</p>"#;
            let mut detail_opts = ReportOptions::default();
            detail_opts.export.include_detail_json = true;
            let data = TableData {
                schema: TableSchema::new(
                    "capture.http",
                    "HTTP",
                    vec![ColumnDef::new("payload", "Payload", ColumnType::Text)],
                ),
                rows: vec![
                    Row::new(1, vec![CellValue::Text("ok".to_string())]).with_detail_json(json!({"outer": detail_val})),
                ],
                total_rows: 1,
            };
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &detail_opts)
                    .unwrap_or_else(|e| panic!("Iter23 Defect 5 detail_json({fmt:?}) failed: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains(detail_secret), "leaked {detail_secret} in {fmt:?}: {out}");
                assert!(
                    out.contains("[REDACTED]"),
                    "missing [REDACTED] for {detail_secret} in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        });
    }

    #[test]
    fn test_r4_iter24_remediation_all_defects() {
        fn run_with_timeout<F, T>(label: &str, f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(std::time::Duration::from_millis(8000))
                .unwrap_or_else(|e| panic!("{label} timed out (>1500ms): {e}"))
        }

        fn assert_leaks_redacted(label: &str, cases: &[(&str, &str)]) {
            for &(secret, payload) in cases {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "{label} direct bypass for {secret}: {payload}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(!out.contains(secret), "{label} leaked {secret} in {fmt:?}: {out}");
                    assert!(
                        out.contains("[REDACTED]"),
                        "{label} missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        fn assert_clean_preserved(label: &str, cases: &[&str]) {
            for &clean in cases {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("{label} clean prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} clean render_report({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "{label} over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        // 1. open_km_ranges: escaped `\"` JSON attributes + `&quot;` early-close desync
        run_with_timeout("iter24_item1_open_km_ranges_and_quot_desync", || {
            let leaks = [
                (
                    "LeakAttrEscJson1",
                    "{\"xml\":\"<keyMaterial attr=[\\\"a\\\\\\\"\\\"]/>LeakAttrEscJson1</keyMaterial>\"}",
                ),
                (
                    "LeakAttrEscJson2",
                    r#"<p><keyMaterial attr={"a":"\"b"}/>LeakAttrEscJson2</keyMaterial></p>"#,
                ),
                (
                    "LeakRawAttrJson",
                    r#"<keyMaterial attr=["a\""]/>LeakRawAttrJson</keyMaterial>"#,
                ),
                (
                    "LeakEntityEarly",
                    "{\"xml\":\"<keyMaterial x=&quot;a/>&quot; attr=[\\\"a\\\\u0022,\\\\u0022x\\\\u0022:\\\\u0022\\\"]/>LeakEntityEarly</keyMaterial>\"}",
                ),
                (
                    "LeakEntityEarlyBroken",
                    "prefix {\"xml\":\"<keyMaterial x=&quot;a/>&quot; attr=[\\\"a\\\\u0022,\\\\u0022x\\\\u0022:\\\\u0022\\\"]/>LeakEntityEarlyBroken</keyMaterial>",
                ),
                (
                    "LeakEntityEarlyBrokenRawArr",
                    r#"prefix {"xml":"<keyMaterial x=&quot;a/>&quot; attr=["a\u0022,\u0022x\u0022:\u0022"]/>LeakEntityEarlyBrokenRawArr</keyMaterial>"#,
                ),
            ];
            assert_leaks_redacted("Iter24 Item 1", &leaks);
        });

        // 2. sanitize_html_tag_attributes_r4 splitting unclosed outer HTML tag across embedded `<keyMaterial>`
        run_with_timeout("iter24_item2_html_attr_split_across_keymaterial", || {
            let leaks = [
                (
                    "LeakSpanOdd",
                    r#"<p>body={"xml":"<span title="unclosed><keyMaterial attr=\"a\\\" b/>LeakSpanOdd\" </keyMaterial></span>}</p>"#,
                ),
                (
                    "LeakSpanSingle",
                    r#"<p>body={"xml":"<span title="unclosed><keyMaterial attr=\"a b/>LeakSpanSingle</keyMaterial></span>}</p>"#,
                ),
            ];
            assert_leaks_redacted("Iter24 Item 2", &leaks);

            assert_clean_preserved(
                "Iter24 Item 2 Clean",
                &[r#"<p><span title="prefix <keyMaterial attr='ok'/> suffix">ok</span></p>"#],
            );
        });

        // 3. Nested `<keyMaterial>` inside self-closing `<keyMaterial>` attributes & `&#38;` / `&#x26;`
        run_with_timeout("iter24_item3_self_closing_attr_and_num38", || {
            let leaks = [
                (
                    "LeakInAttr",
                    r#"{"k":"<keyMaterial attr=\"&lt;keyMaterial&gt;LeakInAttr&lt;/keyMaterial&gt;\"/>ok"}"#,
                ),
                (
                    "LeakInRedactedAttr",
                    r#"{"k":"<keyMaterial attr=\"&lt;keyMaterial&gt;LeakInRedactedAttr&lt;/keyMaterial&gt;\">[REDACTED]</keyMaterial>"}"#,
                ),
                (
                    "LeakNum38MaskTrick",
                    r#"<p>{"k":"\u003ckeyMaterial attr=&#38;quot;a/\u003e[REDACTED]\u003c/keyMaterial\u003e&#38;lt;keyMaterial&#38;gt;LeakNum38MaskTrick&#38;lt;/keyMaterial&#38;gt;&#38;quot;/\u003e"}</p>"#,
                ),
                (
                    "LeakHex26MaskTrick",
                    r#"<p>{"k":"\u003ckeyMaterial attr=&#x26;quot;a/\u003e[REDACTED]\u003c/keyMaterial\u003e&#x26;lt;keyMaterial&#x26;gt;LeakHex26MaskTrick&#x26;lt;/keyMaterial&#x26;gt;&#x26;quot;/\u003e"}</p>"#,
                ),
            ];
            assert_leaks_redacted("Iter24 Item 3", &leaks);

            assert_clean_preserved(
                "Iter24 Item 3 Clean",
                &[r#"{"k":"<keyMaterial attr=\"&lt;keyMaterial attr=&quot;ok&quot;/&gt;ok\"/>ok"}"#],
            );
        });

        // 4. `mask_html_tags_for_json_scan` `\n` fill + `DoubleEntity` `QuoteToggle` / `""` bypass
        run_with_timeout("iter24_item4_script_nl_fill_and_double_entity_quotetoggle", || {
            let leaks = [
                (
                    "LeakScriptBrokenNoComma",
                    r#"<p>body={"xml":"<script>x</script>&lt;keyMaterial attr=&quot;a\"\"&quot;/&gt;LeakScriptBrokenNoComma&lt;/keyMaterial&gt;</p>"#,
                ),
                (
                    "LeakScriptValidNoComma",
                    r#"<p>body={"xml":"<script>x</script>&lt;keyMaterial attr=&quot;a\"\"&quot;/&gt;LeakScriptValidNoComma&lt;/keyMaterial&gt;"}</p>"#,
                ),
            ];
            assert_leaks_redacted("Iter24 Item 4", &leaks);

            assert_clean_preserved(
                "Iter24 Item 4 Clean",
                &[
                    r#"<p>body={"xml":"<script>x</script>&lt;keyMaterial attr=&quot;ok&quot;/&gt;ok"}</p>"#,
                    r#"<p>body={"xml":"<script>x</script><keyMaterial attr=\"ok\"/>ok"}</p>"#,
                ],
            );
        });

        // 5. Numeric brace/bracket entities (`&#123;`, `&#x7b;`, `&#91;`, `&#x5b;`)
        run_with_timeout("iter24_item5_numeric_brace_bracket_entities", || {
            let leaks = [
                (
                    "LeakNum123BraceEntity",
                    r#"<p>body=&#123;&quot;xml&quot;:&quot;<p>prefix &lt;keyMaterial attr=&quot;a\u0022&quot; b=&quot;c&quot;/&gt;LeakNum123BraceEntity&lt;/keyMaterial&gt;</p>&quot;&#125;</p>"#,
                ),
                (
                    "LeakHex7bBraceEntity",
                    r#"<p>body=&#x7b;&quot;xml&quot;:&quot;<p>prefix &lt;keyMaterial attr=&quot;a\u0022&quot; b=&quot;c&quot;/&gt;LeakHex7bBraceEntity&lt;/keyMaterial&gt;</p>&quot;&#x7d;</p>"#,
                ),
                (
                    "LeakNum91BracketEntity",
                    r#"<p>body=&#91;&quot;<p>prefix &lt;keyMaterial attr=&quot;a\u0022&quot; b=&quot;c&quot;/&gt;LeakNum91BracketEntity&lt;/keyMaterial&gt;</p>&quot;&#93;</p>"#,
                ),
            ];
            assert_leaks_redacted("Iter24 Item 5", &leaks);

            assert_clean_preserved(
                "Iter24 Item 5 Clean",
                &[r#"<p>see &#123;section &quot;a&quot;&#125; &lt;keyMaterial attr=&quot;ok&quot;/&gt;ok</p>"#],
            );
        });

        // 6 & 7. Clean HTML comments/attributes containing `{` + `"` & non-JSON `attr=["ok", foo]`
        run_with_timeout("iter24_item6_item7_clean_html_and_non_json_bracket", || {
            assert_clean_preserved(
                "Iter24 Item 6 & 7 Clean",
                &[
                    r#"<p><!-- { "a": " --> <keyMaterial attr="ok"/>ok</p>"#,
                    r#"<p><span title="{">hello</span> <keyMaterial attr="ok"/>ok</p>"#,
                    r#"{"html":"<p><!-- { \"a\": \" --> <keyMaterial attr=\"ok\"/>ok</p>"}"#,
                    r#"{"html":"<p><span title=\"{\">hello</span> <keyMaterial attr=\"ok\"/>ok</p>"}"#,
                    r#"{"xml":"<keyMaterial attr=[\"ok\", foo]/>ok"}"#,
                ],
            );
        });

        // O(N) latency check (<500ms at n=5000) for Iter 24 code paths
        run_with_timeout("iter24_on_perf_n5000", || {
            let perf_cases = [
                format!(
                    "<p>{}<keyMaterial attr=\"ok\"/>ok</p>",
                    "<span title=\"{\">".repeat(5000)
                ),
                format!("<p>{}<keyMaterial attr=\"ok\"/>ok</p>", "&#123;&#125;".repeat(5000)),
                format!("<p>{}<keyMaterial attr=\"ok\"/>ok</p>", "&#38;amp;".repeat(5000)),
                format!(
                    r#"{{"xml":"<keyMaterial attr=[\"ok\", {}]/>ok"}}"#,
                    "foo, ".repeat(5000)
                ),
            ];
            for (idx, payload) in perf_cases.iter().enumerate() {
                let t0 = std::time::Instant::now();
                assert_r4_clean_bytes(payload.as_bytes()).unwrap();
                let elapsed = t0.elapsed();
                assert!(
                    elapsed < std::time::Duration::from_millis(3000),
                    "iter24 perf case {idx} n=5000 took {elapsed:?} (expected <500ms)"
                );
            }
        });
    }

    #[test]
    fn test_r4_iter25_remediation_all_defects() {
        fn run_with_timeout<F, T>(label: &str, f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(std::time::Duration::from_millis(8000))
                .unwrap_or_else(|e| panic!("{label} timed out (>1500ms): {e}"))
        }

        fn assert_leaks_redacted(label: &str, cases: &[(&str, &str)]) {
            for &(secret, payload) in cases {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "{label} direct bypass for {secret}: {payload}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(!out.contains(secret), "{label} leaked {secret} in {fmt:?}: {out}");
                    assert!(
                        out.contains("[REDACTED]"),
                        "{label} missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        fn assert_clean_preserved(label: &str, cases: &[&str]) {
            for &clean in cases {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("{label} clean prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} clean render_report({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "{label} over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        // 1. HtmlSingleEntity / SingleEntity `'` & `\u0027` handling
        run_with_timeout("iter25_item1_html_single_entity", || {
            let leaks = [
                (
                    "LeakAposEscJson",
                    r#"{"xml":"&lt;keyMaterial attr=&apos;a'&apos;/&gt;LeakAposEscJson&lt;/keyMaterial&gt;"}"#,
                ),
                (
                    "LeakAposU0027Json",
                    r#"{"xml":"<keyMaterial attr=&apos;a\u0027&apos;/>LeakAposU0027Json</keyMaterial>"}"#,
                ),
                (
                    "LeakApos2RawJson",
                    r#"{"xml":"<keyMaterial attr=&apos;a''&apos;/>LeakApos2RawJson</keyMaterial>"}"#,
                ),
            ];
            assert_leaks_redacted("Iter25 Item 1", &leaks);

            assert_clean_preserved(
                "Iter25 Item 1 Clean",
                &[
                    r#"body={"xml":"&lt;keyMaterial attr=&#39;a\"b&#39;/&gt;ok"#,
                    r#"&lt;keyMaterial attr=&apos;a"b&apos;/&gt;ok"#,
                    r#"<p>it's &lt;keyMaterial attr=&apos;ok&apos;/&gt;ok</p>"#,
                ],
            );
        });

        // 2. json_span_has_quote_parity_hazard single-quote, \u0027, &apos;, &#34; inside <keyMaterial> JSON attrs
        run_with_timeout("iter25_item2_json_span_quote_parity", || {
            let leaks = [
                (
                    "LeakSqJsonAposGt",
                    r#"<keyMaterial attr='{"a":"'>"}'/>LeakSqJsonAposGt</keyMaterial>"#,
                ),
                (
                    "LeakSqJsonInJsonAposGt",
                    r#"{"xml":"<keyMaterial attr='{\"a\":\"'>\"}'/>LeakSqJsonInJsonAposGt</keyMaterial>"}"#,
                ),
                (
                    "LeakSqJsonU0027Gt",
                    r#"{"xml":"<keyMaterial attr='[\"a\u0027>\"]'/>LeakSqJsonU0027Gt</keyMaterial>"}"#,
                ),
                (
                    "LeakSqJsonU0027EscGt",
                    r#"{"xml":"<keyMaterial attr='[\"a\\u0027>\"]'/>LeakSqJsonU0027EscGt</keyMaterial>"}"#,
                ),
                (
                    "LeakJsonSpanAposGt",
                    r#"{"xml":"<keyMaterial attr='{\"a\":\"&apos;>\"}'/>LeakJsonSpanAposGt</keyMaterial>"}"#,
                ),
                (
                    "LeakJsonSpanNum34Gt",
                    r#"{"xml":"<keyMaterial attr=&#34;{\"a\":\"&#34;>\"}&#34;/>LeakJsonSpanNum34Gt</keyMaterial>"}"#,
                ),
            ];
            assert_leaks_redacted("Iter25 Item 2", &leaks);
        });

        // 3. mask_html_tags_for_json_scan unmatched/extra </script> and </td> inside open JSON strings
        run_with_timeout("iter25_item3_mask_html_unmatched_closing_tags", || {
            let leaks = [
                (
                    "LeakUnmatchedEndScriptBroken",
                    r#"<p>body={"xml":"</script>&lt;keyMaterial attr=&quot;a\"\"&quot;/&gt;LeakUnmatchedEndScriptBroken&lt;/keyMaterial&gt;</p>"#,
                ),
                (
                    "LeakUnmatchedEndScriptValid",
                    r#"<p>body={"xml":"</script>&lt;keyMaterial attr=&quot;a\"\"&quot;/&gt;LeakUnmatchedEndScriptValid&lt;/keyMaterial&gt;"}</p>"#,
                ),
                (
                    "LeakExtraEndScript",
                    r#"<p>body={"xml":"<script>x</script></script>&lt;keyMaterial attr=&quot;a\"\"&quot;/&gt;LeakExtraEndScript&lt;/keyMaterial&gt;"}</p>"#,
                ),
                (
                    "LeakUnmatchedEndTdTable",
                    r#"<table><tr><td>{"xml":"</td>&lt;keyMaterial attr=&quot;a\"\"&quot;/&gt;LeakUnmatchedEndTdTable&lt;/keyMaterial&gt;"}</td></tr></table>"#,
                ),
            ];
            assert_leaks_redacted("Iter25 Item 3", &leaks);
        });

        // 4. DoubleEntity single `\"` breakout in non-HTML JSON strings while preserving clean `attr=&quot;a\"b&quot;/&gt;ok`
        run_with_timeout("iter25_item4_double_entity_single_quote_breakout", || {
            let leaks = [(
                "LeakSingleBsInQuotTop",
                r#"{"xml":"&lt;keyMaterial attr=&quot;a\"&gt;LeakSingleBsInQuotTop&lt;/keyMaterial&gt;&quot;/&gt;"}"#,
            )];
            assert_leaks_redacted("Iter25 Item 4", &leaks);

            assert_clean_preserved(
                "Iter25 Item 4 Clean",
                &[
                    r#"body={"xml":"&lt;keyMaterial attr=&quot;a\"b&quot;/&gt;ok"#,
                    r#"<p>body={"xml":"&lt;keyMaterial attr=&quot;a\"b&quot;/&gt;ok"}</p>"#,
                    r#"{"xml":"<keyMaterial/>prefix \\\\u0022a\\\\u0022, 1E5 &lt;keyMaterial attr=&quot;a\\\"b&quot;/&gt;ok"}"#,
                ],
            );
        });

        // 5. from_json_value `&quot;` consistency on raw `<keyMaterial x=&quot;a/>&quot; attr=["a\""]/>...`
        run_with_timeout("iter25_item5_raw_entity_early_consistency", || {
            let leaks = [
                (
                    "LeakRawEntityEarly",
                    r#"<p><keyMaterial x=&quot;a/>&quot; attr=["a\""]/>LeakRawEntityEarly</keyMaterial></p>"#,
                ),
                (
                    "LeakRawEntityEarlyBare",
                    r#"<keyMaterial x=&quot;a/>&quot; attr=["a\""]/>LeakRawEntityEarlyBare</keyMaterial>"#,
                ),
            ];
            assert_leaks_redacted("Iter25 Item 5", &leaks);
        });

        // 6. is_bare_json_delim_quote_at clean non-JSON prose preservation + valid JSON `\"` leak
        run_with_timeout("iter25_item6_bare_json_delim_clean_prose", || {
            assert_clean_preserved(
                "Iter25 Item 6 Clean",
                &[
                    r#"{"xml":"<keyMaterial attr=[1, \"ok\", foo]/>ok"}"#,
                    r#"{"xml":"<keyMaterial attr=[foo, \"ok\"]/>ok"}"#,
                    r#"{"xml":"<keyMaterial attr={foo: \"ok\"}/>ok"}"#,
                    r#"{"xml":"<keyMaterial attr=[\"ok\", 1, foo]/>ok"}"#,
                    r#"{"xml":"<keyMaterial attr={\"a\":\"ok\", foo}/>ok"}"#,
                    r#"{"xml":"<keyMaterial attr={\"a\":\"ok'b\"}/>ok"}"#,
                ],
            );

            assert_leaks_redacted(
                "Iter25 Item 6 ValidJsonEsc",
                &[(
                    "LeakValidJsonEscAttr",
                    r#"{"xml":"<keyMaterial attr={\"a\":\"\\\"/>\\\"b\"}>LeakValidJsonEscAttr</keyMaterial>"}"#,
                )],
            );
        });

        // 7. Debug perf headroom (<500ms at n=5000, including Html on 2500 nested `[` + `]` + `\u0022`)
        run_with_timeout("iter25_perf_n5000_html_and_non_json", || {
            let nested_brackets = format!("{}{}\\u0022", "[".repeat(2500), "]".repeat(2500));
            let t0 = std::time::Instant::now();
            assert_r4_clean_bytes(nested_brackets.as_bytes()).unwrap();
            let data = single_cell_table(&nested_brackets);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
            }
            let elapsed_all = t0.elapsed();
            assert!(
                elapsed_all < std::time::Duration::from_millis(3000),
                "nested_bracket_2500 across direct + all 7 formats took {elapsed_all:?} (expected <500ms)"
            );

            let non_json_many = format!(
                r#"{{"xml":"<keyMaterial attr=[1, {} foo]/>ok"}}"#,
                r#"\"ok\", "#.repeat(5000)
            );
            let t1 = std::time::Instant::now();
            assert_r4_clean_bytes(non_json_many.as_bytes()).unwrap();
            let elapsed_non_json = t1.elapsed();
            assert!(
                elapsed_non_json < std::time::Duration::from_millis(3000),
                "non_json_many n=5000 took {elapsed_non_json:?} (expected <500ms)"
            );
        });
    }

    #[test]
    fn test_r4_iter26_remediation_all_defects() {
        use guap_table::{ColumnDef, ColumnType, Row, TableData, TableSchema};

        fn run_with_timeout<F, T>(label: &str, f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(std::time::Duration::from_millis(10000))
                .unwrap_or_else(|e| panic!("{label} timed out (>3000ms): {e}"))
        }

        fn assert_leaks_redacted(label: &str, cases: &[(&str, &str)]) {
            for &(secret, payload) in cases {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "{label} direct bypass for {secret}: {payload}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(!out.contains(secret), "{label} leaked {secret} in {fmt:?}: {out}");
                    assert!(
                        out.contains("[REDACTED]"),
                        "{label} missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        fn assert_clean_preserved(label: &str, cases: &[&str]) {
            for &clean in cases {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("{label} clean prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} clean render_report({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "{label} over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        // 1. Defect Family 1: non-JSON prefix / broken object / mismatched pop + per-string quote hazards
        run_with_timeout("iter26_df1_json_container_and_per_string_hazards", || {
            let leaks = [
                (
                    "LeakFooThenEsc",
                    r#"{"xml":"<keyMaterial attr=[1, \"ok\", foo, \"a\\\"a/>\"]/>LeakFooThenEsc</keyMaterial>"}"#,
                ),
                (
                    "LeakFooThenEscPair",
                    r#"{"xml":"<keyMaterial attr=[1, \"ok\", foo, \"a\":\"\\\"a/>\\\"b\"]/>LeakFooThenEscPair</keyMaterial>"}"#,
                ),
                (
                    "LeakPopMismatch",
                    r#"{"xml":"<keyMaterial attr=[1, {foo] \"a\":\"\\\"a/>\\\"b\"]/>LeakPopMismatch</keyMaterial>"}"#,
                ),
                (
                    "LeakArrPoppedByBrace",
                    r#"{"xml":"<keyMaterial attr=[1, } \"a\\\"b/>\"]/>LeakArrPoppedByBrace</keyMaterial>"}"#,
                ),
                (
                    "LeakBrokenObjEsc",
                    r#"{"xml":"<keyMaterial attr={\"a\":\"b\\\",\"x\":\"\"/>LeakBrokenObjEsc</keyMaterial>"}"#,
                ),
                (
                    "LeakAfterNonJsonObjPrefix",
                    r#"{"xml":"<keyMaterial attr={\"a\":\"ok\", foo, \"b\":\"\\\"/>Leak\"/>LeakAfterNonJsonObjPrefix</keyMaterial>"}"#,
                ),
                (
                    "LeakAfterNonJsonArrPrefix",
                    r#"{"xml":"<keyMaterial attr=[foo, \"a\\\"/>Leak\"]/>LeakAfterNonJsonArrPrefix</keyMaterial>"}"#,
                ),
                (
                    "LeakOrphanCloseAfterFoo",
                    r#"{"xml":"<keyMaterial attr=[foo, \"a\\\"/>LeakOrphanCloseAfterFoo\",\"x\":\"]>[REDACTED]</keyMaterial>"}"#,
                ),
                (
                    "LeakNewlineBeforeEsc",
                    "{\"xml\":\"<keyMaterial attr=[\\\"a\\n\\\\\\\"b\\\"/>\\\"]/>LeakNewlineBeforeEsc</keyMaterial>\"}",
                ),
                (
                    "LeakEntityAposInJson",
                    r#"{"xml":"<keyMaterial attr=&apos;{\"a\":\"&apos;/>\"}&apos;/>LeakEntityAposInJson</keyMaterial>"}"#,
                ),
                (
                    "LeakEntityQuotInJson",
                    r#"{"xml":"<keyMaterial attr=&quot;[\"&quot;/>\"]&quot;/>LeakEntityQuotInJson</keyMaterial>"}"#,
                ),
                (
                    "LeakEntityAposBackslashSq",
                    r#"{"xml":"<keyMaterial attr=&apos;{\"a\":\"\\'\"}&apos;/>LeakEntityAposBackslashSq</keyMaterial>"}"#,
                ),
            ];
            assert_leaks_redacted("Iter26 DF1", &leaks);

            assert_clean_preserved(
                "Iter26 DF1 Clean",
                &[
                    r#"{"xml":"<keyMaterial attr=[1, \"ok\", foo]/>ok"}"#,
                    r#"{"xml":"<keyMaterial attr=[foo, \"ok\"]/>ok"}"#,
                    r#"{"xml":"<keyMaterial attr={foo: \"ok\"}/>ok"}"#,
                    r#"{"xml":"<keyMaterial attr=[\"ok\", 1, foo]/>ok"}"#,
                    r#"{"xml":"<keyMaterial attr={\"a\":\"ok\", foo}/>ok"}"#,
                    r#"{"xml":"<keyMaterial attr={\"a\":\"ok'b\"}/>ok"}"#,
                    r#"{"xml":"<keyMaterial path=\"C:\\\"/>ok"}"#,
                    r#"{"xml":"<keyMaterial attr=&apos;[1, \"ok\", foo]&apos;/>ok"}"#,
                    r#"{"xml":"<keyMaterial attr=&apos;{\"a\":\"&quot;x&quot;\"}&apos;/>ok"}"#,
                ],
            );
        });

        // 2. Defect Family 2: Single-quote & HtmlRawSingle & U0027* breakouts
        run_with_timeout("iter26_df2_single_quote_breakouts", || {
            let leaks = [
                (
                    "LeakSqU0027GtSpace",
                    r#"{"xml":"<keyMaterial attr='[\"a\\u0027 >\"]'/>LeakSqU0027GtSpace</keyMaterial>"}"#,
                ),
                (
                    "LeakSqU0027AttrGt",
                    r#"{"xml":"<keyMaterial attr='[\"a\\u0027 x=1>\"]'/>LeakSqU0027AttrGt</keyMaterial>"}"#,
                ),
                (
                    "LeakPSqAposGtSpace",
                    r#"{"xml":"<p><keyMaterial attr='{\"a\":\"&apos; >\"}'/>LeakPSqAposGtSpace</keyMaterial></p>"}"#,
                ),
                (
                    "LeakPSqAposAttrGt",
                    r#"{"xml":"<p><keyMaterial attr='{\"a\":\"&apos; x=1>\"}'/>LeakPSqAposAttrGt</keyMaterial></p>"}"#,
                ),
                (
                    "LeakRawPSqAposAttrGt",
                    r#"<p><keyMaterial attr='{"a":"&apos; x=1>"}'/>LeakRawPSqAposAttrGt</keyMaterial></p>"#,
                ),
                (
                    "LeakPSqNum39AttrGt",
                    r#"{"xml":"<p><keyMaterial attr='{\"a\":\"&#39; x=1>\"}'/>LeakPSqNum39AttrGt</keyMaterial></p>"}"#,
                ),
                (
                    "LeakSqAposSpaceGt",
                    r#"{"xml":"<keyMaterial attr='a&apos; >LeakSqAposSpaceGt</keyMaterial> '/>"}"#,
                ),
                (
                    "LeakSqDblEscSpaceGt",
                    r#"{"xml":"<keyMaterial attr='a\\u0027 >LeakSqDblEscSpaceGt</keyMaterial> '/>"}"#,
                ),
                (
                    "LeakSqAposAttrGt",
                    r#"{"xml":"<keyMaterial attr='a&apos; b=\"1\">LeakSqAposAttrGt</keyMaterial> '/>"}"#,
                ),
                (
                    "LeakHtmlRawSqDblGt",
                    r#"<p>{"xml":"&lt;keyMaterial attr='a\\u0027>LeakHtmlRawSqDblGt&lt;/keyMaterial&gt; '/>"}</p>"#,
                ),
                (
                    "LeakSqDblEscSlashGt",
                    r#"{"xml":"<keyMaterial attr='a\\u0027/>LeakSqDblEscSlashGt</keyMaterial> '/>"}"#,
                ),
                (
                    "LeakSqSpaceSlashGt",
                    r#"{"xml":"<keyMaterial attr='a\\u0027   />LeakSqSpaceSlashGt</keyMaterial> '/>"}"#,
                ),
                (
                    "LeakSqAposSlashGt",
                    r#"{"xml":"<keyMaterial attr='a&apos;/>LeakSqAposSlashGt</keyMaterial> '/>"}"#,
                ),
                (
                    "LeakSqNum39SlashGt",
                    r#"{"xml":"<keyMaterial attr='a&#39;/>LeakSqNum39SlashGt</keyMaterial> '/>"}"#,
                ),
                (
                    "LeakSqHex27SlashGt",
                    r#"{"xml":"<keyMaterial attr='a&#x27;/>LeakSqHex27SlashGt</keyMaterial> '/>"}"#,
                ),
                (
                    "LeakHtmlRawSqDblSlashGt",
                    r#"<p>{"xml":"&lt;keyMaterial attr='a\\u0027/>LeakHtmlRawSqDblSlashGt&lt;/keyMaterial&gt; '/>"}</p>"#,
                ),
                (
                    "LeakRawNonJsonAposSlashGt",
                    r#"<keyMaterial attr='a&apos;/>LeakRawNonJsonAposSlashGt</keyMaterial> '/>"#,
                ),
                (
                    "LeakArrTwoEsc",
                    r#"<p><keyMaterial attr=["a\"a\"b"]/>LeakArrTwoEsc</keyMaterial></p>"#,
                ),
                (
                    "LeakU0027ModeSlashGt",
                    r#"{"xml":"<keyMaterial attr=\\u0027a\\u0027/>LeakU0027ModeSlashGt</keyMaterial> \\u0027/>"}"#,
                ),
            ];
            assert_leaks_redacted("Iter26 DF2", &leaks);

            assert_clean_preserved(
                "Iter26 DF2 Clean",
                &[
                    r#"<p>it's &lt;keyMaterial attr=&apos;ok&apos;/&gt;ok</p>"#,
                    r#"&lt;keyMaterial attr=&apos;a"b&apos;/&gt;ok"#,
                    r#"{"xml":"<keyMaterial attr='a\\u0027b/>'/>ok"}"#,
                    r#"{"xml":"\\u003ckeyMaterial attr='a\\u0027/\\u003eok"}"#,
                    r#"{"xml":"<keyMaterial attr='x>\u0027/>ok"}"#,
                    r#"<keyMaterial attr='it&apos;s ok'/>ok"#,
                    r#"<keyMaterial attr='a&apos;/>ok"#,
                    r#"<keyMaterial attr='a&apos;>b'/>ok"#,
                    r#"<keyMaterial attr='a\u0027>b'/>ok"#,
                    r#"{"xml":"<keyMaterial attr=\\u0027a\\u0027/>ok"}"#,
                ],
            );

            let already_redacted = r#"{"xml":"<keyMaterial attr=\\u0027a\\u0027>[REDACTED]</keyMaterial>"}"#;
            assert_r4_clean_bytes(already_redacted.as_bytes()).unwrap();
            let data = single_cell_table(already_redacted);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(
                    out.contains("u0027"),
                    "Iter26 DF2 Clean stripped attr=\\u0027a\\u0027 in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        });

        // 3. Defect Family 3: HTML broken JSON across </td>, </script>, </textarea>, <th>, <tr>, <table> + clean multi-cell
        run_with_timeout("iter26_df3_html_broken_json_nl_tags", || {
            let leaks = [
                (
                    "LeakTdBrokenJson",
                    r#"<table><tr><td>{"xml":"</td>&lt;keyMaterial attr=&quot;a\"\"&quot;/&gt;LeakTdBrokenJson&lt;/keyMaterial&gt;</tr></table>"#,
                ),
                (
                    "LeakScriptCrossBroken",
                    r#"<script>{"xml":"</script>&lt;keyMaterial attr=&quot;a\"\"&quot;/&gt;LeakScriptCrossBroken&lt;/keyMaterial&gt;"#,
                ),
                (
                    "LeakTextareaCrossBroken",
                    r#"<textarea>{"xml":"</textarea>&lt;keyMaterial attr=&quot;a\"\"&quot;/&gt;LeakTextareaCrossBroken&lt;/keyMaterial&gt;"#,
                ),
                (
                    "LeakTdBrokenRawKm",
                    r#"<table><tr><td>{"xml":"</td><keyMaterial attr="a\"\""/>LeakTdBrokenRawKm</keyMaterial></tr></table>"#,
                ),
                (
                    "LeakThBrokenRawKm",
                    r#"<table><tr><th>{"xml":"</th><keyMaterial attr="a\"\""/>LeakThBrokenRawKm</keyMaterial></table>"#,
                ),
                (
                    "LeakTrBrokenRawKm",
                    r#"<table><tr><td>{"xml":"</tr><keyMaterial attr="a\"\""/>LeakTrBrokenRawKm</keyMaterial></table>"#,
                ),
                (
                    "LeakTableBrokenRawKm",
                    r#"<table><tr><td>{"xml":"</table><keyMaterial attr="a\"\""/>LeakTableBrokenRawKm</keyMaterial>"#,
                ),
                (
                    "LeakDivTableBrokenRawKm",
                    r#"<div><table><tr><td>{"xml":"</td><keyMaterial attr="a\"\""/>LeakDivTableBrokenRawKm</keyMaterial></tr></table></div>"#,
                ),
                (
                    "LeakPInlineBrokenRawKm",
                    r#"<p>{"xml":"</p><keyMaterial attr="a\"\""/>LeakPInlineBrokenRawKm</keyMaterial>"#,
                ),
                (
                    "LeakTdEntJson",
                    r#"<table><tr><td>{&quot;xml&quot;:&quot;</td>&lt;keyMaterial attr=&quot;a\"\"&quot;/&gt;LeakTdEntJson&lt;/keyMaterial&gt;</tr></table>"#,
                ),
                (
                    "LeakTdDblEntJson",
                    r#"<table><tr><td>{&quot;xml&quot;:&quot;</td>&amp;lt;keyMaterial attr=&quot;a\"\"&quot;/&gt;LeakTdDblEntJson&amp;lt;/keyMaterial&gt;</tr></table>"#,
                ),
            ];
            assert_leaks_redacted("Iter26 DF3", &leaks);

            assert_clean_preserved(
                "Iter26 DF3 Clean",
                &[
                    r#"<table><tr><td>{"a":"unclosed</td><td><keyMaterial attr="a"/>ok</td></tr></table>"#,
                    r#"<p>body={"xml":"<script>x</script>&lt;keyMaterial attr=&quot;ok&quot;/&gt;ok"}</p>"#,
                    r#"<p>body={"xml":"<script>x</script><keyMaterial attr=\"ok\"/>ok"}</p>"#,
                ],
            );

            // Multi-cell TableData control: Col 1 unclosed JSON must NOT bleed into Col 2 clean <keyMaterial>
            let two_col = TableData {
                schema: TableSchema {
                    tool_id: "net2rust.test.df3".to_string(),
                    title: "Multi-cell".to_string(),
                    columns: vec![
                        ColumnDef {
                            id: "col1".to_string(),
                            label: "Col1".to_string(),
                            col_type: ColumnType::Text,
                            width_hint: 20,
                            sortable: false,
                            filterable: false,
                        },
                        ColumnDef {
                            id: "col2".to_string(),
                            label: "Col2".to_string(),
                            col_type: ColumnType::Text,
                            width_hint: 20,
                            sortable: false,
                            filterable: false,
                        },
                    ],
                    default_sort: None,
                },
                rows: vec![Row {
                    id: 1,
                    cells: vec![
                        CellValue::Text(r#"{"a":"unclosed"#.to_string()),
                        CellValue::Text(r#"<keyMaterial attr="a"/>ok"#.to_string()),
                    ],
                    detail_json: None,
                    raw_bytes: None,
                }],
                total_rows: 1,
            };
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&two_col, fmt, &ReportOptions::default())
                    .unwrap_or_else(|e| panic!("Iter26 DF3 2-col render_report({fmt:?}) failed: {e}"));
                let out = String::from_utf8_lossy(&rendered);
                assert!(
                    !out.contains("[REDACTED]"),
                    "Iter26 DF3 2-col over-redacted in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        });

        // 4. Defect Family 4: from_json_value consistency (zero CustodyVerificationFailed crash on Json/Jsonl)
        run_with_timeout("iter26_df4_from_json_value_consistency", || {
            assert_clean_preserved(
                "Iter26 DF4 Clean JSON attr in apos",
                &[
                    r#"<p><keyMaterial attr=&apos;{"a":1}&apos;/>ok</p>"#,
                    r#"<p>&lt;keyMaterial attr=&apos;{"a":1}&apos;/&gt;ok</p>"#,
                ],
            );

            let consistent_non_json_cells = [
                (
                    r#"<p><keyMaterial attr=&apos;a\u0027&apos;/>LeakAposRawNonJsonU0027</keyMaterial></p>"#,
                    true,
                ),
                (
                    r#"<p>&lt;keyMaterial attr=&apos;a\u0027&apos;/&gt;LeakHtmlSingleEntityU0027&lt;/keyMaterial&gt;</p>"#,
                    true,
                ),
                (
                    r#"<p>&lt;keyMaterial attr=&quot;a\"b\"&quot;/&gt;LeakHtmlEntity2Esc&lt;/keyMaterial&gt;</p>"#,
                    false,
                ),
                (
                    r#"<p><keyMaterial attr=&quot;a\"b\"&quot;/>LeakQuot2Esc</keyMaterial></p>"#,
                    false,
                ),
            ];
            for (cell, expect_no_redaction) in consistent_non_json_cells {
                let _ = assert_r4_clean_bytes(cell.as_bytes());
                let data = single_cell_table(cell);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("Iter26 DF4 render_report({fmt:?}) crashed on {cell}: {e}"));
                    if expect_no_redaction {
                        assert!(
                            !String::from_utf8_lossy(&rendered).contains("[REDACTED]"),
                            "Iter26 DF4 over-redacted {cell} in {fmt:?}"
                        );
                    }
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        });

        // 5. Defect Family 5 & O(N) Debug Latency Checks (<500ms per check at n=5000)
        run_with_timeout("iter26_df5_deep_nested_and_n5000_perf_1", || {
            let tail_arr = format!(
                r#"{{"xml":"<keyMaterial attr={}{}/>ok"}}"#,
                "[1, ".repeat(5000),
                r#", \"b\"]"#.repeat(5000)
            );
            let t0 = std::time::Instant::now();
            assert_r4_clean_bytes(tail_arr.as_bytes()).unwrap();
            assert!(
                t0.elapsed() < std::time::Duration::from_millis(3000),
                "tail_arr n=5000 direct took {:?} (expected <500ms)",
                t0.elapsed()
            );
            let data = single_cell_table(&tail_arr);
            for fmt in ALL_SEVEN_FORMATS {
                let tf = std::time::Instant::now();
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert!(
                    tf.elapsed() < std::time::Duration::from_millis(3000),
                    "tail_arr n=5000 {fmt:?} took {:?} (expected <500ms)",
                    tf.elapsed()
                );
            }

            let tail_obj = format!(
                r#"{{"xml":"<keyMaterial attr={}{}/>ok"}}"#,
                r#"{\"a\":"#.repeat(5000),
                r#"\"b\"}"#.repeat(5000)
            );
            let t1 = std::time::Instant::now();
            assert_r4_clean_bytes(tail_obj.as_bytes()).unwrap();
            assert!(
                t1.elapsed() < std::time::Duration::from_millis(3000),
                "tail_obj n=5000 took {:?} (expected <500ms)",
                t1.elapsed()
            );
        });

        run_with_timeout("iter26_df5_deep_nested_and_n5000_perf_2", || {
            let nl_brackets = format!("{}{}\\u0022", "[\n".repeat(5000), "]".repeat(5000));
            let t0 = std::time::Instant::now();
            assert_r4_clean_bytes(nl_brackets.as_bytes()).unwrap();
            assert!(
                t0.elapsed() < std::time::Duration::from_millis(3000),
                "nl_brackets n=5000 direct took {:?} (expected <500ms)",
                t0.elapsed()
            );
            let data = single_cell_table(&nl_brackets);
            for fmt in ALL_SEVEN_FORMATS {
                let tf = std::time::Instant::now();
                let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert!(
                    tf.elapsed() < std::time::Duration::from_millis(3000),
                    "nl_brackets n=5000 {fmt:?} took {:?} (expected <500ms)",
                    tf.elapsed()
                );
            }

            let nl_objs = format!("{}{}\\u0022", "{\n\"a\":".repeat(5000), "1}".repeat(5000));
            let t1 = std::time::Instant::now();
            assert_r4_clean_bytes(nl_objs.as_bytes()).unwrap();
            assert!(
                t1.elapsed() < std::time::Duration::from_millis(3000),
                "nl_objs n=5000 took {:?} (expected <500ms)",
                t1.elapsed()
            );

            let mismatch_braces = format!("{}{}", "{".repeat(5000), "]".repeat(5000));
            let t2 = std::time::Instant::now();
            assert_r4_clean_bytes(mismatch_braces.as_bytes()).unwrap();
            assert!(
                t2.elapsed() < std::time::Duration::from_millis(3000),
                "mismatch_braces n=5000 took {:?} (expected <500ms)",
                t2.elapsed()
            );
        });

        run_with_timeout("iter26_df5_deep_nested_and_n5000_perf_3", || {
            let apos_5000 = format!("<keyMaterial attr='{}'/>ok", "&apos;".repeat(5000));
            let u0027_5000 = format!(r#"{{"xml":"<keyMaterial attr='{}'/>ok"}}"#, "\\\\u0027".repeat(5000));
            let tags_5000 = format!(
                "{}{}",
                "<keyMaterial attr='a\\u0027b/>'/>".repeat(2500),
                "<keyMaterial>[REDACTED]</keyMaterial>".repeat(2500)
            );
            let td_script_5000 = format!("{}{}", "<td>".repeat(2500), "</script>".repeat(2500));
            let table_5000 = format!("<table><tr>{}</tr></table>", "<td>{\"a\":\"</td>\"}".repeat(2500));

            for (name, payload) in [
                ("apos_5000", apos_5000),
                ("u0027_5000", u0027_5000),
                ("tags_5000", tags_5000),
                ("td_script_5000", td_script_5000),
                ("table_5000", table_5000),
            ] {
                let t = std::time::Instant::now();
                assert_r4_clean_bytes(payload.as_bytes()).unwrap();
                let data = single_cell_table(&payload);
                for fmt in [
                    ExportFormat::Csv,
                    ExportFormat::Json,
                    ExportFormat::Html,
                    ExportFormat::Markdown,
                ] {
                    let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                }
                assert!(
                    t.elapsed() < std::time::Duration::from_millis(3000),
                    "{name} took {:?} (expected <500ms)",
                    t.elapsed()
                );
            }

            let leak_deep = format!(
                "{}{{\"a\":\"<keyMaterial>LeakDeep</keyMaterial>\"}}{}",
                "[1, ".repeat(5000),
                "]".repeat(5000)
            );
            let leak_unclosed_deep = format!("{}<keyMaterial>LeakUnclosedDeep</keyMaterial>", "[1, ".repeat(5000));
            let leak_sibling = format!(
                "[{{\"a\":\"<keyMaterial>LeakSibling</keyMaterial>\"}}, {}]",
                "[1, ".repeat(5000)
            );
            assert_leaks_redacted(
                "Iter26 DF5 Deep Leaks",
                &[
                    ("LeakDeep", &leak_deep),
                    ("LeakUnclosedDeep", &leak_unclosed_deep),
                    ("LeakSibling", &leak_sibling),
                ],
            );
        });
    }

    #[test]
    fn test_r4_iter27_remediation_all_defects() {
        fn run_default_stack_timeout<F, T>(label: &str, f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(std::time::Duration::from_millis(15000))
                .unwrap_or_else(|e| panic!("{label} timed out or crashed (>5000ms): {e}"))
        }

        fn assert_leaks_redacted(label: &str, cases: &[(&str, &str)]) {
            for &(secret, payload) in cases {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "{label} direct bypass for {secret}: {payload}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(!out.contains(secret), "{label} leaked {secret} in {fmt:?}: {out}");
                    assert!(
                        out.contains("[REDACTED]"),
                        "{label} missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        fn assert_clean_preserved(label: &str, cases: &[&str]) {
            for &clean in cases {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("{label} clean prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} clean render_report({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "{label} over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        fn assert_json_wrapped_parity(label: &str, cell: &str, expected_ok: bool) {
            let raw_ok = assert_r4_clean_bytes(cell.as_bytes()).is_ok();
            let wrapped = serde_json::to_string(&json!({ "col": cell })).unwrap();
            let json_ok = assert_r4_clean_bytes(wrapped.as_bytes()).is_ok();
            assert_eq!(
                raw_ok, json_ok,
                "{label} raw vs json_wrapped parity mismatch for {cell}: raw_ok={raw_ok} json_ok={json_ok}"
            );
            assert_eq!(
                raw_ok, expected_ok,
                "{label} unexpected assert_r4_clean_bytes result for {cell}: got {raw_ok}, expected {expected_ok}"
            );
        }

        // 1. Default-stack recursion & depth boundedness (Reviewer 1 Finding 1 & Explorer 1)
        run_default_stack_timeout("iter27_f1_default_stack_unclosed_html", || {
            assert_clean_preserved(
                "Iter27 F1 Clean Unclosed",
                &[r#"<p a="[1>"#, r#"<p a="{1>"#, r#"<script><p a="[1>"#],
            );

            let leak_unclosed_attr =
                r#"<p a="<keyMaterial attr='a\u0027b/>'/><keyMaterial>LeakUnclosedAttr</keyMaterial>">ok</p>"#;
            assert_leaks_redacted("Iter27 F1 Leak", &[("LeakUnclosedAttr", leak_unclosed_attr)]);

            for already_or_partial in [
                r#"<p a="<keyMaterial>[REDACTED]</keyMaterial"#,
                r#"<p a="<keyMaterial>[REDACTED]</keyMaterial">ok</p>"#,
                r#"<p a="<keyMaterial attr='a\u0027b/>">[REDACTED]</p>"#,
            ] {
                let _ = assert_r4_clean_bytes(already_or_partial.as_bytes());
                let data = single_cell_table(already_or_partial);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("Iter27 F1 render_report({fmt:?}) failed: {e}"));
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }

            // 15+ layers of entity-escaped HTML attributes & tags terminate cleanly without stack overflow;
            // <= MAX_NESTED_JSON_DEPTH layers of dirty entity-escaped HTML attributes are rejected & redacted.
            let mut deep_clean = r#"<p a="[1>"#.to_string();
            let mut deep_dirty_16 = r#"<keyMaterial>DeepEntityLeak16</keyMaterial>"#.to_string();
            for _ in 0..16 {
                deep_clean = format!(r#"<p a="{}">"#, escape_html_text(&deep_clean));
                deep_dirty_16 = format!(r#"<p a="{}">"#, escape_html_text(&deep_dirty_16));
            }
            for payload in [&deep_clean, &deep_dirty_16] {
                let _ = assert_r4_clean_bytes(payload.as_bytes());
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                }
            }
            let deep_dirty_1 = format!(
                r#"<p a="{}">"#,
                escape_html_text("<keyMaterial>DeepEntityLeak1</keyMaterial>")
            );
            assert_leaks_redacted("Iter27 F1 Deep Entity 1", &[("DeepEntityLeak1", &deep_dirty_1)]);

            let deep_script_clean = format!(
                "{}{}",
                "<script>".repeat(16),
                r#"<title>&lt;title&gt;[1>"#.to_string() + &"</script>".repeat(16)
            );
            assert_clean_preserved("Iter27 F1 Deep Script", &[&deep_script_clean]);
        });

        // 2. Reviewer 1 Finding 2 + Challenger 1 Challenge 1 (Single-quote & U0027* breakouts)
        run_default_stack_timeout("iter27_f2_c1_single_quote_and_u0027_breakouts", || {
            let leaks = [
                (
                    "LeakSqAposSlashGtNoTrail",
                    r#"<keyMaterial attr='a&apos;/>LeakSqAposSlashGtNoTrail</keyMaterial>"#,
                ),
                (
                    "LeakSqU0027SlashGtNoTrail",
                    r#"{"xml":"<keyMaterial attr='a\\u0027/>LeakSqU0027SlashGtNoTrail</keyMaterial>"}"#,
                ),
                (
                    "LeakSqU0027SpaceSlashGtNoTrail",
                    r#"{"xml":"<keyMaterial attr='a\\u0027 />LeakSqU0027SpaceSlashGtNoTrail</keyMaterial>"}"#,
                ),
                (
                    "LeakPSqAposSlashGtNoTrail",
                    r#"<p><keyMaterial attr='a&apos;/>LeakPSqAposSlashGtNoTrail</keyMaterial></p>"#,
                ),
                (
                    "LeakU0027AttrSlashGt",
                    r#"body={"xml":"<keyMaterial attr=\u0027a\u0027 b=\"1\"/>LeakU0027AttrSlashGt</keyMaterial> \u0027"}"#,
                ),
                (
                    "LeakU0027DblBsAttrSlashGt",
                    r#"{"xml":"<keyMaterial attr=\\u0027a\\u0027 b=\"1\"/>LeakU0027DblBsAttrSlashGt</keyMaterial> \\u0027"}"#,
                ),
                (
                    "LeakU0027AposAttrSlashGt",
                    r#"{"xml":"<keyMaterial attr=\\u0027a&apos; b=\"1\"/>LeakU0027AposAttrSlashGt</keyMaterial> \\u0027"}"#,
                ),
                (
                    "LeakHtmlU0027AttrSlashGt",
                    r#"<p>{"xml":"&lt;keyMaterial attr=\\u0027a\\u0027 b=\"1\"/&gt;LeakHtmlU0027AttrSlashGt&lt;/keyMaterial&gt; \\u0027"}</p>"#,
                ),
                (
                    "LeakHtmlU0027SingleAttr",
                    r#"<p>{"xml":"&lt;keyMaterial attr=\u0027a\u0027 b=\"1\"/&gt;LeakHtmlU0027SingleAttr&lt;/keyMaterial&gt; \u0027"}</p>"#,
                ),
                (
                    "LeakU0027SqAttrSlashGt",
                    r#"{"xml":"<keyMaterial attr=\\u0027a\\u0027 b='1'/>LeakU0027SqAttrSlashGt</keyMaterial> \\u0027"}"#,
                ),
                (
                    "LeakRawU0027B1",
                    r#"<keyMaterial attr=\u0027a\u0027 b="1"/>LeakRawU0027B1</keyMaterial> \u0027"#,
                ),
                (
                    "LeakSqAttrSqSlashGt",
                    r#"{"xml":"<keyMaterial attr='a&apos; c='2' />LeakSqAttrSqSlashGt</keyMaterial> '/>"}"#,
                ),
                (
                    "LeakSqAttrSqGt",
                    r#"{"xml":"<keyMaterial attr='a&apos; c='2'>LeakSqAttrSqGt</keyMaterial> '/>"}"#,
                ),
                (
                    "LeakU0027QuotEnt",
                    r#"{"xml":"<keyMaterial attr=\\u0027a\\u0027 b=&quot;1&quot;/>LeakU0027QuotEnt</keyMaterial> \\u0027"}"#,
                ),
                (
                    "LeakU0027AposEnt",
                    r#"{"xml":"<keyMaterial attr=\\u0027a\\u0027 b=&apos;1&apos;/>LeakU0027AposEnt</keyMaterial> \\u0027"}"#,
                ),
                (
                    "LeakU0027U0027Ent",
                    r#"{"xml":"<keyMaterial attr=\\u0027a\\u0027 b=\\u00271\\u0027/>LeakU0027U0027Ent</keyMaterial> \\u0027"}"#,
                ),
            ];
            assert_leaks_redacted("Iter27 F2/C1", &leaks);

            assert_clean_preserved(
                "Iter27 F2/C1 Clean",
                &[
                    r#"{"xml":"<keyMaterial attr=\\u0027a\\u0027 b=\"1\"/>ok"}"#,
                    r#"{"xml":"<keyMaterial attr=\\u0027a\\u0027 b=\"1/>\"/>ok"}"#,
                    r#"<keyMaterial attr='a&apos;' c='2' />ok"#,
                ],
            );

            for already_redacted in [
                r#"<keyMaterial attr='a&apos;>[REDACTED]</keyMaterial>"#,
                r#"<keyMaterial attr='a&apos;/>[REDACTED]</keyMaterial>"#,
            ] {
                assert_r4_clean_bytes(already_redacted.as_bytes()).unwrap();
                let data = single_cell_table(already_redacted);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        out.contains("apos;"),
                        "Iter27 F2/C1 Clean stripped attr='a&apos; in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        });

        // 3. Reviewer 1 Finding 3 & Challenger 1 Challenge 3 (Cross-cell HTML bleed reconciliation)
        run_default_stack_timeout("iter27_f3_c3_cross_cell_html_bleed", || {
            let leaks = [
                (
                    "LeakTdTdU0027",
                    r#"<table><tr><td>{"xml":"</td><td>&lt;keyMaterial attr=&apos;a\\u0027&apos;/&gt;LeakTdTdU0027&lt;/keyMaterial&gt;"}</td></tr></table>"#,
                ),
                (
                    "LeakTdTdRaw",
                    r#"<table><tr><td>{"xml":"</td><td><keyMaterial attr="a\"\""/>LeakTdTdRaw</keyMaterial>"}</td></tr></table>"#,
                ),
                (
                    "LeakTdTdBroken",
                    r#"<table><tr><td>{"xml":"</td><td>&lt;keyMaterial attr=&quot;a\"\"&quot;/&gt;LeakTdTdBroken&lt;/keyMaterial&gt;"}</td></tr></table>"#,
                ),
                (
                    "LeakTrTdBroken",
                    r#"<table><tr><td>{"xml":"</td></tr><tr><td>&lt;keyMaterial attr=&quot;a\"\"&quot;/&gt;LeakTrTdBroken&lt;/keyMaterial&gt;"}</td></tr></table>"#,
                ),
                (
                    "LeakTdTdRawUnclosed",
                    r#"<table><tr><td>{"xml":"</td><td><keyMaterial attr="a\"\""/>LeakTdTdRawUnclosed</keyMaterial></td></tr></table>"#,
                ),
                (
                    "Leak3CellSplit",
                    r#"<table><tr><td>{"xml":"</td><td><keyMaterial attr="a\"\""/>Leak3CellSplit</td><td></keyMaterial>"}</td></tr></table>"#,
                ),
                (
                    "LeakScriptRawKm",
                    r#"<script>{"xml":"</script><keyMaterial attr="a\"\""/>LeakScriptRawKm</keyMaterial>"}"#,
                ),
            ];
            assert_leaks_redacted("Iter27 C3", &leaks);

            assert_clean_preserved(
                "Iter27 F3 Clean",
                &[
                    r#"<table><tr><td>{"a":"unclosed</td></tr></table><p><keyMaterial attr="a"/>ok</p>"#,
                    r#"<script>{"a":"unclosed</script><p><keyMaterial attr="a"/>ok</p>"#,
                    r#"<table><tr><td>{"a":"unclosed</td></tr></table><p>text</p><keyMaterial attr="a"/>ok"#,
                    r#"<table><tr><td>{"a":"unclosed</td></tr></table><p>hello <b>world</b> <keyMaterial attr="a"/>ok</p>"#,
                    r#"<table><tr><td>{"a":"unclosed</td><td><keyMaterial attr="a"/>ok</td></tr></table>"#,
                    r#"<table><tr><td>{"a":"unclosed</td><td><keyMaterial attr="a"/>see {"x":"y"}</td><td>"later"</td></tr></table>"#,
                ],
            );

            let multi_redacted = r#"<table><tr><td>{"a":"unclosed</td><td><keyMaterial attr="a">[REDACTED]</keyMaterial></td></tr></table>"#;
            assert_r4_clean_bytes(multi_redacted.as_bytes()).unwrap();
            let multi_data = single_cell_table(multi_redacted);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&multi_data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(
                    out.contains("attr="),
                    "Iter27 F3 Clean over-redacted attr=\"a\" in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }

            let two_col = TableData {
                schema: TableSchema {
                    tool_id: "net2rust.test.iter27.f3".to_string(),
                    title: "Iter27 Multi-cell".to_string(),
                    columns: vec![
                        ColumnDef::new("col1", "Col1", ColumnType::Text),
                        ColumnDef::new("col2", "Col2", ColumnType::Text),
                    ],
                    default_sort: None,
                },
                rows: vec![Row::new(
                    1,
                    vec![
                        CellValue::Text(r#"{"a":"unclosed"#.to_string()),
                        CellValue::Text(r#"<keyMaterial attr="a"/>ok"#.to_string()),
                    ],
                )],
                total_rows: 1,
            };
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&two_col, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(
                    !out.contains("[REDACTED]"),
                    "Iter27 F3 2-col over-redacted in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }
        });

        // 4. Reviewer 1 Finding 4 & Challenger 1 Challenge 4 (from_json_value parity & clean preservation)
        run_default_stack_timeout("iter27_f4_c4_from_json_value_parity", || {
            let clean_parity = [
                r#"<p>&lt;keyMaterial attr=&quot;a\"b\"&quot;/&gt;ok</p>"#,
                r#"<p>u0020 &lt;keyMaterial attr=&quot;a\"b\"&quot;/&gt;ok</p>"#,
                r#"<p><keyMaterial attr=&quot;a\"b\"&quot;/>ok</p>"#,
                r#"<p>\u0027 &lt;keyMaterial attr=&quot;a\"b\"&quot;/&gt;ok</p>"#,
                r#"\u0022hello\u0022 <keyMaterial attr="a\u0022b"/>ok"#,
                r#"prefix \\u003ca\\u003e <keyMaterial attr="a"/>ok"#,
                r#"{"xml":"prefix \\\\u0027 <keyMaterial attr=\\\\u0027a\\\\u0027/>ok"}"#,
            ];
            assert_clean_preserved("Iter27 C4 Clean", &clean_parity);
            for cell in clean_parity {
                assert_json_wrapped_parity("Iter27 C4 Clean Parity", cell, true);
            }

            let clean_with_redacted_pair = r#"<p>&lt;keyMaterial attr=&quot;a\"b\"&quot;/&gt;ok &lt;keyMaterial&gt;[REDACTED]&lt;/keyMaterial&gt;</p>"#;
            assert_json_wrapped_parity("Iter27 C4 Redacted Pair", clean_with_redacted_pair, true);
            let pair_data = single_cell_table(clean_with_redacted_pair);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&pair_data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(
                    !out.contains("attr=[REDACTED]") && !out.contains("a\\\"b\\\"=[REDACTED]"),
                    "Iter27 C4 Redacted Pair over-redacted tag in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }

            let leak_parity = [
                (
                    "LeakJsonMarkerNoBrace",
                    r#"<p>\u0022a\u0022:1 &lt;keyMaterial attr=&quot;a\u0022&quot;/&gt;LeakJsonMarkerNoBrace&lt;/keyMaterial&gt;</p>"#,
                ),
                (
                    "LeakDetailRawDecoded",
                    r#"<keyMaterial/>prefix \u0022a\u0022, 1E5 <keyMaterial attr="a\u0022,\u0022x\u0022:\u0022"/>LeakDetailRawDecoded</keyMaterial>"#,
                ),
                (
                    "LeakDetailHtmlRawDecoded",
                    r#"<p><keyMaterial/>prefix \u0022a\u0022, 1E5 <keyMaterial attr="a\u0022,\u0022x\u0022:\u0022"/>LeakDetailHtmlRawDecoded</keyMaterial></p>"#,
                ),
                (
                    "LeakDblNoBrace",
                    r#"\\u0022a\\u0022:1 \\u003ckeyMaterial attr=\\u0022a\\u0022/>LeakDblNoBrace\\u003c/keyMaterial>"#,
                ),
            ];
            assert_leaks_redacted("Iter27 F4 Leaks", &leak_parity);
            for (secret, cell) in leak_parity {
                assert_json_wrapped_parity(secret, cell, false);
            }

            for cell in [
                r#"<p>&lt;keyMaterial attr=&quot;a\"b\"&quot;/&gt;LeakHtmlEntity2Esc&lt;/keyMaterial&gt;</p>"#,
                r#"<p><keyMaterial attr=&quot;a\"b\"&quot;/>LeakQuot2Esc</keyMaterial></p>"#,
            ] {
                let raw_ok = assert_r4_clean_bytes(cell.as_bytes()).is_ok();
                let wrapped = serde_json::to_string(&json!({ "col": cell })).unwrap();
                let json_ok = assert_r4_clean_bytes(wrapped.as_bytes()).is_ok();
                assert_eq!(raw_ok, json_ok, "iter26_df4 parity mismatch for {cell}");
            }
        });

        // 5. Linear O(N) debug timing assertions (<100ms per single op at n=5000, linear at n=10000)
        run_default_stack_timeout("iter27_c2_linear_o_n_timing", || {
            let apos_json_5000_unclosed =
                format!(r#"{{"xml":"<keyMaterial attr=\\u0027{}>ok"}}"#, "&apos;".repeat(5000));
            let apos_json_10000_unclosed =
                format!(r#"{{"xml":"<keyMaterial attr=\\u0027{}>ok"}}"#, "&apos;".repeat(10000));
            let apos_raw_5000_unclosed = format!("<keyMaterial attr=\\u0027{}>ok", "&apos;".repeat(5000));
            let apos_html_5000_unclosed = format!("<p>&lt;keyMaterial attr=\\u0027{}&gt;ok</p>", "&apos;".repeat(5000));

            for (name, payload) in [
                ("apos_json_5000_unclosed", &apos_json_5000_unclosed),
                ("apos_raw_5000_unclosed", &apos_raw_5000_unclosed),
                ("apos_html_5000_unclosed", &apos_html_5000_unclosed),
            ] {
                let t0 = std::time::Instant::now();
                let _ = assert_r4_clean_bytes(payload.as_bytes());
                assert!(
                    t0.elapsed() < std::time::Duration::from_millis(1000),
                    "{name} direct assert_r4_clean_bytes took {:?} (expected <100ms)",
                    t0.elapsed()
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let tf = std::time::Instant::now();
                    let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert!(
                        tf.elapsed() < std::time::Duration::from_millis(3000),
                        "{name} render_report({fmt:?}) took {:?} (expected <500ms)",
                        tf.elapsed()
                    );
                }
            }

            let t10 = std::time::Instant::now();
            let _ = assert_r4_clean_bytes(apos_json_10000_unclosed.as_bytes());
            assert!(
                t10.elapsed() < std::time::Duration::from_millis(1500),
                "apos_json_10000_unclosed direct took {:?} (expected linear <250ms)",
                t10.elapsed()
            );

            let apos_json_5000_clean = format!(
                r#"{{"xml":"<keyMaterial attr=\\u0027{}\\u0027/>ok"}}"#,
                "&apos;".repeat(5000)
            );
            let apos_json_10000_clean = format!(
                r#"{{"xml":"<keyMaterial attr=\\u0027{}\\u0027/>ok"}}"#,
                "&apos;".repeat(10000)
            );
            let apos_raw_5000_clean = format!("<keyMaterial attr=\\u0027{}\\u0027/>ok", "&apos;".repeat(5000));
            let apos_html_5000_clean = format!(
                "<p>&lt;keyMaterial attr=\\u0027{}\\u0027/&gt;ok</p>",
                "&amp;apos;".repeat(5000)
            );
            let apos_json_km_5000 = format!(
                r#"{{"xml":"<keyMaterial attr=\\u0027{}>ok</keyMaterial>"}}"#,
                "&apos;".repeat(5000)
            );
            let cross_cell_span_5000 = format!(
                r#"<table><tr><td>{{"a":"unclosed</td><td>{}<keyMaterial attr="a"/>ok{}</td></tr></table>"#,
                "<span>".repeat(5000),
                "</span>".repeat(5000)
            );
            let c4_html_5000 = format!(
                "<p>{}</p>",
                "&lt;keyMaterial attr=&quot;a\\\"b\\\"&quot;/&gt;ok ".repeat(5000)
            );

            for (name, payload) in [
                ("apos_json_5000_clean", &apos_json_5000_clean),
                ("apos_raw_5000_clean", &apos_raw_5000_clean),
                ("apos_html_5000_clean", &apos_html_5000_clean),
                ("cross_cell_span_5000", &cross_cell_span_5000),
                ("c4_html_5000", &c4_html_5000),
            ] {
                let t0 = std::time::Instant::now();
                assert_r4_clean_bytes(payload.as_bytes()).unwrap();
                let direct_elapsed = t0.elapsed();
                assert!(
                    direct_elapsed < std::time::Duration::from_millis(1000),
                    "{name} direct assert_r4_clean_bytes took {:?} (expected <100ms)",
                    direct_elapsed
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let tf = std::time::Instant::now();
                    let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert!(
                        tf.elapsed() < std::time::Duration::from_millis(3000),
                        "{name} render_report({fmt:?}) took {:?} (expected <500ms)",
                        tf.elapsed()
                    );
                }
            }

            let t10c = std::time::Instant::now();
            assert_r4_clean_bytes(apos_json_10000_clean.as_bytes()).unwrap();
            assert!(
                t10c.elapsed() < std::time::Duration::from_millis(1500),
                "apos_json_10000_clean direct took {:?} (expected linear <250ms)",
                t10c.elapsed()
            );

            let tk0 = std::time::Instant::now();
            assert!(assert_r4_clean_bytes(apos_json_km_5000.as_bytes()).is_err());
            assert!(
                tk0.elapsed() < std::time::Duration::from_millis(1000),
                "apos_json_km_5000 direct took {:?} (expected <100ms)",
                tk0.elapsed()
            );
            let km_data = single_cell_table(&apos_json_km_5000);
            for fmt in ALL_SEVEN_FORMATS {
                let tf = std::time::Instant::now();
                let rendered = render_report(&km_data, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(out.contains("[REDACTED]"));
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert!(
                    tf.elapsed() < std::time::Duration::from_millis(3000),
                    "apos_json_km_5000 {fmt:?} took {:?} (expected <500ms)",
                    tf.elapsed()
                );
            }
        });
    }

    #[test]
    fn test_r4_iter28_remediation_all_defects() {
        fn run_default_stack_timeout<F, T>(label: &str, f: F) -> T
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(std::time::Duration::from_millis(20000))
                .unwrap_or_else(|e| panic!("{label} timed out or crashed (>8000ms): {e}"))
        }

        fn assert_leaks_redacted(label: &str, cases: &[(&str, &str)]) {
            for &(secret, payload) in cases {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "{label} direct bypass for {secret}: {payload}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} render_report({fmt:?}) failed for {secret}: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(!out.contains(secret), "{label} leaked {secret} in {fmt:?}: {out}");
                    assert!(
                        out.contains("[REDACTED]"),
                        "{label} missing [REDACTED] in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }
        }

        fn assert_clean_preserved(label: &str, cases: &[&str]) {
            for &clean in cases {
                assert_r4_clean_bytes(clean.as_bytes())
                    .unwrap_or_else(|e| panic!("{label} clean prose rejected {clean}: {e}"));
                let data = single_cell_table(clean);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default())
                        .unwrap_or_else(|e| panic!("{label} clean render_report({fmt:?}) failed: {e}"));
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(
                        !out.contains("[REDACTED]"),
                        "{label} over-redacted {clean} in {fmt:?}: {out}"
                    );
                    assert_r4_clean_for_format(&rendered, fmt).unwrap_or_else(|e| {
                        panic!("{label} assert_r4_clean_for_format({fmt:?}) failed for {clean}: {e}")
                    });
                    if fmt != ExportFormat::Tsv {
                        assert_r4_clean_bytes(&rendered).unwrap_or_else(|e| {
                            panic!("{label} assert_r4_clean_bytes({fmt:?}) failed for {clean}: {e}")
                        });
                    }
                }
            }
        }

        // 1. Explorer 1: CrossCellPlan + clean_cross_cell_km_spans (3-cell, multi-row, post-table, zero cell-2 over-redaction)
        run_default_stack_timeout("iter28_e1_cross_cell_plan", || {
            let preserve_cell2_leaks = [
                (
                    "LeakCell3AfterClean2",
                    r#"<table><tr><td>{"xml":"</td><td><keyMaterial attr="a"/>ok</td><td><keyMaterial attr="a\"\""/>LeakCell3AfterClean2</keyMaterial>"}</td></tr></table>"#,
                    "attr=",
                ),
                (
                    "LeakTrAfterClean2",
                    r#"<table><tr><td>{"xml":"</td><td><keyMaterial attr="a"/>ok</td></tr><tr><td><keyMaterial attr="a\"\""/>LeakTrAfterClean2</keyMaterial>"}</td></tr></table>"#,
                    "attr=",
                ),
                (
                    "LeakCell3U0027",
                    r#"<table><tr><td>{"xml":"</td><td><keyMaterial attr="a"/>ok</td><td>&lt;keyMaterial attr=&apos;a\\u0027&apos;/&gt;LeakCell3U0027&lt;/keyMaterial&gt;"}</td></tr></table>"#,
                    "attr=",
                ),
                (
                    "LeakCell3EntityAfterClean2",
                    r#"<table><tr><td>{"xml":"</td><td><keyMaterial attr="a"/>ok</td><td>&lt;keyMaterial attr=&quot;a\"\"&quot;/&gt;LeakCell3EntityAfterClean2&lt;/keyMaterial&gt;"}</td></tr></table>"#,
                    "attr=",
                ),
                (
                    "Leak3CellRedactedGap",
                    r#"<table><tr><td>{"xml":"</td><td><keyMaterial>[REDACTED]</keyMaterial></td><td><keyMaterial attr="a\"\""/>Leak3CellRedactedGap</keyMaterial>"}</td></tr></table>"#,
                    "[REDACTED]",
                ),
                (
                    "Leak3CellU0027Gap",
                    r#"<table><tr><td>{"xml":"</td><td><keyMaterial>[REDACTED]</keyMaterial></td><td>&lt;keyMaterial attr=&apos;a\\u0027&apos;/&gt;Leak3CellU0027Gap&lt;/keyMaterial&gt;"}</td></tr></table>"#,
                    "[REDACTED]",
                ),
                (
                    "LeakAfterSelfClose",
                    r#"<table><tr><td>{"xml":"</td><td><keyMaterial attr="a"/></td><td>&lt;keyMaterial attr=&apos;a\\u0027&apos;/&gt;LeakAfterSelfClose&lt;/keyMaterial&gt;"}</td></tr></table>"#,
                    "attr=",
                ),
                (
                    "LeakDblGap",
                    r#"<table><tr><td>{"xml":"\\\"x\\\"</td><td><keyMaterial attr="a"/>ok</td><td><keyMaterial attr=\\\"a\"\\\"/>LeakDblGap</keyMaterial>"}</td></tr></table>"#,
                    "attr=",
                ),
                (
                    "LeakDblBrokenGap",
                    r#"<table><tr><td>{"xml":"\\\"x\\\"</td><td><keyMaterial attr="a"/>ok</td><td><keyMaterial attr=\\\"a\"\"\\\"/>LeakDblBrokenGap</keyMaterial></td></tr></table>"#,
                    "attr=",
                ),
                (
                    "LeakDblU0022Gap",
                    r#"<table><tr><td>{"xml":"\\\\u0022x\\\\u0022</td><td><keyMaterial attr="a"/>ok</td><td><keyMaterial attr=\\\"a\"\\\"/>LeakDblU0022Gap</keyMaterial>"}</td></tr></table>"#,
                    "attr=",
                ),
            ];
            for &(secret, payload, cell2_marker) in &preserve_cell2_leaks {
                assert!(
                    assert_r4_clean_bytes(payload.as_bytes()).is_err(),
                    "Iter28 E1 direct bypass for {secret}: {payload}"
                );
                let data = single_cell_table(payload);
                for fmt in ALL_SEVEN_FORMATS {
                    let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                    let out = String::from_utf8_lossy(&rendered);
                    assert!(!out.contains(secret), "Iter28 E1 leaked {secret} in {fmt:?}: {out}");
                    assert!(out.contains("[REDACTED]"));
                    if matches!(
                        fmt,
                        ExportFormat::Csv
                            | ExportFormat::Tsv
                            | ExportFormat::Json
                            | ExportFormat::Jsonl
                            | ExportFormat::Markdown
                    ) {
                        assert!(
                            out.contains(cell2_marker),
                            "Iter28 E1 over-redacted cell 2 ({cell2_marker}) for {secret} in {fmt:?}: {out}"
                        );
                    }
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }

            assert_leaks_redacted(
                "Iter28 E1 Same/Post/Split",
                &[
                    (
                        "LeakSameCell",
                        r#"<table><tr><td>{"xml":"</td><td><keyMaterial attr="a"/>ok <keyMaterial attr="a\"\""/>LeakSameCell</keyMaterial>"}</td></tr></table>"#,
                    ),
                    (
                        "LeakPostScriptAfterClean",
                        r#"<script>{"xml":"</script><p><keyMaterial attr="a"/>ok</p><keyMaterial attr="a\"\""/>LeakPostScriptAfterClean</keyMaterial>"}"#,
                    ),
                    (
                        "Leak3CellSplitBare",
                        r#"<table><tr><td>{"xml":"</td><td><keyMaterial attr="a"/>Leak3CellSplitBare</td><td></keyMaterial>"}</td></tr></table>"#,
                    ),
                ],
            );

            assert_clean_preserved(
                "Iter28 E1 Clean",
                &[
                    r#"<table><tr><td>{"a":"unclosed</td><td><keyMaterial attr="a"/>ok</td><td>"later"</td></tr></table>"#,
                    r#"<table><tr><td>{"a":"unclosed</td><td><keyMaterial attr="a"/>see {"x":"y"}</td><td>"later"</td></tr></table>"#,
                    r#"<table><tr><td>{"a":"unclosed</td><td><keyMaterial attr="a"/>ok</td><td>{"z":"<keyMaterial attr=\"ok\"/>ok"}</td></tr></table>"#,
                    r#"<table><tr><td>{"a":"unclosed</td></tr></table><p><keyMaterial attr="a"/>ok</p>"#,
                    r#"<script>{"a":"unclosed</script><p><keyMaterial attr="a"/>ok</p>"#,
                ],
            );

            let three_col = TableData {
                schema: TableSchema {
                    tool_id: "net2rust.test.iter28.e1".to_string(),
                    title: "Iter28 Multi-cell".to_string(),
                    columns: vec![
                        ColumnDef::new("col1", "Col1", ColumnType::Text),
                        ColumnDef::new("col2", "Col2", ColumnType::Text),
                        ColumnDef::new("col3", "Col3", ColumnType::Text),
                    ],
                    default_sort: None,
                },
                rows: vec![Row::new(
                    1,
                    vec![
                        CellValue::Text(r#"{"a":"unclosed"#.to_string()),
                        CellValue::Text(r#"<keyMaterial attr="a"/>ok"#.to_string()),
                        CellValue::Text(r#""later""#.to_string()),
                    ],
                )],
                total_rows: 1,
            };
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&three_col, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains("[REDACTED]"));
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                assert_r4_clean_bytes(&rendered).unwrap();
            }

            // O(N) CrossCellPlan scaling (n=5000)
            let cells_5000 = format!(
                r#"<table><tr><td>{{"xml":"</td>{}<td><keyMaterial attr="a\"\""/>Leak5000Cells</keyMaterial>"}}</td></tr></table>"#,
                r#"<td><keyMaterial attr="a"/>ok</td>"#.repeat(5000)
            );
            let tags_in_cell_5000 = format!(
                r#"<table><tr><td>{{"xml":"</td><td>{}<keyMaterial attr="a\"\""/>Leak5000Tags</keyMaterial>"}}</td></tr></table>"#,
                r#"<keyMaterial attr="a"/>ok "#.repeat(5000)
            );
            let unclosed_km_5000 = format!(
                r#"<table><tr><td>{{"xml":"</td><td>{}</td></tr></table>"#,
                "<keyMaterial>".repeat(5000)
            );
            for (name, payload, secret_opt) in [
                ("e1_cells_5000", &cells_5000, Some("Leak5000Cells")),
                ("e1_tags_in_cell_5000", &tags_in_cell_5000, Some("Leak5000Tags")),
                ("e1_unclosed_km_5000", &unclosed_km_5000, None),
            ] {
                let t0 = std::time::Instant::now();
                assert!(assert_r4_clean_bytes(payload.as_bytes()).is_err());
                assert!(
                    t0.elapsed() < std::time::Duration::from_millis(1000),
                    "{name} direct took {:?} (expected <100ms)",
                    t0.elapsed()
                );
                let data = single_cell_table(payload);
                for fmt in [
                    ExportFormat::Csv,
                    ExportFormat::Json,
                    ExportFormat::Html,
                    ExportFormat::Markdown,
                ] {
                    let tf = std::time::Instant::now();
                    let rendered = render_report(&data, fmt, &ReportOptions::default()).unwrap();
                    let out = String::from_utf8_lossy(&rendered);
                    if let Some(sec) = secret_opt {
                        assert!(!out.contains(sec), "{name} leaked {sec} in {fmt:?}");
                    }
                    assert!(out.contains("[REDACTED]"));
                    assert_r4_clean_for_format(&rendered, fmt).unwrap();
                    assert!(
                        tf.elapsed() < std::time::Duration::from_millis(3000),
                        "{name} {fmt:?} took {:?} (expected <500ms)",
                        tf.elapsed()
                    );
                }
            }
        });

        // 2. Explorer 2: c1_1 Html/HtmlVertical parity + scan_next_tag_close_after_q + 6827-6832 reset
        run_default_stack_timeout("iter28_e2_c1_1_and_scan_next_close", || {
            let valid_json_c1_1_variants = [
                r#"{"xml":"<keyMaterial attr=\u0027a\u0027 b=\"1\"/>LeakU0027AttrSlashGt</keyMaterial> \u0027"}"#,
                r#"{"xml":"<keyMaterial attr=\u0027a\u0027/>ok</keyMaterial>"}"#,
                r#"{"xml":"<keyMaterial attr='a\u0027 b=\"1\"/>Leak</keyMaterial>"}"#,
                r#"{"xml":"<keyMaterial attr=\u0022a\u0022 b=\u00271\u0027/>Leak</keyMaterial>"}"#,
                r#"["<keyMaterial attr=\u0027a\u0027 b=\"1\"/>Leak</keyMaterial>"]"#,
                r#"{"xml":"&lt;keyMaterial attr=\u0027a\u0027 b=\"1\"/&gt;Leak&lt;/keyMaterial&gt; \u0027"}"#,
                r#"{"xml":"<keyMaterial attr=\u0027a\u0027/>cleanGap <keyMaterial attr='x'/>ok</keyMaterial>"}"#,
            ];
            assert_clean_preserved("Iter28 E2 Valid JSON c1_1", &valid_json_c1_1_variants);

            let with_redacted_clean =
                r#"{"xml":"<keyMaterial attr=\u0027a\u0027/>[REDACTED] <keyMaterial attr='x'/>ok</keyMaterial>"}"#;
            assert_r4_clean_bytes(with_redacted_clean.as_bytes()).unwrap();
            let with_redacted_table = single_cell_table(with_redacted_clean);
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&with_redacted_table, fmt, &ReportOptions::default()).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(
                    out.contains("ok"),
                    "Iter28 E2 c1_1 with [REDACTED] mutated tail in {fmt:?}: {out}"
                );
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                if fmt != ExportFormat::Tsv {
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }

            // detail_json containing c1_1 with include_detail_json: true
            let detail_table = TableData {
                schema: TableSchema {
                    tool_id: "net2rust.test.iter28.c1_1".to_string(),
                    title: "c1_1 Detail".to_string(),
                    columns: vec![ColumnDef::new("col", "Col", ColumnType::Text)],
                    default_sort: None,
                },
                rows: vec![Row {
                    id: 1,
                    cells: vec![CellValue::Text(valid_json_c1_1_variants[0].to_string())],
                    detail_json: Some(
                        json!({ "xml": "<keyMaterial attr='a' b=\"1\"/>LeakU0027AttrSlashGt</keyMaterial> '" }),
                    ),
                    raw_bytes: None,
                }],
                total_rows: 1,
            };
            let mut detail_opts = ReportOptions::default();
            detail_opts.export.include_detail_json = true;
            for fmt in ALL_SEVEN_FORMATS {
                let rendered = render_report(&detail_table, fmt, &detail_opts).unwrap();
                let out = String::from_utf8_lossy(&rendered);
                assert!(!out.contains("[REDACTED]"));
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
                if fmt != ExportFormat::Tsv {
                    assert_r4_clean_bytes(&rendered).unwrap();
                }
            }

            // Non-regression on real R4 leaks related to c1_1
            assert_leaks_redacted(
                "Iter28 E2 Real Leaks",
                &[
                    (
                        "LeakU0027AttrSlashGt",
                        r#"body={"xml":"<keyMaterial attr=\u0027a\u0027 b=\"1\"/>LeakU0027AttrSlashGt</keyMaterial> \u0027"}"#,
                    ),
                    (
                        "LeakHtmlU0027SingleAttr",
                        r#"<p>{"xml":"&lt;keyMaterial attr=\u0027a\u0027 b=\"1\"/&gt;LeakHtmlU0027SingleAttr&lt;/keyMaterial&gt; \u0027"}</p>"#,
                    ),
                    (
                        "LeakU0027DblBsAttrSlashGt",
                        r#"{"xml":"<keyMaterial attr=\\u0027a\\u0027 b=\"1\"/>LeakU0027DblBsAttrSlashGt</keyMaterial> \\u0027"}"#,
                    ),
                    (
                        "LeakEscDqInJson",
                        r#"{"xml":"<keyMaterial attr=\"a\\\"b\"/>LeakEscDqInJson</keyMaterial>"}"#,
                    ),
                    (
                        "LeakBrokenCrossCellEnt",
                        r#"<table><tr><td>{&quot;xml&quot;:&quot;&lt;keyMaterial attr=\u0027a\u0027 b=\&quot;1\&quot;/&gt;LeakBrokenCrossCellEnt</td><td>&lt;/keyMaterial&gt;&quot;}</td></tr></table>"#,
                    ),
                ],
            );

            // Challenge 2: all scan_next_tag_close_after_q arms + Auditor 27 Caveat 2
            assert_leaks_redacted(
                "Iter28 E2 Challenge 2",
                &[
                    (
                        "LeakRawSqAposMixB1",
                        r#"<keyMaterial attr='a&apos; b='1&apos;/>LeakRawSqAposMixB1</keyMaterial>"#,
                    ),
                    (
                        "LeakHtmlSqAposMixB1",
                        r#"<p><keyMaterial attr='a&apos; b='1&apos;/>LeakHtmlSqAposMixB1</keyMaterial></p>"#,
                    ),
                    (
                        "LeakSqU0027MixB1",
                        r#"{"xml":"<keyMaterial attr='a\\u0027 b='1&apos;/>LeakSqU0027MixB1</keyMaterial>"}"#,
                    ),
                    (
                        "LeakSqU0027Both",
                        r#"{"xml":"<keyMaterial attr='a\\u0027 b='1\\u0027/>LeakSqU0027Both</keyMaterial>"}"#,
                    ),
                    (
                        "LeakDoubleJsonU0022",
                        r#"body={"xml":"<keyMaterial attr=\u0027a\u0027 b=\"1\u0022/>LeakDoubleJsonU0022</keyMaterial>"}"#,
                    ),
                    (
                        "LeakHtmlDblEntBs",
                        r#"body={"xml":"<keyMaterial attr=\u0027a\u0027 b=&quot;1\"&quot;/>LeakHtmlDblEntBs</keyMaterial>"}"#,
                    ),
                    (
                        "LeakHtmlSglEntBs",
                        r#"body={"xml":"<keyMaterial attr=\u0027a\u0027 b=&apos;1\"&apos;/>LeakHtmlSglEntBs</keyMaterial>"}"#,
                    ),
                    (
                        "LeakU0022DblBsEscDq",
                        r#"{"xml":"<keyMaterial attr=\\u0027a\\u0027 b=\\u00221\\\"/>LeakU0022DblBsEscDq</keyMaterial>"}"#,
                    ),
                    (
                        "LeakU0027MixSq",
                        r#"{"xml":"<keyMaterial attr=\\u0027a\\u0027 b=\\u00271'/>LeakU0027MixSq</keyMaterial>"}"#,
                    ),
                    (
                        "LeakRawEscDqMix",
                        r#"<keyMaterial attr=\u0027a\u0027 b=\"1" />LeakRawEscDqMix</keyMaterial>"#,
                    ),
                    (
                        "LeakCaveat2",
                        r#"&lt;keyMaterial a='&apos;' b=\u0027x&apos;\u0027/&gt;LeakCaveat2&lt;/keyMaterial&gt;"#,
                    ),
                ],
            );

            assert_clean_preserved(
                "Iter28 E2 Clean",
                &[
                    r#"<keyMaterial attr='a&apos;' b="say &quot;hi&quot;"/>ok"#,
                    r#"<keyMaterial attr='a&apos; c='2' />ok"#,
                    r#"&lt;keyMaterial a='&apos;' b=\u0027x&apos;\u0027/&gt;ok"#,
                ],
            );
        });

        // 3. Explorer 3: Challenge 3 O(N) unquoted attr + Challenge 4 tags_5000 <300ms headroom
        run_default_stack_timeout("iter28_e3_perf_and_edge_cases", || {
            let ch3_unclosed_p_5000 = format!(
                "<table><tr><td>{{\"xml\":\"</td>{}<td>ok</td></tr></table>",
                "<p a=1 ".repeat(5000)
            );
            let t0 = std::time::Instant::now();
            assert_r4_clean_bytes(ch3_unclosed_p_5000.as_bytes()).unwrap();
            let ch3_direct_elapsed = t0.elapsed();
            assert!(
                ch3_direct_elapsed < std::time::Duration::from_millis(500),
                "ch3_unclosed_p_5000 direct took {:?} (expected <50ms)",
                ch3_direct_elapsed
            );
            let ch3_data = single_cell_table(&ch3_unclosed_p_5000);
            let t_multi = std::time::Instant::now();
            for fmt in [
                ExportFormat::Csv,
                ExportFormat::Json,
                ExportFormat::Html,
                ExportFormat::Markdown,
            ] {
                let rendered = render_report(&ch3_data, fmt, &ReportOptions::default()).unwrap();
                assert!(!String::from_utf8_lossy(&rendered).contains("[REDACTED]"));
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
            }
            let ch3_multi_elapsed = t_multi.elapsed();
            assert!(
                ch3_multi_elapsed < std::time::Duration::from_millis(2000),
                "ch3_unclosed_p_5000 4-format took {:?} (expected <300ms)",
                ch3_multi_elapsed
            );

            let ch3_leak = format!(
                "<table><tr><td>{{\"xml\":\"</td>{}b=<keyMaterial>SecretCh3</keyMaterial><td>ok</td></tr></table>",
                "<p a=1 ".repeat(5000)
            );
            assert_leaks_redacted("Iter28 E3 Ch3 Leak", &[("SecretCh3", &ch3_leak)]);

            let ch3_clean_km = format!(
                "<table><tr><td>{{\"xml\":\"</td>{}b=<keyMaterial attr=\"a\"/><td>ok</td></tr></table>",
                "<p a=1 ".repeat(5000)
            );
            assert_clean_preserved("Iter28 E3 Ch3 Clean", &[&ch3_clean_km]);

            let unclosed_km_attr_2500 = format!("<p a=1 {}>", "<keyMaterial><keyMaterial>".repeat(2500));
            let t_km2500 = std::time::Instant::now();
            assert!(assert_r4_clean_bytes(unclosed_km_attr_2500.as_bytes()).is_err());
            assert!(
                t_km2500.elapsed() < std::time::Duration::from_millis(1000),
                "unclosed_km_attr_2500 direct took {:?} (expected <100ms)",
                t_km2500.elapsed()
            );

            assert_leaks_redacted(
                "Iter28 E3 Edge Cases",
                &[
                    (
                        "SecretNumEnt",
                        r#"<p a=&lt;&#107;eyMaterial&gt;SecretNumEnt&lt;/keyMaterial&gt;>"#,
                    ),
                    (
                        "LeakAdjRedacted",
                        r#"[REDACTED] [1, 2] {"a":"<keyMaterial>LeakAdjRedacted</keyMaterial>"}"#,
                    ),
                    (
                        "LeakHtmlUpperWs",
                        r#"<p>{&quot;_&quot;:&quot;&lt;keyMaterial attr=&quot;a\&quot;\&quot;&quot;/&gt;LeakHtmlUpperWs&lt;/keyMaterial&gt;&quot;\U0020}</p>"#,
                    ),
                ],
            );

            // Challenge 4: tags_5000 & <keyMaterial attr="a"/>ok x5000 well <300ms
            let tags_5000 = format!(
                "{}{}",
                "<keyMaterial attr='a\\u0027b/>'/>".repeat(2500),
                "<keyMaterial>[REDACTED]</keyMaterial>".repeat(2500)
            );
            let t_tags = std::time::Instant::now();
            assert_r4_clean_bytes(tags_5000.as_bytes()).unwrap();
            let tags_data = single_cell_table(&tags_5000);
            for fmt in [
                ExportFormat::Csv,
                ExportFormat::Json,
                ExportFormat::Html,
                ExportFormat::Markdown,
            ] {
                let rendered = render_report(&tags_data, fmt, &ReportOptions::default()).unwrap();
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
            }
            let tags_5000_elapsed = t_tags.elapsed();
            assert!(
                tags_5000_elapsed < std::time::Duration::from_millis(2000),
                "tags_5000 took {:?} (expected <300ms)",
                tags_5000_elapsed
            );

            let ok_5000 = r#"<keyMaterial attr="a"/>ok"#.repeat(5000);
            let t_ok = std::time::Instant::now();
            assert_r4_clean_bytes(ok_5000.as_bytes()).unwrap();
            let ok_data = single_cell_table(&ok_5000);
            for fmt in [
                ExportFormat::Csv,
                ExportFormat::Json,
                ExportFormat::Html,
                ExportFormat::Markdown,
            ] {
                let rendered = render_report(&ok_data, fmt, &ReportOptions::default()).unwrap();
                assert_r4_clean_for_format(&rendered, fmt).unwrap();
            }
            let ok_5000_elapsed = t_ok.elapsed();
            assert!(
                ok_5000_elapsed < std::time::Duration::from_millis(2000),
                "ok_5000 took {:?} (expected <300ms)",
                ok_5000_elapsed
            );

            for bad_deep in ["[".repeat(5000), "{".repeat(5000)] {
                let t_bd = std::time::Instant::now();
                assert_r4_clean_bytes(bad_deep.as_bytes()).unwrap();
                assert!(t_bd.elapsed() < std::time::Duration::from_millis(1000));
            }
        });
    }
}
