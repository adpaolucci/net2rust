use std::collections::HashSet;
use std::fs;
use std::path::Path;

use chrono::{DateTime, NaiveDate, Utc};
use guap_table::{CellValue, CompareOp, FilterExpr};
use net2rust_core::{NetError, NetResult, OfflineConfig};
use serde::de::DeserializeOwned;

/// Normalizes a Windows GUID string (with or without `{}` braces) into canonical
/// uppercase braced form `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
pub fn parse_guid_flexible(input: &str) -> NetResult<String> {
    let trimmed = input.trim();
    let stripped = trimmed
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(trimmed);

    let parts: Vec<&str> = stripped.split('-').collect();
    if parts.len() != 5
        || parts[0].len() != 8
        || parts[1].len() != 4
        || parts[2].len() != 4
        || parts[3].len() != 4
        || parts[4].len() != 12
        || !parts.iter().all(|part| part.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(NetError::InvalidInput(format!("invalid GUID format: '{input}'")));
    }

    Ok(format!("{{{}}}", stripped.to_ascii_uppercase()))
}

/// Strips surrounding `{}` braces from a validated or raw GUID string.
pub fn strip_guid_braces(input: &str) -> String {
    let trimmed = input.trim();
    trimmed
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(trimmed)
        .to_string()
}

/// Decodes a 16-byte little-endian Windows `SYSTEMTIME` buffer (used by
/// `NetworkList\Profiles\{GUID}\DateLastConnected`) into `DateTime<Utc>`.
///
/// Returns `None` for truncated, all-zero, or invalid calendar values without panicking.
pub fn decode_registry_systemtime(bytes: &[u8]) -> Option<DateTime<Utc>> {
    if bytes.len() < 16 {
        return None;
    }
    let year = u16::from_le_bytes([bytes[0], bytes[1]]) as i32;
    let month = u16::from_le_bytes([bytes[2], bytes[3]]) as u32;
    let _day_of_week = u16::from_le_bytes([bytes[4], bytes[5]]);
    let day = u16::from_le_bytes([bytes[6], bytes[7]]) as u32;
    let hour = u16::from_le_bytes([bytes[8], bytes[9]]) as u32;
    let minute = u16::from_le_bytes([bytes[10], bytes[11]]) as u32;
    let second = u16::from_le_bytes([bytes[12], bytes[13]]) as u32;
    let millis = u16::from_le_bytes([bytes[14], bytes[15]]) as u32;

    if year == 0 && month == 0 && day == 0 {
        return None;
    }
    let date = NaiveDate::from_ymd_opt(year, month, day)?;
    let dt = date.and_hms_milli_opt(hour, minute, second, millis)?;
    Some(dt.and_utc())
}

/// Converts a Windows `FILETIME` (100-nanosecond intervals since 1601-01-01T00:00:00Z)
/// into `DateTime<Utc>`. Returns `None` if zero or prior to the Unix epoch.
pub fn filetime_to_utc(filetime: u64) -> Option<DateTime<Utc>> {
    const UNIX_EPOCH_IN_100NS: u64 = 116_444_736_000_000_000;
    if filetime == 0 || filetime < UNIX_EPOCH_IN_100NS {
        return None;
    }
    let since_unix = filetime - UNIX_EPOCH_IN_100NS;
    let secs = (since_unix / 10_000_000) as i64;
    let nanos = ((since_unix % 10_000_000) * 100) as u32;
    DateTime::<Utc>::from_timestamp(secs, nanos)
}

/// Result of planning a directive-consuming `TableProvider` query.
#[derive(Debug, Clone)]
pub struct FilterPlan {
    pub targets: Vec<String>,
    pub include_defaults: bool,
    pub remaining_filter: Option<FilterExpr>,
}

/// Plans target extraction, default/seed row inclusion, and normalized filter rewriting
/// for directive-consuming `TableProvider`s.
pub fn plan_filter_query<V, N>(
    expr: Option<&FilterExpr>,
    target_cols: &[&str],
    contains_validator: V,
    normalizer: N,
) -> FilterPlan
where
    V: Fn(&str) -> bool,
    N: Fn(&str) -> Option<String>,
{
    let Some(expr) = expr else {
        return FilterPlan {
            targets: Vec::new(),
            include_defaults: true,
            remaining_filter: None,
        };
    };

    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    collect_targets_validated(expr, target_cols, &contains_validator, &mut targets, &mut seen);

    let include_defaults = needs_defaults(expr, target_cols, &contains_validator);
    let canonical_col = target_cols.first().copied();
    let normalized = normalize_filter_expr(expr, target_cols, canonical_col, &contains_validator, &normalizer);
    let remaining_filter = strip_inner_with(&normalized, target_cols, &contains_validator);

    FilterPlan {
        targets,
        include_defaults,
        remaining_filter,
    }
}

/// Extracts string values targeted by `Eq` or validated `Contains` predicates on `target_cols`
/// ONLY from top-level or `And`-conjunctive positions (never from `Or` or `Not`).
pub fn extract_conjunctive_targets<V>(
    expr: Option<&FilterExpr>,
    target_cols: &[&str],
    contains_validator: V,
) -> Vec<String>
where
    V: Fn(&str) -> bool,
{
    let Some(expr) = expr else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    collect_conjunctive_targets(expr, target_cols, &contains_validator, &mut out, &mut seen);
    out
}

/// Normalizes directive predicate values and column aliases on `target_cols` in-place
/// (preserving all boolean combinators `And`/`Or`/`Not`).
pub fn normalize_filter_columns<V, N>(
    expr: Option<&FilterExpr>,
    target_cols: &[&str],
    contains_validator: V,
    normalizer: N,
) -> Option<FilterExpr>
where
    V: Fn(&str) -> bool,
    N: Fn(&str) -> Option<String>,
{
    let expr = expr?;
    let canonical_col = target_cols.first().copied();
    Some(normalize_filter_expr(
        expr,
        target_cols,
        canonical_col,
        &contains_validator,
        &normalizer,
    ))
}

/// Extracts string values targeted by `Eq` or `Contains` predicates on any column in `target_cols`
/// (case-insensitive) from a `FilterExpr`.
pub fn extract_filter_targets(expr: Option<&FilterExpr>, target_cols: &[&str]) -> Vec<String> {
    let Some(expr) = expr else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    collect_targets_validated(expr, target_cols, &|_| true, &mut out, &mut seen);
    out
}

fn collect_conjunctive_targets<V>(
    expr: &FilterExpr,
    target_cols: &[&str],
    contains_validator: &V,
    out: &mut Vec<String>,
    seen: &mut HashSet<String>,
) where
    V: Fn(&str) -> bool,
{
    match expr {
        FilterExpr::Compare {
            column,
            op: CompareOp::Eq,
            value,
        } => {
            if matches_any_col(column, target_cols)
                && let Some(val) = cell_to_target_string(value)
                && seen.insert(val.clone())
            {
                out.push(val);
            }
        }
        FilterExpr::Contains {
            column: Some(column),
            pattern,
            ..
        } => {
            if matches_any_col(column, target_cols) {
                let trimmed = pattern.trim();
                let tokens = split_target_list(trimmed);
                if !tokens.is_empty()
                    && tokens.iter().all(|tok| contains_validator(tok))
                    && seen.insert(trimmed.to_string())
                {
                    out.push(trimmed.to_string());
                }
            }
        }
        FilterExpr::And(items) => {
            for item in items {
                collect_conjunctive_targets(item, target_cols, contains_validator, out, seen);
            }
        }
        _ => {}
    }
}

fn collect_targets_validated<V>(
    expr: &FilterExpr,
    target_cols: &[&str],
    contains_validator: &V,
    out: &mut Vec<String>,
    seen: &mut HashSet<String>,
) where
    V: Fn(&str) -> bool,
{
    match expr {
        FilterExpr::Compare {
            column,
            op: CompareOp::Eq,
            value,
        } => {
            if matches_any_col(column, target_cols)
                && let Some(val) = cell_to_target_string(value)
                && seen.insert(val.clone())
            {
                out.push(val);
            }
        }
        FilterExpr::Contains {
            column: Some(column),
            pattern,
            ..
        } => {
            if matches_any_col(column, target_cols) {
                let trimmed = pattern.trim();
                let tokens = split_target_list(trimmed);
                if !tokens.is_empty()
                    && tokens.iter().all(|tok| contains_validator(tok))
                    && seen.insert(trimmed.to_string())
                {
                    out.push(trimmed.to_string());
                }
            }
        }
        FilterExpr::And(items) | FilterExpr::Or(items) => {
            for item in items {
                collect_targets_validated(item, target_cols, contains_validator, out, seen);
            }
        }
        FilterExpr::Not(_)
        | FilterExpr::Compare { .. }
        | FilterExpr::Contains { column: None, .. }
        | FilterExpr::Regex { .. }
        | FilterExpr::IsNull { .. }
        | FilterExpr::IsNotNull { .. } => {}
    }
}

fn needs_defaults<V>(expr: &FilterExpr, target_cols: &[&str], contains_validator: &V) -> bool
where
    V: Fn(&str) -> bool,
{
    match expr {
        FilterExpr::Compare {
            column,
            op: CompareOp::Eq,
            value,
        } if matches_any_col(column, target_cols) && cell_to_target_string(value).is_some() => false,
        FilterExpr::Contains {
            column: Some(column),
            pattern,
            ..
        } if matches_any_col(column, target_cols) => {
            let tokens = split_target_list(pattern.trim());
            tokens.is_empty() || !tokens.iter().all(|tok| contains_validator(tok))
        }
        FilterExpr::And(items) => items
            .iter()
            .all(|item| needs_defaults(item, target_cols, contains_validator)),
        FilterExpr::Or(items) => items
            .iter()
            .any(|item| needs_defaults(item, target_cols, contains_validator)),
        _ => true,
    }
}

fn normalize_filter_expr<V, N>(
    expr: &FilterExpr,
    target_cols: &[&str],
    canonical_col: Option<&str>,
    contains_validator: &V,
    normalizer: &N,
) -> FilterExpr
where
    V: Fn(&str) -> bool,
    N: Fn(&str) -> Option<String>,
{
    let resolve_col = |col: &str| -> String {
        if matches_any_col(col, target_cols)
            && let Some(canon) = canonical_col
        {
            canon.to_string()
        } else {
            col.to_string()
        }
    };

    match expr {
        FilterExpr::Compare {
            column,
            op: CompareOp::Eq,
            value,
        } if matches_any_col(column, target_cols) => {
            let out_col = resolve_col(column);
            if let Some(raw) = cell_to_target_string(value) {
                if !raw.contains(',') && !raw.contains(';') && contains_validator(&raw) {
                    let val = normalizer(&raw).unwrap_or(raw);
                    return FilterExpr::Compare {
                        column: out_col,
                        op: CompareOp::Eq,
                        value: CellValue::Text(val),
                    };
                }
                let tokens = split_target_list(&raw);
                if tokens.len() > 1 {
                    let branches = tokens
                        .into_iter()
                        .map(|tok| {
                            let val = normalizer(&tok).unwrap_or(tok);
                            FilterExpr::Compare {
                                column: out_col.clone(),
                                op: CompareOp::Eq,
                                value: CellValue::Text(val),
                            }
                        })
                        .collect();
                    return FilterExpr::Or(branches);
                } else if let Some(tok) = tokens.into_iter().next() {
                    let val = normalizer(&tok).unwrap_or(tok);
                    return FilterExpr::Compare {
                        column: out_col,
                        op: CompareOp::Eq,
                        value: CellValue::Text(val),
                    };
                }
            }
            FilterExpr::Compare {
                column: out_col,
                op: CompareOp::Eq,
                value: value.clone(),
            }
        }
        FilterExpr::Compare { column, op, value } => FilterExpr::Compare {
            column: resolve_col(column),
            op: *op,
            value: value.clone(),
        },
        FilterExpr::Contains {
            column: Some(column),
            pattern,
            case_sensitive,
        } if matches_any_col(column, target_cols) => {
            let out_col = resolve_col(column);
            let tokens = split_target_list(pattern.trim());
            if !tokens.is_empty() && tokens.iter().all(|tok| contains_validator(tok)) {
                if tokens.len() > 1 {
                    let branches = tokens
                        .into_iter()
                        .map(|tok| FilterExpr::Contains {
                            column: Some(out_col.clone()),
                            pattern: normalizer(&tok).unwrap_or(tok),
                            case_sensitive: *case_sensitive,
                        })
                        .collect();
                    return FilterExpr::Or(branches);
                } else if let Some(tok) = tokens.into_iter().next() {
                    return FilterExpr::Contains {
                        column: Some(out_col),
                        pattern: normalizer(&tok).unwrap_or(tok),
                        case_sensitive: *case_sensitive,
                    };
                }
            }
            FilterExpr::Contains {
                column: Some(out_col),
                pattern: pattern.clone(),
                case_sensitive: *case_sensitive,
            }
        }
        FilterExpr::Regex {
            column: Some(column),
            pattern,
        } => FilterExpr::Regex {
            column: Some(resolve_col(column)),
            pattern: pattern.clone(),
        },
        FilterExpr::IsNull { column } => FilterExpr::IsNull {
            column: resolve_col(column),
        },
        FilterExpr::IsNotNull { column } => FilterExpr::IsNotNull {
            column: resolve_col(column),
        },
        FilterExpr::And(items) => FilterExpr::And(
            items
                .iter()
                .map(|i| normalize_filter_expr(i, target_cols, canonical_col, contains_validator, normalizer))
                .collect(),
        ),
        FilterExpr::Or(items) => FilterExpr::Or(
            items
                .iter()
                .map(|i| normalize_filter_expr(i, target_cols, canonical_col, contains_validator, normalizer))
                .collect(),
        ),
        FilterExpr::Not(inner) => FilterExpr::Not(Box::new(normalize_filter_expr(
            inner,
            target_cols,
            canonical_col,
            contains_validator,
            normalizer,
        ))),
        other => other.clone(),
    }
}

/// Strips `Eq` / `Contains` directive predicates on `consumed_cols` from a `FilterExpr`
/// while preserving any remaining filter predicates (e.g., `RecordType == "MX"`).
/// Mixed `FilterExpr::Or` expressions (where some branches are non-directive) and `FilterExpr::Not`
/// expressions are preserved intact so `OR`/`NOT` semantics are never corrupted.
pub fn strip_consumed_filter(expr: Option<&FilterExpr>, consumed_cols: &[&str]) -> Option<FilterExpr> {
    let expr = expr?;
    strip_inner_with(expr, consumed_cols, &|_| true)
}

/// Variant of [`strip_consumed_filter`] that only strips `Contains` predicates whose tokens
/// satisfy `contains_validator` (leaving partial substring `Contains` predicates intact).
pub fn strip_consumed_filter_validated<V>(
    expr: Option<&FilterExpr>,
    consumed_cols: &[&str],
    contains_validator: V,
) -> Option<FilterExpr>
where
    V: Fn(&str) -> bool,
{
    let expr = expr?;
    strip_inner_with(expr, consumed_cols, &contains_validator)
}

fn strip_inner_with<V>(expr: &FilterExpr, consumed_cols: &[&str], contains_validator: &V) -> Option<FilterExpr>
where
    V: Fn(&str) -> bool,
{
    match expr {
        FilterExpr::Compare {
            column,
            op: CompareOp::Eq,
            value,
        } if matches_any_col(column, consumed_cols) && cell_to_target_string(value).is_some() => None,
        FilterExpr::Contains {
            column: Some(column),
            pattern,
            ..
        } if matches_any_col(column, consumed_cols) => {
            let tokens = split_target_list(pattern.trim());
            if !tokens.is_empty() && tokens.iter().all(|tok| contains_validator(tok)) {
                None
            } else {
                Some(expr.clone())
            }
        }
        FilterExpr::And(items) => {
            let results: Vec<Option<FilterExpr>> = items
                .iter()
                .map(|item| strip_inner_with(item, consumed_cols, contains_validator))
                .collect();
            let consumed_count = results.iter().filter(|r| r.is_none()).count();
            let all_same_single_eq = if consumed_count > 1 {
                let mut distinct_vals = HashSet::new();
                let mut all_eq = true;
                for (item, res) in items.iter().zip(results.iter()) {
                    if res.is_none() {
                        if let FilterExpr::Compare {
                            column,
                            op: CompareOp::Eq,
                            value,
                        } = item
                            && matches_any_col(column, consumed_cols)
                            && let Some(val) = cell_to_target_string(value)
                        {
                            distinct_vals.insert(val);
                        } else {
                            all_eq = false;
                            break;
                        }
                    }
                }
                all_eq && distinct_vals.len() == 1
            } else {
                true
            };

            let kept: Vec<FilterExpr> = items
                .iter()
                .zip(results)
                .filter_map(|(item, res)| match res {
                    None if all_same_single_eq => None,
                    None => Some(item.clone()),
                    Some(rem) => Some(rem),
                })
                .collect();
            match kept.len() {
                0 => None,
                1 => kept.into_iter().next(),
                _ => Some(FilterExpr::And(kept)),
            }
        }
        FilterExpr::Or(items) => {
            if items
                .iter()
                .all(|item| strip_inner_with(item, consumed_cols, contains_validator).is_none())
            {
                None
            } else {
                Some(expr.clone())
            }
        }
        other => Some(other.clone()),
    }
}

fn matches_any_col(col: &str, candidates: &[&str]) -> bool {
    candidates.iter().any(|c| c.eq_ignore_ascii_case(col))
}

fn cell_to_target_string(value: &CellValue) -> Option<String> {
    match value {
        CellValue::Text(s) => {
            let trimmed = s.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }
        _ => None,
    }
}

/// Splits a comma/semicolon/whitespace-separated target list into non-empty tokens.
pub fn split_target_list(raw: &str) -> Vec<String> {
    raw.split(|c: char| c == ',' || c == ';' || c.is_ascii_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Reads non-empty, non-comment lines from `fixture_dir/<filename>` when configured.
pub fn load_fixture_lines(cfg: &OfflineConfig, filename: &str) -> NetResult<Option<Vec<String>>> {
    let Some(dir) = &cfg.fixture_dir else {
        return Ok(None);
    };
    let path = dir.join(filename);
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path)?;
    let lines = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    Ok(Some(lines))
}

/// Reads and deserializes JSON from `fixture_dir/<filename>` when present.
pub fn load_fixture_json<T: DeserializeOwned>(cfg: &OfflineConfig, filename: &str) -> NetResult<Option<T>> {
    let Some(dir) = &cfg.fixture_dir else {
        return Ok(None);
    };
    let path = dir.join(filename);
    if !path.exists() {
        return Ok(None);
    }
    read_json_file(&path).map(Some)
}

pub fn read_json_file<T: DeserializeOwned>(path: &Path) -> NetResult<T> {
    let text = fs::read_to_string(path)?;
    serde_json::from_str(&text)
        .map_err(|e| NetError::ParseError(format!("failed to parse JSON '{}': {e}", path.display())))
}
