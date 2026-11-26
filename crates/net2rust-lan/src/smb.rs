use std::sync::Arc;
use std::time::Duration;

use guap_mcp::{ActionCommand, ActionRiskLevel, McpToolError};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use net2rust_core::{NetContext, NetError, NetResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::common::reject_unknown_json_keys;
use crate::fixtures;

const MAX_WNET_BUF_BYTES: usize = 4 * 1024 * 1024;

fn next_wnet_buf_u64s(current_u64s: usize, reported_bytes: usize) -> NetResult<usize> {
    let doubled_bytes = current_u64s.saturating_mul(8).saturating_mul(2);
    let needed_bytes = reported_bytes.max(doubled_bytes);
    if needed_bytes > MAX_WNET_BUF_BYTES {
        return Err(NetError::Internal(format!(
            "WNetEnumResourceW buffer exceeded {MAX_WNET_BUF_BYTES} byte limit (requested {needed_bytes} bytes)"
        )));
    }
    Ok(needed_bytes.div_ceil(8))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareRecord {
    pub server: String,
    pub share_name: String,
    pub unc_path: String,
    pub share_type: String,
    pub local_path: Option<String>,
    pub current_uses: Option<u64>,
    pub max_uses: Option<u64>,
    pub remark: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenFileRecord {
    pub file_id: u64,
    pub pathname: String,
    pub username: String,
    pub permissions: String,
    pub locks: u64,
    pub server: String,
}

pub trait ShareBackend: Send + Sync {
    fn enum_local_shares(&self, server: Option<&str>) -> NetResult<Vec<ShareRecord>>;
    fn enum_wnet_resources(&self, max_depth: usize, timeout: Duration) -> NetResult<Vec<ShareRecord>>;
}

pub trait OpenFilesBackend: Send + Sync {
    fn enum_open_files(&self, server: Option<&str>) -> NetResult<Vec<OpenFileRecord>>;
    fn close_open_file(&self, server: Option<&str>, file_id: u32) -> NetResult<()>;
}

/// Pure-Rust decoder for Win32 `SHARE_TYPE` (`STYPE_*`) bitmask.
pub fn format_share_type(raw_type: u32) -> String {
    let base = raw_type & 0xFF;
    let is_special = (raw_type & 0x8000_0000) != 0;
    let base_name = match base {
        0 => {
            if is_special {
                "Admin"
            } else {
                "Disk"
            }
        }
        1 => "Print",
        2 => "Device",
        3 => "IPC",
        _ => "Unknown",
    };
    base_name.to_string()
}

/// Pure-Rust decoder for Win32 `FILE_INFO_3::fi3_permissions` (`PERM_FILE_*`).
pub fn format_file_permissions(perms: u32) -> String {
    let read = (perms & 0x01) != 0;
    let write = (perms & 0x02) != 0;
    let create = (perms & 0x04) != 0;
    let mut parts = Vec::new();
    if read {
        parts.push("Read");
    }
    if write {
        parts.push("Write");
    }
    if create {
        parts.push("Create");
    }
    if parts.is_empty() {
        format!("0x{perms:x}")
    } else {
        parts.join("+")
    }
}

#[derive(Debug, Default)]
pub struct LiveWin32SmbBackend;

impl ShareBackend for LiveWin32SmbBackend {
    fn enum_local_shares(&self, server: Option<&str>) -> NetResult<Vec<ShareRecord>> {
        #[cfg(windows)]
        {
            win32_smb::enum_shares_win32(server)
        }
        #[cfg(not(windows))]
        {
            let _ = server;
            Err(NetError::NotSupported("NetShareEnum requires Windows".into()))
        }
    }

    fn enum_wnet_resources(&self, max_depth: usize, timeout: Duration) -> NetResult<Vec<ShareRecord>> {
        #[cfg(windows)]
        {
            win32_smb::enum_wnet_win32(max_depth, timeout)
        }
        #[cfg(not(windows))]
        {
            let _ = (max_depth, timeout);
            Ok(Vec::new())
        }
    }
}

impl OpenFilesBackend for LiveWin32SmbBackend {
    fn enum_open_files(&self, server: Option<&str>) -> NetResult<Vec<OpenFileRecord>> {
        #[cfg(windows)]
        {
            win32_smb::enum_open_files_win32(server)
        }
        #[cfg(not(windows))]
        {
            let _ = server;
            Err(NetError::NotSupported("NetFileEnum requires Windows".into()))
        }
    }

    fn close_open_file(&self, server: Option<&str>, file_id: u32) -> NetResult<()> {
        #[cfg(windows)]
        {
            win32_smb::close_open_file_win32(server, file_id)
        }
        #[cfg(not(windows))]
        {
            let _ = (server, file_id);
            Err(NetError::NotSupported("NetFileClose requires Windows".into()))
        }
    }
}

#[cfg(windows)]
mod win32_smb {
    use std::ffi::c_void;
    use std::ptr;
    use std::time::{Duration, Instant};

    use net2rust_core::{NetError, NetResult};
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_BAD_NETPATH, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA,
        ERROR_NO_MORE_ITEMS, ERROR_NOT_SUPPORTED, HANDLE, NO_ERROR,
    };
    use windows::Win32::NetworkManagement::NetManagement::{
        MAX_PREFERRED_LENGTH, NERR_FileIdNotFound, NERR_InvalidComputer, NERR_Success, NetApiBufferFree,
    };
    use windows::Win32::NetworkManagement::WNet::{
        NET_RESOURCE_SCOPE, NETRESOURCEW, RESOURCE_CONNECTED, RESOURCE_GLOBALNET, RESOURCE_REMEMBERED,
        RESOURCEDISPLAYTYPE_DIRECTORY, RESOURCEDISPLAYTYPE_NETWORK, RESOURCEDISPLAYTYPE_ROOT,
        RESOURCEDISPLAYTYPE_SHAREADMIN, RESOURCETYPE_ANY, RESOURCEUSAGE_CONTAINER, WNetCloseEnum, WNetEnumResourceW,
        WNetOpenEnumW,
    };
    use windows::Win32::Storage::FileSystem::{
        FILE_INFO_3, NetFileClose, NetFileEnum, NetShareEnum, SHARE_INFO_1, SHARE_INFO_2,
    };
    use windows::core::PCWSTR;

    use super::{OpenFileRecord, ShareRecord, format_file_permissions, format_share_type};
    use crate::common::{pwstr_to_string, to_wide_null};

    // DisplayType constants omitted from `windows 0.62.2` `WNet`:
    const RESOURCEDISPLAYTYPE_GENERIC: u32 = 0;
    const RESOURCEDISPLAYTYPE_DOMAIN: u32 = 1;
    const RESOURCEDISPLAYTYPE_SERVER: u32 = 2;
    const RESOURCEDISPLAYTYPE_SHARE: u32 = 3;
    const RESOURCEDISPLAYTYPE_FILE: u32 = 4;
    const RESOURCEDISPLAYTYPE_GROUP: u32 = 5;
    const RESOURCEDISPLAYTYPE_TREE: u32 = 10;

    struct NetApiBufferGuard(*mut u8);
    impl Drop for NetApiBufferGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was allocated by a NetMgmt API (`NetShareEnum`/`NetFileEnum`).
                unsafe {
                    let _ = NetApiBufferFree(Some(self.0.cast::<c_void>()));
                }
            }
        }
    }

    struct WNetEnumGuard(HANDLE);
    impl Drop for WNetEnumGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: `self.0` was opened by `WNetOpenEnumW`.
                unsafe {
                    let _ = WNetCloseEnum(self.0);
                }
            }
        }
    }

    fn server_label(server: Option<&str>) -> String {
        server
            .map(|s| s.trim_start_matches('\\').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "localhost".to_string())
    }

    pub fn enum_shares_win32(server: Option<&str>) -> NetResult<Vec<ShareRecord>> {
        let server_wide = server.map(to_wide_null);
        let server_pcwstr = server_wide
            .as_ref()
            .map(|w| PCWSTR::from_raw(w.as_ptr()))
            .unwrap_or(PCWSTR::null());

        // Try level 2 first; fall back automatically to level 1 on ERROR_ACCESS_DENIED.
        // R4 SAFETY: NEVER read, dereference, log, or expose `SHARE_INFO_2::shi2_passwd`.
        match enum_shares_level2(server_pcwstr, server) {
            Ok(rows) => Ok(rows),
            Err(NetError::PermissionDenied(_)) => enum_shares_level1(server_pcwstr, server),
            Err(err) => Err(err),
        }
    }

    fn enum_shares_level2(server_pcwstr: PCWSTR, server: Option<&str>) -> NetResult<Vec<ShareRecord>> {
        let mut out = Vec::new();
        let mut resume_handle: u32 = 0;
        let host = server_label(server);

        loop {
            let mut buf_ptr: *mut u8 = ptr::null_mut();
            let mut entries_read = 0u32;
            let mut total_entries = 0u32;
            // SAFETY: Valid `PCWSTR`, out pointers, and `resume_handle`.
            let status = unsafe {
                NetShareEnum(
                    server_pcwstr,
                    2,
                    &mut buf_ptr,
                    MAX_PREFERRED_LENGTH,
                    &mut entries_read,
                    &mut total_entries,
                    Some(&mut resume_handle),
                )
            };
            let _guard = NetApiBufferGuard(buf_ptr);

            if status == ERROR_ACCESS_DENIED.0 {
                return Err(NetError::PermissionDenied(
                    "NetShareEnum level 2 requires elevated privileges".into(),
                ));
            }
            if status != NERR_Success && status != ERROR_MORE_DATA.0 {
                return Err(map_netmgmt_error("NetShareEnum", status));
            }

            if !buf_ptr.is_null() && entries_read > 0 {
                // SAFETY: `buf_ptr` holds `entries_read` `SHARE_INFO_2` structs.
                let slice =
                    unsafe { std::slice::from_raw_parts(buf_ptr.cast::<SHARE_INFO_2>(), entries_read as usize) };
                for item in slice {
                    // SAFETY: `PWSTR` fields inside `SHARE_INFO_2` are valid within `buf_ptr`.
                    // R4 INVARIANT: `item.shi2_passwd` is intentionally untouched and never read.
                    let share_name = unsafe { pwstr_to_string(item.shi2_netname) };
                    let remark = unsafe { pwstr_to_string(item.shi2_remark) };
                    let local_path_raw = unsafe { pwstr_to_string(item.shi2_path) };
                    let local_path = if local_path_raw.is_empty() {
                        None
                    } else {
                        Some(local_path_raw)
                    };
                    let max_uses = if item.shi2_max_uses == u32::MAX {
                        None
                    } else {
                        Some(u64::from(item.shi2_max_uses))
                    };
                    out.push(ShareRecord {
                        server: host.clone(),
                        unc_path: format!(r"\\{host}\{share_name}"),
                        share_name,
                        share_type: format_share_type(item.shi2_type.0),
                        local_path,
                        current_uses: Some(u64::from(item.shi2_current_uses)),
                        max_uses,
                        remark,
                        source: "NetShareEnum".to_string(),
                    });
                }
            }

            if status != ERROR_MORE_DATA.0 {
                break;
            }
        }
        Ok(out)
    }

    fn enum_shares_level1(server_pcwstr: PCWSTR, server: Option<&str>) -> NetResult<Vec<ShareRecord>> {
        let mut out = Vec::new();
        let mut resume_handle: u32 = 0;
        let host = server_label(server);

        loop {
            let mut buf_ptr: *mut u8 = ptr::null_mut();
            let mut entries_read = 0u32;
            let mut total_entries = 0u32;
            // SAFETY: Valid `PCWSTR`, out pointers, and `resume_handle`.
            let status = unsafe {
                NetShareEnum(
                    server_pcwstr,
                    1,
                    &mut buf_ptr,
                    MAX_PREFERRED_LENGTH,
                    &mut entries_read,
                    &mut total_entries,
                    Some(&mut resume_handle),
                )
            };
            let _guard = NetApiBufferGuard(buf_ptr);

            if status != NERR_Success && status != ERROR_MORE_DATA.0 {
                return Err(map_netmgmt_error("NetShareEnum(level 1)", status));
            }

            if !buf_ptr.is_null() && entries_read > 0 {
                // SAFETY: `buf_ptr` holds `entries_read` `SHARE_INFO_1` structs.
                let slice =
                    unsafe { std::slice::from_raw_parts(buf_ptr.cast::<SHARE_INFO_1>(), entries_read as usize) };
                for item in slice {
                    // SAFETY: `PWSTR` fields inside `SHARE_INFO_1` are valid within `buf_ptr`.
                    let share_name = unsafe { pwstr_to_string(item.shi1_netname) };
                    let remark = unsafe { pwstr_to_string(item.shi1_remark) };
                    out.push(ShareRecord {
                        server: host.clone(),
                        unc_path: format!(r"\\{host}\{share_name}"),
                        share_name,
                        share_type: format_share_type(item.shi1_type.0),
                        local_path: None,
                        current_uses: None,
                        max_uses: None,
                        remark,
                        source: "NetShareEnum".to_string(),
                    });
                }
            }

            if status != ERROR_MORE_DATA.0 {
                break;
            }
        }
        Ok(out)
    }

    pub fn enum_wnet_win32(max_depth: usize, timeout: Duration) -> NetResult<Vec<ShareRecord>> {
        let deadline = Instant::now() + timeout;
        let mut out = Vec::new();
        for scope in [RESOURCE_CONNECTED, RESOURCE_REMEMBERED] {
            walk_wnet_scope(scope, None, 0, max_depth, deadline, &mut out)?;
        }
        if Instant::now() < deadline {
            walk_wnet_scope(RESOURCE_GLOBALNET, None, 0, max_depth.min(2), deadline, &mut out)?;
        }
        Ok(out)
    }

    fn walk_wnet_scope(
        scope: NET_RESOURCE_SCOPE,
        container: Option<*const NETRESOURCEW>,
        depth: usize,
        max_depth: usize,
        deadline: Instant,
        out: &mut Vec<ShareRecord>,
    ) -> NetResult<()> {
        if depth > max_depth || Instant::now() >= deadline || out.len() >= 512 {
            return Ok(());
        }

        let mut enum_handle = HANDLE::default();
        // SAFETY: Opens a WNet enumeration handle for the specified scope/container.
        let rc = unsafe { WNetOpenEnumW(scope, RESOURCETYPE_ANY, Default::default(), container, &mut enum_handle) };
        if rc != NO_ERROR {
            return Ok(());
        }
        let _guard = WNetEnumGuard(enum_handle);

        let mut buf: Vec<u64> = vec![0u64; 2048];
        loop {
            if Instant::now() >= deadline || out.len() >= 512 {
                break;
            }
            let mut count = u32::MAX;
            let mut buf_size = (buf.len() * 8) as u32;
            // SAFETY: `buf` is 8-byte aligned and sized `buf_size` bytes.
            let enum_rc = unsafe {
                WNetEnumResourceW(
                    enum_handle,
                    &mut count,
                    buf.as_mut_ptr().cast::<c_void>(),
                    &mut buf_size,
                )
            };
            if enum_rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if enum_rc == ERROR_MORE_DATA {
                let needed_u64s = super::next_wnet_buf_u64s(buf.len(), buf_size as usize)?;
                buf.resize(needed_u64s, 0);
                continue;
            }
            if enum_rc != NO_ERROR {
                break;
            }

            // SAFETY: `WNetEnumResourceW` wrote `count` `NETRESOURCEW` structs at start of `buf`.
            let entries = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<NETRESOURCEW>(), count as usize) };
            for nr in entries {
                if Instant::now() >= deadline || out.len() >= 512 {
                    break;
                }
                // SAFETY: Strings referenced by `nr` live inside `buf`.
                let remote = unsafe { pwstr_to_string(nr.lpRemoteName) };
                let local = unsafe { pwstr_to_string(nr.lpLocalName) };
                let comment = unsafe { pwstr_to_string(nr.lpComment) };
                let provider = unsafe { pwstr_to_string(nr.lpProvider) };

                if !remote.is_empty() && nr.dwDisplayType != RESOURCEDISPLAYTYPE_GENERIC {
                    let display_label = match nr.dwDisplayType {
                        RESOURCEDISPLAYTYPE_DOMAIN => "Domain",
                        RESOURCEDISPLAYTYPE_SERVER => "Server",
                        RESOURCEDISPLAYTYPE_SHARE => "Disk",
                        RESOURCEDISPLAYTYPE_FILE => "File",
                        RESOURCEDISPLAYTYPE_GROUP => "Group",
                        RESOURCEDISPLAYTYPE_TREE => "Tree",
                        x if x == RESOURCEDISPLAYTYPE_NETWORK => "Network",
                        x if x == RESOURCEDISPLAYTYPE_ROOT => "Root",
                        x if x == RESOURCEDISPLAYTYPE_SHAREADMIN => "Admin",
                        x if x == RESOURCEDISPLAYTYPE_DIRECTORY => "Directory",
                        _ => "Disk",
                    };
                    let (server, share_name) = parse_unc_parts(&remote);
                    out.push(ShareRecord {
                        server,
                        share_name,
                        unc_path: remote,
                        share_type: display_label.to_string(),
                        local_path: if local.is_empty() { None } else { Some(local) },
                        current_uses: None,
                        max_uses: None,
                        remark: if comment.is_empty() { provider } else { comment },
                        source: "WNet".to_string(),
                    });
                }

                if scope == RESOURCE_GLOBALNET && (nr.dwUsage & RESOURCEUSAGE_CONTAINER.0) != 0 && depth < max_depth {
                    walk_wnet_scope(
                        RESOURCE_GLOBALNET,
                        Some(nr as *const NETRESOURCEW),
                        depth + 1,
                        max_depth,
                        deadline,
                        out,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn parse_unc_parts(remote: &str) -> (String, String) {
        let trimmed = remote.trim_start_matches('\\');
        if let Some((srv, share)) = trimmed.split_once('\\') {
            (srv.to_string(), share.to_string())
        } else {
            (trimmed.to_string(), String::new())
        }
    }

    pub fn enum_open_files_win32(server: Option<&str>) -> NetResult<Vec<OpenFileRecord>> {
        let server_wide = server.map(to_wide_null);
        let server_pcwstr = server_wide
            .as_ref()
            .map(|w| PCWSTR::from_raw(w.as_ptr()))
            .unwrap_or(PCWSTR::null());
        let host = server_label(server);

        let mut out = Vec::new();
        let mut resume_handle: usize = 0;

        loop {
            let mut buf_ptr: *mut u8 = ptr::null_mut();
            let mut entries_read = 0u32;
            let mut total_entries = 0u32;
            // SAFETY: Valid `PCWSTR`s, out pointers, and `resume_handle` (`usize`).
            let status = unsafe {
                NetFileEnum(
                    server_pcwstr,
                    PCWSTR::null(),
                    PCWSTR::null(),
                    3,
                    &mut buf_ptr,
                    MAX_PREFERRED_LENGTH,
                    &mut entries_read,
                    &mut total_entries,
                    Some(&mut resume_handle),
                )
            };
            let _guard = NetApiBufferGuard(buf_ptr);

            if status != NERR_Success && status != ERROR_MORE_DATA.0 {
                return Err(map_netmgmt_error("NetFileEnum", status));
            }

            if !buf_ptr.is_null() && entries_read > 0 {
                // SAFETY: `buf_ptr` holds `entries_read` `FILE_INFO_3` entries.
                let slice = unsafe { std::slice::from_raw_parts(buf_ptr.cast::<FILE_INFO_3>(), entries_read as usize) };
                for item in slice {
                    // SAFETY: `PWSTR` fields inside `FILE_INFO_3` point within `buf_ptr`.
                    let pathname = unsafe { pwstr_to_string(item.fi3_pathname) };
                    let username = unsafe { pwstr_to_string(item.fi3_username) };
                    out.push(OpenFileRecord {
                        file_id: u64::from(item.fi3_id),
                        pathname,
                        username,
                        permissions: format_file_permissions(item.fi3_permissions.0),
                        locks: u64::from(item.fi3_num_locks),
                        server: host.clone(),
                    });
                }
            }

            if status != ERROR_MORE_DATA.0 {
                break;
            }
        }
        Ok(out)
    }

    pub fn close_open_file_win32(server: Option<&str>, file_id: u32) -> NetResult<()> {
        let server_wide = server.map(to_wide_null);
        let server_pcwstr = server_wide
            .as_ref()
            .map(|w| PCWSTR::from_raw(w.as_ptr()))
            .unwrap_or(PCWSTR::null());

        // SAFETY: `server_pcwstr` is null or points to `server_wide` which outlives the call.
        let status = unsafe { NetFileClose(server_pcwstr, file_id) };
        if status == NERR_Success {
            Ok(())
        } else if status == NERR_FileIdNotFound || status == ERROR_FILE_NOT_FOUND.0 {
            Err(NetError::HardwareNotFound(format!("open file ID {file_id} not found")))
        } else {
            Err(map_netmgmt_error("NetFileClose", status))
        }
    }

    pub(crate) fn map_netmgmt_error(api: &str, status: u32) -> NetError {
        if status == ERROR_ACCESS_DENIED.0 {
            NetError::PermissionDenied(format!(
                "{api} requires Administrator or Server Operator privileges (ERROR_ACCESS_DENIED)"
            ))
        } else if status == ERROR_NOT_SUPPORTED.0 {
            NetError::NotSupported(format!("{api} not supported on target (ERROR_NOT_SUPPORTED)"))
        } else if status == ERROR_INVALID_PARAMETER.0 {
            NetError::InvalidInput(format!("{api} received invalid parameter"))
        } else if status == ERROR_BAD_NETPATH.0 || status == NERR_InvalidComputer {
            NetError::NetworkError(format!("{api} target network path unreachable ({status})"))
        } else if status == NERR_FileIdNotFound || status == ERROR_FILE_NOT_FOUND.0 {
            NetError::HardwareNotFound(format!("{api} file ID not found ({status})"))
        } else {
            NetError::NetworkError(format!("{api} failed with Win32/NERR status {status}"))
        }
    }
}

pub struct SmbShareProvider {
    ctx: NetContext,
    server: Option<String>,
    backend: Arc<dyn ShareBackend>,
}

impl SmbShareProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self {
            ctx,
            server: None,
            backend: Arc::new(LiveWin32SmbBackend),
        }
    }

    pub fn with_server(mut self, server: impl Into<String>) -> Self {
        self.server = Some(server.into());
        self
    }

    pub fn with_backend(mut self, backend: Arc<dyn ShareBackend>) -> Self {
        self.backend = backend;
        self
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "lan.shares",
            "SMB & WNet Shared Resources",
            vec![
                ColumnDef::new("server", "Server", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("share_name", "Share Name", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("unc_path", "UNC Path", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("share_type", "Share Type", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("local_path", "Local Path", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("current_uses", "Current Uses", ColumnType::Uint).with_width_hint(100),
                ColumnDef::new("max_uses", "Max Uses", ColumnType::Uint).with_width_hint(90),
                ColumnDef::new("remark", "Remark", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("source", "API Source", ColumnType::Text).with_width_hint(110),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn collect_records(&self) -> NetResult<Vec<ShareRecord>> {
        if self.ctx.is_offline() {
            return fixtures::load_share_records(&self.ctx);
        }
        let mut records = self.backend.enum_local_shares(self.server.as_deref())?;
        if self.server.is_none() {
            let wnet_timeout = self.ctx.timeout.min(Duration::from_secs(2));
            if let Ok(wnet) = self.backend.enum_wnet_resources(2, wnet_timeout) {
                for rec in wnet {
                    if !records
                        .iter()
                        .any(|existing| existing.unc_path.eq_ignore_ascii_case(&rec.unc_path))
                    {
                        records.push(rec);
                    }
                }
            }
        }
        Ok(records)
    }
}

impl TableProvider for SmbShareProvider {
    fn tool_id(&self) -> &'static str {
        "lan.shares"
    }

    fn description(&self) -> &'static str {
        "Enumerate local SMB shares (NetShareEnum) and WNet network resources"
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
                    "server": rec.server,
                    "share_name": rec.share_name,
                    "unc_path": rec.unc_path,
                    "share_type": rec.share_type,
                    "local_path": rec.local_path,
                    "current_uses": rec.current_uses,
                    "max_uses": rec.max_uses,
                    "remark": rec.remark,
                    "source": rec.source,
                });
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.server),
                        CellValue::Text(rec.share_name),
                        CellValue::Text(rec.unc_path),
                        CellValue::Text(rec.share_type),
                        rec.local_path.map(CellValue::Text).unwrap_or(CellValue::Null),
                        rec.current_uses.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        rec.max_uses.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        CellValue::Text(rec.remark),
                        CellValue::Text(rec.source),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        apply_query(&schema, &rows, req)
    }
}

pub struct SmbOpenFilesProvider {
    ctx: NetContext,
    server: Option<String>,
    backend: Arc<dyn OpenFilesBackend>,
}

impl SmbOpenFilesProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self {
            ctx,
            server: None,
            backend: Arc::new(LiveWin32SmbBackend),
        }
    }

    pub fn with_server(mut self, server: impl Into<String>) -> Self {
        self.server = Some(server.into());
        self
    }

    pub fn with_backend(mut self, backend: Arc<dyn OpenFilesBackend>) -> Self {
        self.backend = backend;
        self
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "lan.openfiles",
            "SMB Server Open Files",
            vec![
                ColumnDef::new("file_id", "File ID", ColumnType::Uint).with_width_hint(90),
                ColumnDef::new("pathname", "Pathname", ColumnType::Text).with_width_hint(280),
                ColumnDef::new("username", "Username", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("permissions", "Permissions", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("locks", "Locks", ColumnType::Uint).with_width_hint(70),
                ColumnDef::new("server", "Server", ColumnType::Text).with_width_hint(140),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn collect_records(&self) -> NetResult<Vec<OpenFileRecord>> {
        if self.ctx.is_offline() {
            return fixtures::load_open_file_records(&self.ctx);
        }
        self.backend.enum_open_files(self.server.as_deref())
    }
}

impl TableProvider for SmbOpenFilesProvider {
    fn tool_id(&self) -> &'static str {
        "lan.openfiles"
    }

    fn description(&self) -> &'static str {
        "List files opened remotely on local or remote SMB servers via NetFileEnum"
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
                    "file_id": rec.file_id,
                    "pathname": rec.pathname,
                    "username": rec.username,
                    "permissions": rec.permissions,
                    "locks": rec.locks,
                    "server": rec.server,
                });
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Uint(rec.file_id),
                        CellValue::Text(rec.pathname),
                        CellValue::Text(rec.username),
                        CellValue::Text(rec.permissions),
                        CellValue::Uint(rec.locks),
                        CellValue::Text(rec.server),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        apply_query(&schema, &rows, req)
    }
}

pub struct OpenFilesCloseAction {
    ctx: NetContext,
    backend: Option<Arc<dyn OpenFilesBackend>>,
}

impl OpenFilesCloseAction {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx, backend: None }
    }

    pub fn with_backend(ctx: NetContext, backend: Arc<dyn OpenFilesBackend>) -> Self {
        Self {
            ctx,
            backend: Some(backend),
        }
    }
}

impl ActionCommand for OpenFilesCloseAction {
    fn command_id(&self) -> &'static str {
        "lan.openfiles.close"
    }

    fn description(&self) -> &'static str {
        "Close an open SMB file handle by ID via NetFileClose (privileged mutating action)"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::PrivilegedMutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "file_id": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 4294967295u64,
                    "description": "SMB open file ID from lan.openfiles (fi3_id)"
                },
                "server": {
                    "type": "string",
                    "description": "Optional UNC server name (e.g. \\\\SERVER); defaults to local machine"
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "Preview close action without calling NetFileClose",
                    "default": false
                },
                "confirm_destructive": {
                    "type": "boolean",
                    "description": "Must be true to permit privileged mutating execution",
                    "default": false
                }
            },
            "required": ["file_id"],
            "additionalProperties": false
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        reject_unknown_json_keys(args, &["file_id", "server", "dry_run", "confirm_destructive"])?;

        let raw_id = args
            .get("file_id")
            .and_then(Value::as_u64)
            .ok_or_else(|| McpToolError::InvalidParams("missing positive integer 'file_id'".into()))?;
        let file_id = u32::try_from(raw_id)
            .ok()
            .filter(|&id| id >= 1)
            .ok_or_else(|| McpToolError::InvalidParams("'file_id' must be in range 1..=u32::MAX".into()))?;

        let server: Option<String> = match args.get("server") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Err(McpToolError::InvalidParams("'server' cannot be an empty string".into()));
                }
                Some(trimmed.to_string())
            }
            Some(_) => {
                return Err(McpToolError::InvalidParams("'server' must be a string".into()));
            }
        };

        if dry_run {
            return Ok(json!({
                "command": "lan.openfiles.close",
                "dry_run": true,
                "would_close": true,
                "closed": false,
                "file_id": file_id,
                "server": server,
            }));
        }

        if let Some(backend) = &self.backend {
            backend
                .close_open_file(server.as_deref(), file_id)
                .map_err(McpToolError::from)?;
            return Ok(json!({
                "command": "lan.openfiles.close",
                "dry_run": false,
                "closed": true,
                "file_id": file_id,
                "server": server,
            }));
        }

        if self.ctx.is_offline() {
            let records = fixtures::load_open_file_records(&self.ctx).map_err(McpToolError::from)?;
            let exists = records.iter().any(|r| {
                r.file_id == u64::from(file_id)
                    && server
                        .as_deref()
                        .is_none_or(|s| r.server.eq_ignore_ascii_case(s.trim_start_matches('\\')))
            });
            if !exists {
                return Err(McpToolError::NotFound(format!(
                    "open file ID {file_id} not found in offline fixture"
                )));
            }
            return Ok(json!({
                "command": "lan.openfiles.close",
                "dry_run": false,
                "offline_simulated": true,
                "closed": true,
                "file_id": file_id,
                "server": server,
            }));
        }

        let live = LiveWin32SmbBackend;
        live.close_open_file(server.as_deref(), file_id)
            .map_err(McpToolError::from)?;

        Ok(json!({
            "command": "lan.openfiles.close",
            "dry_run": false,
            "closed": true,
            "file_id": file_id,
            "server": server,
        }))
    }
}

#[cfg(test)]
mod tests {
    use guap_mcp::JsonRpcError;
    use net2rust_core::NetError;

    use super::*;

    #[test]
    fn test_share_type_and_file_permissions_decoders() {
        assert_eq!(format_share_type(0), "Disk");
        assert_eq!(format_share_type(0x8000_0000), "Admin");
        assert_eq!(format_share_type(1), "Print");
        assert_eq!(format_share_type(3 | 0x8000_0000), "IPC");
        assert_eq!(format_file_permissions(0x01), "Read");
        assert_eq!(format_file_permissions(0x03), "Read+Write");
        assert_eq!(format_file_permissions(0x07), "Read+Write+Create");
    }

    struct MockSmbBackend {
        deny_open_files: bool,
    }

    impl ShareBackend for MockSmbBackend {
        fn enum_local_shares(&self, _server: Option<&str>) -> NetResult<Vec<ShareRecord>> {
            // Simulates level-2 fallback to level-1 (local_path = None, no passwd field anywhere).
            Ok(vec![ShareRecord {
                server: "FILESRV".into(),
                share_name: "Public".into(),
                unc_path: r"\\FILESRV\Public".into(),
                share_type: "Disk".into(),
                local_path: None,
                current_uses: None,
                max_uses: None,
                remark: "Level-1 fallback share".into(),
                source: "NetShareEnum".into(),
            }])
        }
        fn enum_wnet_resources(&self, _max_depth: usize, _timeout: Duration) -> NetResult<Vec<ShareRecord>> {
            Ok(vec![])
        }
    }

    impl OpenFilesBackend for MockSmbBackend {
        fn enum_open_files(&self, _server: Option<&str>) -> NetResult<Vec<OpenFileRecord>> {
            if self.deny_open_files {
                Err(NetError::PermissionDenied("ERROR_ACCESS_DENIED".into()))
            } else {
                Ok(vec![OpenFileRecord {
                    file_id: 42,
                    pathname: r"C:\Shares\Docs\report.pdf".into(),
                    username: "alice".into(),
                    permissions: "Read+Write".into(),
                    locks: 1,
                    server: "FILESRV".into(),
                }])
            }
        }
        fn close_open_file(&self, _server: Option<&str>, file_id: u32) -> NetResult<()> {
            if self.deny_open_files {
                Err(NetError::PermissionDenied("ERROR_ACCESS_DENIED".into()))
            } else if file_id == 42 {
                Ok(())
            } else {
                Err(NetError::HardwareNotFound(format!("open file ID {file_id} not found")))
            }
        }
    }

    #[test]
    fn test_shares_and_openfiles_error_mappings() {
        let shares = SmbShareProvider::new(NetContext::live())
            .with_backend(Arc::new(MockSmbBackend { deny_open_files: false }));
        let data = shares.query(&TableQuery::default()).unwrap();
        assert_eq!(data.total_rows, 1);
        assert_eq!(data.rows[0].cells[4], CellValue::Null); // level-1 fallback omits local_path

        // PermissionDenied -> TableError::Provider for provider, McpToolError::ExecutionFailed (never -32003!) for action
        let denied_provider = SmbOpenFilesProvider::new(NetContext::live())
            .with_backend(Arc::new(MockSmbBackend { deny_open_files: true }));
        assert!(matches!(
            denied_provider.query(&TableQuery::default()),
            Err(TableError::Provider(msg)) if msg.contains("permission denied")
        ));

        let denied_action =
            OpenFilesCloseAction::with_backend(NetContext::live(), Arc::new(MockSmbBackend { deny_open_files: true }));
        let err = denied_action.execute(&json!({ "file_id": 42 }), false).unwrap_err();
        let rpc: JsonRpcError = err.into();
        assert_ne!(rpc.code, JsonRpcError::POLICY_DENIED);
        assert_eq!(rpc.code, JsonRpcError::INTERNAL_ERROR);

        // NotFound mapping on missing file_id
        let ok_action =
            OpenFilesCloseAction::with_backend(NetContext::live(), Arc::new(MockSmbBackend { deny_open_files: false }));
        assert!(matches!(
            ok_action.execute(&json!({ "file_id": 9999 }), false),
            Err(McpToolError::NotFound(_))
        ));
        assert!(ok_action.execute(&json!({ "file_id": 42 }), true).unwrap()["would_close"] == true);
        assert!(ok_action.execute(&json!({ "file_id": 42 }), false).unwrap()["closed"] == true);
    }

    #[test]
    fn test_openfiles_close_rejects_unknown_keys_and_checks_schema_and_wnet_cap() {
        let action =
            OpenFilesCloseAction::with_backend(NetContext::live(), Arc::new(MockSmbBackend { deny_open_files: false }));
        let schema = action.input_schema();
        assert_eq!(schema["properties"]["file_id"]["maximum"], 4_294_967_295u64);

        for dry_run in [true, false] {
            let err = action
                .execute(
                    &json!({
                        "file_id": 42,
                        "confirm_destructive": true,
                        "dry_run": dry_run,
                        "unexpected": "payload"
                    }),
                    dry_run,
                )
                .unwrap_err();
            assert!(
                matches!(err, McpToolError::InvalidParams(ref msg) if msg.contains("unexpected")),
                "expected InvalidParams for unknown key when dry_run={dry_run}, got {err:?}"
            );
        }

        let non_obj = action.execute(&json!("bad"), true).unwrap_err();
        assert!(matches!(non_obj, McpToolError::InvalidParams(_)));

        assert_eq!(next_wnet_buf_u64s(262_144, 0).unwrap(), 524_288);
        assert!(matches!(next_wnet_buf_u64s(524_288, 0), Err(NetError::Internal(_))));
        assert!(matches!(
            next_wnet_buf_u64s(2048, MAX_WNET_BUF_BYTES + 1),
            Err(NetError::Internal(_))
        ));
    }
}
