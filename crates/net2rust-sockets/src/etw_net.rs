use std::ffi::c_void;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;
use net2rust_core::{NetError, NetResult};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_CANCELLED, ERROR_CTX_CLOSE_PENDING, ERROR_SUCCESS,
};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_DISABLE_PROVIDER,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_HEADER_FLAG_64_BIT_HEADER, EVENT_RECORD, EVENT_TRACE_CONTROL_FLUSH,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2,
    OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE, ProcessTrace,
    StartTraceW, TRACE_LEVEL_VERBOSE, WNODE_FLAG_TRACED_GUID,
};
use windows::core::{GUID, PCWSTR, PWSTR};

use crate::etw_decode::{DNS_CLIENT_GUID_STR, KERNEL_NETWORK_GUID_STR, RawEtwRecord, TCPIP_GUID_STR};
use crate::model::filetime_i64_to_utc;

static SESSION_SEQ: AtomicU64 = AtomicU64::new(1);

pub fn kernel_network_guid() -> GUID {
    GUID::from_u128(0x7DD4_2A49_5329_4832_8DFD_43D9_7915_3A88)
}

pub fn tcpip_guid() -> GUID {
    GUID::from_u128(0x2F07_E2EE_15DB_40F1_90EF_9D7B_A282_188A)
}

pub fn dns_client_guid() -> GUID {
    GUID::from_u128(0x1C95_126E_7EEA_49A9_A3FE_A378_B03D_DB4D)
}

fn guid_to_canonical(g: &GUID) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7],
    )
}

struct CollectorState {
    records: std::sync::Mutex<Vec<RawEtwRecord>>,
    stop_flag: Arc<AtomicBool>,
    max_records: usize,
}

unsafe extern "system" fn etw_buffer_callback(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    if logfile.is_null() {
        return 0;
    }
    let ctx = unsafe { (*logfile).Context };
    if ctx.is_null() {
        return 0;
    }
    let state = unsafe { &*(ctx.cast::<CollectorState>()) };
    u32::from(!state.stop_flag.load(Ordering::Acquire))
}

unsafe extern "system" fn etw_event_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }
    let rec = unsafe { &*event_record };
    if rec.UserContext.is_null() {
        return;
    }
    let state = unsafe { &*(rec.UserContext.cast::<CollectorState>()) };
    if state.stop_flag.load(Ordering::Acquire) {
        return;
    }

    let user_data = if rec.UserData.is_null() || rec.UserDataLength == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(rec.UserData.cast::<u8>(), usize::from(rec.UserDataLength)) }.to_vec()
    };

    let header = &rec.EventHeader;
    let timestamp_utc = filetime_i64_to_utc(header.TimeStamp).unwrap_or_else(Utc::now);
    let provider_guid = guid_to_canonical(&header.ProviderId);
    let act = header.ActivityId;
    let mut activity_id = [0u8; 16];
    activity_id[0..4].copy_from_slice(&act.data1.to_le_bytes());
    activity_id[4..6].copy_from_slice(&act.data2.to_le_bytes());
    activity_id[6..8].copy_from_slice(&act.data3.to_le_bytes());
    activity_id[8..16].copy_from_slice(&act.data4);

    let raw = RawEtwRecord {
        provider_guid,
        event_id: header.EventDescriptor.Id,
        version: header.EventDescriptor.Version,
        timestamp_utc,
        header_process_id: header.ProcessId,
        activity_id,
        is_64bit: (header.Flags & (EVENT_HEADER_FLAG_64_BIT_HEADER as u16)) != 0,
        user_data,
    };

    if let Ok(mut guard) = state.records.lock() {
        if guard.len() < state.max_records {
            guard.push(raw);
            if guard.len() >= state.max_records {
                state.stop_flag.store(true, Ordering::Release);
            }
        } else {
            state.stop_flag.store(true, Ordering::Release);
        }
    }
}

struct EtwSessionGuard {
    session_handle: CONTROLTRACE_HANDLE,
    trace_handle: Option<PROCESSTRACE_HANDLE>,
    session_name_utf16: Vec<u16>,
    props_buf: Vec<u64>,
    enabled_providers: Vec<GUID>,
}

impl EtwSessionGuard {
    fn disable_providers(&mut self) {
        for guid in self.enabled_providers.drain(..) {
            unsafe {
                let _ = EnableTraceEx2(
                    self.session_handle,
                    &guid,
                    EVENT_CONTROL_CODE_DISABLE_PROVIDER.0,
                    0,
                    0,
                    0,
                    0,
                    None,
                );
            }
        }
    }

    fn stop_session_only(&mut self) {
        self.disable_providers();
        if self.session_handle.Value != 0 {
            let props_ptr = self.props_buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
            unsafe {
                let _ = ControlTraceW(
                    self.session_handle,
                    PCWSTR(self.session_name_utf16.as_ptr()),
                    props_ptr,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            self.session_handle.Value = 0;
        }
    }

    fn stop_now(&mut self) {
        self.disable_providers();
        if let Some(th) = self.trace_handle.take() {
            let rc = unsafe { CloseTrace(th) };
            let _ = rc == ERROR_SUCCESS || rc == ERROR_CTX_CLOSE_PENDING;
        }
        self.stop_session_only();
    }
}

impl Drop for EtwSessionGuard {
    fn drop(&mut self) {
        self.stop_now();
    }
}

/// Capture real-time ETW events for a single provider over a bounded window derived from `timeout`.
pub fn capture_provider_window(
    tool_tag: &str,
    provider: GUID,
    match_any_keyword: u64,
    timeout: Duration,
    max_rows: Option<usize>,
) -> NetResult<Vec<RawEtwRecord>> {
    let seq = SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
    let session_name = format!("Net2Rust_{tool_tag}_{}_{seq}", std::process::id());
    let mut session_name_utf16: Vec<u16> = session_name.encode_utf16().collect();
    session_name_utf16.push(0);

    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let total_bytes = props_size + session_name_utf16.len() * 2;
    let mut props_buf = vec![0u64; total_bytes.div_ceil(8)];

    let init_props = |buf: &mut [u64]| {
        buf.fill(0);
        let props = unsafe { &mut *(buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>()) };
        props.Wnode.BufferSize = (buf.len() * 8) as u32;
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props.Wnode.ClientContext = 2; // SystemTime (UTC FILETIME)
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props.FlushTimer = 1;
        props.BufferSize = 64;
        props.MinimumBuffers = 2;
        props.MaximumBuffers = 16;
        props.LoggerNameOffset = props_size as u32;
        props.LogFileNameOffset = 0;
    };

    init_props(&mut props_buf);
    let mut session_handle = CONTROLTRACE_HANDLE::default();
    let mut start_rc = unsafe {
        StartTraceW(
            &mut session_handle,
            PCWSTR(session_name_utf16.as_ptr()),
            props_buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
        )
    };
    if start_rc == ERROR_ALREADY_EXISTS {
        init_props(&mut props_buf);
        unsafe {
            let _ = ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                PCWSTR(session_name_utf16.as_ptr()),
                props_buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
                EVENT_TRACE_CONTROL_STOP,
            );
        }
        init_props(&mut props_buf);
        start_rc = unsafe {
            StartTraceW(
                &mut session_handle,
                PCWSTR(session_name_utf16.as_ptr()),
                props_buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
            )
        };
    }

    if start_rc == ERROR_ACCESS_DENIED {
        return Err(NetError::PermissionDenied(
            "ETW StartTraceW requires Administrator or Performance Log Users privileges".to_string(),
        ));
    }
    if start_rc != ERROR_SUCCESS {
        return Err(NetError::DriverUnavailable(format!(
            "StartTraceW failed with Win32 error {}",
            start_rc.0
        )));
    }

    let mut guard = EtwSessionGuard {
        session_handle,
        trace_handle: None,
        session_name_utf16: session_name_utf16.clone(),
        props_buf,
        enabled_providers: Vec::new(),
    };

    let enable_rc = unsafe {
        EnableTraceEx2(
            guard.session_handle,
            &provider,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_VERBOSE as u8,
            match_any_keyword,
            0,
            0,
            None,
        )
    };
    if enable_rc == ERROR_ACCESS_DENIED {
        return Err(NetError::PermissionDenied(format!(
            "ETW provider {} denied access (elevation required)",
            guid_to_canonical(&provider)
        )));
    }
    if enable_rc != ERROR_SUCCESS {
        return Err(NetError::DriverUnavailable(format!(
            "EnableTraceEx2 failed with Win32 error {}",
            enable_rc.0
        )));
    }
    guard.enabled_providers.push(provider);

    if max_rows == Some(0) {
        guard.stop_now();
        return Ok(Vec::new());
    }

    let stop_flag = Arc::new(AtomicBool::new(false));
    let max_records = max_rows.unwrap_or(50_000).clamp(1, 100_000);
    let collector = Box::new(CollectorState {
        records: std::sync::Mutex::new(Vec::new()),
        stop_flag: Arc::clone(&stop_flag),
        max_records,
    });
    let collector_ptr = Box::into_raw(collector);

    let mut logfile = EVENT_TRACE_LOGFILEW::default();
    let mut name_for_open = session_name_utf16;
    logfile.LoggerName = PWSTR(name_for_open.as_mut_ptr());
    logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(etw_event_callback);
    logfile.BufferCallback = Some(etw_buffer_callback);
    logfile.Context = collector_ptr.cast::<c_void>();

    let trace_handle = unsafe { OpenTraceW(&mut logfile) };
    if trace_handle.Value == u64::MAX {
        unsafe {
            drop(Box::from_raw(collector_ptr));
        }
        return Err(NetError::DriverUnavailable(
            "OpenTraceW failed to open real-time ETW consumer handle".to_string(),
        ));
    }
    guard.trace_handle = Some(trace_handle);

    let th_val = trace_handle.Value;
    let join_handle = std::thread::spawn(move || {
        let handles = [PROCESSTRACE_HANDLE { Value: th_val }];
        unsafe {
            let _ = ProcessTrace(&handles, None, None);
        }
    });

    // Bounded capture window so query() never hangs.
    let window = timeout.clamp(Duration::from_millis(50), Duration::from_secs(5));
    let deadline = Instant::now() + window;
    while Instant::now() < deadline && !stop_flag.load(Ordering::Acquire) {
        std::thread::sleep(Duration::from_millis(25));
    }

    // If max_records was NOT reached, keep stop_flag=false while disabling providers,
    // flushing buffered kernel events, and stopping the session so ProcessTrace drains
    // all in-window buffers cleanly before setting stop_flag=true.
    if !stop_flag.load(Ordering::Acquire) {
        guard.disable_providers();
        unsafe {
            let _ = ControlTraceW(
                guard.session_handle,
                PCWSTR(guard.session_name_utf16.as_ptr()),
                guard.props_buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
                EVENT_TRACE_CONTROL_FLUSH,
            );
        }
        guard.stop_session_only();

        let drain_deadline = Instant::now() + Duration::from_millis(250);
        while !join_handle.is_finished() && Instant::now() < drain_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    stop_flag.store(true, Ordering::Release);
    guard.stop_now();
    let _ = join_handle.join();

    // Safe to reclaim collector_ptr now that ProcessTrace has returned and joined.
    let boxed = unsafe { Box::from_raw(collector_ptr) };
    let records = boxed
        .records
        .into_inner()
        .map_err(|_| NetError::Internal("ETW collector mutex poisoned".to_string()))?;

    Ok(records)
}

/// Replay a binary `.etl` file on Windows via `OpenTraceW` + `ProcessTrace`.
pub fn replay_etl_file(path: &Path, expected_provider: Option<&str>) -> NetResult<Vec<RawEtwRecord>> {
    let mut wide_path: Vec<u16> = path.to_string_lossy().encode_utf16().collect();
    wide_path.push(0);

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_check = Arc::clone(&stop_flag);
    let collector = Box::new(CollectorState {
        records: std::sync::Mutex::new(Vec::new()),
        stop_flag,
        max_records: 100_000,
    });
    let collector_ptr = Box::into_raw(collector);

    let mut logfile = EVENT_TRACE_LOGFILEW {
        LogFileName: PWSTR(wide_path.as_mut_ptr()),
        BufferCallback: Some(etw_buffer_callback),
        Context: collector_ptr.cast::<c_void>(),
        ..Default::default()
    };
    logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(etw_event_callback);

    let trace_handle = unsafe { OpenTraceW(&mut logfile) };
    if trace_handle.Value == u64::MAX {
        unsafe {
            drop(Box::from_raw(collector_ptr));
        }
        return Err(NetError::ParseError(format!(
            "OpenTraceW failed on ETL file {}",
            path.display()
        )));
    }

    let handles = [trace_handle];
    let proc_rc = unsafe { ProcessTrace(&handles, None, None) };
    unsafe {
        let _ = CloseTrace(trace_handle);
    }

    let boxed = unsafe { Box::from_raw(collector_ptr) };
    if proc_rc != ERROR_SUCCESS && !(proc_rc == ERROR_CANCELLED && stop_flag_check.load(Ordering::Acquire)) {
        return Err(NetError::ParseError(format!(
            "ProcessTrace failed on {}: Win32 error {}",
            path.display(),
            proc_rc.0
        )));
    }

    let mut records = boxed
        .records
        .into_inner()
        .map_err(|_| NetError::Internal("ETL collector mutex poisoned".to_string()))?;
    if let Some(filter_guid) = expected_provider {
        records.retain(|r| r.provider_guid.eq_ignore_ascii_case(filter_guid));
    }
    Ok(records)
}

#[allow(dead_code)]
pub fn known_provider_guids() -> [&'static str; 3] {
    [KERNEL_NETWORK_GUID_STR, TCPIP_GUID_STR, DNS_CLIENT_GUID_STR]
}
