//! Windows NDIS-PacketCapture ETW (`{2ED6006E-4729-4609-B423-3EE7BCD678EF}`) live consumer,
//! Win32 `.etl` `OpenTraceW` playback, and pure-Rust synthetic `N2RETL1\0` encoder/decoder.

use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use chrono::{DateTime, Utc};
use net2rust_core::{NetError, NetResult};

use super::{CaptureRequest, CapturedPacket, LinkType, MAX_CAPTURE_PACKET_BYTES};

pub const NDIS_PACKET_CAPTURE_GUID_U128: u128 = 0x2ed6_006e_4729_4609_b423_3ee7_bcd6_78ef;
pub const NDIS_PACKET_CAPTURE_GUID_BYTES: [u8; 16] = NDIS_PACKET_CAPTURE_GUID_U128.to_be_bytes();
pub const NDIS_EVENT_ID_PACKET_FRAGMENT: u16 = 1001;
pub const SYNTHETIC_ETL_MAGIC: &[u8; 8] = b"N2RETL1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticEtwRecord {
    pub provider_guid: [u8; 16],
    pub event_id: u16,
    pub timestamp_filetime: i64,
    pub user_data: Vec<u8>,
}

pub fn is_synthetic_etl(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..8] == SYNTHETIC_ETL_MAGIC
}

pub fn filetime_to_utc(filetime: i64) -> Option<DateTime<Utc>> {
    const WINDOWS_TO_UNIX_100NS: i128 = 116_444_736_000_000_000;
    let unix_100ns = i128::from(filetime).checked_sub(WINDOWS_TO_UNIX_100NS)?;
    if unix_100ns < 0 {
        return None;
    }
    let secs = i64::try_from(unix_100ns / 10_000_000).ok()?;
    let subsec_ns = ((unix_100ns % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, subsec_ns)
}

pub fn utc_to_filetime(dt: DateTime<Utc>) -> i64 {
    const WINDOWS_TO_UNIX_100NS: i128 = 116_444_736_000_000_000;
    let ns = i128::from(dt.timestamp_nanos_opt().unwrap_or(0));
    let ft = (ns / 100) + WINDOWS_TO_UNIX_100NS;
    ft.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn infer_ndis_link_type(fragment: &[u8]) -> LinkType {
    if fragment.len() >= 14 {
        let ethertype = u16::from_be_bytes([fragment[12], fragment[13]]);
        let known_eth = matches!(ethertype, 0x0800 | 0x0806 | 0x8100 | 0x86DD | 0x88A8);
        if !known_eth && fragment.len() >= 20 {
            let ver = fragment[0] >> 4;
            if ver == 4 && usize::from(u16::from_be_bytes([fragment[2], fragment[3]])) == fragment.len() {
                return LinkType::RawIp;
            }
            if ver == 6
                && fragment.len() >= 40
                && 40usize + usize::from(u16::from_be_bytes([fragment[4], fragment[5]])) == fragment.len()
            {
                return LinkType::RawIp;
            }
        }
    }
    LinkType::Ethernet
}

/// Pure-Rust decoder for `Microsoft-Windows-NDIS-PacketCapture` Event ID `1001` (`PacketFragment`).
pub fn decode_ndis_packet_fragment(
    event_id: u16,
    timestamp_ft: i64,
    user_data: &[u8],
    packet_no: u64,
) -> NetResult<Option<CapturedPacket>> {
    if event_id != NDIS_EVENT_ID_PACKET_FRAGMENT {
        return Ok(None);
    }
    if user_data.len() < 12 {
        return Err(NetError::ParseError(format!(
            "truncated NDIS PacketCapture event 1001 UserData: expected >= 12 bytes, got {}",
            user_data.len()
        )));
    }

    let miniport_if_index = u32::from_le_bytes([user_data[0], user_data[1], user_data[2], user_data[3]]);
    let _lower_if_index = u32::from_le_bytes([user_data[4], user_data[5], user_data[6], user_data[7]]);
    let fragment_size = u32::from_le_bytes([user_data[8], user_data[9], user_data[10], user_data[11]]);

    let frag_len = fragment_size as usize;
    if frag_len > MAX_CAPTURE_PACKET_BYTES {
        return Err(NetError::ParseError(format!(
            "NDIS PacketCapture fragment_size {fragment_size} exceeds MAX_CAPTURE_PACKET_BYTES"
        )));
    }
    let end = 12usize
        .checked_add(frag_len)
        .ok_or_else(|| NetError::ParseError("NDIS PacketCapture fragment offset overflow".to_string()))?;
    if end > user_data.len() {
        return Err(NetError::ParseError(format!(
            "truncated NDIS PacketCapture fragment: declared {frag_len} bytes, remaining {}",
            user_data.len() - 12
        )));
    }

    let fragment = &user_data[12..end];
    let link_type = infer_ndis_link_type(fragment);

    Ok(Some(CapturedPacket {
        packet_no,
        timestamp: filetime_to_utc(timestamp_ft),
        link_type,
        original_len: fragment_size,
        interface_id: Some(miniport_if_index),
        interface_name: Some(format!("if_{miniport_if_index}")),
        data: fragment.to_vec(),
    }))
}

pub fn build_ndis_fragment_userdata(miniport_if_index: u32, lower_if_index: u32, frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + frame.len());
    out.extend_from_slice(&miniport_if_index.to_le_bytes());
    out.extend_from_slice(&lower_if_index.to_le_bytes());
    out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    out.extend_from_slice(frame);
    out
}

pub fn encode_synthetic_etl(records: &[SyntheticEtwRecord]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + records.len() * 64);
    out.extend_from_slice(SYNTHETIC_ETL_MAGIC);
    let _ = out.write_u32::<LittleEndian>(records.len() as u32);
    for rec in records {
        out.extend_from_slice(&rec.provider_guid);
        let _ = out.write_u16::<LittleEndian>(rec.event_id);
        let _ = out.write_i64::<LittleEndian>(rec.timestamp_filetime);
        let _ = out.write_u32::<LittleEndian>(rec.user_data.len() as u32);
        out.extend_from_slice(&rec.user_data);
    }
    out
}

pub fn encode_packets_as_synthetic_etl(packets: &[CapturedPacket]) -> Vec<u8> {
    let records: Vec<SyntheticEtwRecord> = packets
        .iter()
        .map(|pkt| {
            let ft = pkt.timestamp.map(utc_to_filetime).unwrap_or(0);
            let if_idx = pkt.interface_id.unwrap_or(1);
            SyntheticEtwRecord {
                provider_guid: NDIS_PACKET_CAPTURE_GUID_BYTES,
                event_id: NDIS_EVENT_ID_PACKET_FRAGMENT,
                timestamp_filetime: ft,
                user_data: build_ndis_fragment_userdata(if_idx, if_idx, &pkt.data),
            }
        })
        .collect();
    encode_synthetic_etl(&records)
}

pub fn parse_synthetic_etl(data: &[u8]) -> NetResult<Vec<CapturedPacket>> {
    if !is_synthetic_etl(data) {
        return Err(NetError::ParseError(
            "invalid synthetic ETL header (expected N2RETL1\\0)".to_string(),
        ));
    }
    if data.len() < 12 {
        return Err(NetError::ParseError("truncated synthetic ETL record count".to_string()));
    }

    let mut cur = std::io::Cursor::new(data);
    cur.set_position(8);
    let record_count = cur
        .read_u32::<LittleEndian>()
        .map_err(|e| NetError::ParseError(format!("synthetic ETL record_count read error: {e}")))?;

    let mut packets = Vec::new();
    let mut packet_no = 1u64;

    for idx in 0..record_count {
        let pos = cur.position() as usize;
        // Each record header: 16 (guid) + 2 (event_id) + 8 (ft) + 4 (len) = 30 bytes
        if data.len() - pos < 30 {
            return Err(NetError::ParseError(format!(
                "truncated synthetic ETL record {idx} header at offset {pos}"
            )));
        }
        let mut guid = [0u8; 16];
        std::io::Read::read_exact(&mut cur, &mut guid)
            .map_err(|e| NetError::ParseError(format!("synthetic ETL guid read error: {e}")))?;
        let event_id = cur
            .read_u16::<LittleEndian>()
            .map_err(|e| NetError::ParseError(format!("synthetic ETL event_id read error: {e}")))?;
        let timestamp_ft = cur
            .read_i64::<LittleEndian>()
            .map_err(|e| NetError::ParseError(format!("synthetic ETL timestamp read error: {e}")))?;
        let user_data_len = cur
            .read_u32::<LittleEndian>()
            .map_err(|e| NetError::ParseError(format!("synthetic ETL user_data_len read error: {e}")))?;

        let ulen = user_data_len as usize;
        if ulen > MAX_CAPTURE_PACKET_BYTES {
            return Err(NetError::ParseError(format!(
                "synthetic ETL record {idx} user_data_len {user_data_len} exceeds limit"
            )));
        }
        let ustart = cur.position() as usize;
        let uend = ustart
            .checked_add(ulen)
            .ok_or_else(|| NetError::ParseError("synthetic ETL user_data offset overflow".to_string()))?;
        if uend > data.len() {
            return Err(NetError::ParseError(format!(
                "truncated synthetic ETL record {idx} payload: needed {ulen} bytes, available {}",
                data.len() - ustart
            )));
        }

        let user_data = &data[ustart..uend];
        cur.set_position(uend as u64);

        if guid == NDIS_PACKET_CAPTURE_GUID_BYTES
            && let Some(pkt) = decode_ndis_packet_fragment(event_id, timestamp_ft, user_data, packet_no)?
        {
            packets.push(pkt);
            packet_no += 1;
        }
    }

    Ok(packets)
}

#[cfg(windows)]
mod win_etw {
    use std::ffi::c_void;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use net2rust_core::{NetError, NetResult};
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_CANCELLED, ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND,
        WIN32_ERROR,
    };
    use windows::Win32::System::Diagnostics::Etw::{
        CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
        EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
        EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
        ProcessTrace, StartTraceW, TRACE_LEVEL_VERBOSE, WNODE_FLAG_TRACED_GUID,
    };
    use windows::core::{GUID, PCWSTR, PWSTR};

    use super::{CapturedPacket, NDIS_PACKET_CAPTURE_GUID_U128, decode_ndis_packet_fragment};

    const NDIS_GUID: GUID = GUID::from_u128(NDIS_PACKET_CAPTURE_GUID_U128);

    #[repr(C)]
    struct TracePropertiesBuf {
        props: EVENT_TRACE_PROPERTIES,
        name_buf: [u16; 128],
    }

    impl TracePropertiesBuf {
        fn new_real_time(session_guid: GUID) -> Self {
            let mut buf = Self {
                props: EVENT_TRACE_PROPERTIES::default(),
                name_buf: [0u16; 128],
            };
            buf.props.Wnode.BufferSize = std::mem::size_of::<Self>() as u32;
            buf.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            buf.props.Wnode.ClientContext = 2; // FILETIME SystemTime
            buf.props.Wnode.Guid = session_guid;
            buf.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            buf.props.FlushTimer = 1;
            buf.props.BufferSize = 64;
            buf.props.MinimumBuffers = 4;
            buf.props.MaximumBuffers = 64;
            buf.props.LoggerNameOffset = std::mem::offset_of!(Self, name_buf) as u32;
            buf
        }

        fn new_stop() -> Self {
            let mut buf = Self {
                props: EVENT_TRACE_PROPERTIES::default(),
                name_buf: [0u16; 128],
            };
            buf.props.Wnode.BufferSize = std::mem::size_of::<Self>() as u32;
            buf.props.LoggerNameOffset = std::mem::offset_of!(Self, name_buf) as u32;
            buf
        }
    }

    struct CallbackState {
        packets: Mutex<Vec<CapturedPacket>>,
        stop_flag: Arc<AtomicBool>,
        max_packets: Option<usize>,
        next_packet_no: Mutex<u64>,
    }

    unsafe extern "system" fn on_event_record(event_record: *mut EVENT_RECORD) {
        if event_record.is_null() {
            return;
        }
        // SAFETY: ETW guarantees a valid EVENT_RECORD pointer for the duration of the callback.
        let rec = unsafe { &*event_record };
        if rec.EventHeader.ProviderId != NDIS_GUID || rec.UserData.is_null() || rec.UserDataLength == 0 {
            return;
        }
        let ctx_ptr = rec.UserContext as *const CallbackState;
        if ctx_ptr.is_null() {
            return;
        }
        // SAFETY: `CallbackState` outlives `ProcessTrace` on the owning thread.
        let state = unsafe { &*ctx_ptr };
        if state.stop_flag.load(Ordering::Acquire) {
            return;
        }

        // SAFETY: `UserData` points to `UserDataLength` bytes for the callback duration.
        let user_data =
            unsafe { std::slice::from_raw_parts(rec.UserData as *const u8, usize::from(rec.UserDataLength)) };
        let event_id = rec.EventHeader.EventDescriptor.Id;
        let ts_ft = rec.EventHeader.TimeStamp;

        let mut pno_guard = match state.next_packet_no.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let pno = *pno_guard;
        if let Ok(Some(pkt)) = decode_ndis_packet_fragment(event_id, ts_ft, user_data, pno)
            && let Ok(mut vec) = state.packets.lock()
        {
            vec.push(pkt);
            *pno_guard += 1;
            if let Some(cap) = state.max_packets
                && vec.len() >= cap
            {
                state.stop_flag.store(true, Ordering::Release);
            }
        }
    }

    unsafe extern "system" fn on_buffer(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
        if logfile.is_null() {
            return 0;
        }
        // SAFETY: ETW passes a valid pointer to EVENT_TRACE_LOGFILEW.
        let lf = unsafe { &*logfile };
        if lf.Context.is_null() {
            return 1;
        }
        // SAFETY: `Context` points to `CallbackState` for the lifetime of `ProcessTrace`.
        let state = unsafe { &*(lf.Context as *const CallbackState) };
        if state.stop_flag.load(Ordering::Acquire) { 0 } else { 1 }
    }

    struct NdisEtwSessionGuard {
        session_handle: CONTROLTRACE_HANDLE,
        trace_handle: Option<PROCESSTRACE_HANDLE>,
        session_name_w: Vec<u16>,
    }

    impl Drop for NdisEtwSessionGuard {
        fn drop(&mut self) {
            if let Some(th) = self.trace_handle.take()
                && th.Value != u64::MAX
            {
                // SAFETY: Valid PROCESSTRACE_HANDLE opened by OpenTraceW.
                let _ = unsafe { CloseTrace(th) };
            }
            if self.session_handle.Value != 0 {
                let mut stop_buf = TracePropertiesBuf::new_stop();
                // SAFETY: Stops the real-time ETW session created in `capture_live`.
                let err = unsafe {
                    ControlTraceW(
                        self.session_handle,
                        PCWSTR(self.session_name_w.as_ptr()),
                        &mut stop_buf.props,
                        EVENT_TRACE_CONTROL_STOP,
                    )
                };
                let _ = (err == ERROR_SUCCESS) || (err == ERROR_WMI_INSTANCE_NOT_FOUND);
            }
        }
    }

    fn map_win32_err(err: WIN32_ERROR, op: &str) -> NetError {
        if err == ERROR_ACCESS_DENIED {
            NetError::PermissionDenied(format!(
                "{op}: Administrator elevation or 'Performance Log Users' group membership required for NDIS ETW packet capture"
            ))
        } else {
            NetError::DriverUnavailable(format!("{op} failed with Win32 error {}", err.0))
        }
    }

    pub fn capture_live(max_packets: Option<usize>, timeout: Duration) -> NetResult<Vec<CapturedPacket>> {
        let pid = std::process::id();
        let session_name = format!("net2rust-ndis-capture-{pid}");
        let mut session_name_w: Vec<u16> = session_name.encode_utf16().chain(std::iter::once(0)).collect();
        let session_guid = GUID::from_u128(0x7c8e_9120_0000_4000_8000_0000_0000_0000u128 | u128::from(pid));

        let mut props_buf = TracePropertiesBuf::new_real_time(session_guid);
        let mut session_handle = CONTROLTRACE_HANDLE::default();

        // SAFETY: `props_buf` has valid BufferSize and LoggerNameOffset, and `session_name_w` is NUL-terminated.
        let mut status = unsafe {
            StartTraceW(
                &mut session_handle,
                PCWSTR(session_name_w.as_ptr()),
                &mut props_buf.props,
            )
        };
        if status == ERROR_ALREADY_EXISTS {
            let mut stop_buf = TracePropertiesBuf::new_stop();
            // SAFETY: Stop stale session with same name before retrying.
            let _ = unsafe {
                ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    PCWSTR(session_name_w.as_ptr()),
                    &mut stop_buf.props,
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            props_buf = TracePropertiesBuf::new_real_time(session_guid);
            status = unsafe {
                StartTraceW(
                    &mut session_handle,
                    PCWSTR(session_name_w.as_ptr()),
                    &mut props_buf.props,
                )
            };
        }
        if status != ERROR_SUCCESS {
            return Err(map_win32_err(status, "StartTraceW"));
        }

        let mut guard = NdisEtwSessionGuard {
            session_handle,
            trace_handle: None,
            session_name_w: session_name_w.clone(),
        };

        // SAFETY: `session_handle` is active and `NDIS_GUID` is static.
        let enable_status = unsafe {
            EnableTraceEx2(
                session_handle,
                &NDIS_GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_VERBOSE as u8,
                u64::MAX,
                0,
                0,
                None,
            )
        };
        if enable_status != ERROR_SUCCESS {
            return Err(map_win32_err(enable_status, "EnableTraceEx2(NDIS-PacketCapture)"));
        }

        let stop_flag = Arc::new(AtomicBool::new(false));
        let state = Arc::new(CallbackState {
            packets: Mutex::new(Vec::new()),
            stop_flag: Arc::clone(&stop_flag),
            max_packets,
            next_packet_no: Mutex::new(1),
        });

        let state_ptr = Arc::as_ptr(&state) as *mut c_void;
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(session_name_w.as_mut_ptr()),
            BufferCallback: Some(on_buffer),
            Context: state_ptr,
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(on_event_record);

        // SAFETY: `logfile` points to valid session name and callbacks; `state` lives across the call.
        let trace_handle = unsafe { OpenTraceW(&mut logfile) };
        if trace_handle.Value == u64::MAX {
            return Err(NetError::DriverUnavailable(
                "OpenTraceW failed to open NDIS real-time ETW session".to_string(),
            ));
        }
        guard.trace_handle = Some(trace_handle);

        let handle_val = trace_handle.Value;
        let worker = std::thread::spawn(move || {
            let th = PROCESSTRACE_HANDLE { Value: handle_val };
            // SAFETY: `th` is open and `state` stays alive in this function until `worker.join()` completes.
            unsafe { ProcessTrace(&[th], None, None) }
        });

        let window = timeout.clamp(Duration::from_millis(50), Duration::from_secs(2));
        let deadline = std::time::Instant::now() + window;
        while std::time::Instant::now() < deadline && !stop_flag.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(25));
        }
        stop_flag.store(true, Ordering::Release);

        let mut stop_buf = TracePropertiesBuf::new_stop();
        // SAFETY: Stops the real-time session so `ProcessTrace` unblocks cleanly.
        let _ = unsafe {
            ControlTraceW(
                session_handle,
                PCWSTR(session_name_w.as_ptr()),
                &mut stop_buf.props,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        let _ = worker.join();
        drop(guard);

        let packets = state
            .packets
            .lock()
            .map_err(|_| NetError::Internal("ETW packet buffer mutex poisoned".to_string()))?
            .clone();
        Ok(packets)
    }

    pub fn read_etl_file(path: &Path, max_packets: Option<usize>) -> NetResult<Vec<CapturedPacket>> {
        let path_str = path.to_string_lossy();
        let mut path_w: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();

        let stop_flag = Arc::new(AtomicBool::new(false));
        let state = Arc::new(CallbackState {
            packets: Mutex::new(Vec::new()),
            stop_flag,
            max_packets,
            next_packet_no: Mutex::new(1),
        });

        let mut logfile = EVENT_TRACE_LOGFILEW {
            LogFileName: PWSTR(path_w.as_mut_ptr()),
            BufferCallback: Some(on_buffer),
            Context: Arc::as_ptr(&state) as *mut c_void,
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(on_event_record);

        // SAFETY: `logfile` references valid NUL-terminated path and `state` outlives `ProcessTrace`.
        let trace_handle = unsafe { OpenTraceW(&mut logfile) };
        if trace_handle.Value == u64::MAX {
            return Err(NetError::ParseError(format!(
                "OpenTraceW could not open ETL file '{}'",
                path.display()
            )));
        }

        // SAFETY: Single-threaded synchronous file playback until EOF or `stop_flag`.
        let status = unsafe { ProcessTrace(&[trace_handle], None, None) };
        // SAFETY: Always close the opened trace handle.
        let _ = unsafe { CloseTrace(trace_handle) };

        let stopped_early = status == ERROR_CANCELLED && state.stop_flag.load(Ordering::Acquire);
        if status != ERROR_SUCCESS && !stopped_early {
            return Err(NetError::ParseError(format!(
                "ProcessTrace failed on ETL file '{}' with Win32 error {}",
                path.display(),
                status.0
            )));
        }

        let packets = state
            .packets
            .lock()
            .map_err(|_| NetError::Internal("ETW file buffer mutex poisoned".to_string()))?
            .clone();
        Ok(packets)
    }
}

pub fn capture_live(req: &CaptureRequest, timeout: std::time::Duration) -> NetResult<Vec<CapturedPacket>> {
    #[cfg(windows)]
    {
        win_etw::capture_live(req.max_packets, timeout)
    }
    #[cfg(not(windows))]
    {
        let _ = (req, timeout);
        Err(NetError::NotSupported(
            "Windows NDIS-PacketCapture ETW is only supported on Windows".to_string(),
        ))
    }
}

pub fn read_native_etl_file(path: &Path, max_packets: Option<usize>) -> NetResult<Vec<CapturedPacket>> {
    #[cfg(windows)]
    {
        win_etw::read_etl_file(path, max_packets)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, max_packets);
        Err(NetError::NotSupported(
            "Native Windows .etl OpenTraceW playback requires Windows".to_string(),
        ))
    }
}
