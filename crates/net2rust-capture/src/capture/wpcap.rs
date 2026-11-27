//! Optional dynamic `wpcap.dll` (Npcap) loader via `libloading` with graceful fallback.

use std::ffi::{CStr, CString, c_char, c_int, c_long, c_void};
#[cfg(windows)]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::DateTime;
use libloading::Library;
use net2rust_core::{NetError, NetResult};

use super::{CaptureRequest, CapturedPacket, LinkType};

#[repr(C)]
pub struct PcapT {
    _private: [u8; 0],
}

#[repr(C)]
pub struct PcapIfT {
    pub next: *mut PcapIfT,
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub addresses: *mut c_void,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PcapTimeval {
    pub tv_sec: c_long,
    pub tv_usec: c_long,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PcapPkthdr {
    pub ts: PcapTimeval,
    pub caplen: u32,
    pub len: u32,
}

pub type FnPcapFindAllDevs = unsafe extern "C" fn(*mut *mut PcapIfT, *mut c_char) -> c_int;
pub type FnPcapFreeAllDevs = unsafe extern "C" fn(*mut PcapIfT);
pub type FnPcapCreate = unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut PcapT;
pub type FnPcapSetSnaplen = unsafe extern "C" fn(*mut PcapT, c_int) -> c_int;
pub type FnPcapSetPromisc = unsafe extern "C" fn(*mut PcapT, c_int) -> c_int;
pub type FnPcapSetTimeout = unsafe extern "C" fn(*mut PcapT, c_int) -> c_int;
pub type FnPcapSetRfmon = unsafe extern "C" fn(*mut PcapT, c_int) -> c_int;
pub type FnPcapCanSetRfmon = unsafe extern "C" fn(*mut PcapT) -> c_int;
pub type FnPcapActivate = unsafe extern "C" fn(*mut PcapT) -> c_int;
pub type FnPcapNextEx = unsafe extern "C" fn(*mut PcapT, *mut *const PcapPkthdr, *mut *const u8) -> c_int;
pub type FnPcapClose = unsafe extern "C" fn(*mut PcapT);
pub type FnPcapDatalink = unsafe extern "C" fn(*mut PcapT) -> c_int;
pub type FnPcapGetErr = unsafe extern "C" fn(*mut PcapT) -> *const c_char;

const PCAP_ERRBUF_SIZE: usize = 256;
const PCAP_ERROR_NO_SUCH_DEVICE: c_int = -5;
const PCAP_ERROR_RFMON_NOTSUP: c_int = -6;
const PCAP_ERROR_PERM_DENIED: c_int = -8;

pub struct WpcapLibrary {
    _lib: Library,
    pcap_findalldevs: FnPcapFindAllDevs,
    pcap_freealldevs: FnPcapFreeAllDevs,
    pcap_create: FnPcapCreate,
    pcap_set_snaplen: FnPcapSetSnaplen,
    pcap_set_promisc: FnPcapSetPromisc,
    pcap_set_timeout: FnPcapSetTimeout,
    pcap_set_rfmon: FnPcapSetRfmon,
    pcap_can_set_rfmon: FnPcapCanSetRfmon,
    pcap_activate: FnPcapActivate,
    pcap_next_ex: FnPcapNextEx,
    pcap_close: FnPcapClose,
    pcap_datalink: FnPcapDatalink,
    pcap_geterr: FnPcapGetErr,
}

// SAFETY: Resolved function pointers inside `wpcap.dll` are process-global symbols tied to `_lib`.
unsafe impl Send for WpcapLibrary {}
// SAFETY: Resolved function pointers inside `wpcap.dll` are safe to share across threads.
unsafe impl Sync for WpcapLibrary {}

fn load_wpcap_library_handle() -> NetResult<Library> {
    #[cfg(windows)]
    {
        const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
        const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

        let sys_root = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("WINDIR"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        let npcap_path = sys_root.join(r"System32\Npcap\wpcap.dll");

        if npcap_path.exists() {
            // SAFETY: Loading Npcap's wpcap.dll using explicit System32 + DLL load dir flags avoids CWD hijacking.
            if let Ok(lib) = unsafe {
                libloading::os::windows::Library::load_with_flags(
                    &npcap_path,
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            } {
                return Ok(lib.into());
            }
        }

        // SAFETY: System32-restricted search for wpcap.dll.
        if let Ok(lib) =
            unsafe { libloading::os::windows::Library::load_with_flags("wpcap.dll", LOAD_LIBRARY_SEARCH_SYSTEM32) }
        {
            return Ok(lib.into());
        }

        // SAFETY: Standard fallback lookup for wpcap.dll.
        unsafe { Library::new("wpcap.dll") }.map_err(|e| {
            NetError::DriverUnavailable(format!(
                "Npcap (wpcap.dll) is not installed or could not be loaded ({e}); use NDIS ETW or --offline"
            ))
        })
    }

    #[cfg(not(windows))]
    {
        // SAFETY: Attempt dynamic libpcap on Unix hosts when explicitly invoked.
        unsafe { Library::new("libpcap.so.0.8") }
            .or_else(|_| unsafe { Library::new("libpcap.so") })
            .map_err(|e| NetError::DriverUnavailable(format!("wpcap/libpcap unavailable: {e}")))
    }
}

impl WpcapLibrary {
    pub fn load() -> NetResult<Arc<Self>> {
        let lib = load_wpcap_library_handle()?;
        // SAFETY: All symbols match standard Npcap/libpcap C ABI signatures verified against wpcap.dll.
        unsafe {
            let pcap_findalldevs = *lib
                .get::<FnPcapFindAllDevs>(b"pcap_findalldevs\0")
                .map_err(|e| NetError::DriverUnavailable(format!("missing pcap_findalldevs: {e}")))?;
            let pcap_freealldevs = *lib
                .get::<FnPcapFreeAllDevs>(b"pcap_freealldevs\0")
                .map_err(|e| NetError::DriverUnavailable(format!("missing pcap_freealldevs: {e}")))?;
            let pcap_create = *lib
                .get::<FnPcapCreate>(b"pcap_create\0")
                .map_err(|e| NetError::DriverUnavailable(format!("missing pcap_create: {e}")))?;
            let pcap_set_snaplen = *lib
                .get::<FnPcapSetSnaplen>(b"pcap_set_snaplen\0")
                .map_err(|e| NetError::DriverUnavailable(format!("missing pcap_set_snaplen: {e}")))?;
            let pcap_set_promisc = *lib
                .get::<FnPcapSetPromisc>(b"pcap_set_promisc\0")
                .map_err(|e| NetError::DriverUnavailable(format!("missing pcap_set_promisc: {e}")))?;
            let pcap_set_timeout = *lib
                .get::<FnPcapSetTimeout>(b"pcap_set_timeout\0")
                .map_err(|e| NetError::DriverUnavailable(format!("missing pcap_set_timeout: {e}")))?;
            let pcap_set_rfmon = *lib
                .get::<FnPcapSetRfmon>(b"pcap_set_rfmon\0")
                .map_err(|e| NetError::DriverUnavailable(format!("missing pcap_set_rfmon: {e}")))?;
            let pcap_can_set_rfmon = *lib
                .get::<FnPcapCanSetRfmon>(b"pcap_can_set_rfmon\0")
                .map_err(|e| NetError::DriverUnavailable(format!("missing pcap_can_set_rfmon: {e}")))?;
            let pcap_activate = *lib
                .get::<FnPcapActivate>(b"pcap_activate\0")
                .map_err(|e| NetError::DriverUnavailable(format!("missing pcap_activate: {e}")))?;
            let pcap_next_ex = *lib
                .get::<FnPcapNextEx>(b"pcap_next_ex\0")
                .map_err(|e| NetError::DriverUnavailable(format!("missing pcap_next_ex: {e}")))?;
            let pcap_close = *lib
                .get::<FnPcapClose>(b"pcap_close\0")
                .map_err(|e| NetError::DriverUnavailable(format!("missing pcap_close: {e}")))?;
            let pcap_datalink = *lib
                .get::<FnPcapDatalink>(b"pcap_datalink\0")
                .map_err(|e| NetError::DriverUnavailable(format!("missing pcap_datalink: {e}")))?;
            let pcap_geterr = *lib
                .get::<FnPcapGetErr>(b"pcap_geterr\0")
                .map_err(|e| NetError::DriverUnavailable(format!("missing pcap_geterr: {e}")))?;

            Ok(Arc::new(Self {
                _lib: lib,
                pcap_findalldevs,
                pcap_freealldevs,
                pcap_create,
                pcap_set_snaplen,
                pcap_set_promisc,
                pcap_set_timeout,
                pcap_set_rfmon,
                pcap_can_set_rfmon,
                pcap_activate,
                pcap_next_ex,
                pcap_close,
                pcap_datalink,
                pcap_geterr,
            }))
        }
    }

    pub fn list_interfaces(&self) -> NetResult<Vec<(String, Option<String>)>> {
        let mut alldevs: *mut PcapIfT = std::ptr::null_mut();
        let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];
        // SAFETY: Valid pointers for `alldevs` and `errbuf`.
        let rc = unsafe { (self.pcap_findalldevs)(&mut alldevs, errbuf.as_mut_ptr()) };
        if rc != 0 {
            let msg = unsafe { CStr::from_ptr(errbuf.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            return Err(NetError::DriverUnavailable(format!("pcap_findalldevs failed: {msg}")));
        }

        let mut out = Vec::new();
        let mut cur = alldevs;
        while !cur.is_null() {
            // SAFETY: Non-null node in linked list owned until `pcap_freealldevs`.
            let dev = unsafe { &*cur };
            if !dev.name.is_null() {
                let name = unsafe { CStr::from_ptr(dev.name) }.to_string_lossy().into_owned();
                let desc = if dev.description.is_null() {
                    None
                } else {
                    Some(
                        unsafe { CStr::from_ptr(dev.description) }
                            .to_string_lossy()
                            .into_owned(),
                    )
                };
                out.push((name, desc));
            }
            cur = dev.next;
        }
        if !alldevs.is_null() {
            // SAFETY: Frees device list allocated by `pcap_findalldevs`.
            unsafe { (self.pcap_freealldevs)(alldevs) };
        }
        Ok(out)
    }
}

pub struct WpcapHandle {
    lib: Arc<WpcapLibrary>,
    ptr: *mut PcapT,
}

impl Drop for WpcapHandle {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: `self.lib` stays alive until after `pcap_close` returns.
            unsafe { (self.lib.pcap_close)(self.ptr) };
            self.ptr = std::ptr::null_mut();
        }
    }
}

fn map_pcap_status(code: c_int, lib: &WpcapLibrary, handle: *mut PcapT, op: &str) -> NetError {
    let err_msg = if handle.is_null() {
        String::new()
    } else {
        // SAFETY: `handle` is non-null and `pcap_geterr` returns NUL-terminated string.
        let ptr = unsafe { (lib.pcap_geterr)(handle) };
        if ptr.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned()
        }
    };
    match code {
        PCAP_ERROR_PERM_DENIED => NetError::PermissionDenied(format!(
            "{op}: Npcap permission denied (Administrator elevation required): {err_msg}"
        )),
        PCAP_ERROR_NO_SUCH_DEVICE => NetError::HardwareNotFound(format!("{op}: device not found: {err_msg}")),
        PCAP_ERROR_RFMON_NOTSUP => {
            NetError::NotSupported(format!("{op}: 802.11 monitor mode (RFMON) not supported: {err_msg}"))
        }
        other => NetError::DriverUnavailable(format!("{op} failed with pcap code {other}: {err_msg}")),
    }
}

pub fn probe_npcap() -> NetResult<Arc<WpcapLibrary>> {
    WpcapLibrary::load()
}

pub fn capture_live(req: &CaptureRequest, timeout: Duration) -> NetResult<Vec<CapturedPacket>> {
    let lib = WpcapLibrary::load()?;
    let iface_name = match &req.interface {
        Some(name) => name.clone(),
        None => {
            let devs = lib.list_interfaces()?;
            devs.into_iter()
                .map(|(n, _)| n)
                .next()
                .ok_or_else(|| NetError::HardwareNotFound("no Npcap capture interfaces found".to_string()))?
        }
    };

    let c_iface = CString::new(iface_name.as_str())
        .map_err(|_| NetError::InvalidInput("interface name contains interior NUL byte".to_string()))?;
    let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];

    // SAFETY: Valid C string and error buffer.
    let ptr = unsafe { (lib.pcap_create)(c_iface.as_ptr(), errbuf.as_mut_ptr()) };
    if ptr.is_null() {
        let msg = unsafe { CStr::from_ptr(errbuf.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        return Err(NetError::DriverUnavailable(format!("pcap_create failed: {msg}")));
    }

    let handle = WpcapHandle {
        lib: Arc::clone(&lib),
        ptr,
    };

    let snaplen = if req.snaplen == 0 { 65535 } else { req.snaplen as c_int };
    // SAFETY: Valid `pcap_t` handle prior to `pcap_activate`.
    unsafe {
        (lib.pcap_set_snaplen)(handle.ptr, snaplen);
        (lib.pcap_set_promisc)(handle.ptr, if req.promiscuous { 1 } else { 0 });
        (lib.pcap_set_timeout)(handle.ptr, 100);
    }

    if req.monitor_mode {
        // SAFETY: Valid `pcap_t` handle prior to activation.
        let can_rfmon = unsafe { (lib.pcap_can_set_rfmon)(handle.ptr) };
        if can_rfmon == 0 {
            return Err(NetError::NotSupported(format!(
                "802.11 monitor mode (RFMON) is not supported on interface '{iface_name}'"
            )));
        }
        if can_rfmon < 0 {
            return Err(map_pcap_status(can_rfmon, &lib, handle.ptr, "pcap_can_set_rfmon"));
        }
        let rf_rc = unsafe { (lib.pcap_set_rfmon)(handle.ptr, 1) };
        if rf_rc < 0 {
            return Err(map_pcap_status(rf_rc, &lib, handle.ptr, "pcap_set_rfmon"));
        }
    }

    // SAFETY: Activates configured capture handle.
    let act_rc = unsafe { (lib.pcap_activate)(handle.ptr) };
    if act_rc < 0 {
        return Err(map_pcap_status(act_rc, &lib, handle.ptr, "pcap_activate"));
    }

    // SAFETY: Activated handle returns DLT_* link type.
    let dlt = unsafe { (lib.pcap_datalink)(handle.ptr) };
    let link_type = if dlt >= 0 {
        LinkType::from(dlt as u32)
    } else {
        LinkType::Ethernet
    };

    let mut packets = Vec::new();
    let deadline = Instant::now() + timeout.clamp(Duration::from_millis(50), Duration::from_secs(2));
    let mut packet_no = 1u64;

    while Instant::now() < deadline {
        if let Some(max) = req.max_packets
            && packets.len() >= max
        {
            break;
        }
        let mut pkt_hdr: *const PcapPkthdr = std::ptr::null();
        let mut pkt_data: *const u8 = std::ptr::null();
        // SAFETY: Valid activated handle and output pointers.
        let rc = unsafe { (lib.pcap_next_ex)(handle.ptr, &mut pkt_hdr, &mut pkt_data) };
        match rc {
            1 if !pkt_hdr.is_null() && !pkt_data.is_null() => {
                // SAFETY: `pcap_next_ex == 1` guarantees valid header and `caplen` data bytes until next call.
                let hdr = unsafe { &*pkt_hdr };
                let cap_len = hdr.caplen as usize;
                let data = unsafe { std::slice::from_raw_parts(pkt_data, cap_len) }.to_vec();
                #[allow(clippy::useless_conversion)]
                let tv_sec = i64::from(hdr.ts.tv_sec);
                let ts = DateTime::from_timestamp(tv_sec, (hdr.ts.tv_usec.max(0) as u32) * 1_000);
                packets.push(CapturedPacket {
                    packet_no,
                    timestamp: ts,
                    link_type,
                    original_len: hdr.len,
                    interface_id: Some(0),
                    interface_name: Some(iface_name.clone()),
                    data,
                });
                packet_no += 1;
            }
            0 => continue,
            -2 => break,
            err => return Err(map_pcap_status(err, &lib, handle.ptr, "pcap_next_ex")),
        }
    }

    Ok(packets)
}
