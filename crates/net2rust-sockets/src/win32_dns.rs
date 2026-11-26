use std::ffi::c_void;

use net2rust_core::{NetError, NetResult};
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, FreeLibrary, GetLastError, HMODULE};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::core::{PWSTR, s, w};

use crate::model::RawDnsCacheEntry;

#[repr(C)]
struct DnsCacheEntryRaw {
    next: *mut DnsCacheEntryRaw,
    name: PWSTR,
    record_type: u16,
    data_length: u16,
    flags: u32,
}

type DnsGetCacheDataTableFn = unsafe extern "system" fn(*mut *mut DnsCacheEntryRaw) -> i32;
type DnsFreeFn = unsafe extern "system" fn(*const c_void, i32);

struct LibraryGuard(HMODULE);

impl Drop for LibraryGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = FreeLibrary(self.0);
            }
        }
    }
}

struct DnsListGuard {
    head: *mut DnsCacheEntryRaw,
    free_fn: DnsFreeFn,
}

impl Drop for DnsListGuard {
    fn drop(&mut self) {
        if !self.head.is_null() {
            // DnsFreeRecordList = 1
            unsafe { (self.free_fn)(self.head.cast::<c_void>(), 1) };
        }
    }
}

/// Dynamically load `dnsapi.dll` and read the local Windows DNS resolver cache via `DnsGetCacheDataTable`.
pub fn query_dns_cache_table() -> NetResult<Vec<RawDnsCacheEntry>> {
    let module = unsafe { LoadLibraryW(w!("dnsapi.dll")) }
        .map_err(|e| NetError::DriverUnavailable(format!("failed to load dnsapi.dll: {e}")))?;
    let _lib_guard = LibraryGuard(module);

    let get_cache_ptr = unsafe { GetProcAddress(module, s!("DnsGetCacheDataTable")) }.ok_or_else(|| {
        NetError::DriverUnavailable("DnsGetCacheDataTable export missing from dnsapi.dll".to_string())
    })?;
    let free_ptr = unsafe { GetProcAddress(module, s!("DnsFree")) }
        .or_else(|| unsafe { GetProcAddress(module, s!("DnsRecordListFree")) })
        .ok_or_else(|| NetError::DriverUnavailable("DnsFree export missing from dnsapi.dll".to_string()))?;

    let get_cache: DnsGetCacheDataTableFn = unsafe { std::mem::transmute(get_cache_ptr) };
    let dns_free: DnsFreeFn = unsafe { std::mem::transmute(free_ptr) };

    let mut head: *mut DnsCacheEntryRaw = std::ptr::null_mut();
    let ok = unsafe { get_cache(&mut head) };
    if ok == 0 && head.is_null() {
        let gle = unsafe { GetLastError() };
        if gle == ERROR_ACCESS_DENIED {
            return Err(NetError::PermissionDenied(
                "DnsGetCacheDataTable returned ERROR_ACCESS_DENIED".to_string(),
            ));
        }
        // Per live host probe, non-elevated/empty DNS cache returns BOOL=0, NULL, GLE=0.
        return Ok(Vec::new());
    }

    let _list_guard = DnsListGuard {
        head,
        free_fn: dns_free,
    };

    let mut out = Vec::new();
    let mut cur = head;
    let mut steps = 0usize;
    while !cur.is_null() && steps < 100_000 {
        steps += 1;
        let entry = unsafe { &*cur };
        let name = if entry.name.is_null() {
            String::new()
        } else {
            unsafe { entry.name.to_string().unwrap_or_default() }
        };
        if !name.is_empty() {
            out.push(RawDnsCacheEntry {
                name,
                record_type: entry.record_type,
                data_length: entry.data_length,
                flags: entry.flags,
            });
        }
        cur = entry.next;
    }

    Ok(out)
}
