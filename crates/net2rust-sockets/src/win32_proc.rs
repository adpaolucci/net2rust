use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    GetOwnerModuleFromPidAndInfo, TCPIP_OWNER_MODULE_BASIC_INFO, TCPIP_OWNER_MODULE_INFO_BASIC,
};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ, QueryFullProcessImageNameW,
};
use windows::core::{PCWSTR, PWSTR};

use crate::model::RawProcessMeta;

pub struct HandleGuard(pub HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[derive(Default)]
pub struct ProcessResolver {
    cache: HashMap<u32, RawProcessMeta>,
}

impl ProcessResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resolve(&mut self, pid: u32) -> RawProcessMeta {
        if let Some(cached) = self.cache.get(&pid) {
            return cached.clone();
        }
        let meta = resolve_pid_live(pid);
        self.cache.insert(pid, meta.clone());
        meta
    }

    pub fn resolve_with_owner_module(&mut self, pid: u32, info: Option<&[u64; 16]>) -> RawProcessMeta {
        let mut meta = self.resolve(pid);
        if meta.name.is_none()
            && let Some(owner_info) = info
            && let Some((mod_name, mod_path)) = query_owner_module(pid, owner_info)
        {
            meta.name = Some(mod_name);
            if meta.path.is_none() {
                meta.path = mod_path;
            }
            self.cache.insert(pid, meta.clone());
        }
        meta
    }
}

fn resolve_pid_live(pid: u32) -> RawProcessMeta {
    if pid == 0 {
        return RawProcessMeta {
            pid,
            name: Some("System Idle Process".to_string()),
            path: None,
            user: Some("NT AUTHORITY\\SYSTEM".to_string()),
        };
    }
    if pid == 4 {
        return RawProcessMeta {
            pid,
            name: Some("System".to_string()),
            path: None,
            user: Some("NT AUTHORITY\\SYSTEM".to_string()),
        };
    }

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
    let Ok(proc_handle) = handle else {
        return RawProcessMeta {
            pid,
            name: None,
            path: None,
            user: None,
        };
    };
    let _guard = HandleGuard(proc_handle);

    let mut path = query_full_image_name(proc_handle);
    if path.is_none()
        && let Ok(vm_handle) = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
    {
        let _vm_guard = HandleGuard(vm_handle);
        path = query_module_file_name(vm_handle);
    }

    let name = path
        .as_deref()
        .and_then(|p| Path::new(p).file_name().and_then(|s| s.to_str()))
        .map(ToOwned::to_owned);

    let user = query_process_user(proc_handle);

    RawProcessMeta { pid, name, path, user }
}

fn query_full_image_name(handle: HANDLE) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len) };
    if ok.is_ok() && len > 0 {
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    } else {
        None
    }
}

fn query_module_file_name(handle: HANDLE) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    let len = unsafe { GetModuleFileNameExW(Some(handle), None, &mut buf) };
    if len > 0 {
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    } else {
        None
    }
}

fn query_process_user(proc_handle: HANDLE) -> Option<String> {
    let mut token = HANDLE::default();
    if unsafe { OpenProcessToken(proc_handle, TOKEN_QUERY, &mut token) }.is_err() {
        return None;
    }
    let _token_guard = HandleGuard(token);

    let mut needed = 0u32;
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    if needed == 0 {
        return None;
    }

    let mut aligned = vec![0u64; (needed as usize).max(std::mem::size_of::<TOKEN_USER>()).div_ceil(8)];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(aligned.as_mut_ptr().cast::<c_void>()),
            (aligned.len() * 8) as u32,
            &mut needed,
        )
    }
    .is_err()
    {
        return None;
    }

    if (needed as usize) < std::mem::size_of::<TOKEN_USER>()
        || aligned.len().saturating_mul(8) < std::mem::size_of::<TOKEN_USER>()
    {
        return None;
    }

    let token_user = unsafe { &*(aligned.as_ptr().cast::<TOKEN_USER>()) };
    let psid = token_user.User.Sid;

    let mut name_len = 0u32;
    let mut dom_len = 0u32;
    let mut sid_use = SID_NAME_USE::default();
    let _ = unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            psid,
            None,
            &mut name_len,
            None,
            &mut dom_len,
            &mut sid_use,
        )
    };
    if name_len == 0 {
        return None;
    }

    let mut name_buf = vec![0u16; name_len as usize];
    let mut dom_buf = vec![0u16; dom_len.max(1) as usize];
    let res = unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            psid,
            Some(PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            if dom_len > 0 {
                Some(PWSTR(dom_buf.as_mut_ptr()))
            } else {
                None
            },
            &mut dom_len,
            &mut sid_use,
        )
    };
    if res.is_err() {
        return None;
    }

    let user = String::from_utf16_lossy(&name_buf[..name_len as usize]);
    let domain = if dom_len > 0 {
        String::from_utf16_lossy(&dom_buf[..dom_len as usize])
    } else {
        String::new()
    };

    if domain.is_empty() {
        Some(user)
    } else {
        Some(format!("{domain}\\{user}"))
    }
}

fn query_owner_module(pid: u32, info: &[u64; 16]) -> Option<(String, Option<String>)> {
    let mut size = 0u32;
    let rc = unsafe {
        GetOwnerModuleFromPidAndInfo(
            pid,
            info.as_ptr(),
            TCPIP_OWNER_MODULE_INFO_BASIC,
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if rc != ERROR_INSUFFICIENT_BUFFER.0 || size == 0 {
        return None;
    }

    let mut aligned = vec![
        0u64;
        (size as usize)
            .max(std::mem::size_of::<TCPIP_OWNER_MODULE_BASIC_INFO>())
            .div_ceil(8)
    ];
    let rc2 = unsafe {
        GetOwnerModuleFromPidAndInfo(
            pid,
            info.as_ptr(),
            TCPIP_OWNER_MODULE_INFO_BASIC,
            aligned.as_mut_ptr().cast::<c_void>(),
            &mut size,
        )
    };
    if rc2 != 0
        || (size as usize) < std::mem::size_of::<TCPIP_OWNER_MODULE_BASIC_INFO>()
        || aligned.len().saturating_mul(8) < std::mem::size_of::<TCPIP_OWNER_MODULE_BASIC_INFO>()
    {
        return None;
    }

    let basic = unsafe { &*(aligned.as_ptr().cast::<TCPIP_OWNER_MODULE_BASIC_INFO>()) };
    let name = if basic.pModuleName.is_null() {
        return None;
    } else {
        unsafe { basic.pModuleName.to_string().ok()? }
    };
    let path = if basic.pModulePath.is_null() {
        None
    } else {
        unsafe { basic.pModulePath.to_string().ok() }
    };
    if name.is_empty() { None } else { Some((name, path)) }
}
