use std::collections::BTreeMap;
use std::mem::size_of;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use net2rust_core::{NetError, NetResult};
use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisementReceivedEventArgs, BluetoothLEAdvertisementType, BluetoothLEAdvertisementWatcher,
    BluetoothLEAdvertisementWatcherStoppedEventArgs, BluetoothLEScanningMode,
};
use windows::Devices::Bluetooth::{BluetoothAddressType, BluetoothError};
use windows::Foundation::TypedEventHandler;
use windows::Storage::Streams::{DataReader, IBuffer};
use windows::Win32::Devices::Bluetooth::{
    BLUETOOTH_DEVICE_INFO, BLUETOOTH_DEVICE_SEARCH_PARAMS, BLUETOOTH_FIND_RADIO_PARAMS, BLUETOOTH_RADIO_INFO,
    BluetoothFindDeviceClose, BluetoothFindFirstDevice, BluetoothFindFirstRadio, BluetoothFindNextDevice,
    BluetoothFindNextRadio, BluetoothFindRadioClose, BluetoothGetDeviceInfo, BluetoothGetRadioInfo,
    HBLUETOOTH_DEVICE_FIND, HBLUETOOTH_RADIO_FIND,
};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_DEVICE_NOT_CONNECTED, ERROR_NO_MORE_ITEMS, ERROR_NOT_FOUND, ERROR_SUCCESS,
    HANDLE, RPC_E_CHANGED_MODE, SYSTEMTIME,
};
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};
use windows::core::{GUID, HRESULT, Ref};

use crate::backend::{BleAdvertisementRecord, BluetoothBackend, BluetoothClassicDevice, BluetoothRadioInfo};
use crate::ble_ad::{format_uuid16, format_uuid128_be};
use crate::bt_lookup::mac_from_bt_u64;

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct RadioFindGuard(HBLUETOOTH_RADIO_FIND);

impl Drop for RadioFindGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = BluetoothFindRadioClose(self.0);
            }
        }
    }
}

struct DeviceFindGuard(HBLUETOOTH_DEVICE_FIND);

impl Drop for DeviceFindGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = BluetoothFindDeviceClose(self.0);
            }
        }
    }
}

struct RoInitGuard {
    should_uninit: bool,
}

impl RoInitGuard {
    fn new_mta() -> NetResult<Self> {
        let res = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
        match res {
            Ok(()) => Ok(Self { should_uninit: true }),
            Err(e) if e.code() == RPC_E_CHANGED_MODE => Ok(Self { should_uninit: false }),
            Err(e) => Err(NetError::DriverUnavailable(format!("RoInitialize failed: {e}"))),
        }
    }
}

impl Drop for RoInitGuard {
    fn drop(&mut self) {
        if self.should_uninit {
            unsafe { RoUninitialize() };
        }
    }
}

fn is_win32_no_hardware(code: HRESULT) -> bool {
    code == HRESULT::from_win32(ERROR_NO_MORE_ITEMS.0)
        || code == HRESULT::from_win32(ERROR_NOT_FOUND.0)
        || code == HRESULT::from_win32(ERROR_DEVICE_NOT_CONNECTED.0)
}

fn map_bt_win32_err(err: &windows::core::Error, context: &str) -> NetError {
    let code = err.code();
    if code == HRESULT::from_win32(ERROR_ACCESS_DENIED.0) {
        NetError::PermissionDenied(format!("{context}: access denied ({err})"))
    } else if is_win32_no_hardware(code) {
        NetError::HardwareNotFound(format!("{context}: no local Bluetooth radio installed ({err})"))
    } else {
        NetError::DriverUnavailable(format!("{context}: {err}"))
    }
}

pub fn map_bluetooth_error(err: BluetoothError, context: &str) -> NetError {
    match err {
        BluetoothError::RadioNotAvailable | BluetoothError::DisabledByUser => {
            NetError::HardwareNotFound(format!("{context}: Bluetooth radio unavailable or disabled by user"))
        }
        BluetoothError::DisabledByPolicy | BluetoothError::ConsentRequired => {
            NetError::PermissionDenied(format!("{context}: Bluetooth disabled by policy or consent required"))
        }
        BluetoothError::NotSupported | BluetoothError::TransportNotSupported => {
            NetError::NotSupported(format!("{context}: Bluetooth LE transport not supported"))
        }
        BluetoothError::ResourceInUse | BluetoothError::DeviceNotConnected | BluetoothError::OtherError => {
            NetError::DriverUnavailable(format!("{context}: Bluetooth driver error ({})", err.0))
        }
        _ => NetError::DriverUnavailable(format!("{context}: Bluetooth error ({})", err.0)),
    }
}

fn utf16_array_to_string(arr: &[u16]) -> String {
    let len = arr.iter().position(|&c| c == 0).unwrap_or(arr.len());
    String::from_utf16_lossy(&arr[..len])
}

pub fn systemtime_to_datetime(st: SYSTEMTIME) -> Option<DateTime<Utc>> {
    if st.wYear == 0 {
        return None;
    }
    let date = NaiveDate::from_ymd_opt(i32::from(st.wYear), u32::from(st.wMonth), u32::from(st.wDay))?;
    let dt = date.and_hms_milli_opt(
        u32::from(st.wHour),
        u32::from(st.wMinute),
        u32::from(st.wSecond),
        u32::from(st.wMilliseconds),
    )?;
    Some(Utc.from_utc_datetime(&dt))
}

fn winrt_datetime_to_utc(universal_time: i64) -> DateTime<Utc> {
    // Windows FILETIME / WinRT DateTime: 100-ns intervals since 1601-01-01T00:00:00Z.
    const UNIX_EPOCH_100NS: i64 = 116_444_736_000_000_000;
    let unix_100ns = universal_time.saturating_sub(UNIX_EPOCH_100NS);
    let secs = unix_100ns.div_euclid(10_000_000);
    let nanos = (unix_100ns.rem_euclid(10_000_000) * 100) as u32;
    Utc.timestamp_opt(secs, nanos).single().unwrap_or_else(Utc::now)
}

fn read_ibuffer(buffer: &IBuffer) -> windows::core::Result<Vec<u8>> {
    let reader = DataReader::FromBuffer(buffer)?;
    let len = reader.UnconsumedBufferLength()? as usize;
    let mut bytes = vec![0u8; len];
    if len > 0 {
        reader.ReadBytes(&mut bytes)?;
    }
    Ok(bytes)
}

fn guid_to_ble_uuid(g: &GUID) -> String {
    // Check standard Bluetooth Base UUID: 0000XXXX-0000-1000-8000-00805f9b34fb
    if g.data2 == 0x0000
        && g.data3 == 0x1000
        && g.data4 == [0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb]
        && (g.data1 & 0xFFFF_0000) == 0
    {
        return format_uuid16(g.data1 as u16);
    }
    let mut be = [0u8; 16];
    be[0..4].copy_from_slice(&g.data1.to_be_bytes());
    be[4..6].copy_from_slice(&g.data2.to_be_bytes());
    be[6..8].copy_from_slice(&g.data3.to_be_bytes());
    be[8..16].copy_from_slice(&g.data4);
    format_uuid128_be(&be)
}

fn addr_type_label(t: BluetoothAddressType) -> &'static str {
    if t == BluetoothAddressType::Public {
        "Public"
    } else if t == BluetoothAddressType::Random {
        "Random"
    } else {
        "Unspecified"
    }
}

fn adv_type_label(t: BluetoothLEAdvertisementType) -> &'static str {
    if t == BluetoothLEAdvertisementType::ConnectableUndirected {
        "ConnectableUndirected"
    } else if t == BluetoothLEAdvertisementType::ConnectableDirected {
        "ConnectableDirected"
    } else if t == BluetoothLEAdvertisementType::ScannableUndirected {
        "ScannableUndirected"
    } else if t == BluetoothLEAdvertisementType::NonConnectableUndirected {
        "NonConnectableUndirected"
    } else if t == BluetoothLEAdvertisementType::ScanResponse {
        "ScanResponse"
    } else if t == BluetoothLEAdvertisementType::Extended {
        "Extended"
    } else {
        "Unknown"
    }
}

#[derive(Debug, Default)]
struct BleWatchState {
    devices: BTreeMap<u64, BleAdvertisementRecord>,
    stopped: bool,
    stopped_error: Option<BluetoothError>,
}

#[derive(Debug, Default)]
pub struct Win32BluetoothBackend;

impl Win32BluetoothBackend {
    pub fn new() -> Self {
        Self
    }

    fn open_radio_handles(&self) -> NetResult<Vec<HandleGuard>> {
        let params = BLUETOOTH_FIND_RADIO_PARAMS {
            dwSize: size_of::<BLUETOOTH_FIND_RADIO_PARAMS>() as u32,
        };
        let mut first_handle = HANDLE::default();
        let find = unsafe { BluetoothFindFirstRadio(&params, &mut first_handle) }
            .map_err(|e| map_bt_win32_err(&e, "BluetoothFindFirstRadio"))?;
        let find_guard = RadioFindGuard(find);

        let mut handles = Vec::new();
        if !first_handle.is_invalid() {
            handles.push(HandleGuard(first_handle));
        }

        loop {
            let mut next_handle = HANDLE::default();
            match unsafe { BluetoothFindNextRadio(find_guard.0, &mut next_handle) } {
                Ok(()) => {
                    if !next_handle.is_invalid() {
                        handles.push(HandleGuard(next_handle));
                    }
                }
                Err(e) if e.code() == HRESULT::from_win32(ERROR_NO_MORE_ITEMS.0) => break,
                Err(_) => break,
            }
        }

        if handles.is_empty() {
            return Err(NetError::HardwareNotFound(
                "no local Bluetooth radio installed".to_string(),
            ));
        }
        Ok(handles)
    }
}

impl BluetoothBackend for Win32BluetoothBackend {
    fn list_radios(&self) -> NetResult<Vec<BluetoothRadioInfo>> {
        let handles = self.open_radio_handles()?;
        let mut radios = Vec::with_capacity(handles.len());
        for h in handles {
            let mut info = BLUETOOTH_RADIO_INFO {
                dwSize: size_of::<BLUETOOTH_RADIO_INFO>() as u32,
                ..Default::default()
            };
            let rc = unsafe { BluetoothGetRadioInfo(h.0, &mut info) };
            if rc != ERROR_SUCCESS.0 {
                continue;
            }
            let addr_u64 = unsafe { info.address.Anonymous.ullLong };
            radios.push(BluetoothRadioInfo {
                name: utf16_array_to_string(&info.szName),
                address: mac_from_bt_u64(addr_u64),
                class_of_device: info.ulClassofDevice,
                lmp_subversion: info.lmpSubversion,
                manufacturer_id: info.manufacturer,
            });
        }
        Ok(radios)
    }

    fn list_classic_devices(&self) -> NetResult<Vec<BluetoothClassicDevice>> {
        let handles = self.open_radio_handles()?;
        let mut seen = BTreeMap::<u64, BluetoothClassicDevice>::new();

        for radio in handles {
            let search = BLUETOOTH_DEVICE_SEARCH_PARAMS {
                dwSize: size_of::<BLUETOOTH_DEVICE_SEARCH_PARAMS>() as u32,
                fReturnAuthenticated: true.into(),
                fReturnRemembered: true.into(),
                fReturnUnknown: true.into(),
                fReturnConnected: true.into(),
                fIssueInquiry: false.into(),
                cTimeoutMultiplier: 0,
                hRadio: radio.0,
            };

            let mut dev_info = BLUETOOTH_DEVICE_INFO {
                dwSize: size_of::<BLUETOOTH_DEVICE_INFO>() as u32,
                ..Default::default()
            };

            let find = match unsafe { BluetoothFindFirstDevice(&search, &mut dev_info) } {
                Ok(f) => DeviceFindGuard(f),
                Err(e) if e.code() == HRESULT::from_win32(ERROR_NO_MORE_ITEMS.0) => continue,
                Err(e) => return Err(map_bt_win32_err(&e, "BluetoothFindFirstDevice")),
            };

            loop {
                let mut refreshed = dev_info;
                refreshed.dwSize = size_of::<BLUETOOTH_DEVICE_INFO>() as u32;
                let _ = unsafe { BluetoothGetDeviceInfo(Some(radio.0), &mut refreshed) };

                let addr_u64 = unsafe { refreshed.Address.Anonymous.ullLong };
                seen.insert(
                    addr_u64,
                    BluetoothClassicDevice {
                        name: utf16_array_to_string(&refreshed.szName),
                        address: mac_from_bt_u64(addr_u64),
                        class_of_device: refreshed.ulClassofDevice,
                        connected: refreshed.fConnected.as_bool(),
                        remembered: refreshed.fRemembered.as_bool(),
                        authenticated: refreshed.fAuthenticated.as_bool(),
                        last_seen: systemtime_to_datetime(refreshed.stLastSeen),
                        last_used: systemtime_to_datetime(refreshed.stLastUsed),
                    },
                );

                dev_info = BLUETOOTH_DEVICE_INFO {
                    dwSize: size_of::<BLUETOOTH_DEVICE_INFO>() as u32,
                    ..Default::default()
                };
                match unsafe { BluetoothFindNextDevice(find.0, &mut dev_info) } {
                    Ok(()) => {}
                    Err(e) if e.code() == HRESULT::from_win32(ERROR_NO_MORE_ITEMS.0) => break,
                    Err(_) => break,
                }
            }
        }

        Ok(seen.into_values().collect())
    }

    fn scan_ble_advertisements(&self, duration: Duration) -> NetResult<Vec<BleAdvertisementRecord>> {
        let watch_window = duration.clamp(Duration::from_millis(250), Duration::from_secs(3));
        let handle = std::thread::spawn(move || -> NetResult<Vec<BleAdvertisementRecord>> {
            let _ro = RoInitGuard::new_mta()?;

            let watcher = BluetoothLEAdvertisementWatcher::new()
                .map_err(|e| NetError::NotSupported(format!("BluetoothLEAdvertisementWatcher unavailable: {e}")))?;
            let _ = watcher.SetScanningMode(BluetoothLEScanningMode::Active);

            let shared = Arc::new((Mutex::new(BleWatchState::default()), Condvar::new()));
            let rx_shared = Arc::clone(&shared);
            let stop_shared = Arc::clone(&shared);

            let rx_handler =
                TypedEventHandler::<BluetoothLEAdvertisementWatcher, BluetoothLEAdvertisementReceivedEventArgs>::new(
                    move |_sender, args: Ref<'_, BluetoothLEAdvertisementReceivedEventArgs>| {
                        let Some(args) = args.as_ref() else {
                            return Ok(());
                        };
                        let addr_u64 = args.BluetoothAddress()?;
                        let rssi = args.RawSignalStrengthInDBm()?;
                        let adv_type = args
                            .AdvertisementType()
                            .map(adv_type_label)
                            .unwrap_or("Unknown")
                            .to_string();
                        let addr_type = args
                            .BluetoothAddressType()
                            .map(addr_type_label)
                            .unwrap_or("Unspecified")
                            .to_string();
                        let tx_power = args.TransmitPowerLevelInDBm().ok().and_then(|r| r.Value().ok());
                        let last_seen = args
                            .Timestamp()
                            .map(|dt| winrt_datetime_to_utc(dt.UniversalTime))
                            .unwrap_or_else(|_| Utc::now());

                        let adv = args.Advertisement()?;
                        let local_name = adv.LocalName().map(|h| h.to_string_lossy()).unwrap_or_default();
                        let flags = adv.Flags().ok().and_then(|f| f.Value().ok()).map(|f| f.0 as u8);

                        let mut service_uuids = Vec::new();
                        if let Ok(uuids) = adv.ServiceUuids() {
                            for g in &uuids {
                                let s = guid_to_ble_uuid(&g);
                                if !service_uuids.contains(&s) {
                                    service_uuids.push(s);
                                }
                            }
                        }

                        let mut manufacturer_data = Vec::new();
                        if let Ok(mfgs) = adv.ManufacturerData() {
                            for m in &mfgs {
                                if let (Ok(cid), Ok(buf)) = (m.CompanyId(), m.Data())
                                    && let Ok(bytes) = read_ibuffer(&buf)
                                {
                                    manufacturer_data.push((cid, bytes));
                                }
                            }
                        }

                        let mut data_sections = Vec::new();
                        if let Ok(sections) = adv.DataSections() {
                            for sec in &sections {
                                if let (Ok(dtype), Ok(buf)) = (sec.DataType(), sec.Data())
                                    && let Ok(bytes) = read_ibuffer(&buf)
                                {
                                    data_sections.push((dtype, bytes));
                                }
                            }
                        }

                        if let Ok(mut guard) = rx_shared.0.lock() {
                            let entry = guard.devices.entry(addr_u64).or_insert_with(|| BleAdvertisementRecord {
                                address: mac_from_bt_u64(addr_u64),
                                address_type: addr_type.clone(),
                                advertisement_type: adv_type.clone(),
                                rssi_dbm: rssi,
                                tx_power_dbm: tx_power,
                                local_name: local_name.clone(),
                                flags,
                                service_uuids: Vec::new(),
                                manufacturer_data: Vec::new(),
                                data_sections: Vec::new(),
                                last_seen,
                            });

                            entry.rssi_dbm = rssi;
                            entry.last_seen = last_seen;
                            if entry.tx_power_dbm.is_none() {
                                entry.tx_power_dbm = tx_power;
                            }
                            if !local_name.is_empty() {
                                entry.local_name = local_name;
                            }
                            if entry.flags.is_none() {
                                entry.flags = flags;
                            }
                            for u in service_uuids {
                                if !entry.service_uuids.contains(&u) {
                                    entry.service_uuids.push(u);
                                }
                            }
                            for mfg in manufacturer_data {
                                if !entry.manufacturer_data.contains(&mfg) {
                                    entry.manufacturer_data.push(mfg);
                                }
                            }
                            for sec in data_sections {
                                if !entry.data_sections.contains(&sec) {
                                    entry.data_sections.push(sec);
                                }
                            }
                        }
                        Ok(())
                    },
                );

            let stop_handler = TypedEventHandler::<
                BluetoothLEAdvertisementWatcher,
                BluetoothLEAdvertisementWatcherStoppedEventArgs,
            >::new(
                move |_sender, args: Ref<'_, BluetoothLEAdvertisementWatcherStoppedEventArgs>| {
                    let err = args.as_ref().and_then(|a| a.Error().ok());
                    if let Ok(mut guard) = stop_shared.0.lock() {
                        guard.stopped = true;
                        guard.stopped_error = err;
                    }
                    stop_shared.1.notify_all();
                    Ok(())
                },
            );

            let rx_token = watcher
                .Received(&rx_handler)
                .map_err(|e| NetError::DriverUnavailable(format!("watcher.Received failed: {e}")))?;
            let stop_token = watcher
                .Stopped(&stop_handler)
                .map_err(|e| NetError::DriverUnavailable(format!("watcher.Stopped failed: {e}")))?;

            if let Err(e) = watcher.Start() {
                let _ = watcher.RemoveReceived(rx_token);
                let _ = watcher.RemoveStopped(stop_token);
                drop(watcher);
                return Err(NetError::HardwareNotFound(format!(
                    "BluetoothLEAdvertisementWatcher::Start failed: {e}"
                )));
            }

            {
                let guard = shared
                    .0
                    .lock()
                    .map_err(|_| NetError::Internal("BLE watch state lock poisoned".to_string()))?;
                let _ = shared.1.wait_timeout_while(guard, watch_window, |s| !s.stopped);
            }

            let _ = watcher.Stop();
            let _ = watcher.RemoveReceived(rx_token);
            let _ = watcher.RemoveStopped(stop_token);
            drop(watcher);

            let guard = shared
                .0
                .lock()
                .map_err(|_| NetError::Internal("BLE watch state lock poisoned".to_string()))?;
            if let Some(bt_err) = guard.stopped_error
                && bt_err != BluetoothError::Success
                && guard.devices.is_empty()
            {
                return Err(map_bluetooth_error(bt_err, "BluetoothLEAdvertisementWatcher"));
            }
            Ok(guard.devices.values().cloned().collect())
        });

        handle
            .join()
            .map_err(|_| NetError::Internal("WinRT BLE watcher thread panicked".to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bluetooth_error_mapping_and_systemtime_guard() {
        assert!(matches!(
            map_bluetooth_error(BluetoothError::RadioNotAvailable, "ble"),
            NetError::HardwareNotFound(_)
        ));
        assert!(matches!(
            map_bluetooth_error(BluetoothError::DisabledByUser, "ble"),
            NetError::HardwareNotFound(_)
        ));
        assert!(matches!(
            map_bluetooth_error(BluetoothError::DisabledByPolicy, "ble"),
            NetError::PermissionDenied(_)
        ));
        assert!(matches!(
            map_bluetooth_error(BluetoothError::ConsentRequired, "ble"),
            NetError::PermissionDenied(_)
        ));
        assert!(matches!(
            map_bluetooth_error(BluetoothError::NotSupported, "ble"),
            NetError::NotSupported(_)
        ));
        assert!(matches!(
            map_bluetooth_error(BluetoothError::ResourceInUse, "ble"),
            NetError::DriverUnavailable(_)
        ));

        let zero_st = SYSTEMTIME::default();
        assert_eq!(systemtime_to_datetime(zero_st), None);

        let valid_st = SYSTEMTIME {
            wYear: 2026,
            wMonth: 11,
            wDay: 20,
            wHour: 12,
            wMinute: 30,
            wSecond: 45,
            wMilliseconds: 0,
            ..Default::default()
        };
        assert!(systemtime_to_datetime(valid_st).is_some());
    }
}
