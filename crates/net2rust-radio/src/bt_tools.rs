use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use net2rust_core::{MacAddr, NetContext};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::backend::{BluetoothBackend, BluetoothClassicDevice, BtSnapshot};
use crate::ble_ad::{encode_ad_sections, format_hex_upper, parse_ble_ad};
use crate::bt_cod::decode_cod;
use crate::bt_lookup::{lookup_company_id, lookup_oui};

pub fn bt_providers(ctx: &NetContext, backend: Arc<dyn BluetoothBackend>) -> Vec<Arc<dyn TableProvider>> {
    vec![
        Arc::new(BtViewProvider::new(ctx.clone(), Arc::clone(&backend))),
        Arc::new(BtLogProvider::new(ctx.clone(), Arc::clone(&backend))),
        Arc::new(BtClProvider::new(ctx.clone(), Arc::clone(&backend))),
        Arc::new(BleViewProvider::new(ctx.clone(), backend)),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BtLogEventType {
    Arrived,
    Departed,
}

impl BtLogEventType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Arrived => "Arrived",
            Self::Departed => "Departed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtLogEvent {
    pub event_time: DateTime<Utc>,
    pub event_type: BtLogEventType,
    pub device_name: String,
    pub address: MacAddr,
    pub device_class: String,
    pub vendor: String,
}

pub fn snapshot_from_devices(devices: &[BluetoothClassicDevice]) -> BtSnapshot {
    let mut map = BtSnapshot::new();
    for dev in devices {
        map.insert(dev.address, dev.clone());
    }
    map
}

pub fn diff_snapshots(prev: &BtSnapshot, curr: &BtSnapshot, at: DateTime<Utc>) -> Vec<BtLogEvent> {
    let mut events = Vec::new();

    for (addr, dev) in curr {
        if !prev.contains_key(addr) {
            let cod = decode_cod(dev.class_of_device);
            events.push(BtLogEvent {
                event_time: at,
                event_type: BtLogEventType::Arrived,
                device_name: dev.name.clone(),
                address: *addr,
                device_class: cod.summary,
                vendor: lookup_oui(addr),
            });
        }
    }

    for (addr, dev) in prev {
        if !curr.contains_key(addr) {
            let cod = decode_cod(dev.class_of_device);
            events.push(BtLogEvent {
                event_time: at,
                event_type: BtLogEventType::Departed,
                device_name: dev.name.clone(),
                address: *addr,
                device_class: cod.summary,
                vendor: lookup_oui(addr),
            });
        }
    }

    events
}

pub struct BtViewProvider {
    ctx: NetContext,
    backend: Arc<dyn BluetoothBackend>,
}

impl BtViewProvider {
    pub fn new(ctx: NetContext, backend: Arc<dyn BluetoothBackend>) -> Self {
        Self { ctx, backend }
    }
}

impl TableProvider for BtViewProvider {
    fn tool_id(&self) -> &'static str {
        "radio.bt-view"
    }

    fn description(&self) -> &'static str {
        "BluetoothView equivalent: Bluetooth Classic device discovery monitor."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Bluetooth Classic Devices",
            vec![
                ColumnDef::new("device_name", "Device Name", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("address", "Address", ColumnType::MacAddr).with_width_hint(140),
                ColumnDef::new("device_class", "Device Class", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("class_hex", "Class Hex", ColumnType::Text).with_width_hint(95),
                ColumnDef::new("connected", "Connected", ColumnType::Bool).with_width_hint(90),
                ColumnDef::new("remembered", "Remembered", ColumnType::Bool).with_width_hint(95),
                ColumnDef::new("authenticated", "Authenticated", ColumnType::Bool).with_width_hint(105),
                ColumnDef::new("last_seen", "Last Seen", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("last_used", "Last Used", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("vendor", "Vendor", ColumnType::Text).with_width_hint(180),
            ],
        )
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let devices = self.backend.list_classic_devices()?;
        let schema = self.schema();
        let mut rows = Vec::with_capacity(devices.len());

        for (idx, dev) in devices.into_iter().enumerate() {
            let cod = decode_cod(dev.class_of_device);
            let vendor = lookup_oui(&dev.address);
            let class_hex = format!("0x{:06X}", dev.class_of_device);
            let name = if dev.name.is_empty() {
                "<Unnamed>".to_string()
            } else {
                dev.name.clone()
            };

            let detail = json!({
                "device_name": name,
                "address": dev.address.to_colon_string(),
                "class_of_device": class_hex,
                "decoded_cod": cod,
                "connected": dev.connected,
                "remembered": dev.remembered,
                "authenticated": dev.authenticated,
                "last_seen": dev.last_seen,
                "last_used": dev.last_used,
                "vendor": vendor,
            });

            rows.push(
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(name),
                        CellValue::Text(dev.address.to_colon_string()),
                        CellValue::Text(cod.summary),
                        CellValue::Text(class_hex),
                        CellValue::Bool(dev.connected),
                        CellValue::Bool(dev.remembered),
                        CellValue::Bool(dev.authenticated),
                        dev.last_seen.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        dev.last_used.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Text(vendor),
                    ],
                )
                .with_detail_json(detail),
            );
        }

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&schema, &rows, req)
    }
}

#[derive(Debug, Default)]
struct BtLogState {
    prev: Option<BtSnapshot>,
    history: Vec<BtLogEvent>,
    offline_replayed: bool,
}

const MAX_BT_LOG_HISTORY: usize = 4096;

pub struct BtLogProvider {
    ctx: NetContext,
    backend: Arc<dyn BluetoothBackend>,
    state: Mutex<BtLogState>,
}

impl BtLogProvider {
    pub fn new(ctx: NetContext, backend: Arc<dyn BluetoothBackend>) -> Self {
        Self {
            ctx,
            backend,
            state: Mutex::new(BtLogState::default()),
        }
    }
}

impl TableProvider for BtLogProvider {
    fn tool_id(&self) -> &'static str {
        "radio.bt-log"
    }

    fn description(&self) -> &'static str {
        "BluetoothLogView equivalent: Bluetooth device arrival and departure event log."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Bluetooth Arrival / Departure Log",
            vec![
                ColumnDef::new("event_time", "Event Time", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("event_type", "Event Type", ColumnType::Text).with_width_hint(95),
                ColumnDef::new("device_name", "Device Name", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("address", "Address", ColumnType::MacAddr).with_width_hint(140),
                ColumnDef::new("device_class", "Device Class", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("vendor", "Vendor", ColumnType::Text).with_width_hint(180),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let schema = self.schema();
        let mut guard = self
            .state
            .lock()
            .map_err(|_| TableError::Provider("bt-log state lock poisoned".to_string()))?;

        if let Some(snapshots) = self.backend.offline_log_snapshots() {
            if !guard.offline_replayed {
                for (at, devs) in snapshots {
                    let curr = snapshot_from_devices(&devs);
                    let prev = guard.prev.take().unwrap_or_default();
                    let delta = diff_snapshots(&prev, &curr, at);
                    guard.history.extend(delta);
                    guard.prev = Some(curr);
                }
                guard.offline_replayed = true;
            }
        } else {
            let devices = self.backend.list_classic_devices()?;
            let curr = snapshot_from_devices(&devices);
            let prev = guard.prev.take().unwrap_or_default();
            let delta = diff_snapshots(&prev, &curr, Utc::now());
            guard.history.extend(delta);
            guard.prev = Some(curr);
        }

        if guard.history.len() > MAX_BT_LOG_HISTORY {
            let excess = guard.history.len() - MAX_BT_LOG_HISTORY;
            guard.history.drain(0..excess);
        }

        let mut rows: Vec<Row> = guard
            .history
            .iter()
            .enumerate()
            .map(|(idx, ev)| {
                let detail = json!({
                    "event_time": ev.event_time,
                    "event_type": ev.event_type.as_str(),
                    "device_name": ev.device_name,
                    "address": ev.address.to_colon_string(),
                    "device_class": ev.device_class,
                    "vendor": ev.vendor,
                });
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Timestamp(ev.event_time),
                        CellValue::Text(ev.event_type.as_str().to_string()),
                        CellValue::Text(ev.device_name.clone()),
                        CellValue::Text(ev.address.to_colon_string()),
                        CellValue::Text(ev.device_class.clone()),
                        CellValue::Text(ev.vendor.clone()),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&schema, &rows, req)
    }
}

pub struct BtClProvider {
    ctx: NetContext,
    backend: Arc<dyn BluetoothBackend>,
}

impl BtClProvider {
    pub fn new(ctx: NetContext, backend: Arc<dyn BluetoothBackend>) -> Self {
        Self { ctx, backend }
    }
}

impl TableProvider for BtClProvider {
    fn tool_id(&self) -> &'static str {
        "radio.bt-cl"
    }

    fn description(&self) -> &'static str {
        "BluetoothCL equivalent: deterministic Bluetooth Classic enumeration."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Bluetooth Classic CLI Enumeration",
            vec![
                ColumnDef::new("address", "Address", ColumnType::MacAddr).with_width_hint(140),
                ColumnDef::new("name", "Name", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("class_of_device", "Class of Device", ColumnType::Text).with_width_hint(95),
                ColumnDef::new("major_class", "Major Class", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("minor_class", "Minor Class", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("connected", "Connected", ColumnType::Bool).with_width_hint(90),
                ColumnDef::new("remembered", "Remembered", ColumnType::Bool).with_width_hint(95),
                ColumnDef::new("authenticated", "Authenticated", ColumnType::Bool).with_width_hint(105),
                ColumnDef::new("last_used", "Last Used", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("vendor", "Vendor", ColumnType::Text).with_width_hint(180),
            ],
        )
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let devices = self.backend.list_classic_devices()?;
        let schema = self.schema();
        let mut rows = Vec::with_capacity(devices.len());

        for (idx, dev) in devices.into_iter().enumerate() {
            let cod = decode_cod(dev.class_of_device);
            let vendor = lookup_oui(&dev.address);
            let class_hex = format!("0x{:06X}", dev.class_of_device);

            let detail = json!({
                "address": dev.address.to_colon_string(),
                "name": dev.name,
                "class_of_device": class_hex,
                "decoded_cod": cod,
                "connected": dev.connected,
                "remembered": dev.remembered,
                "authenticated": dev.authenticated,
                "last_seen": dev.last_seen,
                "last_used": dev.last_used,
                "vendor": vendor,
            });

            rows.push(
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(dev.address.to_colon_string()),
                        CellValue::Text(dev.name),
                        CellValue::Text(class_hex),
                        CellValue::Text(cod.major_class.to_string()),
                        CellValue::Text(cod.minor_class),
                        CellValue::Bool(dev.connected),
                        CellValue::Bool(dev.remembered),
                        CellValue::Bool(dev.authenticated),
                        dev.last_used.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Text(vendor),
                    ],
                )
                .with_detail_json(detail),
            );
        }

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&schema, &rows, req)
    }
}

pub struct BleViewProvider {
    ctx: NetContext,
    backend: Arc<dyn BluetoothBackend>,
}

impl BleViewProvider {
    pub fn new(ctx: NetContext, backend: Arc<dyn BluetoothBackend>) -> Self {
        Self { ctx, backend }
    }
}

impl TableProvider for BleViewProvider {
    fn tool_id(&self) -> &'static str {
        "radio.ble"
    }

    fn description(&self) -> &'static str {
        "BluetoothLEView equivalent: Bluetooth Low Energy (BLE) advertisement, RSSI, service UUID, and manufacturer data scanner."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Bluetooth Low Energy (BLE) Advertisements",
            vec![
                ColumnDef::new("address", "Address", ColumnType::MacAddr).with_width_hint(140),
                ColumnDef::new("address_type", "Address Type", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("local_name", "Local Name", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("rssi", "RSSI (dBm)", ColumnType::Int).with_width_hint(90),
                ColumnDef::new("tx_power", "Tx Power (dBm)", ColumnType::Int).with_width_hint(105),
                ColumnDef::new("advertisement_type", "Adv Type", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("service_uuids", "Service UUIDs", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("manufacturer_company", "Manufacturer", ColumnType::Text).with_width_hint(170),
                ColumnDef::new("manufacturer_data_hex", "Mfg Data (Hex)", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("appearance", "Appearance", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("flags", "Flags", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("last_seen", "Last Seen", ColumnType::Timestamp).with_width_hint(170),
            ],
        )
        .with_default_sort(3, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let duration = self
            .ctx
            .timeout
            .clamp(Duration::from_millis(250), Duration::from_secs(3));
        let records = self.backend.scan_ble_advertisements(duration)?;
        let schema = self.schema();
        let mut rows = Vec::with_capacity(records.len());

        for (idx, rec) in records.into_iter().enumerate() {
            let raw_ad = encode_ad_sections(&rec.data_sections);
            let parsed_ad = if raw_ad.is_empty() {
                None
            } else {
                parse_ble_ad(&raw_ad).ok()
            };

            let local_name = if !rec.local_name.is_empty() {
                rec.local_name.clone()
            } else {
                parsed_ad
                    .as_ref()
                    .and_then(|p| p.local_name.clone())
                    .unwrap_or_default()
            };

            let mut uuids = rec.service_uuids.clone();
            if let Some(p) = &parsed_ad {
                for u in &p.service_uuids {
                    if !uuids.contains(u) {
                        uuids.push(u.clone());
                    }
                }
            }
            let uuids_joined = uuids.join(", ");

            let tx_power = rec
                .tx_power_dbm
                .or_else(|| parsed_ad.as_ref().and_then(|p| p.tx_power_dbm.map(i16::from)));

            let (mfg_company, mfg_hex) = if let Some((cid, data)) = rec.manufacturer_data.first() {
                let name = lookup_company_id(*cid)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("0x{cid:04X}"));
                (name, format_hex_upper(data))
            } else if let Some(m) = parsed_ad.as_ref().and_then(|p| p.manufacturer_data.first()) {
                let name = m
                    .company_name
                    .clone()
                    .unwrap_or_else(|| format!("0x{:04X}", m.company_id));
                (name, format_hex_upper(&m.data))
            } else {
                (lookup_oui(&rec.address), String::new())
            };

            let appearance = parsed_ad
                .as_ref()
                .and_then(|p| p.appearance_label.clone())
                .unwrap_or_default();

            let flags_str = rec
                .flags
                .or_else(|| parsed_ad.as_ref().and_then(|p| p.flags))
                .map(|f| crate::ble_ad::decode_flags(f).join(", "))
                .unwrap_or_default();

            let detail = json!({
                "address": rec.address.to_colon_string(),
                "address_type": rec.address_type,
                "advertisement_type": rec.advertisement_type,
                "rssi_dbm": rec.rssi_dbm,
                "tx_power_dbm": tx_power,
                "local_name": local_name,
                "service_uuids": uuids,
                "manufacturer_data": rec.manufacturer_data.iter().map(|(cid, d)| json!({
                    "company_id": format!("0x{cid:04X}"),
                    "company_name": lookup_company_id(*cid),
                    "data_hex": format_hex_upper(d),
                })).collect::<Vec<_>>(),
                "parsed_ad": parsed_ad,
                "last_seen": rec.last_seen,
            });

            let mut row = Row::new(
                idx as u64 + 1,
                vec![
                    CellValue::Text(rec.address.to_colon_string()),
                    CellValue::Text(rec.address_type),
                    CellValue::Text(local_name),
                    CellValue::Int(i64::from(rec.rssi_dbm)),
                    tx_power
                        .map(|t| CellValue::Int(i64::from(t)))
                        .unwrap_or(CellValue::Null),
                    CellValue::Text(rec.advertisement_type),
                    CellValue::Text(uuids_joined),
                    CellValue::Text(mfg_company),
                    CellValue::Text(mfg_hex),
                    CellValue::Text(appearance),
                    CellValue::Text(flags_str),
                    CellValue::Timestamp(rec.last_seen),
                ],
            )
            .with_detail_json(detail);

            if !raw_ad.is_empty() {
                row = row.with_raw_bytes(raw_ad);
            }
            rows.push(row);
        }

        self.ctx.apply_row_limit(&mut rows);
        apply_query(&schema, &rows, req)
    }
}
