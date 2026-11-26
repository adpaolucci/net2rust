use std::collections::HashSet;
use std::sync::Arc;

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use net2rust_core::NetContext;

use crate::model::{plan_filter_query, split_target_list};
use crate::oui_db::{OfflineOuiDb, OuiRecord};

pub const TOOL_ID: &str = "osint.oui";
pub const DESCRIPTION: &str = "Embedded offline IEEE MA-L/MA-M/MA-S MAC OUI vendor lookup.";

pub fn schema() -> TableSchema {
    TableSchema::new(
        TOOL_ID,
        "IEEE MAC OUI Vendor Lookup",
        vec![
            ColumnDef::new("MACPrefix", "MAC Prefix", ColumnType::Text).with_width_hint(140),
            ColumnDef::new("VendorName", "Vendor Name", ColumnType::Text).with_width_hint(240),
            ColumnDef::new("Address", "Address", ColumnType::Text).with_width_hint(200),
            ColumnDef::new("Country", "Country", ColumnType::Text).with_width_hint(80),
            ColumnDef::new("RegistryBlock", "Registry Block", ColumnType::Text).with_width_hint(110),
        ],
    )
}

pub struct OuiProvider {
    ctx: NetContext,
    schema: TableSchema,
}

impl OuiProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx, schema: schema() }
    }

    pub fn load_db(&self) -> Result<OfflineOuiDb, TableError> {
        let mut db = OfflineOuiDb::embedded();
        if let Some(cfg) = self.ctx.offline_config()
            && let Some(path) = &cfg.oui_db_path
        {
            db.merge_csv_file(path)?;
        }
        Ok(db)
    }
}

impl TableProvider for OuiProvider {
    fn tool_id(&self) -> &'static str {
        TOOL_ID
    }

    fn description(&self) -> &'static str {
        DESCRIPTION
    }

    fn schema(&self) -> TableSchema {
        self.schema.clone()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let db = self.load_db()?;
        let plan = plan_filter_query(
            req.filter.as_ref(),
            &["MACPrefix", "MAC", "MACAddress"],
            OfflineOuiDb::is_valid_lookup_input,
            |tok| db.lookup_str(tok).ok().map(|rec| rec.mac_prefix),
        );
        let tokens: Vec<String> = plan
            .targets
            .iter()
            .flat_map(|s| {
                if OfflineOuiDb::is_valid_lookup_input(s) {
                    vec![s.trim().to_string()]
                } else {
                    split_target_list(s)
                }
            })
            .collect();

        let records: Vec<OuiRecord> = if tokens.is_empty() {
            db.all_records()
        } else {
            let mut out = Vec::with_capacity(tokens.len());
            let mut seen = HashSet::new();
            for tok in tokens {
                let rec = db.lookup_str(&tok)?;
                if seen.insert((rec.mac_prefix.clone(), rec.registry_block)) {
                    out.push(rec);
                }
            }
            if plan.include_defaults {
                for rec in db.all_records() {
                    if seen.insert((rec.mac_prefix.clone(), rec.registry_block)) {
                        out.push(rec);
                    }
                }
            }
            out
        };

        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, rec)| {
                let detail = serde_json::to_value(&rec).unwrap_or(serde_json::Value::Null);
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.mac_prefix),
                        CellValue::Text(rec.vendor_name),
                        CellValue::Text(rec.address),
                        CellValue::Text(rec.country),
                        CellValue::Text(rec.registry_block.as_str().to_string()),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        let forwarded = TableQuery {
            filter: plan.remaining_filter,
            sort: req.sort.clone(),
            columns: req.columns.clone(),
            offset: req.offset,
            limit: req.limit,
        };
        let mut data = apply_query(&self.schema, &rows, &forwarded)?;
        if let Some(max) = self.ctx.max_rows {
            data.rows.truncate(max);
        }
        Ok(data)
    }
}

pub fn provider(ctx: &NetContext) -> Arc<dyn TableProvider> {
    Arc::new(OuiProvider::new(ctx.clone()))
}
