use std::net::IpAddr;
use std::sync::Arc;

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use net2rust_core::{NetContext, NetError};

use crate::geoip_db::OfflineIpDb;
use crate::model::{plan_filter_query, split_target_list};

pub const TOOL_ID: &str = "osint.ipoffline";
pub const DESCRIPTION: &str = "Embedded offline IPv4/IPv6 CIDR to country and ASN lookup.";

pub fn schema() -> TableSchema {
    TableSchema::new(
        TOOL_ID,
        "Embedded GeoIP & ASN Lookup",
        vec![
            ColumnDef::new("IPAddress", "IP Address", ColumnType::IpAddr).with_width_hint(160),
            ColumnDef::new("CountryCode", "Country Code", ColumnType::Text).with_width_hint(90),
            ColumnDef::new("CountryName", "Country Name", ColumnType::Text).with_width_hint(180),
            ColumnDef::new("Continent", "Continent", ColumnType::Text).with_width_hint(100),
            ColumnDef::new("ASN", "ASN", ColumnType::Uint).with_width_hint(90),
            ColumnDef::new("ASName", "AS Name", ColumnType::Text).with_width_hint(200),
        ],
    )
}

pub struct IpOfflineProvider {
    ctx: NetContext,
    schema: TableSchema,
}

impl IpOfflineProvider {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx, schema: schema() }
    }

    pub fn load_db(&self) -> Result<OfflineIpDb, TableError> {
        let mut db = OfflineIpDb::embedded();
        if let Some(cfg) = self.ctx.offline_config()
            && let Some(path) = &cfg.geoip_db_path
        {
            db.merge_csv_file(path)?;
        }
        Ok(db)
    }
}

impl TableProvider for IpOfflineProvider {
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
            &["IPAddress", "IP"],
            |tok| tok.parse::<IpAddr>().is_ok(),
            |tok| tok.parse::<IpAddr>().ok().map(|ip| ip.to_string()),
        );
        let mut ips: Vec<IpAddr> = Vec::new();
        for token in plan.targets.iter().flat_map(|s| split_target_list(s)) {
            let ip: IpAddr = token
                .parse()
                .map_err(|_| TableError::from(NetError::InvalidInput(format!("invalid IP address '{token}'"))))?;
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        if plan.include_defaults || ips.is_empty() {
            for seed in OfflineIpDb::default_seed_ips() {
                if let Ok(ip) = seed.parse::<IpAddr>()
                    && !ips.contains(&ip)
                {
                    ips.push(ip);
                }
            }
        }

        let mut rows = Vec::with_capacity(ips.len());
        for (idx, ip) in ips.into_iter().enumerate() {
            let rec = db.lookup(ip);
            let detail = serde_json::to_value(&rec).unwrap_or(serde_json::Value::Null);
            rows.push(
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rec.ip_address),
                        CellValue::Text(rec.country_code),
                        CellValue::Text(rec.country_name),
                        CellValue::Text(rec.continent),
                        rec.asn.map(|n| CellValue::Uint(n as u64)).unwrap_or(CellValue::Null),
                        CellValue::Text(rec.as_name),
                    ],
                )
                .with_detail_json(detail),
            );
        }

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
    Arc::new(IpOfflineProvider::new(ctx.clone()))
}
