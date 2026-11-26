use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineConfig {
    pub fixture_dir: Option<PathBuf>,
    pub pcap_path: Option<PathBuf>,
    pub etl_path: Option<PathBuf>,
    pub oui_db_path: Option<PathBuf>,
    pub geoip_db_path: Option<PathBuf>,
    pub scenario: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionMode {
    #[default]
    Live,
    Offline(OfflineConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetContext {
    pub mode: ExecutionMode,
    pub timeout: Duration,
    pub max_rows: Option<usize>,
    pub allow_npcap: bool,
    pub redact_sensitive_headers: bool,
}

impl Default for NetContext {
    fn default() -> Self {
        Self {
            mode: ExecutionMode::Live,
            timeout: Duration::from_secs(5),
            max_rows: None,
            allow_npcap: true,
            redact_sensitive_headers: true,
        }
    }
}

impl NetContext {
    pub fn live() -> Self {
        Self::default()
    }

    pub fn offline(config: OfflineConfig) -> Self {
        Self {
            mode: ExecutionMode::Offline(config),
            ..Self::default()
        }
    }

    pub fn is_offline(&self) -> bool {
        matches!(self.mode, ExecutionMode::Offline(_))
    }

    pub fn offline_config(&self) -> Option<&OfflineConfig> {
        match &self.mode {
            ExecutionMode::Live => None,
            ExecutionMode::Offline(cfg) => Some(cfg),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_rows(mut self, max_rows: Option<usize>) -> Self {
        self.max_rows = max_rows;
        self
    }

    pub fn with_allow_npcap(mut self, allow_npcap: bool) -> Self {
        self.allow_npcap = allow_npcap;
        self
    }

    pub fn with_redact_sensitive_headers(mut self, redact: bool) -> Self {
        self.redact_sensitive_headers = redact;
        self
    }

    pub fn apply_row_limit<T>(&self, rows: &mut Vec<T>) {
        if let Some(limit) = self.max_rows {
            rows.truncate(limit);
        }
    }
}
