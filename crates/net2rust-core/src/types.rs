use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use guap_mcp::ActionCommand;
use guap_table::TableProvider;
use serde::{Deserialize, Serialize};

use crate::{NetContext, NetError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolCategory {
    Sockets,
    Capture,
    Lan,
    Osint,
    Radio,
}

impl ToolCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sockets => "sockets",
            Self::Capture => "capture",
            Self::Lan => "lan",
            Self::Osint => "osint",
            Self::Radio => "radio",
        }
    }

    pub const fn all() -> &'static [ToolCategory] {
        &[Self::Sockets, Self::Capture, Self::Lan, Self::Osint, Self::Radio]
    }
}

impl fmt::Display for ToolCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ToolCategory {
    type Err = NetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sockets" => Ok(Self::Sockets),
            "capture" => Ok(Self::Capture),
            "lan" => Ok(Self::Lan),
            "osint" => Ok(Self::Osint),
            "radio" => Ok(Self::Radio),
            other => Err(NetError::InvalidInput(format!("unknown tool category: {other}"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub id: &'static str,
    pub category: ToolCategory,
    pub subcommand: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    pub read_only: bool,
    pub has_mutating_action: bool,
}

pub trait DomainCrateExport {
    fn category() -> ToolCategory;
    fn tool_descriptors() -> Vec<ToolDescriptor>;
    fn providers(ctx: &NetContext) -> Vec<Arc<dyn TableProvider>>;
    fn actions(ctx: &NetContext) -> Vec<Arc<dyn ActionCommand>>;
}
