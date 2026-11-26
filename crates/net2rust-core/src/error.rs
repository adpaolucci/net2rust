use guap_mcp::McpToolError;
use guap_table::TableError;
use thiserror::Error;

pub type NetResult<T> = Result<T, NetError>;

#[derive(Debug, Error)]
pub enum NetError {
    #[error("permission denied (elevation or capability required): {0}")]
    PermissionDenied(String),

    #[error("required driver or capture backend unavailable: {0}")]
    DriverUnavailable(String),

    #[error("hardware or interface not found: {0}")]
    HardwareNotFound(String),

    #[error("network unavailable: {0}")]
    NetworkUnavailable(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("parse error: {0}")]
    ParseError(String),

    #[error("network operation error: {0}")]
    NetworkError(String),

    #[error("unsupported on this platform or configuration: {0}")]
    NotSupported(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("internal error: {0}")]
    Internal(String),
}

impl From<NetError> for TableError {
    fn from(err: NetError) -> Self {
        TableError::Provider(err.to_string())
    }
}

impl From<NetError> for McpToolError {
    fn from(err: NetError) -> Self {
        // Keep JsonRpcError::POLICY_DENIED (-32003) strictly reserved for PolicyMode /
        // confirm_destructive gates in guap-mcp; OS-level permission failures map to ExecutionFailed.
        match err {
            NetError::InvalidInput(msg) => McpToolError::InvalidParams(msg),
            NetError::HardwareNotFound(msg) => McpToolError::NotFound(msg),
            other => McpToolError::ExecutionFailed(other.to_string()),
        }
    }
}
