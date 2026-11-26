use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;

use guap_mcp::{ActionCommand, ActionRiskLevel, McpToolError};
use net2rust_core::{CidrV4, CidrV6, ExecutionMode, NetContext, NetError};
use serde_json::{Value, json};

use crate::offline;

pub const ACTION_ID_PORTS_CLOSE: &str = "sockets.ports.close";
pub const ACTION_ID_ROUTES_ADD: &str = "sockets.routes.add";
pub const ACTION_ID_ROUTES_DELETE: &str = "sockets.routes.delete";

pub fn build_all_actions(ctx: &NetContext) -> Vec<Arc<dyn ActionCommand>> {
    vec![
        Arc::new(ClosePortAction::new(ctx.clone())),
        Arc::new(AddRouteAction::new(ctx.clone())),
        Arc::new(DeleteRouteAction::new(ctx.clone())),
    ]
}

fn validate_allowed_keys(obj: &serde_json::Map<String, Value>, allowed: &[&str]) -> Result<(), McpToolError> {
    for key in obj.keys() {
        if key != "dry_run" && key != "confirm_destructive" && !allowed.contains(&key.as_str()) {
            return Err(McpToolError::InvalidParams(format!("unexpected parameter '{key}'")));
        }
    }
    Ok(())
}

fn required_str<'a>(obj: &'a serde_json::Map<String, Value>, key: &str) -> Result<&'a str, McpToolError> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| McpToolError::InvalidParams(format!("missing or invalid string parameter '{key}'")))
}

fn required_port(obj: &serde_json::Map<String, Value>, key: &str, min: u16) -> Result<u16, McpToolError> {
    let raw = obj
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| McpToolError::InvalidParams(format!("missing or invalid integer parameter '{key}'")))?;
    let port = u16::try_from(raw)
        .map_err(|_| McpToolError::InvalidParams(format!("parameter '{key}' out of port range 0..=65535")))?;
    if port < min {
        return Err(McpToolError::InvalidParams(format!(
            "parameter '{key}' must be >= {min}"
        )));
    }
    Ok(port)
}

#[derive(Debug, Clone)]
struct ParsedRouteSpec {
    destination: IpAddr,
    prefix_length: u8,
    next_hop: IpAddr,
    interface_index: Option<u32>,
    interface_alias: Option<String>,
    metric: u32,
}

fn parse_route_spec(args: &Value, require_or_allow_metric: bool) -> Result<ParsedRouteSpec, McpToolError> {
    let obj = args
        .as_object()
        .ok_or_else(|| McpToolError::InvalidParams("arguments must be a JSON object".to_string()))?;

    let allowed: &[&str] = if require_or_allow_metric {
        &[
            "destination",
            "prefix_length",
            "next_hop",
            "interface_index",
            "interface_alias",
            "metric",
        ]
    } else {
        &[
            "destination",
            "prefix_length",
            "next_hop",
            "interface_index",
            "interface_alias",
        ]
    };
    validate_allowed_keys(obj, allowed)?;

    let dest_str = required_str(obj, "destination")?;
    let explicit_prefix = match obj.get("prefix_length") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let p = v
                .as_u64()
                .ok_or_else(|| McpToolError::InvalidParams("prefix_length must be an integer".to_string()))?;
            let p_u8 =
                u8::try_from(p).map_err(|_| McpToolError::InvalidParams("prefix_length out of range".to_string()))?;
            Some(p_u8)
        }
    };

    let (destination, prefix_length) = if let Some((ip_part, p_part)) = dest_str.split_once('/') {
        let parsed_prefix: u8 = p_part
            .parse()
            .map_err(|_| McpToolError::InvalidParams(format!("invalid CIDR prefix in '{dest_str}'")))?;
        if let Some(exp) = explicit_prefix
            && exp != parsed_prefix
        {
            return Err(McpToolError::InvalidParams(format!(
                "conflicting prefix_length ({exp}) and CIDR suffix (/{parsed_prefix})"
            )));
        }
        let ip = IpAddr::from_str(ip_part)
            .map_err(|_| McpToolError::InvalidParams(format!("invalid destination IP '{ip_part}'")))?;
        match ip {
            IpAddr::V4(v4) => {
                let cidr = CidrV4::new(v4, parsed_prefix).map_err(McpToolError::from)?;
                (IpAddr::V4(cidr.network()), cidr.prefix_len())
            }
            IpAddr::V6(v6) => {
                let cidr = CidrV6::new(v6, parsed_prefix).map_err(McpToolError::from)?;
                (IpAddr::V6(cidr.network()), cidr.prefix_len())
            }
        }
    } else {
        let ip = IpAddr::from_str(dest_str)
            .map_err(|_| McpToolError::InvalidParams(format!("invalid destination IP '{dest_str}'")))?;
        match ip {
            IpAddr::V4(v4) => {
                let plen = explicit_prefix.unwrap_or(32);
                let cidr = CidrV4::new(v4, plen).map_err(McpToolError::from)?;
                (IpAddr::V4(cidr.network()), cidr.prefix_len())
            }
            IpAddr::V6(v6) => {
                let plen = explicit_prefix.unwrap_or(128);
                let cidr = CidrV6::new(v6, plen).map_err(McpToolError::from)?;
                (IpAddr::V6(cidr.network()), cidr.prefix_len())
            }
        }
    };

    let next_hop_str = required_str(obj, "next_hop")?;
    let next_hop = IpAddr::from_str(next_hop_str)
        .map_err(|_| McpToolError::InvalidParams(format!("invalid next_hop IP '{next_hop_str}'")))?;

    match (destination, next_hop) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {}
        _ => {
            return Err(McpToolError::InvalidParams(
                "destination and next_hop IP address families must match".to_string(),
            ));
        }
    }

    let interface_index = match obj.get("interface_index") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let idx = v
                .as_u64()
                .ok_or_else(|| McpToolError::InvalidParams("interface_index must be an integer".to_string()))?;
            let idx_u32 = u32::try_from(idx)
                .ok()
                .filter(|&i| i >= 1)
                .ok_or_else(|| McpToolError::InvalidParams("interface_index must be >= 1".to_string()))?;
            Some(idx_u32)
        }
    };

    let interface_alias = match obj.get("interface_alias") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let alias =
                v.as_str().map(str::trim).filter(|s| !s.is_empty()).ok_or_else(|| {
                    McpToolError::InvalidParams("interface_alias must be a non-empty string".to_string())
                })?;
            Some(alias.to_string())
        }
    };

    if interface_index.is_none() && interface_alias.is_none() {
        return Err(McpToolError::InvalidParams(
            "at least one of interface_index or interface_alias is required".to_string(),
        ));
    }

    let metric = if require_or_allow_metric {
        match obj.get("metric") {
            None | Some(Value::Null) => 0,
            Some(v) => {
                let m = v
                    .as_u64()
                    .ok_or_else(|| McpToolError::InvalidParams("metric must be an integer".to_string()))?;
                u32::try_from(m)
                    .ok()
                    .filter(|&x| x <= 4_294_967_294)
                    .ok_or_else(|| McpToolError::InvalidParams("metric must be <= 4294967294".to_string()))?
            }
        }
    } else {
        0
    };

    Ok(ParsedRouteSpec {
        destination,
        prefix_length,
        next_hop,
        interface_index,
        interface_alias,
        metric,
    })
}

// 1. sockets.ports.close (SetTcpEntry)
pub struct ClosePortAction {
    ctx: NetContext,
}

impl ClosePortAction {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

impl ActionCommand for ClosePortAction {
    fn command_id(&self) -> &'static str {
        ACTION_ID_PORTS_CLOSE
    }

    fn description(&self) -> &'static str {
        "Terminate an active IPv4 TCP connection using SetTcpEntry (MIB_TCP_STATE_DELETE_TCB)"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::PrivilegedMutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "local_addr": { "type": "string", "description": "Local IPv4 address (e.g. 192.168.1.50)" },
                "local_port": { "type": "integer", "minimum": 1, "maximum": 65535 },
                "remote_addr": { "type": "string", "description": "Remote IPv4 address (e.g. 93.184.216.34)" },
                "remote_port": { "type": "integer", "minimum": 0, "maximum": 65535 }
            },
            "required": ["local_addr", "local_port", "remote_addr", "remote_port"],
            "additionalProperties": false
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let obj = args
            .as_object()
            .ok_or_else(|| McpToolError::InvalidParams("arguments must be a JSON object".to_string()))?;
        validate_allowed_keys(obj, &["local_addr", "local_port", "remote_addr", "remote_port"])?;

        let local_str = required_str(obj, "local_addr")?;
        let remote_str = required_str(obj, "remote_addr")?;
        let local_ip = IpAddr::from_str(local_str)
            .map_err(|_| McpToolError::InvalidParams(format!("invalid local_addr '{local_str}'")))?;
        let remote_ip = IpAddr::from_str(remote_str)
            .map_err(|_| McpToolError::InvalidParams(format!("invalid remote_addr '{remote_str}'")))?;

        let local_v4: Ipv4Addr = match local_ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                return Err(NetError::NotSupported(
                    "SetTcpEntry only supports IPv4 TCP connections; IPv6 cannot be closed via SetTcpEntry".to_string(),
                )
                .into());
            }
        };
        let remote_v4: Ipv4Addr = match remote_ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                return Err(NetError::NotSupported(
                    "SetTcpEntry only supports IPv4 TCP connections; IPv6 cannot be closed via SetTcpEntry".to_string(),
                )
                .into());
            }
        };

        let local_port = required_port(obj, "local_port", 1)?;
        let remote_port = required_port(obj, "remote_port", 0)?;

        if dry_run {
            return Ok(json!({
                "dry_run": true,
                "command": ACTION_ID_PORTS_CLOSE,
                "would_close": {
                    "local_addr": local_v4.to_string(),
                    "local_port": local_port,
                    "remote_addr": remote_v4.to_string(),
                    "remote_port": remote_port,
                },
                "state": "MIB_TCP_STATE_DELETE_TCB"
            }));
        }

        match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => {
                offline::close_offline_socket(cfg, local_v4, local_port, remote_v4, remote_port)?;
            }
            ExecutionMode::Live => {
                #[cfg(windows)]
                {
                    crate::win32_iphelper::close_tcp_socket_live(local_v4, local_port, remote_v4, remote_port)?;
                }
                #[cfg(not(windows))]
                {
                    return Err(NetError::NotSupported("SetTcpEntry is only available on Windows".to_string()).into());
                }
            }
        }

        Ok(json!({
            "dry_run": false,
            "closed": true,
            "local_addr": local_v4.to_string(),
            "local_port": local_port,
            "remote_addr": remote_v4.to_string(),
            "remote_port": remote_port,
        }))
    }
}

// 2. sockets.routes.add (CreateIpForwardEntry2)
pub struct AddRouteAction {
    ctx: NetContext,
}

impl AddRouteAction {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

impl ActionCommand for AddRouteAction {
    fn command_id(&self) -> &'static str {
        ACTION_ID_ROUTES_ADD
    }

    fn description(&self) -> &'static str {
        "Add a persistent or active IPv4/IPv6 route via CreateIpForwardEntry2"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::PrivilegedMutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "destination": { "type": "string", "description": "Destination IP or CIDR (e.g. 10.20.0.0/16 or 10.20.0.0)" },
                "prefix_length": { "type": "integer", "minimum": 0, "maximum": 128 },
                "next_hop": { "type": "string", "description": "Gateway IPv4/IPv6 address (0.0.0.0 or :: for on-link)" },
                "interface_index": { "type": "integer", "minimum": 1 },
                "interface_alias": { "type": "string", "minLength": 1 },
                "metric": { "type": "integer", "minimum": 0, "maximum": 4294967294u64 }
            },
            "required": ["destination", "next_hop"],
            "additionalProperties": false
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let spec = parse_route_spec(args, true)?;

        if dry_run {
            return Ok(json!({
                "dry_run": true,
                "command": ACTION_ID_ROUTES_ADD,
                "route": {
                    "destination": spec.destination.to_string(),
                    "prefix_length": spec.prefix_length,
                    "next_hop": spec.next_hop.to_string(),
                    "interface_index": spec.interface_index,
                    "interface_alias": spec.interface_alias,
                    "metric": spec.metric,
                }
            }));
        }

        match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => {
                offline::add_offline_route(
                    cfg,
                    spec.destination,
                    spec.prefix_length,
                    spec.next_hop,
                    spec.interface_index,
                    spec.interface_alias.as_deref(),
                    spec.metric,
                )?;
            }
            ExecutionMode::Live => {
                #[cfg(windows)]
                {
                    crate::win32_iphelper::add_route_live(
                        spec.destination,
                        spec.prefix_length,
                        spec.next_hop,
                        spec.interface_index,
                        spec.interface_alias.as_deref(),
                        spec.metric,
                    )?;
                }
                #[cfg(not(windows))]
                {
                    return Err(NetError::NotSupported(
                        "CreateIpForwardEntry2 is only available on Windows".to_string(),
                    )
                    .into());
                }
            }
        }

        Ok(json!({
            "dry_run": false,
            "added": true,
            "route": {
                "destination": spec.destination.to_string(),
                "prefix_length": spec.prefix_length,
                "next_hop": spec.next_hop.to_string(),
                "interface_index": spec.interface_index,
                "interface_alias": spec.interface_alias,
                "metric": spec.metric,
            }
        }))
    }
}

// 3. sockets.routes.delete (DeleteIpForwardEntry2)
pub struct DeleteRouteAction {
    ctx: NetContext,
}

impl DeleteRouteAction {
    pub fn new(ctx: NetContext) -> Self {
        Self { ctx }
    }
}

impl ActionCommand for DeleteRouteAction {
    fn command_id(&self) -> &'static str {
        ACTION_ID_ROUTES_DELETE
    }

    fn description(&self) -> &'static str {
        "Delete an existing IPv4/IPv6 route via DeleteIpForwardEntry2"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::PrivilegedMutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "destination": { "type": "string", "description": "Destination IP or CIDR (e.g. 10.20.0.0/16)" },
                "prefix_length": { "type": "integer", "minimum": 0, "maximum": 128 },
                "next_hop": { "type": "string", "description": "Gateway IPv4/IPv6 address" },
                "interface_index": { "type": "integer", "minimum": 1 },
                "interface_alias": { "type": "string", "minLength": 1 }
            },
            "required": ["destination", "next_hop"],
            "additionalProperties": false
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let spec = parse_route_spec(args, false)?;

        if dry_run {
            return Ok(json!({
                "dry_run": true,
                "command": ACTION_ID_ROUTES_DELETE,
                "route": {
                    "destination": spec.destination.to_string(),
                    "prefix_length": spec.prefix_length,
                    "next_hop": spec.next_hop.to_string(),
                    "interface_index": spec.interface_index,
                    "interface_alias": spec.interface_alias,
                }
            }));
        }

        match &self.ctx.mode {
            ExecutionMode::Offline(cfg) => {
                offline::delete_offline_route(
                    cfg,
                    spec.destination,
                    spec.prefix_length,
                    spec.next_hop,
                    spec.interface_index,
                    spec.interface_alias.as_deref(),
                )?;
            }
            ExecutionMode::Live => {
                #[cfg(windows)]
                {
                    crate::win32_iphelper::delete_route_live(
                        spec.destination,
                        spec.prefix_length,
                        spec.next_hop,
                        spec.interface_index,
                        spec.interface_alias.as_deref(),
                    )?;
                }
                #[cfg(not(windows))]
                {
                    return Err(NetError::NotSupported(
                        "DeleteIpForwardEntry2 is only available on Windows".to_string(),
                    )
                    .into());
                }
            }
        }

        Ok(json!({
            "dry_run": false,
            "deleted": true,
            "route": {
                "destination": spec.destination.to_string(),
                "prefix_length": spec.prefix_length,
                "next_hop": spec.next_hop.to_string(),
                "interface_index": spec.interface_index,
                "interface_alias": spec.interface_alias,
            }
        }))
    }
}
