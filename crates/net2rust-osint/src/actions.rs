use std::sync::Arc;

use guap_mcp::{ActionCommand, ActionRiskLevel, McpToolError};
use net2rust_core::NetContext;
use serde_json::{Value, json};

use crate::tools::net_profiles::{
    MockNetProfilesBackend, NetProfilesBackend, build_net_profiles_backend, validate_profile_target,
};
use crate::tools::set_dns::{DnsBackend, MockDnsBackend, build_dns_backend, validate_set_dns_args};

pub const ACTION_SET_DNS_APPLY: &str = "osint.set-dns.apply";
pub const ACTION_NET_PROFILES_CONNECT: &str = "osint.net-profiles.connect";
pub const ACTION_NET_PROFILES_DISCONNECT: &str = "osint.net-profiles.disconnect";

pub struct SetDnsApplyAction {
    backend: Arc<dyn DnsBackend>,
}

impl SetDnsApplyAction {
    pub fn new(backend: Arc<dyn DnsBackend>) -> Self {
        Self { backend }
    }
}

impl ActionCommand for SetDnsApplyAction {
    fn command_id(&self) -> &'static str {
        ACTION_SET_DNS_APPLY
    }

    fn description(&self) -> &'static str {
        "Apply static DNS servers or reset to DHCP on a network interface (honors dry_run)."
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::PrivilegedMutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Interface GUID ({...} or 36-char), friendly alias (e.g., Ethernet), or NDIS name"
                },
                "servers": {
                    "type": "array",
                    "description": "DNS server IP addresses (empty array resets to DHCP/automatic)",
                    "items": { "type": "string" },
                    "default": []
                },
                "ipv6": {
                    "type": "boolean",
                    "description": "Target IPv6 DNS settings instead of IPv4",
                    "default": false
                }
            },
            "required": ["interface"]
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let obj = args
            .as_object()
            .ok_or_else(|| McpToolError::InvalidParams("arguments must be a JSON object".into()))?;
        let interface = obj
            .get("interface")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing required string 'interface'".into()))?;

        let servers = match obj.get("servers") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(arr)) => {
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    let s = item
                        .as_str()
                        .ok_or_else(|| McpToolError::InvalidParams("'servers' items must be IP strings".into()))?;
                    out.push(s.to_string());
                }
                out
            }
            Some(_) => {
                return Err(McpToolError::InvalidParams(
                    "'servers' must be an array of IP strings".into(),
                ));
            }
        };

        let ipv6 = match obj.get("ipv6") {
            None | Some(Value::Null) => None,
            Some(Value::Bool(b)) => Some(*b),
            Some(_) => return Err(McpToolError::InvalidParams("'ipv6' must be a boolean".into())),
        };

        let req = validate_set_dns_args(interface, &servers, ipv6)?;
        let res = self.backend.apply_dns(&req, dry_run)?;
        serde_json::to_value(res).map_err(McpToolError::from)
    }
}

pub struct NetProfileToggleAction {
    backend: Arc<dyn NetProfilesBackend>,
    connect: bool,
}

impl NetProfileToggleAction {
    pub fn new(backend: Arc<dyn NetProfilesBackend>, connect: bool) -> Self {
        Self { backend, connect }
    }
}

impl ActionCommand for NetProfileToggleAction {
    fn command_id(&self) -> &'static str {
        if self.connect {
            ACTION_NET_PROFILES_CONNECT
        } else {
            ACTION_NET_PROFILES_DISCONNECT
        }
    }

    fn description(&self) -> &'static str {
        if self.connect {
            "Connect/enable the adapter associated with a Windows NetworkList profile (honors dry_run)."
        } else {
            "Disconnect/disable the adapter associated with a Windows NetworkList profile (honors dry_run)."
        }
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::PrivilegedMutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "profile_id": {
                    "type": "string",
                    "description": "NetworkList profile GUID ({...} or 36-char)"
                },
                "profile_name": {
                    "type": "string",
                    "description": "NetworkList profile display name"
                },
                "interface": {
                    "type": "string",
                    "description": "Optional explicit adapter GUID/alias when profile has no active connection"
                }
            }
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let obj = args
            .as_object()
            .ok_or_else(|| McpToolError::InvalidParams("arguments must be a JSON object".into()))?;

        let profile_id = match obj.get("profile_id") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.as_str()),
            Some(_) => return Err(McpToolError::InvalidParams("'profile_id' must be a string".into())),
        };
        let profile_name = match obj.get("profile_name") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.as_str()),
            Some(_) => return Err(McpToolError::InvalidParams("'profile_name' must be a string".into())),
        };
        let interface = match obj.get("interface") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.as_str()),
            Some(_) => return Err(McpToolError::InvalidParams("'interface' must be a string".into())),
        };

        let target = validate_profile_target(profile_id, profile_name, interface)?;
        let res = self.backend.set_profile_connection(&target, self.connect, dry_run)?;
        serde_json::to_value(res).map_err(McpToolError::from)
    }
}

pub fn actions(ctx: &NetContext) -> Vec<Arc<dyn ActionCommand>> {
    let dns_backend: Arc<dyn DnsBackend> = build_dns_backend(ctx).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "failed to load offline set_dns fixture; falling back to default mock backend");
        Arc::new(MockDnsBackend::default())
    });
    let net_backend: Arc<dyn NetProfilesBackend> = build_net_profiles_backend(ctx).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "failed to load offline net_profiles fixture; falling back to default mock backend");
        Arc::new(MockNetProfilesBackend::default())
    });

    vec![
        Arc::new(SetDnsApplyAction::new(dns_backend)),
        Arc::new(NetProfileToggleAction::new(Arc::clone(&net_backend), true)),
        Arc::new(NetProfileToggleAction::new(net_backend, false)),
    ]
}
