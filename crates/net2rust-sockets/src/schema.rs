use guap_table::{ColumnDef, ColumnType, SortDirection, TableSchema};
use net2rust_core::{ToolCategory, ToolDescriptor};

pub const TOOL_ID_PORTS: &str = "sockets.ports";
pub const TOOL_ID_TCPLOG: &str = "sockets.tcplog";
pub const TOOL_ID_LIVE: &str = "sockets.live";
pub const TOOL_ID_APP_NET: &str = "sockets.app-net";
pub const TOOL_ID_PROC_TCP: &str = "sockets.proc-tcp";
pub const TOOL_ID_TCP_ERRORS: &str = "sockets.tcp-errors";
pub const TOOL_ID_DNS_LOG: &str = "sockets.dns-log";
pub const TOOL_ID_COUNTERS: &str = "sockets.counters";
pub const TOOL_ID_ADAPTER_WATCH: &str = "sockets.adapter-watch";
pub const TOOL_ID_INTERFACES: &str = "sockets.interfaces";
pub const TOOL_ID_ROUTES: &str = "sockets.routes";
pub const TOOL_ID_NEIGHBORS: &str = "sockets.neighbors";
pub const TOOL_ID_PATHS: &str = "sockets.paths";

pub fn all_tool_descriptors() -> Vec<ToolDescriptor> {
    vec![
        ToolDescriptor {
            id: TOOL_ID_PORTS,
            category: ToolCategory::Sockets,
            subcommand: "ports",
            nirsoft_name: "CurrPorts",
            description: "List active TCP/UDP listening and connected sockets with process metadata",
            read_only: true,
            has_mutating_action: true,
        },
        ToolDescriptor {
            id: TOOL_ID_TCPLOG,
            category: ToolCategory::Sockets,
            subcommand: "tcplog",
            nirsoft_name: "TcpLogView",
            description: "Track TCP open, close, and listen state transitions via snapshot diffing and ETW",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: TOOL_ID_LIVE,
            category: ToolCategory::Sockets,
            subcommand: "live",
            nirsoft_name: "LiveTcpUdpWatch",
            description: "Observe live TCP/UDP byte and packet counters per socket tuple via Kernel-Network ETW",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: TOOL_ID_APP_NET,
            category: ToolCategory::Sockets,
            subcommand: "app-net",
            nirsoft_name: "AppNetworkCounter",
            description: "Aggregate TCP/UDP sent and received traffic and throughput per process",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: TOOL_ID_PROC_TCP,
            category: ToolCategory::Sockets,
            subcommand: "proc-tcp",
            nirsoft_name: "ProcessTCPSummary",
            description: "Summarize TCP connection states, UDP endpoints, and EStats byte totals per PID",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: TOOL_ID_TCP_ERRORS,
            category: ToolCategory::Sockets,
            subcommand: "tcp-errors",
            nirsoft_name: "TCPConnectProblemView",
            description: "Monitor TCP connection failures, timeouts, resets, and retransmissions via TCPIP ETW",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: TOOL_ID_DNS_LOG,
            category: ToolCategory::Sockets,
            subcommand: "dns-log",
            nirsoft_name: "DNSLookupView",
            description: "Trace DNS client queries, responses, latencies, and local DNS resolver cache",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: TOOL_ID_COUNTERS,
            category: ToolCategory::Sockets,
            subcommand: "counters",
            nirsoft_name: "NetworkCountersWatch",
            description: "Inspect IPv4/IPv6, TCP, UDP, and ICMP protocol stack counters and per-second rates",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: TOOL_ID_ADAPTER_WATCH,
            category: ToolCategory::Sockets,
            subcommand: "adapter-watch",
            nirsoft_name: "AdapterWatch",
            description: "Monitor per-adapter link speed, byte totals, Rx/Tx throughput, errors, and discards",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: TOOL_ID_INTERFACES,
            category: ToolCategory::Sockets,
            subcommand: "interfaces",
            nirsoft_name: "NetworkInterfacesView",
            description: "Enumerate network interface hardware, IP, gateway, DNS, and DHCP configuration",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: TOOL_ID_ROUTES,
            category: ToolCategory::Sockets,
            subcommand: "routes",
            nirsoft_name: "NetRouteView",
            description: "Inspect and manage IPv4/IPv6 kernel routing table entries",
            read_only: true,
            has_mutating_action: true,
        },
        ToolDescriptor {
            id: TOOL_ID_NEIGHBORS,
            category: ToolCategory::Sockets,
            subcommand: "neighbors",
            nirsoft_name: "IPNeighborsView",
            description: "Inspect ARP and IPv6 NDP neighbor cache entries with OUI vendor resolution",
            read_only: true,
            has_mutating_action: false,
        },
        ToolDescriptor {
            id: TOOL_ID_PATHS,
            category: ToolCategory::Sockets,
            subcommand: "paths",
            nirsoft_name: "IPPathTableView",
            description: "Inspect IP path MTU, RTT mean/deviation, next-hop, and link speeds",
            read_only: true,
            has_mutating_action: false,
        },
    ]
}

pub fn schema_ports() -> TableSchema {
    TableSchema::new(
        TOOL_ID_PORTS,
        "Active TCP/UDP Ports (CurrPorts)",
        vec![
            ColumnDef::new("process_name", "ProcessName", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(75),
            ColumnDef::new("protocol", "Protocol", ColumnType::Text).with_width_hint(75),
            ColumnDef::new("local_addr", "LocalAddr", ColumnType::IpAddr).with_width_hint(150),
            ColumnDef::new("local_port", "LocalPort", ColumnType::Uint).with_width_hint(85),
            ColumnDef::new("remote_addr", "RemoteAddr", ColumnType::IpAddr).with_width_hint(150),
            ColumnDef::new("remote_port", "RemotePort", ColumnType::Uint).with_width_hint(85),
            ColumnDef::new("state", "State", ColumnType::Text).with_width_hint(110),
            ColumnDef::new("process_path", "ProcessPath", ColumnType::Text).with_width_hint(260),
            ColumnDef::new("user_name", "UserName", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("created_time", "CreatedTime", ColumnType::Timestamp).with_width_hint(175),
        ],
    )
    .with_default_sort(1, SortDirection::Asc)
}

pub fn schema_tcplog() -> TableSchema {
    TableSchema::new(
        TOOL_ID_TCPLOG,
        "TCP Connection Log (TcpLogView)",
        vec![
            ColumnDef::new("event_time", "EventTime", ColumnType::Timestamp).with_width_hint(175),
            ColumnDef::new("event_type", "EventType", ColumnType::Text).with_width_hint(90),
            ColumnDef::new("local_addr", "LocalAddr", ColumnType::IpAddr).with_width_hint(150),
            ColumnDef::new("local_port", "LocalPort", ColumnType::Uint).with_width_hint(85),
            ColumnDef::new("remote_addr", "RemoteAddr", ColumnType::IpAddr).with_width_hint(150),
            ColumnDef::new("remote_port", "RemotePort", ColumnType::Uint).with_width_hint(85),
            ColumnDef::new("state", "State", ColumnType::Text).with_width_hint(110),
            ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(75),
            ColumnDef::new("process_name", "ProcessName", ColumnType::Text).with_width_hint(150),
        ],
    )
    .with_default_sort(0, SortDirection::Desc)
}

pub fn schema_live() -> TableSchema {
    TableSchema::new(
        TOOL_ID_LIVE,
        "Live TCP/UDP Watch (LiveTcpUdpWatch)",
        vec![
            ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(175),
            ColumnDef::new("protocol", "Protocol", ColumnType::Text).with_width_hint(75),
            ColumnDef::new("local_addr", "LocalAddr", ColumnType::IpAddr).with_width_hint(150),
            ColumnDef::new("local_port", "LocalPort", ColumnType::Uint).with_width_hint(85),
            ColumnDef::new("remote_addr", "RemoteAddr", ColumnType::IpAddr).with_width_hint(150),
            ColumnDef::new("remote_port", "RemotePort", ColumnType::Uint).with_width_hint(85),
            ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(75),
            ColumnDef::new("process_name", "ProcessName", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("sent_bytes", "SentBytes", ColumnType::BytesSize).with_width_hint(115),
            ColumnDef::new("recvd_bytes", "RecvdBytes", ColumnType::BytesSize).with_width_hint(115),
            ColumnDef::new("send_packets", "SendPackets", ColumnType::Uint).with_width_hint(100),
            ColumnDef::new("recv_packets", "RecvPackets", ColumnType::Uint).with_width_hint(100),
        ],
    )
    .with_default_sort(8, SortDirection::Desc)
}

pub fn schema_app_net() -> TableSchema {
    TableSchema::new(
        TOOL_ID_APP_NET,
        "Application Network Counter (AppNetworkCounter)",
        vec![
            ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(75),
            ColumnDef::new("process_name", "ProcessName", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("process_path", "ProcessPath", ColumnType::Text).with_width_hint(260),
            ColumnDef::new("tcp_sent_bytes", "TcpSentBytes", ColumnType::BytesSize).with_width_hint(120),
            ColumnDef::new("tcp_recvd_bytes", "TcpRecvdBytes", ColumnType::BytesSize).with_width_hint(120),
            ColumnDef::new("udp_sent_bytes", "UdpSentBytes", ColumnType::BytesSize).with_width_hint(120),
            ColumnDef::new("udp_recvd_bytes", "UdpRecvdBytes", ColumnType::BytesSize).with_width_hint(120),
            ColumnDef::new("send_speed_bps", "SendSpeedBps", ColumnType::Uint).with_width_hint(120),
            ColumnDef::new("recv_speed_bps", "RecvSpeedBps", ColumnType::Uint).with_width_hint(120),
        ],
    )
    .with_default_sort(3, SortDirection::Desc)
}

pub fn schema_proc_tcp() -> TableSchema {
    TableSchema::new(
        TOOL_ID_PROC_TCP,
        "Process TCP/UDP Summary (ProcessTCPSummary)",
        vec![
            ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(75),
            ColumnDef::new("process_name", "ProcessName", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("established_count", "EstablishedCount", ColumnType::Uint).with_width_hint(120),
            ColumnDef::new("listen_count", "ListenCount", ColumnType::Uint).with_width_hint(100),
            ColumnDef::new("time_wait_count", "TimeWaitCount", ColumnType::Uint).with_width_hint(110),
            ColumnDef::new("udp_endpoints", "UdpEndpoints", ColumnType::Uint).with_width_hint(110),
            ColumnDef::new("total_bytes_sent", "TotalBytesSent", ColumnType::BytesSize).with_width_hint(130),
            ColumnDef::new("total_bytes_recvd", "TotalBytesRecvd", ColumnType::BytesSize).with_width_hint(130),
        ],
    )
    .with_default_sort(2, SortDirection::Desc)
}

pub fn schema_tcp_errors() -> TableSchema {
    TableSchema::new(
        TOOL_ID_TCP_ERRORS,
        "TCP Connect Problems (TCPConnectProblemView)",
        vec![
            ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(175),
            ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(75),
            ColumnDef::new("process_name", "ProcessName", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("local_port", "LocalPort", ColumnType::Uint).with_width_hint(85),
            ColumnDef::new("remote_addr", "RemoteAddr", ColumnType::IpAddr).with_width_hint(150),
            ColumnDef::new("remote_port", "RemotePort", ColumnType::Uint).with_width_hint(85),
            ColumnDef::new("attempt_count", "AttemptCount", ColumnType::Uint).with_width_hint(105),
            ColumnDef::new("error_status", "ErrorStatus", ColumnType::Text).with_width_hint(120),
        ],
    )
    .with_default_sort(0, SortDirection::Desc)
}

pub fn schema_dns_log() -> TableSchema {
    TableSchema::new(
        TOOL_ID_DNS_LOG,
        "DNS Lookup View (DNSLookupView)",
        vec![
            ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(175),
            ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(75),
            ColumnDef::new("process_name", "ProcessName", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("query_name", "QueryName", ColumnType::Text).with_width_hint(220),
            ColumnDef::new("query_type", "QueryType", ColumnType::Text).with_width_hint(85),
            ColumnDef::new("status", "Status", ColumnType::Text).with_width_hint(110),
            ColumnDef::new("result_records", "ResultRecords", ColumnType::Text).with_width_hint(260),
            ColumnDef::new("latency_ms", "LatencyMs", ColumnType::Duration).with_width_hint(95),
        ],
    )
    .with_default_sort(0, SortDirection::Desc)
}

pub fn schema_counters() -> TableSchema {
    TableSchema::new(
        TOOL_ID_COUNTERS,
        "Protocol Stack Counters (NetworkCountersWatch)",
        vec![
            ColumnDef::new("counter_group", "CounterGroup", ColumnType::Text).with_width_hint(110),
            ColumnDef::new("metric_name", "MetricName", ColumnType::Text).with_width_hint(210),
            ColumnDef::new("value", "Value", ColumnType::Uint).with_width_hint(130),
            ColumnDef::new("delta_per_sec", "DeltaPerSec", ColumnType::Float).with_width_hint(120),
        ],
    )
    .with_default_sort(0, SortDirection::Asc)
}

pub fn schema_adapter_watch() -> TableSchema {
    TableSchema::new(
        TOOL_ID_ADAPTER_WATCH,
        "Network Adapter Watch (AdapterWatch)",
        vec![
            ColumnDef::new("adapter_name", "AdapterName", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("description", "Description", ColumnType::Text).with_width_hint(240),
            ColumnDef::new("media_state", "MediaState", ColumnType::Text).with_width_hint(135),
            ColumnDef::new("link_speed", "LinkSpeed", ColumnType::Uint).with_width_hint(130),
            ColumnDef::new("bytes_sent", "BytesSent", ColumnType::BytesSize).with_width_hint(120),
            ColumnDef::new("bytes_recvd", "BytesRecvd", ColumnType::BytesSize).with_width_hint(120),
            ColumnDef::new("rx_rate_bps", "RxRateBps", ColumnType::Float).with_width_hint(115),
            ColumnDef::new("tx_rate_bps", "TxRateBps", ColumnType::Float).with_width_hint(115),
            ColumnDef::new("errors", "Errors", ColumnType::Uint).with_width_hint(90),
            ColumnDef::new("discards", "Discards", ColumnType::Uint).with_width_hint(90),
        ],
    )
    .with_default_sort(0, SortDirection::Asc)
}

pub fn schema_interfaces() -> TableSchema {
    TableSchema::new(
        TOOL_ID_INTERFACES,
        "Network Interfaces (NetworkInterfacesView)",
        vec![
            ColumnDef::new("interface_name", "InterfaceName", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("description", "Description", ColumnType::Text).with_width_hint(230),
            ColumnDef::new("guid", "Guid", ColumnType::Text).with_width_hint(260),
            ColumnDef::new("mac_address", "MacAddress", ColumnType::MacAddr).with_width_hint(140),
            ColumnDef::new("operational_status", "OperationalStatus", ColumnType::Text).with_width_hint(120),
            ColumnDef::new("if_type", "IfType", ColumnType::Text).with_width_hint(120),
            ColumnDef::new("speed_mbps", "SpeedMbps", ColumnType::Uint).with_width_hint(100),
            ColumnDef::new("ipv4", "IPv4", ColumnType::Text).with_width_hint(180),
            ColumnDef::new("ipv6", "IPv6", ColumnType::Text).with_width_hint(220),
            ColumnDef::new("gateway", "Gateway", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("dns_servers", "DnsServers", ColumnType::Text).with_width_hint(190),
            ColumnDef::new("dhcp_enabled", "DhcpEnabled", ColumnType::Bool).with_width_hint(95),
        ],
    )
    .with_default_sort(0, SortDirection::Asc)
}

pub fn schema_routes() -> TableSchema {
    TableSchema::new(
        TOOL_ID_ROUTES,
        "IP Routing Table (NetRouteView)",
        vec![
            ColumnDef::new("destination", "Destination", ColumnType::IpAddr).with_width_hint(160),
            ColumnDef::new("prefix_length", "PrefixLength", ColumnType::Uint).with_width_hint(95),
            ColumnDef::new("next_hop", "NextHop", ColumnType::IpAddr).with_width_hint(160),
            ColumnDef::new("interface_index", "InterfaceIndex", ColumnType::Uint).with_width_hint(105),
            ColumnDef::new("interface_alias", "InterfaceAlias", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("metric", "Metric", ColumnType::Uint).with_width_hint(80),
            ColumnDef::new("protocol", "Protocol", ColumnType::Text).with_width_hint(110),
            ColumnDef::new("age", "Age", ColumnType::Duration).with_width_hint(110),
        ],
    )
    .with_default_sort(5, SortDirection::Asc)
}

pub fn schema_neighbors() -> TableSchema {
    TableSchema::new(
        TOOL_ID_NEIGHBORS,
        "IP Neighbors (IPNeighborsView)",
        vec![
            ColumnDef::new("interface_index", "InterfaceIndex", ColumnType::Uint).with_width_hint(105),
            ColumnDef::new("ip_address", "IPAddress", ColumnType::IpAddr).with_width_hint(175),
            ColumnDef::new("mac_address", "MacAddress", ColumnType::MacAddr).with_width_hint(145),
            ColumnDef::new("state", "State", ColumnType::Text).with_width_hint(105),
            ColumnDef::new("is_router", "IsRouter", ColumnType::Bool).with_width_hint(80),
            ColumnDef::new("vendor_oui", "VendorOUI", ColumnType::Text).with_width_hint(180),
        ],
    )
    .with_default_sort(0, SortDirection::Asc)
}

pub fn schema_paths() -> TableSchema {
    TableSchema::new(
        TOOL_ID_PATHS,
        "IP Path Table (IPPathTableView)",
        vec![
            ColumnDef::new("source_ip", "SourceIP", ColumnType::IpAddr).with_width_hint(165),
            ColumnDef::new("destination_ip", "DestinationIP", ColumnType::IpAddr).with_width_hint(175),
            ColumnDef::new("next_hop", "NextHop", ColumnType::IpAddr).with_width_hint(165),
            ColumnDef::new("link_speed_tx", "LinkSpeedTx", ColumnType::Uint).with_width_hint(125),
            ColumnDef::new("link_speed_rx", "LinkSpeedRx", ColumnType::Uint).with_width_hint(125),
            ColumnDef::new("rtt_mean_ms", "RttMeanMs", ColumnType::Uint).with_width_hint(100),
            ColumnDef::new("rtt_deviation_ms", "RttDeviationMs", ColumnType::Uint).with_width_hint(115),
            ColumnDef::new("mtu", "Mtu", ColumnType::Uint).with_width_hint(80),
        ],
    )
    .with_default_sort(1, SortDirection::Asc)
}
