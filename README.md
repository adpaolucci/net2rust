# `net2rust` — 55 Pure-Rust Network Diagnostics, ETW Capture, LAN, OSINT & Wi-Fi/BLE Tools with Dual Win32/Iced GUIs, CLI & MCP Server

Part of the **GUAP** Ecosystem (`guap.ca`) • [**Project Hub: https://net2rust.guap.ca**](https://net2rust.guap.ca) • [**Project Wiki**](https://github.com/adpaolucci/net2rust/wiki)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Rust: 2024](https://img.shields.io/badge/Rust-2024%20(1.88%2B)-orange.svg)](Cargo.toml)
[![Workspace: 11 Crates](https://img.shields.io/badge/Workspace-11%20Crates-emerald.svg)](Cargo.toml)
[![Tools: 55 Views](https://img.shields.io/badge/Tools-55%20Views-teal.svg)](metadata.json)
[![GUI: WinSafe Win32 + Iced 0.14](https://img.shields.io/badge/GUI-WinSafe%20Win32%20%2B%20Iced%200.14-cyan.svg)](crates/net2rust-win32)
[![MCP: stdio JSON-RPC 2.0](https://img.shields.io/badge/MCP-stdio%20JSON--RPC%202.0-purple.svg)](crates/net2rust-mcp)

Ready-to-submit **WinGet** & **Homebrew** manifests live in [`packaging/`](packaging/README.md).

**`net2rust`** is a memory-safe, credential-free network diagnostics, packet telemetry, LAN discovery, OSINT, and Wi-Fi/Bluetooth suite written in Rust (Edition 2024, MSRV `1.88`) on top of [`guap-kit`](../guap-kit):
1. **`net2rust-win32`** (**WinSafe `0.0.29`**) — Zero-GPU native Win32 Common Controls GUI (`LVS_OWNERDATA` virtual grid, ComCtl v6, Per-Monitor DPI v2).
2. **`net2rust-iced`** (**Iced `0.14`**) — Cross-platform retained-mode GUI (`wgpu` + `tiny-skia` CPU fallback).
3. **`net2rust`** — Unified CLI with all 55 subcommands, `--offline` fixture/file testing, and `guap-export` Merkle custody reports.
4. **`net2rust-mcp`** — JSON-RPC 2.0 `stdio` MCP server (`2024-11-05`) with strict read-only vs. mutating `PolicyMode` gates.

---

## Workspace Architecture

```text
net2rust/
├── Cargo.toml                  # 11-crate workspace (Edition 2024, MSRV 1.88, Apache-2.0)
├── deny.toml                   # cargo-deny v2 supply-chain & license policy
├── mcp.json                    # Standard MCP client manifest (`net2rust-mcp`)
├── smithery.yaml               # Smithery tool catalog (55 tools)
├── metadata.json               # Machine-readable suite & 55-tool manifest
├── packaging/                  # WinGet & Homebrew manifests
└── crates/
    ├── net2rust-core/          # `#![forbid(unsafe_code)]` NetError, NetContext, MAC/CIDR/packet primitives, R4 sanitizers
    ├── net2rust-sockets/       # 13 socket, interface, route, neighbor, and ETW telemetry tools
    ├── net2rust-capture/       # 11 zero-driver NDIS ETW, optional Npcap, and offline PCAP/PCAPNG/ETL analyzers
    ├── net2rust-lan/           # 11 LAN ping, GeoIP traceroute, ARP/NetBIOS scan, SMB shares/open-files, WOL tools
    ├── net2rust-osint/         # 10 WHOIS/RDAP, offline GeoIP/OUI, DNS, hosting, and DNS/profile tools
    ├── net2rust-radio/         # 10 Wi-Fi BSS/profile and Bluetooth Classic/BLE tools (no plaintext key recovery)
    ├── net2rust-report/        # CSV/TSV/JSON/JSONL/HTML/Markdown exports + SHA-256/512 Merkle custody
    ├── net2rust-mcp/           # Policy-gated MCP JSON-RPC 2.0 stdio server (`net2rust-mcp`)
    ├── net2rust-cli/           # Unified CLI (`net2rust`)
    ├── net2rust-win32/         # Native Win32 GUI (`net2rust-win32`)
    └── net2rust-iced/          # Cross-platform Iced GUI (`net2rust-iced`)
```

---

## 55-Tool Matrix

### `net2rust-sockets` (13 Tools)
| CLI Subcommand | NirSoft Equivalent | Mechanism / OS API | MCP Policy |
| :--- | :--- | :--- | :--- |
| `sockets ports` | `CurrPorts` | `GetExtendedTcpTable` / `GetExtendedUdpTable` | ReadOnly + Mutating `ActionCommand` (`SetTcpEntry`) |
| `sockets tcplog` | `TcpLogView` | TCP state transition polling / ETW | ReadOnly |
| `sockets live` | `LiveTcpUdpWatch` | ETW `Microsoft-Windows-Kernel-Network` | ReadOnly |
| `sockets app-net` | `AppNetworkCounter` | ETW per-process byte/packet aggregation | ReadOnly |
| `sockets proc-tcp` | `ProcessTCPSummary` | Per-PID TCP state summary | ReadOnly |
| `sockets tcp-errors` | `TCPConnectProblemView` | ETW TCPIP connect/retransmit failures | ReadOnly |
| `sockets dns-log` | `DNSLookupView` | ETW `Microsoft-Windows-DNS-Client` + `DnsGetCacheDataTable` | ReadOnly |
| `sockets counters` | `NetworkCountersWatch` | `GetIpStatisticsEx` / `GetTcpStatisticsEx` / `GetUdpStatisticsEx` / `GetIcmpStatisticsEx` | ReadOnly |
| `sockets adapter-watch` | `AdapterWatch` | `GetIfTable2` throughput & error deltas | ReadOnly |
| `sockets interfaces` | `NetworkInterfacesView` | `GetAdaptersAddresses` + registry adapter config | ReadOnly |
| `sockets routes` | `NetRouteView` | `GetIpForwardTable2` | ReadOnly + Mutating `ActionCommand` (`CreateIpForwardEntry2`/`DeleteIpForwardEntry2`) |
| `sockets neighbors` | `IPNeighborsView` | `GetIpNetTable2` + OUI lookup | ReadOnly |
| `sockets paths` | `IPPathTableView` | `GetIpPathTable` | ReadOnly |

### `net2rust-capture` (11 Tools — R4 Credential-Free)
| CLI Subcommand | NirSoft Equivalent | Mechanism / OS API | MCP Policy |
| :--- | :--- | :--- | :--- |
| `capture sniff` | `SmartSniff` | NDIS ETW / optional `wpcap.dll` / PCAP/PCAPNG/ETL | ReadOnly |
| `capture traffic` | `NetworkTrafficView` | Flow aggregation by protocol, IP, port | ReadOnly |
| `capture http` | `HTTPNetworkSniffer` | HTTP request/response metadata (`Authorization` redacted) | ReadOnly |
| `capture dns` | `DNSQuerySniffer` | RFC 1035 wire DNS parser | ReadOnly |
| `capture dhcp` | `DHCPLogView` | BOOTP/DHCPv4 transaction parser | ReadOnly |
| `capture mdns` | `mDNSView` | Multicast DNS (UDP 5353) / DNS-SD decoder | ReadOnly |
| `capture whois-lan` | `WhoIsConnectedSniffer` | Passive ARP/DHCP/mDNS/NetBIOS/SSDP discovery | ReadOnly |
| `capture cookies` | `WebCookiesSniffer` | Cookie names & attributes (auth tokens redacted per R4) | ReadOnly |
| `capture website` | `WebSiteSniffer` | Static HTTP asset metadata reconstruction | ReadOnly |
| `capture latency` | `NetworkLatencyView` | Passive TCP SYN / SYN-ACK RTT analyzer | ReadOnly |
| `capture wifi-mon` | `WifiChannelMonitor` | 802.11 RadioTap / beacon / probe channel stats | ReadOnly |

### `net2rust-lan` (11 Tools)
| CLI Subcommand | NirSoft Equivalent | Mechanism / OS API | MCP Policy |
| :--- | :--- | :--- | :--- |
| `lan ping` | `PingInfoView` | `IcmpSendEcho2` / `Icmp6SendEcho2` / TCP ping | ReadOnly |
| `lan trace` | `CountryTraceRoute` | TTL-stepped ICMP trace + offline GeoIP | ReadOnly |
| `lan scan` | `LANIPScanner` | Concurrent ARP, ICMP, NetBIOS, TCP scan | ReadOnly |
| `lan wnetwatcher` | `Wireless Network Watcher` | Subnet ARP sweep (`SendARP`) + OUI | ReadOnly |
| `lan connect-log` | `NetworkConnectLog` | LAN host arrival/departure diff log | ReadOnly |
| `lan wol` | `WakeMeOnLan` | Host inventory + magic packet sender | ReadOnly + Mutating `ActionCommand` |
| `lan netbios` | `NetBScanner` | UDP 137 NBSTAT NetBIOS query | ReadOnly |
| `lan shares` | `NetResView` | `NetShareEnum` + `WNetOpenEnumW` | ReadOnly |
| `lan openfiles` | `NetworkOpenedFiles` | `NetFileEnum` | ReadOnly + Mutating `ActionCommand` (`NetFileClose`) |
| `lan resolve` | `FastResolver` | Parallel forward/reverse DNS & OUI lookup | ReadOnly |
| `lan speedtest` | `DownTester` | HTTP/HTTPS throughput benchmark | ReadOnly |

### `net2rust-osint` (10 Tools)
| CLI Subcommand | NirSoft Equivalent | Mechanism / OS API | MCP Policy |
| :--- | :--- | :--- | :--- |
| `osint ipnet` | `IPNetInfo` | RIR WHOIS (TCP 43) & RDAP lookup | ReadOnly |
| `osint whosip` | `WhosIP` | IP WHOIS/RDAP referral resolution | ReadOnly |
| `osint ipoffline` | `IPInfoOffline` | Embedded offline IPv4/IPv6 CIDR GeoIP/ASN | ReadOnly |
| `osint whois-domain` | `WhoisThisDomain` | IANA + registrar WHOIS/RDAP | ReadOnly |
| `osint whoiscl` | `WhoisCL` | Batch CLI WHOIS query engine | ReadOnly |
| `osint dns` | `DNSDataView` | Direct RFC 1035 / `DnsQuery_W` record lookup | ReadOnly |
| `osint hosting` | `DomainHostingView` | Aggregated WHOIS, DNS, ASN, HTTP/MX profiler | ReadOnly |
| `osint oui` | `MACAddressView` | Embedded offline IEEE OUI lookup | ReadOnly |
| `osint set-dns` | `QuickSetDNS` | Interface DNS settings + `SetInterfaceDnsSettings` | ReadOnly + Mutating `ActionCommand` |
| `osint net-profiles` | `NetConnectChoose` | `INetworkListManager` profile inspector | ReadOnly + Mutating `ActionCommand` |

### `net2rust-radio` (10 Tools — R4 Zero Plaintext Keys)
| CLI Subcommand | NirSoft Equivalent | Mechanism / OS API | MCP Policy |
| :--- | :--- | :--- | :--- |
| `radio wifi-info` | `WifiInfoView` | `WlanGetNetworkBssList` IE parser | ReadOnly |
| `radio wifi-scan` | `WirelessNetView` | Continuous `WlanGetAvailableNetworkList` | ReadOnly |
| `radio wifi-console` | `WirelessNetConsole` | Streaming console Wi-Fi scan | ReadOnly |
| `radio wifi-conn` | `WirelessConnectionInfo` | `WlanQueryInterface` PHY/RSSI/rate telemetry | ReadOnly |
| `radio wifi-profiles` | `ManageWirelessNetworks` | `WlanGetProfileList` / `WlanGetProfile` (`<keyMaterial>` redacted) | ReadOnly + Mutating `ActionCommand` |
| `radio wifi-hosted` | `HostedNetworkStarter` | `WlanHostedNetworkQueryStatus` | ReadOnly + Mutating `ActionCommand` |
| `radio bt-view` | `BluetoothView` | `BluetoothFindFirstDevice` discovery monitor | ReadOnly |
| `radio bt-log` | `BluetoothLogView` | Bluetooth arrival/departure event log | ReadOnly |
| `radio bt-cl` | `BluetoothCL` | Deterministic Bluetooth Classic enumeration | ReadOnly |
| `radio ble` | `BluetoothLEView` | WinRT `BluetoothLEAdvertisementWatcher` | ReadOnly |

---

## Privilege, Driver & Offline Modes (R3)

- Live OS/ETW/hardware APIs degrade gracefully with structured `NetError` variants (`PermissionDenied`, `DriverUnavailable`, `HardwareNotFound`, `NetworkUnavailable`) when Administrator elevation, optional `wpcap.dll`, or Wi-Fi/Bluetooth radios are absent.
- Pass `--offline` (or construct `NetContext::offline(...)`) to execute deterministic synthetic fixtures and offline `.pcap`/`.pcapng`/`.etl` captures with zero hardware or network access.

## R4 Scope & Exclusions

- **No `cred2rust` / No Credential Dumping**: Excludes `SniffPass`, `WirelessKeyView`, `WifiKeyView`, DPAPI/Vault/LSA secret extraction, and browser/mail password recovery.
- **No Plaintext Wi-Fi Keys**: `FORBIDDEN_WLAN_PROFILE_FLAG` (`0x0000_0004` / `WLAN_PROFILE_GET_PLAINTEXT_KEY`) is never passed, and `<keyMaterial>` elements are redacted.
- **No Sensitive HTTP Token Leakage**: `Authorization`, `Proxy-Authorization`, API key headers, and auth-bearing cookies are redacted by default.
- **No DLL Injection / API Hooking**: Excludes `SocketSniff` injection and `RunAsDate`-style hooking.
- **No Retired Legacy Tools**: Excludes all 39 retired legacy NirSoft utilities.

---

## Building from Source

```powershell
cargo test --workspace --offline
cargo build --workspace --release --offline
```

Emitted binaries in `target/release/`:
- `net2rust.exe` — Unified CLI
- `net2rust-win32.exe` — Native Win32 GUI (`winsafe 0.0.29`)
- `net2rust-iced.exe` — Cross-platform Iced GUI (`iced 0.14`)
- `net2rust-mcp.exe` — Policy-gated MCP JSON-RPC 2.0 stdio server
