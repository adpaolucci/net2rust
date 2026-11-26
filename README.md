# `net2rust` — 55-Tool Pure-Rust Network Diagnostics, ETW Capture, LAN, OSINT & Wi-Fi/BLE Suite

Part of the **GUAP** Ecosystem (`guap.ca`) • [**Project Hub & Web Documentation: https://net2rust.guap.ca**](https://net2rust.guap.ca) • [**Project Wiki**](https://github.com/adpaolucci/net2rust/wiki)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Rust: 2024](https://img.shields.io/badge/Rust-2024%20(1.88%2B)-orange.svg)](Cargo.toml)
[![Workspace: 11 Crates](https://img.shields.io/badge/Workspace-11%20Crates-emerald.svg)](Cargo.toml)
[![GUI: WinSafe Win32 + Iced 0.14](https://img.shields.io/badge/GUI-WinSafe%20Win32%20%2B%20Iced%200.14-cyan.svg)](crates/net2rust-win32)
[![MCP: stdio JSON-RPC](https://img.shields.io/badge/MCP-stdio%20JSON--RPC%202.0-purple.svg)](crates/net2rust-mcp)

Ready-to-submit **WinGet** & **Homebrew** manifests live in [`packaging/`](packaging/README.md).

**`net2rust`** is a memory-safe, credential-free 55-tool network diagnostics, packet telemetry, LAN discovery, OSINT, and Wi-Fi/Bluetooth suite written in Rust (Edition 2024, MSRV `1.88`) on top of [`guap-kit`](https://github.com/adpaolucci/guap-kit):
1. **`net2rust-win32`** (**WinSafe `0.0.29`**) — Native zero-GPU Win32 Common Controls console (`LVS_OWNERDATA` virtual grid, ComCtl v6, Per-Monitor DPI v2).
2. **`net2rust-iced`** (**Iced `0.14`**) — Cross-platform retained-mode GUI (`wgpu` + `tiny-skia` CPU fallback).
3. **`net2rust`** — Unified CLI exposing all 55 subcommands, `--offline` fixture/PCAP/PCAPNG/ETL playback, `GetNir` filter/sort, and `guap-export` Merkle custody reports.
4. **`net2rust-mcp`** — Policy-gated JSON-RPC 2.0 (`2024-11-05`) `stdio` MCP server exposing **68 tools** (**55** read-only `TableProvider`s + **13** mutating `ActionCommand`s).

---

## Comparison: `net2rust` vs. Legacy Network Utilities

| Capability | `net2rust` | Legacy NirSoft Network Utilities | Raw `netsh` / `tshark` Scripts |
|---|---|---|---|
| **Unified Suite Coverage** | **55 tools across 5 domains in 1 CLI, Dual GUI & MCP server** | 55 separate executables | Disparate OS tools & parsers |
| **Zero-Driver Packet Capture** | **Native Windows NDIS ETW + optional `wpcap.dll` + offline `.pcap`/`.pcapng`/`.etl`** | Mandatory WinPcap/Npcap on capture tools | External Npcap/Wireshark install |
| **Offline Determinism** | **`--offline`, `--fixture-dir`, `--pcap`, `--etl`, embedded IP/ASN/OUI DBs** | Live adapter state only on most tools | Live interfaces required |
| **Credential & Token Hygiene** | **Zero `WLAN_PROFILE_GET_PLAINTEXT_KEY`; `<keyMaterial>` & auth headers redacted** | Legacy password/sniffing risk | Unredacted captures |
| **Agent & Forensic Exports** | **68 policy-gated MCP endpoints + 7 `guap-export` formats + Merkle `CustodyManifest`** | Manual GUI save/copy | Ad-hoc CSV/text parsing |

---

## Workspace Architecture

```text
net2rust/
├── Cargo.toml                  # 11-crate workspace (Edition 2024, MSRV 1.88, Apache-2.0)
├── deny.toml                   # cargo-deny v2 supply-chain & license policy
├── mcp.json                    # Standard MCP client manifest (`net2rust-mcp`)
├── smithery.yaml               # Smithery tool catalog (68 endpoints)
├── metadata.json               # Machine-readable suite & 55-tool manifest
├── packaging/                  # WinGet & Homebrew manifests
└── crates/
    ├── net2rust-core/          # `#![forbid(unsafe_code)]` NetError, NetContext, MAC/CIDR/packet primitives, R4 sanitizers
    ├── net2rust-sockets/       # 13 socket, interface, route, neighbor, and ETW telemetry tools + 3 mutating actions
    ├── net2rust-capture/       # 11 zero-driver NDIS ETW, optional Npcap, and offline PCAP/PCAPNG/ETL analyzers
    ├── net2rust-lan/           # 11 LAN ping, GeoIP traceroute, ARP/NetBIOS scan, SMB shares/open-files, WOL + 2 mutating actions
    ├── net2rust-osint/         # 10 WHOIS/RDAP, offline GeoIP/OUI, DNS, hosting, and DNS/profile tools + 3 mutating actions
    ├── net2rust-radio/         # 10 Wi-Fi BSS/profile & Bluetooth Classic/BLE tools + 5 mutating actions (zero plaintext keys)
    ├── net2rust-report/        # CSV/TSV/JSON/JSONL/HTML/Markdown exports + SHA-256/512 Merkle custody + R4 HTML/JSON sanitizers
    ├── net2rust-mcp/           # Policy-gated MCP JSON-RPC 2.0 stdio server (`net2rust-mcp`, 68 endpoints)
    ├── net2rust-cli/           # Unified CLI (`net2rust`)
    ├── net2rust-win32/         # Native Win32 GUI (`net2rust-win32`)
    └── net2rust-iced/          # Cross-platform Iced 0.14 GUI (`net2rust-iced`)
```

---

## 55-Tool Matrix

### `net2rust-sockets` (13 Tools)
| CLI Subcommand | NirSoft Equivalent | Mechanism / OS API | MCP Policy |
| :--- | :--- | :--- | :--- |
| `sockets ports` | `CurrPorts` | `GetExtendedTcpTable` / `GetExtendedUdpTable` | `sockets.ports` + `sockets.ports.close` `[MUT]` |
| `sockets tcplog` | `TcpLogView` | TCP state transition polling / ETW | `sockets.tcplog` |
| `sockets live` | `LiveTcpUdpWatch` | ETW `Microsoft-Windows-Kernel-Network` | `sockets.live` |
| `sockets app-net` | `AppNetworkCounter` | ETW per-process byte/packet aggregation | `sockets.app-net` |
| `sockets proc-tcp` | `ProcessTCPSummary` | Per-PID TCP state summary | `sockets.proc-tcp` |
| `sockets tcp-errors` | `TCPConnectProblemView` | ETW TCPIP connect/retransmit failures | `sockets.tcp-errors` |
| `sockets dns-log` | `DNSLookupView` | ETW `Microsoft-Windows-DNS-Client` + `DnsGetCacheDataTable` | `sockets.dns-log` |
| `sockets counters` | `NetworkCountersWatch` | `GetIpStatisticsEx` / `GetTcpStatisticsEx` / `GetUdpStatisticsEx` / `GetIcmpStatisticsEx` | `sockets.counters` |
| `sockets adapter-watch` | `AdapterWatch` | `GetIfTable2` throughput & error deltas | `sockets.adapter-watch` |
| `sockets interfaces` | `NetworkInterfacesView` | `GetAdaptersAddresses` + registry adapter config | `sockets.interfaces` |
| `sockets routes` | `NetRouteView` | `GetIpForwardTable2` | `sockets.routes` + `sockets.routes.add`/`delete` `[MUT]` |
| `sockets neighbors` | `IPNeighborsView` | `GetIpNetTable2` + OUI lookup | `sockets.neighbors` |
| `sockets paths` | `IPPathTableView` | `GetIpPathTable` | `sockets.paths` |

### `net2rust-capture` (11 Tools — R4 Credential-Free)
| CLI Subcommand | NirSoft Equivalent | Mechanism / OS API | MCP Tool ID |
| :--- | :--- | :--- | :--- |
| `capture sniff` | `SmartSniff` | NDIS ETW / optional `wpcap.dll` / PCAP/PCAPNG/ETL | `capture.sniff` |
| `capture traffic` | `NetworkTrafficView` | Flow aggregation by protocol, IP, port | `capture.traffic` |
| `capture http` | `HTTPNetworkSniffer` | HTTP request/response metadata (`Authorization` redacted) | `capture.http` |
| `capture dns` | `DNSQuerySniffer` | RFC 1035 wire DNS parser | `capture.dns` |
| `capture dhcp` | `DHCPLogView` | BOOTP/DHCPv4 transaction parser | `capture.dhcp` |
| `capture mdns` | `mDNSView` | Multicast DNS (UDP 5353) / DNS-SD decoder | `capture.mdns` |
| `capture whois-lan` | `WhoIsConnectedSniffer` | Passive ARP/DHCP/mDNS/NetBIOS/SSDP discovery | `capture.whois-lan` |
| `capture cookies` | `WebCookiesSniffer` | Cookie names & attributes (auth tokens redacted per R4) | `capture.cookies` |
| `capture website` | `WebSiteSniffer` | Static HTTP asset metadata reconstruction | `capture.website` |
| `capture latency` | `NetworkLatencyView` | Passive TCP SYN / SYN-ACK RTT analyzer | `capture.latency` |
| `capture wifi-mon` | `WifiChannelMonitor` | 802.11 RadioTap / beacon / probe channel stats | `capture.wifi-mon` |

### `net2rust-lan` (11 Tools)
| CLI Subcommand | NirSoft Equivalent | Mechanism / OS API | MCP Policy |
| :--- | :--- | :--- | :--- |
| `lan ping` | `PingInfoView` | `IcmpSendEcho2` / `Icmp6SendEcho2` / TCP ping | `lan.ping` |
| `lan trace` | `CountryTraceRoute` | TTL-stepped ICMP trace + offline GeoIP | `lan.trace` |
| `lan scan` | `LANIPScanner` | Concurrent ARP, ICMP, NetBIOS, TCP scan | `lan.scan` |
| `lan wnetwatcher` | `Wireless Network Watcher` | Subnet ARP sweep (`SendARP`) + OUI | `lan.wnetwatcher` |
| `lan connect-log` | `NetworkConnectLog` | LAN host arrival/departure diff log | `lan.connect-log` |
| `lan wol` | `WakeMeOnLan` | Host inventory + magic packet sender | `lan.wol` + `lan.wol.send` `[MUT]` |
| `lan netbios` | `NetBScanner` | UDP 137 NBSTAT NetBIOS query | `lan.netbios` |
| `lan shares` | `NetResView` | `NetShareEnum` + `WNetOpenEnumW` | `lan.shares` |
| `lan openfiles` | `NetworkOpenedFiles` | `NetFileEnum` | `lan.openfiles` + `lan.openfiles.close` `[MUT]` |
| `lan resolve` | `FastResolver` | Parallel forward/reverse DNS & OUI lookup | `lan.resolve` |
| `lan speedtest` | `DownTester` | HTTP/HTTPS throughput benchmark | `lan.speedtest` |

### `net2rust-osint` (10 Tools)
| CLI Subcommand | NirSoft Equivalent | Mechanism / OS API | MCP Policy |
| :--- | :--- | :--- | :--- |
| `osint ipnet` | `IPNetInfo` | RIR WHOIS (TCP 43) & RDAP lookup | `osint.ipnet` |
| `osint whosip` | `WhosIP` | IP WHOIS/RDAP referral resolution | `osint.whosip` |
| `osint ipoffline` | `IPInfoOffline` | Embedded offline IPv4/IPv6 CIDR GeoIP/ASN | `osint.ipoffline` |
| `osint whois-domain` | `WhoisThisDomain` | IANA + registrar WHOIS/RDAP | `osint.whois-domain` |
| `osint whoiscl` | `WhoisCL` | Batch CLI WHOIS query engine | `osint.whoiscl` |
| `osint dns` | `DNSDataView` | Direct RFC 1035 / `DnsQuery_W` record lookup | `osint.dns` |
| `osint hosting` | `DomainHostingView` | Aggregated WHOIS, DNS, ASN, HTTP/MX profiler | `osint.hosting` |
| `osint oui` | `MACAddressView` | Embedded offline IEEE OUI lookup | `osint.oui` |
| `osint set-dns` | `QuickSetDNS` | Interface DNS settings + `SetInterfaceDnsSettings` | `osint.set-dns` + `osint.set-dns.apply` `[MUT]` |
| `osint net-profiles` | `NetConnectChoose` | `INetworkListManager` profile inspector | `osint.net-profiles` + `connect`/`disconnect` `[MUT]` |

### `net2rust-radio` (10 Tools — R4 Zero Plaintext Keys)
| CLI Subcommand | NirSoft Equivalent | Mechanism / OS API | MCP Policy |
| :--- | :--- | :--- | :--- |
| `radio wifi-info` | `WifiInfoView` | `WlanGetNetworkBssList` IE parser | `radio.wifi-info` |
| `radio wifi-scan` | `WirelessNetView` | Continuous `WlanGetAvailableNetworkList` | `radio.wifi-scan` |
| `radio wifi-console` | `WirelessNetConsole` | Streaming console Wi-Fi scan | `radio.wifi-console` |
| `radio wifi-conn` | `WirelessConnectionInfo` | `WlanQueryInterface` PHY/RSSI/rate telemetry | `radio.wifi-conn` |
| `radio wifi-profiles` | `ManageWirelessNetworks` | `WlanGetProfileList` / `WlanGetProfile` (`<keyMaterial>` redacted) | `radio.wifi-profiles` + `set-order`/`delete`/`toggle-auto` `[MUT]` |
| `radio wifi-hosted` | `HostedNetworkStarter` | `WlanHostedNetworkQueryStatus` | `radio.wifi-hosted` + `start`/`stop` `[MUT]` |
| `radio bt-view` | `BluetoothView` | `BluetoothFindFirstDevice` discovery monitor | `radio.bt-view` |
| `radio bt-log` | `BluetoothLogView` | Bluetooth arrival/departure event log | `radio.bt-log` |
| `radio bt-cl` | `BluetoothCL` | Deterministic Bluetooth Classic enumeration | `radio.bt-cl` |
| `radio ble` | `BluetoothLEView` | WinRT `BluetoothLEAdvertisementWatcher` | `radio.ble` |

---

## Privilege, Driver & Offline Modes (R3)

- Live OS/ETW/hardware APIs degrade gracefully with structured `NetError` variants (`PermissionDenied`, `DriverUnavailable`, `HardwareNotFound`, `NetworkUnavailable`) when Administrator elevation, optional `wpcap.dll`, Windows Location permission, or Wi-Fi/Bluetooth radios are absent.
- Pass `--offline`, `--fixture-dir <PATH>`, `--pcap <PATH>`, `--etl <PATH>`, or `--scenario <NAME>` to run deterministically with zero live hardware or network access.

## R4 Scope & Exclusions

- **No `cred2rust` / No Credential Dumping**: Excludes `SniffPass`, `WirelessKeyView`, `WifiKeyView`, DPAPI/Vault/LSA secret extraction, and browser/mail password recovery.
- **No Plaintext Wi-Fi Keys**: `FORBIDDEN_WLAN_PROFILE_FLAG` (`0x0000_0004` / `WLAN_PROFILE_GET_PLAINTEXT_KEY`) is never passed, and `<keyMaterial>` elements are redacted by `net2rust-report`.
- **No Sensitive HTTP Token Leakage**: `Authorization`, `Proxy-Authorization`, API key headers, and auth-bearing cookies are redacted by default.
- **No DLL Injection / API Hooking**: Excludes `SocketSniff` injection and `RunAsDate`-style hooking.
- **No Retired Legacy Tools**: Excludes all 39 retired legacy NirSoft utilities.

---

## Usage Examples (CLI, Dual GUI & MCP)

```powershell
# List all 55 tools and 13 mutating ActionCommands
net2rust list-tools

# Deterministic offline inspection & PCAP capture analysis
net2rust --offline --format json sockets ports
net2rust --offline --pcap capture.pcap --filter "protocol == TCP" --format csv --out sniff.csv --custody-out custody.json capture sniff
net2rust --offline --format json radio wifi-profiles

# Policy-gated mutating ActionCommands (preview vs explicit confirmation)
net2rust --dry-run action osint.set-dns.apply --args '{"interface":"Ethernet","servers":["9.9.9.9"]}'

# Launch GUIs or MCP server
net2rust gui             # Native Win32 virtual list GUI (net2rust-win32)
net2rust gui --iced      # Cross-platform Iced 0.14 GUI (net2rust-iced)
net2rust mcp --tools     # Print all 68 MCP tool schemas (55 read-only + 13 mutating)
net2rust-mcp             # Start ReadOnlyOnly JSON-RPC 2.0 stdio server (see mcp.json)
```

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

---

## Wiki Documentation

Explore the full [`net2rust` Project Wiki](https://github.com/adpaolucci/net2rust/wiki):
- [Architecture](https://github.com/adpaolucci/net2rust/wiki/Architecture)
- [Network Capture, OSINT, Radio & 55-Tool Matrix](https://github.com/adpaolucci/net2rust/wiki/Network-Capture-OSINT-Radio-and-55-Tool-Matrix)
- [CLI Reference](https://github.com/adpaolucci/net2rust/wiki/CLI-Reference)
- [Dual-GUI Guide (Win32 & Iced)](https://github.com/adpaolucci/net2rust/wiki/Dual-GUI-Guide)
- [GUI Framework Decision & Comparison](https://github.com/adpaolucci/net2rust/wiki/GUI-Framework-Decision-and-Comparison)
- [MCP Server Guide](https://github.com/adpaolucci/net2rust/wiki/MCP-Server-Guide)
- [Reports & Forensic Exports](https://github.com/adpaolucci/net2rust/wiki/Reports-and-Forensic-Exports)
- [Validation Rules & Status Codes](https://github.com/adpaolucci/net2rust/wiki/Validation-Rules-and-Status-Codes)
- [Building, Testing & CI/CD](https://github.com/adpaolucci/net2rust/wiki/Building-Testing-and-CI-CD)
- [Security & Stability](https://github.com/adpaolucci/net2rust/wiki/Security-and-Stability)

## License

Licensed under the [**Apache License, Version 2.0**](LICENSE). See [`NOTICE`](NOTICE) for attribution.
