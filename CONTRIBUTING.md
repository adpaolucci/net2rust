# Contributing to `net2rust`

Thank you for your interest in contributing to `net2rust`!

## Code Architecture

The workspace is organized into 11 modular crates under `crates/`:
- `crates/net2rust-core`: Shared `NetError`, `ExecutionMode`/`NetContext`, `ToolCategory`, `ToolDescriptor`, `DomainCrateExport`, MAC/CIDR/packet primitives, and R4 safety sanitizers (`#![forbid(unsafe_code)]`).
- `crates/net2rust-sockets`: 13 socket, interface, route, neighbor, and ETW telemetry tools.
- `crates/net2rust-capture`: 11 NDIS ETW, optional Npcap, and offline PCAP/PCAPNG/ETL protocol analyzers (R4 credential-free).
- `crates/net2rust-lan`: 11 LAN ping, GeoIP traceroute, ARP/NetBIOS scan, SMB shares/open-files, resolver, speedtest, and Wake-on-LAN tools.
- `crates/net2rust-osint`: 10 WHOIS/RDAP, offline GeoIP/OUI, DNS, hosting, and DNS/profile tools.
- `crates/net2rust-radio`: 10 Wi-Fi BSS/profile and Bluetooth Classic/BLE tools (never extracts plaintext Wi-Fi keys).
- `crates/net2rust-report`: `guap-export` integration and SHA-256/512 Merkle chain-of-custody reporting.
- `crates/net2rust-mcp`: Model Context Protocol (MCP) JSON-RPC 2.0 `stdio` server (`net2rust-mcp`) with `PolicyMode` gates.
- `crates/net2rust-cli`: Unified CLI binary (`net2rust`) exposing all 55 subcommands, `--offline` mode, exports, MCP, and GUI launching.
- `crates/net2rust-win32`: Native zero-GPU Win32 desktop console built on `winsafe` (`net2rust-win32`).
- `crates/net2rust-iced`: Cross-platform retained-mode desktop console built on `iced 0.14` (`net2rust-iced`).

## Development Workflow

1. Fork and clone the repository alongside `guap-kit` (`../guap-kit`).
2. Ensure you have Rust `1.88+` installed (`rustup update stable`).
3. Run checks, formatting, linter, and tests:
   ```powershell
   cargo fmt --all -- --check
   cargo check --workspace --all-targets
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```
4. Open a Pull Request with clear commit messages and deterministic offline tests.

## Guidelines
- **R4 Safety First**: Never implement credential extraction, password sniffing, DPAPI/Vault/LSA dumping, Wi-Fi plaintext key recovery (`WLAN_PROFILE_GET_PLAINTEXT_KEY`), or DLL injection/API hooking.
- **Graceful Degradation**: Live OS/ETW/hardware calls must return structured `NetError` variants (`PermissionDenied`, `DriverUnavailable`, `HardwareNotFound`, `NetworkUnavailable`) rather than panicking when elevation, optional drivers, or hardware are absent.
- **Offline Testability**: Every parser, analyzer, and provider must support deterministic offline fixtures via `NetContext::offline(...)`.
- **Logging**: Use `tracing` macros writing diagnostics to `stderr` so CLI `stdout` and MCP `stdio` JSON-RPC streams remain clean.
