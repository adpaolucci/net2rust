# Changelog

All notable changes to `net2rust` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-23

### Added
- **Modular 11-Crate Pure-Rust Workspace (Edition 2024, MSRV `1.88`, Apache-2.0)**: `net2rust-core`, `net2rust-sockets`, `net2rust-capture`, `net2rust-lan`, `net2rust-osint`, `net2rust-radio`, `net2rust-report`, `net2rust-mcp`, `net2rust-cli`, `net2rust-win32`, and `net2rust-iced`, built on `guap-kit`.
- **55 Network, Capture, LAN, OSINT & Radio Tools**: Coverage across `-sockets` (13), `-capture` (11), `-lan` (11), `-osint` (10), and `-radio` (10) with deterministic `--offline` fixture/file testing and graceful non-privileged/missing-hardware diagnostics.
- **R4 Safety & Redaction Enforcement**: Zero credential sniffing, zero Wi-Fi plaintext key extraction (`WLAN_PROFILE_GET_PLAINTEXT_KEY` prohibited), zero DLL injection/hooking, and zero retired legacy NirSoft utilities.
- **Dual Pure-Rust GUIs, CLI, Merkle Reports & Policy-Gated MCP**: `net2rust`, `net2rust-win32` (`winsafe 0.0.29`), `net2rust-iced` (`iced 0.14`), and `net2rust-mcp` (`2024-11-05` JSON-RPC stdio with `PolicyMode` gates).
