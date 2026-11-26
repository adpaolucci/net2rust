# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.1.x` | :white_check_mark: |

## Safety, Privacy & R4 Exclusion Guarantees

`net2rust` is engineered for defensive network diagnostics, packet telemetry, and forensic reporting with strict safety boundaries:

1. **Zero Credential Extraction or Password Sniffing**:
   - `net2rust` explicitly excludes `SniffPass`, `WirelessKeyView`, `WifiKeyView`, `Network Password Recovery`, `Dialupass`, `Remote Desktop PassView`, and all `cred2rust`-style secret dumpers.
   - `net2rust-capture` (`capture http`, `capture cookies`) extracts protocol headers/metadata only and redacts `Authorization`, `Proxy-Authorization`, `X-Api-Key`, `X-Auth-Token`, and auth-bearing cookie tokens (`session`, `token`, `auth`, `jwt`, `sid`, `passwd`, `password`, `secret`, `csrf`, `xsrf`, `bearer`, `apikey`, `api_key`, `credential`).
   - `net2rust-radio` (`radio wifi-profiles`) **never** passes `WLAN_PROFILE_GET_PLAINTEXT_KEY` (`0x00000004`) to `WlanGetProfile` and redacts any `<keyMaterial>` element via `sanitize_wlan_profile_xml`.
2. **Zero DLL Injection or API Hooking**:
   - `net2rust` excludes `SocketSniff` Winsock DLL injection and all `CreateRemoteThread` / `NtCreateThreadEx` / IAT hooking mechanisms. Live packet and socket monitoring uses Windows Event Tracing (`Microsoft-Windows-NDIS-PacketCapture`, `Microsoft-Windows-Kernel-Network`, `Microsoft-Windows-DNS-Client`, `Microsoft-Windows-TCPIP`) and optional dynamic `wpcap.dll` loading.
3. **Zero Retired Legacy Protocols/Tools**:
   - None of the 39 retired legacy NirSoft utilities (IE/ActiveX/Flash/RTMP/Win9x/legacy IM/FTP password tools) are included.
4. **MCP Policy Gates & Dry-Run Guards**:
   - All 55 `TableProvider` views are strictly read-only. Mutating `ActionCommand`s (close socket, route add/delete, Wake-on-LAN, close SMB file, set DNS, switch network profile, manage WLAN profile, hosted network start/stop) are blocked by default in `net2rust-mcp` (`PolicyMode::ReadOnlyOnly`, JSON-RPC `-32003`) unless explicitly enabled with `--allow-mutating` and `confirm_destructive: true`, and honor `dry_run`.

## Reporting a Vulnerability

If you discover a security vulnerability, parser panic, credential-redaction bypass, or MCP policy-gate bypass:
1. **Do not disclose it publicly** via GitHub Issues.
2. Submit a report privately via GitHub Private Vulnerability Reporting under the Security tab:
   `https://github.com/adpaolucci/net2rust/security/advisories/new`
3. You will receive an acknowledgment within 48 hours.
4. A security patch and advisory will be coordinated and released promptly.
