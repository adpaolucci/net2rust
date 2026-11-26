# Packaging Manifests (`WinGet` & `Homebrew`)

This directory stores ready-to-submit package manager manifests matching published GitHub Releases for **`net2rust`**.

## 1. Windows Package Manager (`winget`)

Validate and submit the YAML manifests in `packaging/winget/manifests/a/adpaolucci/net2rust/<version>/`:

```powershell
# Local validation using winget CLI
winget validate --manifest .\packaging\winget\manifests\a\adpaolucci\net2rust\0.1.0

# Or submit an automated PR to microsoft/winget-pkgs using wingetcreate
wingetcreate submit .\packaging\winget\manifests\a\adpaolucci\net2rust\0.1.0
```

Installed portable command aliases: `net2rust`, `net2rust-win32`, `net2rust-iced`, `net2rust-mcp`.

## 2. Homebrew (`macOS` & `Linux`)

Copy `packaging/homebrew/net2rust.rb` into `Formula/net2rust.rb` of a tap repository (e.g., `adpaolucci/homebrew-tap`):

```bash
brew install adpaolucci/tap/net2rust
# Or test locally directly from file:
brew install --formula ./packaging/homebrew/net2rust.rb
brew test net2rust
```
