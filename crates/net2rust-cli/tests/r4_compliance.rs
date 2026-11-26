#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use guap_table::TableQuery;
use net2rust_cli::{all_actions, all_providers, all_tool_descriptors};
use net2rust_core::{FORBIDDEN_WLAN_PROFILE_FLAG, NetContext, OfflineConfig};
use net2rust_report::{ExportFormat, ReportOptions, assert_r4_clean_bytes, render_report};

const FORBIDDEN_PATTERNS: &[(&str, &str)] = &[
    // Excluded cred2rust & credential-dumping tools/APIs (R4)
    ("cred2rust", "excluded cred2rust suite"),
    ("webbrowserpassview", "prohibited credential recovery tool"),
    ("chromepass", "prohibited credential recovery tool"),
    ("passwordfox", "prohibited credential recovery tool"),
    ("mail passview", "prohibited credential recovery tool"),
    ("mailpv", "prohibited credential recovery tool"),
    ("outlookpassview", "prohibited credential recovery tool"),
    ("wirelesskeyview", "prohibited Wi-Fi key recovery tool"),
    ("wifikeyview", "prohibited Wi-Fi key recovery tool"),
    ("credentialsfileview", "prohibited credential recovery tool"),
    ("vaultpasswordview", "prohibited credential recovery tool"),
    ("lsasecretsview", "prohibited LSA secret dumper"),
    ("lsasecretsdump", "prohibited LSA secret dumper"),
    ("securityquestionsview", "prohibited credential recovery tool"),
    ("dialupass", "prohibited credential recovery tool"),
    ("asterisk logger", "prohibited password logger"),
    ("bulletspassview", "prohibited password recovery tool"),
    ("protected storage passview", "prohibited password recovery tool"),
    ("vncpassview", "prohibited password recovery tool"),
    ("routerpassview", "prohibited password recovery tool"),
    ("produkey", "prohibited key extractor"),
    ("sniffpass", "prohibited network password sniffer"),
    ("credenumeratew", "prohibited Windows credential API"),
    ("credenumerate", "prohibited Windows credential API"),
    ("vaultenumerateitems", "prohibited Windows Vault API"),
    ("vaultgetitem", "prohibited Windows Vault API"),
    ("lsaretrieveprivatedata", "prohibited LSA secret API"),
    ("cryptunprotectdata", "prohibited DPAPI decryption API"),
    ("wlan_profile_get_plaintext_key", "prohibited Wi-Fi plaintext key flag"),
    // Excluded DLL injection & API hooking tools/APIs (R4)
    ("runasdate", "prohibited API hooking tool"),
    ("socketsniff", "prohibited DLL injection sniffer"),
    ("injecteddll", "prohibited DLL injection tool"),
    ("createremotethread", "prohibited DLL injection API"),
    ("ntcreatethreadex", "prohibited DLL injection API"),
    ("queueuserapc", "prohibited APC injection API"),
    ("setwindowshookexw", "prohibited global hook API"),
    ("setwindowshookex", "prohibited global hook API"),
    ("writeprocessmemory", "prohibited remote memory write API"),
    // Retired obsolete legacy NirSoft tools (R4)
    ("iecacheview", "retired legacy IE tool"),
    ("iehistoryview", "retired legacy IE tool"),
    ("iecookiesview", "retired legacy IE tool"),
    ("iesessionview", "retired legacy IE tool"),
    ("iedownloadview", "retired legacy IE tool"),
    ("iepassview", "retired legacy IE credential tool"),
    ("urlstringgrabber", "retired legacy IE/Opera tool"),
    ("favoritesview", "retired legacy IE tool"),
    ("webvideocap", "retired legacy Flash/IE tool"),
    ("flashcookiesview", "retired legacy Flash tool"),
    ("rtmpdumphelper", "retired legacy Flash/RTMP hook tool"),
    ("activexhelper", "retired legacy ActiveX tool"),
    ("win9xpv", "retired legacy Win9x tool"),
    ("9xprotect", "retired legacy Win9x tool"),
    ("msnpass", "retired legacy MSN tool"),
    ("messenpass", "retired legacy IM tool"),
    ("skypelogview", "retired legacy Skype tool"),
    ("skypecontactsview", "retired legacy Skype tool"),
    ("pcanywherecif", "retired legacy pcANYWHERE tool"),
    ("accesspassview", "retired legacy Access tool"),
    ("accesspv", "retired legacy Access tool"),
    ("oeview", "retired legacy Outlook Express tool"),
    ("dbxtract", "retired legacy Outlook Express tool"),
    ("wlmpv", "retired legacy Windows Live Mail tool"),
    ("netscapecacheview", "retired legacy Netscape tool"),
    ("nshistoryview", "retired legacy Netscape tool"),
    ("paltalkpass", "retired legacy IM tool"),
    ("mirandapass", "retired legacy IM tool"),
    ("trillianpass", "retired legacy IM tool"),
    ("pidginpass", "retired legacy IM tool"),
    ("googletalkpass", "retired legacy IM tool"),
    ("gizmopass", "retired legacy IM tool"),
    ("icqpass", "retired legacy IM tool"),
    ("aimpass", "retired legacy IM tool"),
    ("winupdateslist", "retired legacy WinXP updates tool"),
    ("drwatsonlogview", "retired legacy DrWatson tool"),
    ("livecontactsview", "retired legacy Windows Live tool"),
    ("winmailpass", "retired legacy Windows Mail tool"),
    ("silverlightcache", "retired legacy Silverlight tool"),
    ("javacacheview", "retired legacy Java plugin tool"),
    ("siteshoter", "retired legacy IE Trident tool"),
    ("htmldocedit", "retired legacy IE Trident tool"),
    ("systrayrefresh", "retired legacy Win9x/XP tray tool"),
    ("taskbarhide", "retired legacy Win9x/XP tray tool"),
    ("indexdatview", "retired legacy IE index.dat tool"),
    ("smartftp", "retired legacy FTP credential tool"),
    ("cuteftp", "retired legacy FTP credential tool"),
    ("flashfxp", "retired legacy FTP credential tool"),
];

fn collect_crate_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if matches!(name, "target" | ".git" | "tests") {
                continue;
            }
            collect_crate_files(&path, out);
        } else if let Some(file_name) = path.file_name().and_then(|s| s.to_str())
            && (file_name == "Cargo.toml"
                || file_name == "build.rs"
                || path.extension().and_then(|e| e.to_str()) == Some("rs"))
        {
            out.push(path);
        }
    }
}

fn scan_text(label: &str, text: &str, violations: &mut Vec<String>) {
    let lower = text.to_ascii_lowercase();
    for (pattern, reason) in FORBIDDEN_PATTERNS {
        if lower.contains(pattern) {
            violations.push(format!("{label}: matched '{pattern}' ({reason})"));
        }
    }
}

#[test]
fn r4_workspace_sources_manifests_and_metadata_scan() {
    assert_eq!(FORBIDDEN_WLAN_PROFILE_FLAG, 0x0000_0004);

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();

    // Assert exact 11 canonical crates and no cred2rust directory.
    let expected_crates: BTreeSet<&str> = [
        "net2rust-core",
        "net2rust-sockets",
        "net2rust-capture",
        "net2rust-lan",
        "net2rust-osint",
        "net2rust-radio",
        "net2rust-report",
        "net2rust-mcp",
        "net2rust-cli",
        "net2rust-win32",
        "net2rust-iced",
    ]
    .into_iter()
    .collect();

    let actual_crates: BTreeSet<String> = fs::read_dir(workspace_root.join("crates"))
        .unwrap()
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(actual_crates.len(), 11);
    for c in &expected_crates {
        assert!(actual_crates.contains(*c), "missing expected crate '{c}'");
    }
    assert!(!actual_crates.iter().any(|c| c.contains("cred")));

    let mut files = vec![
        workspace_root.join("Cargo.toml"),
        workspace_root.join("metadata.json"),
        workspace_root.join("smithery.yaml"),
        workspace_root.join("mcp.json"),
    ];
    collect_crate_files(&workspace_root.join("crates"), &mut files);
    assert!(
        files.len() >= 60,
        "expected >= 60 manifests/sources/metadata files, got {}",
        files.len()
    );

    let mut violations = Vec::new();
    let mut forbidden_flag_files = Vec::new();
    for path in &files {
        let content = fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        scan_text(&path.display().to_string(), &content, &mut violations);
        if content.contains("FORBIDDEN_WLAN_PROFILE_FLAG") {
            forbidden_flag_files.push(path.to_string_lossy().replace('\\', "/"));
        }
    }

    assert!(
        violations.is_empty(),
        "R4 compliance violations found:\n{}",
        violations.join("\n")
    );

    // FORBIDDEN_WLAN_PROFILE_FLAG may only appear in core r4/lib and radio win32_wlan safety assertions.
    for path in &forbidden_flag_files {
        assert!(
            path.ends_with("net2rust-core/src/r4.rs")
                || path.ends_with("net2rust-core/src/lib.rs")
                || path.ends_with("net2rust-radio/src/win32_wlan.rs"),
            "unexpected reference to FORBIDDEN_WLAN_PROFILE_FLAG in '{path}'"
        );
    }

    // Also verify WLAN_PROFILE_READ_FLAGS == 0 in win32_wlan.rs.
    let win32_wlan = fs::read_to_string(workspace_root.join("crates/net2rust-radio/src/win32_wlan.rs")).unwrap();
    assert!(win32_wlan.contains("pub const WLAN_PROFILE_READ_FLAGS: u32 = 0;"));
}

#[test]
fn r4_runtime_providers_actions_and_capture_wifi_redaction() {
    let ctx = NetContext::offline(OfflineConfig::default());
    let descriptors = all_tool_descriptors();
    let providers = all_providers(&ctx);
    let actions = all_actions(&ctx);

    assert_eq!(descriptors.len(), 55);
    assert_eq!(providers.len(), 55);
    assert_eq!(actions.len(), 13);

    let mut violations = Vec::new();
    for d in &descriptors {
        scan_text(&format!("descriptor:{}", d.id), d.id, &mut violations);
        scan_text(&format!("descriptor_name:{}", d.id), d.nirsoft_name, &mut violations);
        scan_text(&format!("descriptor_desc:{}", d.id), d.description, &mut violations);
    }
    for p in &providers {
        let schema = p.schema();
        scan_text(&format!("provider:{}", p.tool_id()), p.tool_id(), &mut violations);
        scan_text(
            &format!("provider_desc:{}", p.tool_id()),
            p.description(),
            &mut violations,
        );
        scan_text(
            &format!("provider_title:{}", p.tool_id()),
            &schema.title,
            &mut violations,
        );
        for col in &schema.columns {
            scan_text(
                &format!("provider_col:{}:{}", p.tool_id(), col.id),
                &col.label,
                &mut violations,
            );
        }

        let data = p.query(&TableQuery::default()).unwrap();
        let mut opts = ReportOptions::default();
        opts.export.include_detail_json = true;
        let json_bytes = render_report(&data, ExportFormat::Json, &opts).unwrap();
        assert_r4_clean_bytes(&json_bytes).unwrap();
    }
    for a in &actions {
        scan_text(&format!("action:{}", a.command_id()), a.command_id(), &mut violations);
        scan_text(
            &format!("action_desc:{}", a.command_id()),
            a.description(),
            &mut violations,
        );
    }

    assert!(
        violations.is_empty(),
        "runtime R4 metadata violations found:\n{}",
        violations.join("\n")
    );

    // Specifically inspect radio.wifi-profiles and capture.http / capture.cookies outputs.
    let wifi_profiles = providers.iter().find(|p| p.tool_id() == "radio.wifi-profiles").unwrap();
    let wifi_data = wifi_profiles.query(&TableQuery::default()).unwrap();
    let mut opts = ReportOptions::default();
    opts.export.include_detail_json = true;
    let wifi_json = String::from_utf8(render_report(&wifi_data, ExportFormat::Json, &opts).unwrap()).unwrap();
    assert!(!wifi_json.contains("SYNTHETIC-PROTECTED-BLOB"));
    assert!(wifi_json.contains("[REDACTED]"));

    for cap_id in ["capture.http", "capture.cookies"] {
        let cap = providers.iter().find(|p| p.tool_id() == cap_id).unwrap();
        let cap_data = cap.query(&TableQuery::default()).unwrap();
        let cap_json = String::from_utf8(render_report(&cap_data, ExportFormat::Json, &opts).unwrap()).unwrap();
        assert!(!cap_json.contains("Bearer "));
        assert!(!cap_json.contains("Basic "));
    }
}
