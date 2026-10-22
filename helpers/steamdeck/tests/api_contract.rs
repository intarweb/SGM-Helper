use std::fs;
use std::path::Path;

use assert_cmd::Command;
use httpmock::Method::{GET, POST};
use httpmock::MockServer;
use serde_json::Value;
use tempfile::TempDir;

const PS1_MEMCARD_SIZE: usize = 131_072;
const PS1_FRAME_SIZE: usize = 128;
const PS1_DEXDRIVE_HEADER_LENGTH: usize = 3904;
const PS1_DEXDRIVE_MAGIC: &[u8] = b"123-456-STD";

fn set_frame_checksum(bytes: &mut [u8], frame_index: usize) {
    let start = frame_index * PS1_FRAME_SIZE;
    let end = start + PS1_FRAME_SIZE;
    let frame = &mut bytes[start..end];
    let checksum = frame[..PS1_FRAME_SIZE - 1]
        .iter()
        .fold(0u8, |acc, value| acc ^ value);
    frame[PS1_FRAME_SIZE - 1] = checksum;
}

fn build_valid_ps1_memcard() -> Vec<u8> {
    let mut bytes = vec![0u8; PS1_MEMCARD_SIZE];
    bytes[0] = b'M';
    bytes[1] = b'C';

    for frame_index in 1..=15 {
        let start = frame_index * PS1_FRAME_SIZE;
        bytes[start] = 0xA0;
        bytes[start + 8] = 0xFF;
        bytes[start + 9] = 0xFF;
        set_frame_checksum(&mut bytes, frame_index);
    }

    let trailing_start = 63 * PS1_FRAME_SIZE;
    bytes[trailing_start] = b'M';
    bytes[trailing_start + 1] = b'C';
    set_frame_checksum(&mut bytes, 0);
    set_frame_checksum(&mut bytes, 63);
    bytes
}

fn encode_ps1_dexdrive(raw: &[u8]) -> Vec<u8> {
    let mut header = vec![0u8; PS1_DEXDRIVE_HEADER_LENGTH];
    header[..PS1_DEXDRIVE_MAGIC.len()].copy_from_slice(PS1_DEXDRIVE_MAGIC);
    header[18] = 0x01;
    header[20] = 0x01;
    header[21] = b'M';
    [header, raw.to_vec()].concat()
}

fn write_config(
    tmp: &TempDir,
    server: &MockServer,
    root: &Path,
    state_dir: &Path,
) -> std::path::PathBuf {
    let config_path = tmp.path().join("config.ini");
    let body = format!(
        "URL=\"127.0.0.1\"\nPORT=\"{}\"\nROOT=\"{}\"\nSTATE_DIR=\"{}\"\nWATCH=\"false\"\nWATCH_INTERVAL=\"1\"\n",
        server.port(),
        root.display(),
        state_dir.display()
    );
    fs::write(&config_path, body).unwrap();
    config_path
}

#[test]
fn login_with_app_password_persists_token() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_test","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"mister@example.com"}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(config)
        .arg("login")
        .arg("--email")
        .arg("mister@example.com")
        .arg("--app-password")
        .arg("secret")
        .assert()
        .success();

    let auth_path = state_dir.join("auth.json");
    assert!(auth_path.exists());
    let auth: Value = serde_json::from_str(&fs::read_to_string(auth_path).unwrap()).unwrap();
    assert_eq!(auth["token"], "tok_test");
}

#[test]
fn login_with_password_uses_login_and_token_endpoints() {
    let server = MockServer::start();
    let login = server.mock(|when, then| {
        when.method(POST).path("/auth/login");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"password@example.com"}}"#);
    });
    let token = server.mock(|when, then| {
        when.method(POST).path("/auth/token");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_password","expiresInDays":7}"#);
    });
    let me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"password@example.com"}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(config)
        .arg("login")
        .arg("--email")
        .arg("password@example.com")
        .arg("--password")
        .arg("secret")
        .assert()
        .success();

    assert_eq!(login.calls(), 1);
    assert_eq!(token.calls(), 1);
    assert_eq!(me.calls(), 1);

    let auth_path = state_dir.join("auth.json");
    assert!(auth_path.exists());
    let auth: Value = serde_json::from_str(&fs::read_to_string(auth_path).unwrap()).unwrap();
    assert_eq!(auth["token"], "tok_password");
}

#[test]
fn backend_forced_dry_run_marks_the_summary_and_uploads_nothing() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_dry","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"dry@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"success":true,"count":1,"rom":{"sha1":"dry123","md5":"md5v","fileName":"wario.sav"}}"#,
            );
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let _config_sync = server.mock(|when, then| {
        when.method(POST).path("/helpers/config/sync");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"accepted":true,"global":{"dryRun":true}}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-dry","sha256":"sha-dry"}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Nintendo/Game Boy")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Nintendo/Game Boy/wario.sav"),
        vec![0x00u8; 32768],
    )
    .unwrap();
    // A save the classifier cannot place: skipped before any write is decided.
    fs::create_dir_all(root.join("misc")).unwrap();
    fs::write(root.join("misc/unknown.sav"), vec![0x00u8; 32768]).unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("dry@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "sync failed: {stdout}");
    assert!(
        stdout.contains("Sync complete (DRY RUN)"),
        "summary line carries no dry-run marker: {stdout}"
    );
    assert!(
        stdout.contains("uploaded=0 downloaded=0"),
        "dry run counted a simulation as work done: {stdout}"
    );
    assert!(
        stdout.contains(
            "skipped=1 rejected_n64_controller_pak=0 refused_size_mismatch=0 \
             refused_flattened_components=0 accepted_not_stored=0 \
             rejected_permanent=0 duplicate_ignored=0 skipped_by_policy=1 errors=0 would_upload=1 would_download=0"
        ),
        "a skipped save was counted as a simulated upload, or the simulation was missed: {stdout}"
    );
    assert_eq!(upload.calls(), 0);
}

#[test]
fn port_save_dry_run_counts_a_simulation_not_an_upload() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_port","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"port@example.com"}}"#);
    });
    let _latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-port","sha256":"sha-port"}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    let port_save = root.join("ports/OcarinaOfTime/Save/global.sav");
    fs::create_dir_all(port_save.parent().unwrap()).unwrap();
    fs::write(&port_save, vec![0x00u8; 4096]).unwrap();
    fs::create_dir_all(&state_dir).unwrap();

    let config = tmp.path().join("config.ini");
    let ports_root = root.join("ports");
    let body = format!(
        "URL=\"127.0.0.1\"\nPORT=\"{}\"\nROOT=\"{}\"\nSTATE_DIR=\"{}\"\nWATCH=\"true\"\nWATCH_INTERVAL=\"1\"\n\n[source.ports]\nLABEL=\"Ports\"\nKIND=\"ports\"\nSAVE_PATH=\"{}\"\n",
        server.port(),
        root.display(),
        state_dir.display(),
        ports_root.display()
    );
    fs::write(&config, body).unwrap();

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("port@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .arg("--dry-run")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "sync failed: {stdout}");
    assert!(
        stdout.contains("uploaded=0 downloaded=0"),
        "dry run counted a simulation as work done: {stdout}"
    );
    assert!(
        stdout.contains("would_upload=1"),
        "the port-save dry run did not count the upload it skipped: {stdout}"
    );
    assert_eq!(upload.calls(), 0);
}

#[test]
fn a_permanently_refused_save_is_not_uploaded_again() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_reject","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"reject@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"success":true,"count":1,"rom":{"sha1":"reject123","md5":"md5v","fileName":"wario.sav"}}"#,
            );
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(422)
            .header("content-type", "application/json")
            .body(r#"{"success":false,"reason":"snes raw save payload is blank"}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Nintendo/Game Boy")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Nintendo/Game Boy/wario.sav"),
        vec![0x00u8; 32768],
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("reject@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .assert()
        .success();

    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "second sync failed: {stdout}");
    assert!(
        stdout.contains("rejected_permanent=1"),
        "the refused save was not counted as permanently rejected: {stdout}"
    );
    assert!(
        stdout.contains("errors=0"),
        "the refused save was retried instead of skipped: {stdout}"
    );
    assert_eq!(upload.calls(), 1);
}

#[test]
fn sync_uploads_when_no_cloud_save_exists() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_sync","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"sync@example.com"}}"#);
    });
    let rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"success":true,"count":1,"rom":{"sha1":"abc123","md5":"md5v","fileName":"wario.sav"}}"#,
            );
    });
    let save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-1","sha256":"sha-up"}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Nintendo/Game Boy")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Nintendo/Game Boy/wario.sav"),
        vec![0x00u8; 32768],
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("sync@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(config)
        .arg("sync")
        .assert()
        .success();

    assert_eq!(rom_lookup.calls(), 1);
    assert_eq!(save_latest.calls(), 1);
    assert_eq!(upload.calls(), 1);
}

#[test]
fn sync_reports_conflict_when_backend_marks_conflict() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_conflict","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"conflict@example.com"}}"#);
    });

    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"rom-sha1","md5":"rom-md5"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":true,"sha256":"cloud-different","version":2,"id":"save-cloud"}"#);
    });
    let _conflict_check = server.mock(|when, then| {
        when.method(GET).path("/conflicts/check");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"exists":true,"conflictId":"conf-1","cloudSha256":"cloud-different","cloudVersion":2,"cloudSaveId":"save-cloud"}"#);
    });
    let conflict_report = server.mock(|when, then| {
        when.method(POST).path("/conflicts/report");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"created":true,"conflictId":"conf-1"}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Nintendo/Super Nintendo")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Nintendo/Super Nintendo/chrono.sav"),
        vec![0x00u8; 32768],
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("conflict@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(config)
        .arg("sync")
        .assert()
        .success();

    assert!(conflict_report.calls() >= 1);
}

#[test]
fn sync_accepts_ps1_gme_and_uploads_normalized_payload() {
    let expected_line = "ps-line:psx:retroarch:memory-card-1";
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_ps1","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"ps1@example.com"}}"#);
    });
    let rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"ps1sha","md5":"ps1md5"}}"#);
    });
    let save_latest = server.mock(|when, then| {
        when.method(GET)
            .path("/save/latest")
            .query_param("romSha1", expected_line)
            .query_param("slotName", "Memory Card 1");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST)
            .path("/saves")
            .body_includes("name=\"rom_sha1\"")
            .body_includes(expected_line)
            .body_includes("name=\"slotName\"")
            .body_includes("Memory Card 1")
            .body_includes("name=\"device_type\"")
            .body_includes("retroarch");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-ps1","sha256":"sha-up"}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Sony/PSX")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let raw = build_valid_ps1_memcard();
    fs::write(root.join("Sony/PSX/ff7.gme"), encode_ps1_dexdrive(&raw)).unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("ps1@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(config)
        .arg("sync")
        .assert()
        .success();

    assert_eq!(rom_lookup.calls(), 0);
    assert_eq!(save_latest.calls(), 1);
    assert_eq!(upload.calls(), 1);
}

#[test]
fn sync_auto_enrolls_when_gate_is_open_without_login() {
    let server = MockServer::start();
    let auto_status = server.mock(|when, then| {
        when.method(GET).path("/auth/app-passwords/auto-enroll");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"active":true}"#);
    });
    let auto_token = server.mock(|when, then| {
        when.method(POST)
            .path("/auth/token/app-password")
            .body_includes("\"deviceType\":\"steamdeck\"")
            .body_includes("\"helperName\":\"sgm-steamdeck-helper\"");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"RSM-AAAA-BBBB","plainTextKey":"RSM-AAAA-BBBB"}"#);
    });
    let rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"abc123","md5":"md5v"}}"#);
    });
    let save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-1","sha256":"sha-up"}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Nintendo/Game Boy")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Nintendo/Game Boy/wario.sav"),
        vec![0x00u8; 32768],
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(config)
        .arg("sync")
        .assert()
        .success();

    assert_eq!(auto_status.calls(), 1);
    assert_eq!(auto_token.calls(), 1);
    assert_eq!(rom_lookup.calls(), 1);
    assert_eq!(save_latest.calls(), 1);
    assert_eq!(upload.calls(), 1);

    let auth_path = state_dir.join("auth.json");
    assert!(auth_path.exists());
    let auth: Value = serde_json::from_str(&fs::read_to_string(auth_path).unwrap()).unwrap();
    assert_eq!(auth["token"], "RSM-AAAA-BBBB");
}

#[test]
fn a_routing_error_does_not_make_a_save_terminal() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_rt","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"rt@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"rtsha","md5":"rtmd5"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    // A misrouted request: the bare body a Go mux returns, naming no save.
    let upload_routed_away = server.mock(|when, then| {
        when.method(POST).path("/saves").body_includes("broken.sav");
        then.status(404)
            .header("content-type", "text/plain")
            .body("404 page not found");
    });
    let upload_ok = server.mock(|when, then| {
        when.method(POST)
            .path("/saves")
            .body_includes("healthy.sav");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-rt","sha256":"sha-up"}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Nintendo/Game Boy")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Nintendo/Game Boy/broken.sav"),
        vec![0x01u8; 32768],
    )
    .unwrap();
    fs::write(
        root.join("Nintendo/Game Boy/healthy.sav"),
        // Not a printable byte: a payload of ASCII space-and-above is treated
        // as a text file and never classified as a save.
        vec![0x11u8; 32768],
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("rt@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    let first = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let first_stdout = String::from_utf8_lossy(&first.stdout);

    assert!(first.status.success(), "first sync failed: {first_stdout}");
    assert_eq!(
        upload_routed_away.calls(),
        1,
        "the misrouted save was never attempted: {first_stdout}"
    );
    assert!(
        first_stdout.contains("rejected_permanent=0"),
        "a routing failure was recorded as a permanent rejection: {first_stdout}"
    );
    assert!(
        upload_ok.calls() == 1,
        "a healthy save in the same pass did not sync: {first_stdout}"
    );

    let second = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let second_stdout = String::from_utf8_lossy(&second.stdout);

    assert!(
        second.status.success(),
        "second sync failed: {second_stdout}"
    );
    assert_eq!(
        upload_routed_away.calls(),
        2,
        "the save was not retried after a routing failure: {second_stdout}"
    );
    assert!(
        second_stdout.contains("rejected_permanent=0"),
        "a routing failure survived into the next pass as terminal: {second_stdout}"
    );
}

#[test]
fn a_stale_routing_marker_is_dropped_and_the_save_retried() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_st","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"st@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"stsha","md5":"stmd5"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-st","sha256":"sha-up"}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Nintendo/Game Boy")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let save = root.join("Nintendo/Game Boy/wario.sav");
    fs::write(&save, vec![0xaau8; 32768]).unwrap();

    // What the older build left behind: a marker for a bare routing 404.
    let state = serde_json::json!({
        "entries": {},
        "terminal_rejections": {
            save.to_string_lossy().to_string(): {
                "sha256": "8bee41c7e371d35c63d39a502b41e0d2ff0f3453d9aa1bb90a33046a0a002b24",
                "status": 404,
                "reason": "HTTP request faalde: status=404 Not Found body=404 page not found",
                "recorded_at": "2026-10-20T00:00:00Z"
            }
        }
    });
    fs::write(
        state_dir.join("sync_state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();

    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("st@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "sync failed: {stdout}");
    assert_eq!(
        upload.calls(),
        1,
        "the save was still treated as permanently refused: {stdout}"
    );
    assert!(
        stdout.contains("rejected_permanent=0"),
        "a stale routing marker was counted as a real refusal: {stdout}"
    );

    let written = fs::read_to_string(state_dir.join("sync_state.json")).unwrap();
    assert!(
        !written.contains("404 page not found"),
        "the stale routing marker is still in the state file: {written}"
    );
}

fn controller_pak_with_start_pages(start_pages: &[u16]) -> Vec<u8> {
    // A 32 KiB controller pak with a valid ID sector. Each start page marks a
    // note the pak directory holds; an empty list is a pak that has never been
    // written, which is what a MiSTer leaves behind for every game.
    let bank_count = 1u8;
    let mut pak = vec![0u8; 32 * 1024];
    let notes_offset = (1 + 2 * usize::from(bank_count)) * 256;
    for (index, start_page) in start_pages.iter().enumerate() {
        let base = notes_offset + index * 32;
        pak[base + 6..base + 8].copy_from_slice(&start_page.to_be_bytes());
        pak[base + 16..base + 26].copy_from_slice(b"WIPEOUT 64");
    }
    for base in [0x0020usize, 0x0060, 0x0080, 0x00c0] {
        let sector = &mut pak[base..base + 32];
        sector[26] = bank_count;
        let sum = sector[..28]
            .as_chunks::<2>()
            .0
            .iter()
            .fold(0u16, |acc, pair| {
                acc.wrapping_add(u16::from_be_bytes(*pair))
            });
        sector[28..30].copy_from_slice(&sum.to_be_bytes());
        sector[30..32].copy_from_slice(&0xfff2u16.wrapping_sub(sum).to_be_bytes());
    }
    pak
}

#[test]
fn sync_skips_an_empty_controller_pak_without_uploading() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_n64","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"n64@example.com"}}"#);
    });
    let rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"n64sha","md5":"n64md5"}}"#);
    });
    let save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-n64","sha256":"sha-up"}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Nintendo/N64")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Nintendo/N64/Wipeout 64_1.cpk"),
        controller_pak_with_start_pages(&[]),
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("n64@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "sync failed: {stdout}");
    assert_eq!(
        upload.calls(),
        0,
        "an empty controller pak was uploaded, so the server will refuse it again: {stdout}"
    );
    assert!(
        stdout.contains(
            "scanned=1 uploaded=0 downloaded=0 in_sync=0 conflicts=0 skipped=0 \
             rejected_n64_controller_pak=1"
        ),
        "the refusal was not counted as an empty controller pak: {stdout}"
    );
    let _ = (rom_lookup, save_latest);
}

#[test]
fn sync_uploads_a_controller_pak_that_holds_a_note() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_n64","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"n64@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"n64sha","md5":"n64md5"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-n64","sha256":"sha-up"}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Nintendo/N64")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Nintendo/N64/Wipeout 64.cpk"),
        controller_pak_with_start_pages(&[5]),
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("n64@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "sync failed: {stdout}");
    assert_eq!(
        upload.calls(),
        1,
        "a controller pak holding a note was not uploaded: {stdout}"
    );
    assert!(
        !stdout.contains("rejected_n64_controller_pak=1"),
        "a pak with a note in it was counted as empty: {stdout}"
    );
}

#[test]
fn a_failed_config_fetch_keeps_the_last_backend_policy() {
    // The server forced a dry run. If the next pass cannot reach the config
    // endpoint, dropping the override would sync live -- failing open on the
    // one setting that exists to stop writes.
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_policy","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"policy@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"pol123","md5":"md5v","fileName":"wario.sav"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let mut config_sync = server.mock(|when, then| {
        when.method(POST).path("/helpers/config/sync");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"accepted":true,"global":{"dryRun":true}}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-pol","sha256":"sha-pol"}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Nintendo/Game Boy")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Nintendo/Game Boy/wario.sav"),
        vec![0x00u8; 32768],
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("policy@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    let first = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let first_stdout = String::from_utf8_lossy(&first.stdout);
    assert!(
        first_stdout.contains("Sync complete (DRY RUN)"),
        "first pass should honour the forced dry run: {first_stdout}"
    );

    // The endpoint now fails. The policy it last sent has to survive.
    config_sync.delete();
    let _config_down = server.mock(|when, then| {
        when.method(POST).path("/helpers/config/sync");
        then.status(500)
            .header("content-type", "application/json")
            .body(r#"{"success":false}"#);
    });

    let second = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let second_stdout = String::from_utf8_lossy(&second.stdout);
    let second_stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        second_stdout.contains("Sync complete (DRY RUN)"),
        "a failed config fetch dropped the policy and synced live: {second_stdout}"
    );
    assert!(
        second_stderr.contains("applying the last policy it sent"),
        "the fallback was silent: {second_stderr}"
    );
    assert_eq!(upload.calls(), 0, "dry run must not upload");
}
#[cfg(unix)]
#[test]
fn an_unreadable_save_is_an_error_not_a_quiet_skip() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_unreadable","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"unreadable@example.com"}}"#);
    });
    let _config_sync = server.mock(|when, then| {
        when.method(POST).path("/helpers/config/sync");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"accepted":true,"global":{"dryRun":true}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    // No path hint, so classification would find no system and the file would
    // be counted as an ordinary skip. That is the silent-loss shape: an
    // unreadable save reported as "not a save".
    fs::create_dir_all(root.join("misc")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let save = root.join("misc/wario.sav");
    fs::write(&save, vec![0x00u8; 32768]).unwrap();
    fs::set_permissions(&save, fs::Permissions::from_mode(0o000)).unwrap();

    let config = write_config(&tmp, &server, &root, &state_dir);
    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("unreadable@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Restore so the tempdir can be removed.
    let _ = fs::set_permissions(&save, fs::Permissions::from_mode(0o644));

    assert!(
        stderr.contains("Cannot read save") && stderr.contains("wario.sav"),
        "an unreadable save was not reported: {stderr}"
    );
    assert!(
        stdout.contains("errors=1"),
        "the unreadable save was not counted as an error: {stdout}"
    );
    assert!(
        !stdout.contains("scanned=0"),
        "the file was not counted as scanned: {stdout}"
    );

    let state = fs::read_to_string(state_dir.join("sync_state.json")).unwrap_or_default();
    assert!(
        !state.contains("terminal_rejections\" : {"),
        "an unreadable save was recorded as a terminal rejection: {state}"
    );
}

#[test]
fn a_success_body_without_a_version_is_still_a_stored_save() {
    // The server's success body is {"success":true,"save":{"id","sha256"}} --
    // no version. Reading a missing version as "nothing was stored" reported
    // every such upload as accepted-and-discarded while the record was on disk.
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_nov","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"noversion@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"nov123","md5":"md5v","fileName":"wario.sav"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let _config_sync = server.mock(|when, then| {
        when.method(POST).path("/helpers/config/sync");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"accepted":true}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-nov","sha256":"sha-nov"}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Nintendo/Game Boy")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Nintendo/Game Boy/wario.sav"),
        vec![0x00u8; 32768],
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("noversion@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(
        upload.calls(),
        1,
        "the save should be uploaded exactly once"
    );
    assert!(
        stdout.contains("uploaded=1"),
        "a stored save without a version was not counted as uploaded: {stdout}"
    );
    assert!(
        stdout.contains("accepted_not_stored=0"),
        "a stored save without a version was counted as discarded: {stdout}"
    );
}

#[test]
fn an_arcade_save_sends_the_machine_it_belongs_to() {
    // A MAME save lives at nvram/<machine>/<file>; the file name is the
    // machine's own filename and says nothing about the game. The server names
    // the record after what the helper sends, so the machine travels with the
    // upload -- otherwise a restore writes the save into a directory no
    // machine reads.
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_arcade","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"arcade@example.com"}}"#);
    });
    // The romset is the machine, not the file: a nvram component's own name
    // (29f016a) matches no rom anywhere.
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET)
            .path("/rom/lookup")
            .query_param("filenameStem", "galaga");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"arc123","md5":"md5v","fileName":"galaga.zip"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let _config_sync = server.mock(|when, then| {
        when.method(POST).path("/helpers/config/sync");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"accepted":true}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST)
            .path("/saves")
            .body_includes("name=\"machine\"")
            .body_includes("galaga");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-arc","sha256":"sha-arc","version":1}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("nvram/galaga")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(root.join("nvram/galaga/29f016a.27h"), vec![0x11u8; 4096]).unwrap();

    let config_path = tmp.path().join("config.ini");
    let body = format!(
        "URL=\"127.0.0.1\"\nPORT=\"{}\"\nROOT=\"{}\"\nSTATE_DIR=\"{}\"\nWATCH=\"false\"\nWATCH_INTERVAL=\"1\"\n\n[source.arcade]\nLABEL=\"Arcade nvram\"\nKIND=\"mister-fpga\"\nPROFILE=\"mister\"\nSAVE_PATH=\"{}\"\nROM_PATH=\"{}\"\nRECURSIVE=\"true\"\nSYSTEMS=\"arcade\"\n",
        server.port(),
        root.display(),
        state_dir.display(),
        root.join("nvram").display(),
        root.join("roms").display()
    );
    fs::write(&config_path, body).unwrap();

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config_path)
        .arg("login")
        .arg("--email")
        .arg("arcade@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config_path)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        upload.calls(),
        1,
        "the arcade upload carried no machine; sync said: {stdout}"
    );
}

#[test]
fn a_combined_n64_save_uploads_with_the_retroarch_profile() {
    // mupen64plus-next writes one file holding EEPROM, pak templates, SRAM and
    // FlashRAM. The server splits it only for the RetroArch profile, so the
    // file's form decides the profile -- a SteamDeck's source profile is
    // Generic, which maps to a profile that cannot take the bundle.
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_n64b","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"n64bundle@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"n64b123","md5":"md5v","fileName":"1080 Snowboarding.zip"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let _config_sync = server.mock(|when, then| {
        when.method(POST).path("/helpers/config/sync");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"accepted":true}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST)
            .path("/saves")
            .body_includes("n64/retroarch");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-n64b","sha256":"sha-n64b","version":1}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("saves/n64")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let mut bundle = vec![0u8; 0x48800];
    for (index, value) in bundle[0x20800..0x28800].iter_mut().enumerate() {
        *value = (index % 251) as u8 + 1;
    }
    fs::write(
        root.join("saves/n64/1080 Snowboarding (Japan, USA).srm"),
        bundle,
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("n64bundle@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    // A save under ROOT/saves is discovered by both the root and the saves
    // root, so it uploads twice; the property is that it uploads at all, and
    // only under the retroarch profile.
    assert!(
        upload.calls() >= 1,
        "the combined N64 save was not uploaded with the retroarch profile; sync said: {stdout}"
    );
}

fn arcade_config(
    tmp: &tempfile::TempDir,
    server: &MockServer,
    root: &std::path::Path,
    state_dir: &std::path::Path,
) -> std::path::PathBuf {
    let config_path = tmp.path().join("config-arcade.ini");
    let body = format!(
        "URL=\"127.0.0.1\"\nPORT=\"{}\"\nROOT=\"{}\"\nSTATE_DIR=\"{}\"\nWATCH=\"false\"\nWATCH_INTERVAL=\"1\"\n\n[source.arcade]\nLABEL=\"Arcade nvram\"\nKIND=\"mister-fpga\"\nPROFILE=\"mister\"\nSAVE_PATH=\"{}\"\nROM_PATH=\"{}\"\nRECURSIVE=\"true\"\nSYSTEMS=\"arcade\"\n",
        server.port(),
        root.display(),
        state_dir.display(),
        root.join("nvram").display(),
        root.join("roms").display()
    );
    fs::write(&config_path, body).unwrap();
    config_path
}

fn arcade_login(binary: &str, config: &std::path::Path) {
    Command::cargo_bin(binary)
        .unwrap()
        .arg("--config")
        .arg(config)
        .arg("login")
        .arg("--email")
        .arg("arcade@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
}

fn arcade_sync(binary: &str, config: &std::path::Path) -> String {
    let output = Command::cargo_bin(binary)
        .unwrap()
        .arg("--config")
        .arg(config)
        .arg("sync")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sync failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn arcade_common_mocks(server: &MockServer) {
    let _ = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_arcade","expiresInDays":7}"#);
    });
    let _ = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"arcade@example.com"}}"#);
    });
    let _ = server.mock(|when, then| {
        when.method(GET)
            .path("/rom/lookup")
            .query_param("filenameStem", "galaga");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"arc123","md5":"md5v","fileName":"galaga.zip"}}"#);
    });
    let _ = server.mock(|when, then| {
        when.method(POST).path("/helpers/config/sync");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"accepted":true}"#);
    });
    let _ = server.mock(|when, then| {
        when.method(GET).path("/conflicts/check");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false}"#);
    });
}

// A MAME component's size is a property of its device: a 128-byte eeprom and
// an 8192-byte eeprom belong to different machines. A cloud payload of the
// wrong size for the file it would replace is another component's save, and
// writing it destroys the local one. The refusal is counted and named,
// because a MAME update can legitimately resize a component and the operator
// has to see that instead of a silent skip.
#[test]
fn a_download_that_changes_a_components_size_is_refused() {
    let binary = "sgm-steamdeck-helper";
    let server = MockServer::start();
    arcade_common_mocks(&server);
    let _latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":true,"sha256":"sha-cloud","version":9,"id":"save-cloud"}"#);
    });
    let download = server.mock(|when, then| {
        when.method(GET).path("/saves/download");
        then.status(200)
            .header("content-type", "application/octet-stream")
            .body(vec![0x5Au8; 8192]);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("nvram/galaga")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let local = root.join("nvram/galaga/eeprom");
    let local_bytes = vec![0x11u8; 128];
    fs::write(&local, &local_bytes).unwrap();

    let config = arcade_config(&tmp, &server, &root, &state_dir);
    arcade_login(binary, &config);
    let output = arcade_sync(binary, &config);

    assert_eq!(
        download.calls(),
        1,
        "the cloud save was not fetched: {output}"
    );
    assert_eq!(
        fs::read(&local).unwrap(),
        local_bytes,
        "the component was overwritten with a payload of the wrong size: {output}"
    );
    assert!(
        output.contains("refused_size_mismatch=1"),
        "the refusal is not counted in the summary: {output}"
    );
    assert!(
        output.contains("8192") && output.contains("128"),
        "the refusal does not name both sizes: {output}"
    );
    assert!(
        output.contains("save-cloud"),
        "the refusal does not name the record that was refused: {output}"
    );
}

// Every component of a machine holding identical bytes is what a fan-out
// corruption leaves behind: real chips are different devices with different
// contents. Uploading that set publishes the damage to every device that
// later restores the machine.
#[test]
fn a_machine_whose_components_are_all_identical_is_not_uploaded() {
    let binary = "sgm-steamdeck-helper";
    let server = MockServer::start();
    arcade_common_mocks(&server);
    let _latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-arc","sha256":"sha-arc","version":1}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("nvram/galaga")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    // Not printable: an extensionless nvram component that reads as text is
    // not discovered as a save at all.
    let shared = vec![0xA5u8; 2048];
    fs::write(root.join("nvram/galaga/eeprom"), &shared).unwrap();
    fs::write(root.join("nvram/galaga/game"), &shared).unwrap();
    fs::write(root.join("nvram/galaga/ioasic"), &shared).unwrap();

    let config = arcade_config(&tmp, &server, &root, &state_dir);
    arcade_login(binary, &config);
    let output = arcade_sync(binary, &config);

    assert_eq!(
        upload.calls(),
        0,
        "a flattened component set was uploaded: {output}"
    );
    assert!(
        output.contains("refused_flattened_components=3"),
        "the refusal is not counted for every component: {output}"
    );
    assert!(
        output.contains("corruption signal"),
        "the refusal does not say why: {output}"
    );
}

// The live refusal names the save twice -- a generic `message` and a specific
// `reason` -- and carries the status code. A longer body is not a different
// kind of refusal, but the error text is truncated when recorded, so a body
// that is cut mid-string parses as nothing and the save is retried forever.
#[test]
fn a_long_blank_refusal_is_still_permanent() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_blank","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"blank@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"blank123","md5":"md5v","fileName":"goldensun.srm"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(422)
            .header("content-type", "application/json")
            .body(r#"{"error":"Unprocessable Entity","message":"unsupported or unrecognized save format; only known consoles/arcade are allowed","reason":"gba raw save payload is blank (all 0xFF)","statusCode":422}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Nintendo/Game Boy Advance")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Nintendo/Game Boy Advance/Golden Sun.srm"),
        vec![0xFFu8; 65536],
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("blank@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    let first = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let first_out = String::from_utf8_lossy(&first.stdout);
    assert!(
        first_out.contains("rejected_permanent=1") && first_out.contains("errors=0"),
        "the refusal was counted as a failed pass on its first sighting: {first_out}"
    );
    let first_calls = upload.calls();

    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "second sync failed: {stdout}");
    assert!(
        stdout.contains("rejected_permanent=1") && stdout.contains("errors=0"),
        "a blank refusal was retried instead of held as permanent: {stdout}"
    );
    assert_eq!(
        upload.calls(),
        first_calls,
        "the blank save was uploaded again on the second pass: {stdout}"
    );
}

// The Steam Machine's own shape: a RetroArch source rooted at
// saves/, a gba file under saves/gba, and the server's blank refusal. The
// refusal has to land in the state file, or every pass re-uploads it.
#[test]
fn a_blank_refusal_from_a_retroarch_source_is_held_permanently() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_blank","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"blank@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"blank123","md5":"md5v","fileName":"goldensun.srm"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(422)
            .header("content-type", "application/json")
            .body(r#"{"error":"Unprocessable Entity","message":"unsupported or unrecognized save format; only known consoles/arcade are allowed","reason":"gba raw save payload is blank (all 0xFF)","statusCode":422}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("saves/gba")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("saves/gba/Golden Sun (USA, Europe).srm"),
        vec![0xFFu8; 65536],
    )
    .unwrap();

    let config_path = tmp.path().join("config.ini");
    let body = format!(
        "URL=\"127.0.0.1\"\nPORT=\"{}\"\nROOT=\"{}\r\"\nSTATE_DIR=\"{}\"\nWATCH=\"false\"\nWATCH_INTERVAL=\"1\"\n\n[source.retroarch]\nLABEL=\"retroarch steamdeck\"\nKIND=\"retroarch\"\nPROFILE=\"retroarch\"\nSAVE_PATH=\"{}\"\nROM_PATH=\"{}\"\nRECURSIVE=\"true\"\nSYSTEMS=\"gba\"\n",
        server.port(),
        root.display(),
        state_dir.display(),
        root.join("saves").display(),
        root.join("roms").display()
    );
    fs::write(&config_path, body).unwrap();

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config_path)
        .arg("login")
        .arg("--email")
        .arg("blank@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let first = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config_path)
        .arg("sync")
        .output()
        .unwrap();
    let first_out = String::from_utf8_lossy(&first.stdout);
    assert!(
        first_out.contains("rejected_permanent=1") && first_out.contains("errors=0"),
        "the refusal was counted as a failed pass on its first sighting: {first_out}"
    );

    let state = fs::read_to_string(state_dir.join("sync_state.json")).unwrap();
    assert!(
        state.contains("terminal_rejections"),
        "the refusal never reached the state file: {state}"
    );

    let first_calls = upload.calls();
    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config_path)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("rejected_permanent=1") && stdout.contains("errors=0"),
        "the blank save was retried: {stdout}"
    );
    assert_eq!(
        upload.calls(),
        first_calls,
        "the blank save was uploaded again"
    );
}

// A duplicate the server declined to store is still an answer: it kept its own
// copy and told us so. The pass that saw it re-armed itself, because the next
// pass looked for a cloud sha that could never equal the local one and uploaded
// again -- an arcade machine repeated that every four seconds for hours. The
// declined payload is remembered by its hash, so an unchanged file is reported
// once and a changed file is uploaded again.
#[test]
fn a_duplicate_the_server_declines_is_not_uploaded_again() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_dup","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"dup@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"dup123","md5":"md5v","fileName":"dupe.rom"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"duplicate":true,"duplicateDisposition":"ignored-latest","save":{"id":"save-dup","sha256":"sha-cloud","version":4},"success":true}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Nintendo/Game Boy")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Nintendo/Game Boy/wario.sav"),
        vec![0xA5u8; 32768],
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("dup@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .assert()
        .success();
    let after_first = upload.calls();
    assert_eq!(after_first, 1, "the first pass did not upload");

    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        upload.calls(),
        after_first,
        "a save the server already held was uploaded again: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        stdout.contains("duplicate_ignored=1") && stdout.contains("uploaded=0"),
        "the second pass did not report the duplicate as settled: {stdout}"
    );
}

// An adapter rewrites the payload on the way out: a `.gme` card goes up as a
// raw 128 KiB card, so the canonical hash and the file's own hash differ. A
// duplicate settled against the canonical hash would never match the file on
// the next pass and would upload forever -- the loop this is meant to stop,
// alive exactly on the formats that transform.
#[test]
fn a_duplicate_on_a_converted_save_is_not_uploaded_again() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_gme","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"gme@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"ps1sha","md5":"ps1md5","fileName":"card.rom"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"duplicate":true,"duplicateDisposition":"ignored-latest","save":{"id":"save-gme","sha256":"sha-cloud","version":2},"success":true}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Sony/PSX")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let raw = build_valid_ps1_memcard();
    fs::write(root.join("Sony/PSX/ff7.gme"), encode_ps1_dexdrive(&raw)).unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("gme@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .assert()
        .success();
    let after_first = upload.calls();
    assert_eq!(after_first, 1, "the first pass did not upload the card");

    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        upload.calls(),
        after_first,
        "a converted save the server already held was uploaded again: {stdout}\nSTDERR: {stderr}"
    );
}

// A sync client must not change a save's length under the game. The server
// stores a canonical form, and a canonical form is not the artifact: writing a
// padded payload overan 8 KiB save leaves the game reading a file it never
// wrote.
#[test]
fn a_download_that_would_resize_a_save_is_refused() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_resize","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"resize@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"resize123","md5":"md5v","fileName":"phantasy.rom"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":true,"sha256":"sha-cloud","version":2,"id":"save-cloud"}"#);
    });
    let _conflict = server.mock(|when, then| {
        when.method(GET).path("/conflicts/check");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false}"#);
    });
    let download = server.mock(|when, then| {
        when.method(GET).path("/saves/download");
        then.status(200)
            .header("content-type", "application/octet-stream")
            .body(vec![0x11u8; 65536]);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Sega/Master System")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let local = root.join("Sega/Master System/Phantasy Star (USA, Europe) (Rev A).srm");
    let local_bytes = vec![0xA5u8; 8192];
    fs::write(&local, &local_bytes).unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("resize@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(download.calls() <= 1, "downloaded more than once: {stdout}");
    assert_eq!(
        fs::read(&local).unwrap(),
        local_bytes,
        "the save was resized under the game: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        stdout.contains("refused_size_mismatch=1"),
        "the refusal is not reported: {stdout}"
    );
}

// A local save that differs from the record is a new version. Dropping it
// silently is data loss; refusing to write it is a conflict to report. The
// device remembers the copy it last synced, so a differing file is its own
// edit and goes up as a new version.
#[test]
fn a_changed_save_is_uploaded_over_the_existing_track() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_change","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"change@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"change123","md5":"md5v","fileName":"kirby.rom"}}"#);
    });
    let _conflict = server.mock(|when, then| {
        when.method(GET).path("/conflicts/check");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false}"#);
    });
    // Pass 1 has no record, so the local save goes up and its hash is
    // remembered. Pass 2 answers with that hash at v1, as the server would.
    let mut latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-new","sha256":"sha-local","version":2}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Nintendo/Game Boy")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let save = root.join("Nintendo/Game Boy/Kirby.srm");
    fs::write(&save, vec![0xA5u8; 8192]).unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("change@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let first = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "first sync failed: {}\nSTDERR: {}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );

    let file_sha = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(fs::read(&save).unwrap());
        format!("{:x}", hasher.finalize())
    };
    latest.delete();
    let _latest = server.mock(move |when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(
                r#"{{"success":true,"exists":true,"sha256":"{file_sha}","version":1,"id":"save-server"}}"#
            ));
    });

    // Not printable: a save that reads as text is not discovered as a save.
    fs::write(&save, vec![0xC3u8; 8192]).unwrap();
    let before = upload.calls();
    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        upload.calls() > before,
        "a local edit was neither uploaded nor reported as a conflict: {stdout}\nSTDERR: {stderr}"
    );
}

// Real carts carry 2 KiB and 16 KiB SRAM banks, so a Sega save is not always a
// power of two. Madden NFL '94 (2114 B) and Shining in the Darkness (16128 B)
// were dropped as "unsupported" and never reached the server.
#[test]
fn a_sega_save_of_an_irregular_size_is_uploaded() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_sega","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"sega@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"sega123","md5":"md5v","fileName":"madden.rom"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-sega","sha256":"sha-sega","version":1}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Sega/Genesis")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Sega/Genesis/Madden NFL '94 (USA, Europe).srm"),
        vec![0xC7u8; 2114],
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("sega@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        upload.calls(),
        1,
        "a real Sega save of an irregular size never reached the server: {stdout}\nSTDERR: {stderr}"
    );
}

// The RTC sidecar carries a clock, not a save. As its own record it re-uploads
// every pass, and written to a sibling name it destroys the save beside it.
#[test]
fn an_rtc_sidecar_is_not_uploaded_as_its_own_save() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_rtc","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"rtc@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"rtc123","md5":"md5v","fileName":"crystal.rom"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-rtc","sha256":"sha-rtc","version":1}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Nintendo/Game Boy Color")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Nintendo/Game Boy Color/Pokemon Crystal.rtc"),
        vec![0x13u8; 8],
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("rtc@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        upload.calls(),
        0,
        "the RTC sidecar was uploaded as a save: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        stderr.contains("RTC sidecar travels with its save"),
        "the sidecar was skipped without saying so: {stderr}"
    );
    assert!(
        stdout.contains("skipped_by_policy=1"),
        "the sidecar skip is not counted: {stdout}"
    );
}

// A DeSmuME .dsv is the raw backup plus a 122-byte footer, so its own length is
// not a power of two and it is not the size the server's raw check knows. The
// container decides the profile: .dsv means nds/desmume, and the server strips
// the footer for that profile only.
#[test]
fn a_dsv_uploads_as_the_desmume_profile() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_dsv","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"dsv@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"dsv123","md5":"md5v","fileName":"mkds.rom"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST)
            .path("/saves")
            .body_includes("nds/desmume");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-dsv","sha256":"sha-dsv","version":1}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("saves/nds")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("saves/nds/Mario Kart DS (USA).dsv"),
        vec![0xC5u8; 262144 + 122],
    )
    .unwrap();
    let config = tmp.path().join("config-nds.ini");
    fs::write(
        &config,
        format!(
            "URL=\"127.0.0.1\"\nPORT=\"{}\"\nROOT=\"{}\"\nSTATE_DIR=\"{}\"\nWATCH=\"false\"\nWATCH_INTERVAL=\"1\"\n\n[source.nds]\nLABEL=\"nds\"\nKIND=\"mister-fpga\"\nPROFILE=\"mister\"\nSAVE_PATH=\"{}\"\nROM_PATH=\"{}\"\nRECURSIVE=\"true\"\nSYSTEMS=\"nds\"\n",
            server.port(),
            root.display(),
            state_dir.display(),
            root.join("saves").display(),
            root.join("roms").display()
        ),
    )
    .unwrap();

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("dsv@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        upload.calls(),
        1,
        "a .dsv was not uploaded with the DeSmuME profile: {stdout}\nSTDERR: {stderr}"
    );
}

// A Sega upload declares the profile its save belongs to. The server validates
// a declared profile as that console's raw save; without one it refuses the
// upload outright, so a save never reaches the size checks at all.
#[test]
fn a_genesis_upload_declares_its_runtime_profile() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_sega","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"sega@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"sega123","md5":"md5v","fileName":"madden.rom"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST)
            .path("/saves")
            .body_includes("genesis/genesis-plus-gx");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-sega","sha256":"sha-sega","version":1}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Sega/Genesis")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Sega/Genesis/Madden NFL '94 (USA, Europe).srm"),
        vec![0xC7u8; 2114],
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("sega@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        upload.calls(),
        1,
        "a Genesis upload did not declare a runtime profile: {stdout}\nSTDERR: {stderr}"
    );
}

// NDS restores go through the same container rule as uploads: a .dsv is
// DeSmuME's, and the server refuses a download that does not name the profile.
// Without this the restore fails with "runtimeProfile is required" and the save
// never lands on the device.
#[test]
fn a_missing_dsv_is_restored_with_the_desmume_profile() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_restore","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"restore@example.com"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":true,"sha256":"remote-sha","version":2,"id":"save-remote"}"#);
    });
    let _list = server.mock(|when, then| {
        when.method(GET).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"total":1,"limit":100,"offset":0,"saves":[{"id":"save-remote","filename":"Mario Kart DS (USA).dsv","displayTitle":"Mario Kart DS","systemSlug":"nds","sha256":"remote-sha","version":2,"latestSizeBytes":262266}]}"#);
    });
    let download = server.mock(|when, then| {
        when.method(GET)
            .path("/saves/download")
            .query_param("runtimeProfile", "nds/desmume");
        then.status(200).body(vec![0xC5u8; 262144]);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("saves/nds")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let missing = root.join("saves/nds/Mario Kart DS (USA).dsv");
    assert!(!missing.exists());

    let sync_state = format!(
        r#"{{
  "entries": {{
    "{}": {{
      "sha256": "old-sha",
      "rom_sha1": "dsv-rom-sha",
      "version": 1,
      "system_slug": "nds",
      "local_container": "native",
      "adapter_profile": "identity",
      "source_kind": "steamdeck",
      "source_name": "default-steamdeck",
      "updated_at": "2026-01-01T00:00:00Z"
    }}
  }}
}}"#,
        missing.display()
    );
    fs::write(state_dir.join("sync_state.json"), sync_state).unwrap();
    let config = tmp.path().join("config-nds.ini");
    fs::write(
        &config,
        format!(
            "URL=\"127.0.0.1\"\nPORT=\"{}\"\nROOT=\"{}\"\nSTATE_DIR=\"{}\"\nWATCH=\"false\"\nWATCH_INTERVAL=\"1\"\n\n[source.nds]\nLABEL=\"nds\"\nKIND=\"steamdeck\"\nPROFILE=\"retroarch\"\nSAVE_PATH=\"{}\"\nROM_PATH=\"{}\"\nRECURSIVE=\"true\"\nSYSTEMS=\"nds\"\n",
            server.port(),
            root.display(),
            state_dir.display(),
            root.join("saves").display(),
            root.join("roms").display()
        ),
    )
    .unwrap();

    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("restore@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    Command::cargo_bin("sgm-steamdeck-helper")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .assert()
        .success();

    assert!(
        download.calls() >= 1,
        "the .dsv restore did not declare the DeSmuME profile; the file exists: {}",
        missing.exists()
    );
    assert!(missing.exists(), "the .dsv was not restored");
}

fn fork22_helper() -> Command {
    Command::cargo_bin("sgm-steamdeck-helper").unwrap()
}

// RetroDECK gives a Nintendo DS save whatever name RetroArch chose, and a
// DeSmuME container turns up as a `.sav` as readily as a `.dsv`. The footer is
// what makes it a container: the file's own length is not a power of two, but
// the backup inside it is. Judged by the name alone the file was refused as an
// unsupported size, and with no DeSmuME profile the server would have measured
// the footer as part of the save.
#[test]
fn a_desmume_container_under_a_sav_name_uploads_as_desmume() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_sav","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"sav@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"sav123","md5":"md5v","fileName":"nsmb.rom"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST)
            .path("/saves")
            .body_includes("nds/desmume");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-sav","sha256":"sha-sav","version":1}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("saves/nds")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("saves/nds/New Super Mario Bros. (USA).sav"),
        vec![0xC5u8; 262144 + 122],
    )
    .unwrap();
    let config = tmp.path().join("config-nds-sav.ini");
    fs::write(
        &config,
        format!(
            "URL=\"127.0.0.1\"\nPORT=\"{}\"\nROOT=\"{}\"\nSTATE_DIR=\"{}\"\nWATCH=\"false\"\nWATCH_INTERVAL=\"1\"\n\n[source.nds]\nLABEL=\"nds\"\nKIND=\"mister-fpga\"\nPROFILE=\"mister\"\nSAVE_PATH=\"{}\"\nROM_PATH=\"{}\"\nRECURSIVE=\"true\"\nSYSTEMS=\"nds\"\n",
            server.port(),
            root.display(),
            state_dir.display(),
            root.join("saves").display(),
            root.join("roms").display()
        ),
    )
    .unwrap();

    fork22_helper()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("sav@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = fork22_helper()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        upload.calls(),
        1,
        "a DeSmuME container under a .sav name was not uploaded as nds/desmume: {stdout}\nSTDERR: {stderr}"
    );
}

// A MiSTer PC Engine core is called `tgfx16` locally, and the server knows the
// system as `pc-engine`. Sending the local name made a save look like it
// belonged to a system the source's own SYSTEMS list did not carry, so a PC
// Engine save was skipped as out of policy and never reached the server.
#[test]
fn a_mister_system_is_sent_by_the_name_the_server_knows() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_pce","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"pce@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"pce123","md5":"md5v","fileName":"bonk.rom"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST)
            .path("/saves")
            .body_includes("pc-engine/mister");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-pce","sha256":"sha-pce","version":1}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("saves/tgfx16")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("saves/tgfx16/Bonk's Adventure (USA).sav"),
        vec![0xC7u8; 2048],
    )
    .unwrap();
    let config = tmp.path().join("config-pce.ini");
    fs::write(
        &config,
        format!(
            "URL=\"127.0.0.1\"\nPORT=\"{}\"\nROOT=\"{}\"\nSTATE_DIR=\"{}\"\nWATCH=\"false\"\nWATCH_INTERVAL=\"1\"\n\n[source.pcengine]\nLABEL=\"pc engine\"\nKIND=\"mister-fpga\"\nPROFILE=\"mister\"\nSAVE_PATH=\"{}\"\nROM_PATH=\"{}\"\nRECURSIVE=\"true\"\nSYSTEMS=\"pc-engine\"\n",
            server.port(),
            root.display(),
            state_dir.display(),
            root.join("saves").display(),
            root.join("roms").display()
        ),
    )
    .unwrap();

    fork22_helper()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("pce@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = fork22_helper()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        upload.calls(),
        1,
        "a PC Engine upload did not name the system the server knows: {stdout}\nSTDERR: {stderr}"
    );
}

fn rename_helper() -> Command {
    Command::cargo_bin("sgm-steamdeck-helper").unwrap()
}

// RetroDECK writes one game's save under more than one name: "Madden NFL 94"
// and "Madden NFL '94 (USA, Europe)" are the same cartridge, and the server
// reads the second spelling as a new game at a size its table does not list,
// so the authenticated upload is refused and retried every pass. A save whose
// content this pass already synced for the same game under another spelling is
// settled instead of uploaded -- but a different game with the same bytes is
// still uploaded, because two blank saves are not one save.
#[test]
fn a_rename_of_a_synced_save_is_not_uploaded_again() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_rename","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"rename@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"madden-sha1","md5":"md5v","fileName":"madden.rom"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"success":true,"save":{"id":"save-madden","sha256":"sha-madden","version":1}}"#,
            );
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Sega/Genesis")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let short = root.join("Sega/Genesis/Madden NFL 94.srm");
    fs::write(&short, vec![0xC7u8; 2114]).unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    rename_helper()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("rename@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();

    let first = rename_helper()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    assert_eq!(
        upload.calls(),
        1,
        "the first copy was not uploaded: {}\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );

    // The emulator now writes the same save under its full, region-tagged name.
    fs::write(
        root.join("Sega/Genesis/Madden NFL '94 (USA, Europe).srm"),
        vec![0xC7u8; 2114],
    )
    .unwrap();
    let second = rename_helper()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let second_stdout = String::from_utf8_lossy(&second.stdout);
    let second_stderr = String::from_utf8_lossy(&second.stderr);
    assert_eq!(
        upload.calls(),
        1,
        "the renamed copy was uploaded as a second game:\n{second_stdout}\n{second_stderr}"
    );
    // Both spellings settle against each other -- neither is uploaded, and on
    // the next pass neither asks again.
    assert!(
        second_stdout.contains("duplicate_ignored=2"),
        "the rename was skipped without being counted:\n{second_stdout}\n{second_stderr}"
    );
    assert!(
        second_stderr.contains("under another name"),
        "the skip does not say why:\n{second_stderr}"
    );

    // A different game that happens to hold the same bytes is not the same save.
    fs::write(
        root.join("Sega/Genesis/Sonic the Hedgehog.srm"),
        vec![0xC7u8; 2114],
    )
    .unwrap();
    let third = rename_helper()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    assert_eq!(
        upload.calls(),
        2,
        "a different game holding the same bytes was collapsed into another game's save:\n{}\n{}",
        String::from_utf8_lossy(&third.stdout),
        String::from_utf8_lossy(&third.stderr)
    );
}

fn expiry_helper() -> Command {
    Command::cargo_bin("sgm-steamdeck-helper").unwrap()
}

fn fork23_state_file(
    state_dir: &std::path::Path,
    save_path: &std::path::Path,
    recorded_at: &str,
    helper_version: Option<&str>,
) {
    use sha2::Digest as _;
    let bytes = fs::read(save_path).unwrap();
    let sha = hex::encode(sha2::Sha256::digest(&bytes));
    let mut rejection = serde_json::json!({
        "sha256": sha,
        "status": 422,
        "reason": r#"HTTP request faalde: status=422 Unprocessable Entity body={"error":"genesis raw save size 2114 is not recognized"}"#,
        "recorded_at": recorded_at,
    });
    if let Some(version) = helper_version {
        rejection["helper_version"] = serde_json::json!(version);
    }
    let mut rejections = serde_json::Map::new();
    rejections.insert(save_path.to_string_lossy().to_string(), rejection);
    let state = serde_json::json!({
        "entries": {},
        "terminal_rejections": rejections,
        "duplicate_uploads": {},
    });
    fs::write(
        state_dir.join("sync_state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();
}

fn fork23_now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

// A refusal is a statement about the server at one moment, and the marker that
// remembers it is keyed on bytes that never change. Without an expiry, a server
// fixed afterwards is never asked again, and the log line reads as a live
// refusal. A marker recorded by another release is presented to the server once
// more.
#[test]
fn a_refusal_recorded_by_another_release_is_probed_again() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_reprobe","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"reprobe@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"reprobe-sha1","md5":"md5v","fileName":"madden.rom"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-reprobe","sha256":"sha-reprobe","version":1}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Sega/Genesis")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let save = root.join("Sega/Genesis/Madden NFL '94 (USA, Europe).srm");
    fs::write(&save, vec![0xC7u8; 2114]).unwrap();
    fork23_state_file(&state_dir, &save, &fork23_now_rfc3339(), Some("0.0.1"));
    let config = write_config(&tmp, &server, &root, &state_dir);

    expiry_helper()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("reprobe@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = expiry_helper()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        upload.calls(),
        1,
        "a refusal from another release was never presented to the server again:\n{stdout}\n{stderr}"
    );
    assert!(
        stderr.contains("Re-probing"),
        "the retry does not say the refusal was stale:\n{stderr}"
    );
}

// The control: a refusal from this release, recorded recently, is still trusted
// -- but the log line says when it was recorded, so a fixed server cannot look
// like a present-tense refusal.
#[test]
fn a_refusal_from_this_release_is_not_probed_again() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_hold","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"hold@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"hold-sha1","md5":"md5v","fileName":"madden.rom"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-hold","sha256":"sha-hold","version":1}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Sega/Genesis")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let save = root.join("Sega/Genesis/Madden NFL '94 (USA, Europe).srm");
    fs::write(&save, vec![0xC7u8; 2114]).unwrap();
    let recorded_at = fork23_now_rfc3339();
    fork23_state_file(
        &state_dir,
        &save,
        &recorded_at,
        Some(sgm_steamdeck_helper::state::build_identity()),
    );
    let config = write_config(&tmp, &server, &root, &state_dir);

    expiry_helper()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("hold@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = expiry_helper()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        upload.calls(),
        0,
        "a current refusal was probed again:\n{stdout}\n{stderr}"
    );
    assert!(
        stderr.contains("Not retrying") && stderr.contains(&recorded_at),
        "the skip line does not date the refusal:\n{stderr}"
    );
}

fn placeholder_helper() -> Command {
    Command::cargo_bin("sgm-steamdeck-helper").unwrap()
}

// The server answers an unrecognised stem with a live game record: name
// "Unknown", no system, and a sha1 derived from the stem rather than from any
// cartridge. The helper keys the save on that sha1, and the key carries no
// system, so two games sharing a title on different systems can answer each
// other's lookups. The operator has to be told which of the two happened.
#[test]
fn an_unrecognised_title_is_named_as_a_placeholder_key() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_placeholder","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"placeholder@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"count":1,"rom":{"fileName":"Unknown.srm","game":{"id":878081,"name":"Unknown","system":null},"sha1":"15f817b3db4e843f203c4eb7949486532715a08f","md5":"139d88db2fec53ba778c7d5d999c51a5"},"success":true}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-placeholder","sha256":"sha-placeholder","version":1}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Sega/Genesis")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Sega/Genesis/Defenders of Oasis (USA, Europe).srm"),
        vec![0xC7u8; 2114],
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    placeholder_helper()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("placeholder@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = placeholder_helper()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The save is still uploaded: this change reports, it does not re-key.
    assert_eq!(
        upload.calls(),
        1,
        "the save was not uploaded:\n{stdout}\n{stderr}"
    );
    assert!(
        stderr.contains("did not recognise"),
        "the placeholder key was not named:\n{stderr}"
    );
    assert!(
        stderr.contains("no cartridge produced"),
        "the warning does not say the key came from nowhere:\n{stderr}"
    );
}

// The control: a resolved record says nothing, so the warning stays meaningful.
#[test]
fn a_resolved_title_is_not_reported_as_a_placeholder() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_resolved","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"resolved@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"count":1,"rom":{"fileName":"Madden NFL 94.md","game":{"id":7,"name":"Madden NFL 94","system":{"id":3,"name":"Genesis"}},"sha1":"8043ef4bca0c4cdbdb15d99186f5c976b1ce3ce8","md5":"abc"},"success":true}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let _upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-resolved","sha256":"sha-resolved","version":1}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Sega/Genesis")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Sega/Genesis/Madden NFL 94.srm"),
        vec![0xC7u8; 2114],
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    placeholder_helper()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("resolved@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = placeholder_helper()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stderr.contains("did not recognise"),
        "a resolved record was reported as a placeholder:\n{stderr}"
    );
}

fn ps2_helper() -> Command {
    Command::cargo_bin("sgm-steamdeck-helper").unwrap()
}

// A PCSX2 memory card is a PS2 filesystem image. A file that does not begin
// with the superblock is not a card at all, and the generic "no system profile
// accepts a 8650752 byte .ps2 file" sends an operator looking for a missing
// size-table entry. The refusal says what it actually is.
#[test]
fn an_unformatted_ps2_memory_card_says_why_it_is_refused() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_ps2","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"ps2@example.com"}}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-ps2","sha256":"sha-ps2","version":1}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    let card = root.join("saves/ps2/pcsx2/memcards/Mcd001.ps2");
    fs::create_dir_all(card.parent().unwrap()).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(&card, vec![0xFFu8; 8 * 1024 * 1024 + 256 * 1024]).unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    ps2_helper()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("ps2@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = ps2_helper()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(upload.calls(), 0, "an unformatted card was uploaded");
    assert!(
        stderr.contains("PS2 memory-card superblock"),
        "the refusal does not say the image is not a card:\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("skipped_by_policy=1"),
        "the skip is not counted:\n{stdout}"
    );
}

fn pce_helper() -> Command {
    Command::cargo_bin("sgm-steamdeck-helper").unwrap()
}

// A PC Engine save is classified as the MiSTer core's name, `tgfx16`, and the
// server knows the system as `pc-engine` and requires a runtime profile for it.
// No arm matched the local name, so the upload carried no profile and was
// refused with "runtimeProfile is required for projection-capable helper
// uploads" -- the last step between these saves and the store.
#[test]
fn a_pc_engine_upload_declares_its_runtime_profile() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_pce","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"pce@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"pce-rom-sha1","md5":"md5v","fileName":"bomberman.rom"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST)
            .path("/saves")
            .body_includes("pc-engine/retroarch-beetle-pce");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-pce","sha256":"sha-pce","version":1}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("saves/pcengine")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("saves/pcengine/Bomberman '93 (USA).srm"),
        vec![0xA5u8; 2048],
    )
    .unwrap();
    let config = tmp.path().join("config-pce.ini");
    fs::write(
        &config,
        format!(
            "URL=\"127.0.0.1\"\nPORT=\"{}\"\nROOT=\"{}\"\nSTATE_DIR=\"{}\"\nWATCH=\"false\"\nWATCH_INTERVAL=\"1\"\n\n[source.retrodeck]\nLABEL=\"RetroDeck\"\nKIND=\"retroarch\"\nPROFILE=\"retroarch\"\nSAVE_PATH=\"{}\"\nROM_PATH=\"{}\"\nRECURSIVE=\"true\"\nSYSTEMS=\"pc-engine\"\n",
            server.port(),
            root.display(),
            state_dir.display(),
            root.join("saves").display(),
            root.join("roms").display()
        ),
    )
    .unwrap();

    pce_helper()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("pce@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = pce_helper()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        upload.calls(),
        1,
        "a PC Engine upload did not declare pc-engine/retroarch-beetle-pce:\n{stdout}\n{stderr}"
    );
}

fn dryrun_helper() -> Command {
    Command::cargo_bin("sgm-steamdeck-helper").unwrap()
}

// A dry run looks without touching: it must not upload. The backend can force a
// dry run (covered elsewhere); this is the operator's own flag, on a save that
// would otherwise upload.
#[test]
fn a_cli_dry_run_uploads_nothing() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_clidry","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"clidry@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"clidry123","md5":"md5v","fileName":"madden.rom"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"success":true,"save":{"id":"save-clidry","sha256":"sha-clidry","version":1}}"#,
            );
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Sega/Genesis")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Sega/Genesis/Madden NFL 94.srm"),
        vec![0xC7u8; 2114],
    )
    .unwrap();
    let config = write_config(&tmp, &server, &root, &state_dir);

    dryrun_helper()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("clidry@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = dryrun_helper()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .arg("--dry-run")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(upload.calls(), 0, "a dry run uploaded:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("DRY RUN"),
        "the summary does not say it was a dry run:\n{stdout}\nSTDERR: {stderr}"
    );
}

fn override_helper() -> Command {
    Command::cargo_bin("sgm-steamdeck-helper").unwrap()
}

// The backend may force a dry run; it may not turn one the operator asked for
// into a live sync. The flag is the thing an operator uses to look at a store
// without changing it.
#[test]
fn a_backend_policy_does_not_cancel_a_requested_dry_run() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_override","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"override@example.com"}}"#);
    });
    let _config_sync = server.mock(|when, then| {
        when.method(POST).path("/helpers/config/sync");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"accepted":true,"global":{"dryRun":false}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"override123","md5":"md5v","fileName":"madden.rom"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"save":{"id":"save-override","sha256":"sha-override","version":1}}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("Sega/Genesis")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("Sega/Genesis/Madden NFL 94.srm"),
        vec![0xC7u8; 2114],
    )
    .unwrap();
    let config = tmp.path().join("config-override.ini");
    fs::write(
        &config,
        format!(
            "URL=\"127.0.0.1\"\nPORT=\"{}\"\nROOT=\"{}\"\nSTATE_DIR=\"{}\"\nWATCH=\"false\"\nWATCH_INTERVAL=\"1\"\n\n[source.genesis]\nLABEL=\"genesis\"\nKIND=\"retroarch\"\nPROFILE=\"retroarch\"\nSAVE_PATH=\"{}\"\nROM_PATH=\"{}\"\nRECURSIVE=\"true\"\nSYSTEMS=\"genesis\"\n",
            server.port(),
            root.display(),
            state_dir.display(),
            root.join("Sega").display(),
            root.join("roms").display()
        ),
    )
    .unwrap();

    override_helper()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("override@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = override_helper()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .arg("--dry-run")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        upload.calls(),
        0,
        "a backend policy turned a requested dry run into a live sync:\n{stdout}\n{stderr}"
    );
}

fn named_helper() -> Command {
    Command::cargo_bin("sgm-steamdeck-helper").unwrap()
}

// A refusal has to say which request produced it. Without that, a report of two
// uploads under a dry run cannot be matched to the branch that issued them.
#[test]
fn a_refusal_names_the_request_it_came_from() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_named","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"named@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"count":1,"rom":{"sha1":"named-sha1","md5":"md5v","fileName":"defenders.rom"}}"#);
    });
    let _save_latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false,"sha256":null,"version":null,"id":null}"#);
    });
    let _conflicts = server.mock(|when, then| {
        when.method(GET).path("/conflicts/check");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"exists":false}"#);
    });
    let _upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(400)
            .header("content-type", "application/json")
            .body(r#"{"error":"Bad Request","message":"runtimeProfile \"genesis/retroarch-genesis-plus-gx\" belongs to genesis, but this save is recorded as game-gear","statusCode":400}"#);
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("RetroArch/saves/genesis")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("RetroArch/saves/genesis/Defenders of Oasis (USA, Europe).srm"),
        vec![0xC7u8; 65536],
    )
    .unwrap();
    let config = tmp.path().join("config-named.ini");
    fs::write(
        &config,
        format!(
            "URL=\"127.0.0.1\"\nPORT=\"{}\"\nROOT=\"{}\"\nSTATE_DIR=\"{}\"\nWATCH=\"false\"\nWATCH_INTERVAL=\"1\"\n\n[source.retroarch]\nLABEL=\"RetroArch\"\nKIND=\"retroarch\"\nPROFILE=\"retroarch\"\nSAVE_PATH=\"{}\"\nROM_PATH=\"{}\"\nRECURSIVE=\"true\"\nSYSTEMS=\"genesis\"\n",
            server.port(),
            root.display(),
            state_dir.display(),
            root.join("RetroArch/saves").display(),
            root.join("roms").display()
        ),
    )
    .unwrap();

    named_helper()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("named@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = named_helper()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("Refused"),
        "the refusal was not reported:\n{stderr}"
    );
    assert!(
        stderr.contains("POST /saves (multipart upload)"),
        "the refusal does not name the request:\n{stderr}"
    );
}

fn lookup_helper() -> Command {
    Command::cargo_bin("sgm-steamdeck-helper").unwrap()
}

// A lookup that the server refuses is not a save the server refused. It used to
// be recorded as a permanent rejection of the save, which is why a mismatch on
// the lookup (a profile that belongs to another system) froze two saves for
// days and looked like an upload refusal in the log.
#[test]
fn a_refused_lookup_is_not_a_permanent_rejection_of_the_save() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path("/auth/token/app-password");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"token":"tok_lookup","expiresInDays":7}"#);
    });
    let _me = server.mock(|when, then| {
        when.method(GET).path("/auth/me");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"success":true,"user":{"email":"lookup@example.com"}}"#);
    });
    let _rom_lookup = server.mock(|when, then| {
        when.method(GET).path("/rom/lookup");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"count":1,"rom":{"fileName":"Unknown.srm","game":{"id":878081,"name":"Unknown","system":null},"sha1":"42e3a0c0ad9ad9df53284b030b7fdf00f658d413","md5":"139d88db2fec53ba778c7d5d999c51a5"},"success":true}"#);
    });
    let _latest = server.mock(|when, then| {
        when.method(GET).path("/save/latest");
        then.status(400)
            .header("content-type", "application/json")
            .body(r#"{"error":"Bad Request","message":"runtimeProfile \"genesis/retroarch-genesis-plus-gx\" belongs to genesis, but this save is recorded as game-gear","statusCode":400}"#);
    });
    let upload = server.mock(|when, then| {
        when.method(POST).path("/saves");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"success":true,"save":{"id":"save-lookup","sha256":"sha-lookup","version":1}}"#,
            );
    });

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(root.join("RetroArch/saves/genesis")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        root.join("RetroArch/saves/genesis/Defenders of Oasis (USA, Europe).srm"),
        vec![0xC7u8; 65536],
    )
    .unwrap();
    let config = tmp.path().join("config-lookup.ini");
    fs::write(
        &config,
        format!(
            "URL=\"127.0.0.1\"\nPORT=\"{}\"\nROOT=\"{}\"\nSTATE_DIR=\"{}\"\nWATCH=\"false\"\nWATCH_INTERVAL=\"1\"\n\n[source.retroarch]\nLABEL=\"RetroArch\"\nKIND=\"retroarch\"\nPROFILE=\"retroarch\"\nSAVE_PATH=\"{}\"\nROM_PATH=\"{}\"\nRECURSIVE=\"true\"\nSYSTEMS=\"genesis\"\n",
            server.port(),
            root.display(),
            state_dir.display(),
            root.join("RetroArch/saves").display(),
            root.join("roms").display()
        ),
    )
    .unwrap();

    lookup_helper()
        .arg("--config")
        .arg(&config)
        .arg("login")
        .arg("--email")
        .arg("lookup@example.com")
        .arg("--app-password")
        .arg("pw")
        .assert()
        .success();
    let output = lookup_helper()
        .arg("--config")
        .arg(&config)
        .arg("sync")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        upload.calls(),
        0,
        "an upload was attempted:\n{stdout}\n{stderr}"
    );
    assert!(
        stderr.contains("GET /save/latest"),
        "the failure does not name the request that failed:\n{stderr}"
    );
    let state = fs::read_to_string(state_dir.join("sync_state.json")).unwrap_or_default();
    assert!(
        !state.contains("terminal_rejections") || state.contains("\"terminal_rejections\": {}"),
        "a refused lookup was stored as a permanent rejection of the save:\n{state}"
    );
}
