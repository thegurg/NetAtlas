//! CLI integration tests. These use a temporary data directory and never touch
//! the user's real database or network.

use std::path::PathBuf;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

fn command_in(dir: &TempDir) -> (Command, PathBuf) {
    let db = dir.path().join("netatlas.db");
    let mut command = Command::cargo_bin("netatlas").unwrap();
    command
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .arg("--db")
        .arg(&db);
    (command, db)
}

fn command() -> (TempDir, Command, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let (command, db) = command_in(&dir);
    (dir, command, db)
}

#[test]
fn help_lists_phase_one_commands() {
    let (_dir, mut command, _db) = command();
    let output = command.arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in ["interfaces", "discover", "devices", "device", "oui"] {
        assert!(stdout.contains(expected), "help did not mention {expected}");
    }
}

#[test]
fn empty_database_lists_no_devices_as_json() {
    let (_dir, mut command, _db) = command();
    let output = command.args(["devices", "--json"]).output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["devices"], Value::Array(Vec::new()));
}

#[test]
fn missing_device_returns_not_found_exit_code() {
    let (_dir, mut command, _db) = command();
    let output = command
        .args(["device", "00000000-0000-0000-0000-000000000001", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&output.stderr).contains("was not found"));
}

#[test]
fn invalid_mac_is_a_usage_error() {
    let (_dir, mut command, _db) = command();
    let output = command
        .args(["oui", "lookup", "not-a-mac"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a valid MAC"));
}

#[test]
fn oui_status_reports_the_embedded_source() {
    let (_dir, mut command, _db) = command();
    let output = command.args(["oui", "status", "--json"]).output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    let source = &value["source"];
    assert_eq!(source["version"], "2026-11-11");
    assert!(source["record_count"].as_i64().unwrap() > 10_000);
    assert!(source["content_sha256"].as_str().unwrap().len() == 64);
}

#[test]
fn oui_import_and_lookup_round_trip() {
    let (dir, mut command, _db) = command();
    let fixture = dir.path().join("fixture.csv");
    std::fs::write(
        &fixture,
        "Registry,Assignment,Organization Name\nMA-L,001122,Example Networks\n",
    )
    .unwrap();

    let output = command
        .args([
            "oui",
            "import",
            fixture.to_str().unwrap(),
            "--version",
            "fixture-1",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["import"]["record_count"], 1);
    assert_eq!(value["import"]["version"], "fixture-1");

    let (mut command, _db) = command_in(&dir);
    let output = command
        .args(["oui", "lookup", "00:11:22:33:44:55", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["match"]["organization"], "Example Networks");
}
