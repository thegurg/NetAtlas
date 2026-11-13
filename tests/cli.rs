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
fn help_lists_available_commands() {
    let (_dir, mut command, _db) = command();
    let output = command.arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "interfaces",
        "discover",
        "devices",
        "device",
        "map",
        "changes",
        "history",
        "oui",
        "dns",
    ] {
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

#[test]
fn invalid_segment_filter_is_a_usage_error() {
    let (_dir, mut command, _db) = command();
    let output = command
        .args(["devices", "--segment", "not-a-prefix", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a valid CIDR"));
}

#[test]
fn empty_map_returns_empty_groups_as_json() {
    let (_dir, mut command, _db) = command();
    let output = command.args(["map", "--json"]).output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["map"]["segments"], Value::Array(Vec::new()));
    assert_eq!(value["map"]["unassigned"], Value::Array(Vec::new()));
    assert!(value["map"]["note"].as_str().unwrap().contains("logical"));
}

#[test]
fn changes_without_sessions_is_not_an_error() {
    let (_dir, mut command, _db) = command();
    let output = command.args(["changes", "--json"]).output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["changes"], Value::Null);
    assert!(value["note"].as_str().unwrap().contains("No scan sessions"));
}

#[test]
fn missing_history_device_returns_not_found_exit_code() {
    let (_dir, mut command, _db) = command();
    let output = command
        .args(["history", "00000000-0000-0000-0000-000000000001", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&output.stderr).contains("was not found"));
}

fn spawn_dns_server(answer: &'static str) -> (u16, std::thread::JoinHandle<()>) {
    use hickory_resolver::proto::op::{Message, OpCode};
    use hickory_resolver::proto::rr::rdata::A;
    use hickory_resolver::proto::rr::{RData, Record};

    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let mut buffer = [0_u8; 4_096];
        let (length, peer) = socket.recv_from(&mut buffer).unwrap();
        let request = Message::from_vec(&buffer[..length]).unwrap();
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.metadata.recursion_available = true;
        for query in &request.queries {
            response.add_query(query.clone());
        }
        if let Some(query) = request.queries.first() {
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                300,
                RData::A(A(answer.parse().unwrap())),
            ));
        }
        let bytes = response.to_vec().unwrap();
        socket.send_to(&bytes, peer).unwrap();
    });
    (port, handle)
}

#[test]
fn dns_query_records_a_response_and_history() {
    let (port, server) = spawn_dns_server("192.0.2.1");
    let (dir, mut command, _db) = command();
    let resolver = format!("127.0.0.1:{port}");
    let output = command
        .args([
            "dns",
            "query",
            "example.test",
            "--type",
            "A",
            "--resolver",
            &resolver,
            "--timeout-ms",
            "1000",
            "--json",
        ])
        .output()
        .unwrap();
    server.join().unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["saved"], true);
    let measurement = &value["measurements"][0];
    assert_eq!(measurement["query"]["name"], "example.test.");
    assert_eq!(measurement["query"]["record_type"], "A");
    assert_eq!(measurement["outcome"], "response");
    assert_eq!(measurement["response"]["rcode"], "no_error");
    assert_eq!(
        measurement["response"]["answers"][0]["value"]["address"],
        "192.0.2.1"
    );
    assert_eq!(measurement["response"]["answers"][0]["ttl"], 300);
    assert_eq!(measurement["dnssec"]["validation"], "not_performed");

    let (mut command, _db) = command_in(&dir);
    let output = command.args(["dns", "history", "--json"]).output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["history"].as_array().unwrap().len(), 1);
    assert_eq!(value["history"][0]["query"]["name"], "example.test.");
}

#[test]
fn dns_transport_failure_returns_operational_exit_code() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let (_dir, mut command, _db) = command();
    let resolver = format!("127.0.0.1:{port}");
    let output = command
        .args([
            "dns",
            "query",
            "example.test",
            "--type",
            "A",
            "--resolver",
            &resolver,
            "--timeout-ms",
            "100",
            "--no-save",
            "--json",
        ])
        .output()
        .unwrap();
    drop(socket);

    assert_eq!(output.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["saved"], false);
    assert_eq!(value["measurements"][0]["outcome"], "timeout");
    assert_eq!(
        value["measurements"][0]["dnssec"]["validation"],
        "not_performed"
    );
    assert!(value["measurements"][0]["response"].is_null());
}

#[test]
fn dns_compare_detects_differing_answers() {
    let (first_port, first) = spawn_dns_server("192.0.2.1");
    let (second_port, second) = spawn_dns_server("192.0.2.2");
    let (_dir, mut command, _db) = command();
    let first_resolver = format!("127.0.0.1:{first_port}");
    let second_resolver = format!("127.0.0.1:{second_port}");
    let output = command
        .args([
            "dns",
            "compare",
            "example.test",
            "--type",
            "A",
            "--resolver",
            &first_resolver,
            "--resolver",
            &second_resolver,
            "--no-save",
            "--json",
        ])
        .output()
        .unwrap();
    first.join().unwrap();
    second.join().unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let comparison = &value["comparison"]["comparisons"][0];
    assert_eq!(comparison["responded"], 2);
    assert_eq!(comparison["comparable"], true);
    assert_eq!(comparison["answers_consistent"], false);
    assert_eq!(comparison["consistent"], false);
    assert_eq!(value["comparison"]["consistent"], false);
}

#[test]
fn dns_invalid_record_type_is_a_usage_error() {
    let (_dir, mut command, _db) = command();
    let output = command
        .args([
            "dns",
            "query",
            "example.test",
            "--type",
            "ANY",
            "--resolver",
            "127.0.0.1:9",
            "--no-save",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid DNS record type"));
}

#[test]
fn dns_compare_requires_two_resolvers() {
    let (_dir, mut command, _db) = command();
    let output = command
        .args([
            "dns",
            "compare",
            "example.test",
            "--type",
            "A",
            "--resolver",
            "127.0.0.1:9",
            "--no-save",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("at least two distinct resolvers"));
}

#[test]
fn dns_history_without_measurements_is_empty() {
    let (_dir, mut command, _db) = command();
    let output = command.args(["dns", "history", "--json"]).output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["history"], Value::Array(Vec::new()));
}
