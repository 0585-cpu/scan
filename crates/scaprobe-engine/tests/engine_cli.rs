use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

fn engine_path() -> &'static str {
    env!("CARGO_BIN_EXE_scaprobe-engine")
}

#[test]
fn version_flag_prints_engine_version() {
    let output = Command::new(engine_path())
        .arg("--version")
        .output()
        .expect("run scaprobe-engine --version");

    assert!(
        output.status.success(),
        "engine --version failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    assert!(stdout.trim().starts_with("scaprobe-engine "));
}

#[test]
fn scan_open_banner_service_emits_expected_ndjson_schema() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let port = listener.local_addr().expect("listener addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept scanner connection");
        stream
            .write_all(b"SSH-2.0-ScaprobeIntegrationTest\r\n")
            .expect("write banner");
        thread::sleep(Duration::from_millis(100));
    });
    let port_arg = port.to_string();

    let events = run_engine_scan(&[
        "--scan-id",
        "integration-open",
        "--targets",
        "127.0.0.1",
        "--ports",
        &port_arg,
        "--timeout-ms",
        "1000",
        "--concurrency",
        "4",
        "--rate-limit-per-sec",
        "1000",
        "--service-probe",
    ]);

    server.join().expect("server thread join");
    assert_eq!(
        events.len(),
        2,
        "expected one port event and one summary event: {events:?}"
    );

    let port_event = events
        .iter()
        .find(|event| event["event"] == "port")
        .expect("port event");
    assert_port_event_schema(port_event);
    assert_eq!(port_event["scan_id"], "integration-open");
    assert_eq!(port_event["host"], "127.0.0.1");
    assert_eq!(port_event["port"].as_u64(), Some(u64::from(port)));
    assert_eq!(port_event["protocol"], "tcp");
    assert_eq!(port_event["state"], "open");
    assert_eq!(port_event["service_name"], "ssh");
    assert!(port_event["service_confidence"].as_f64().unwrap() >= 0.98);
    assert_eq!(
        port_event["banner"].as_str(),
        Some("SSH protocol=2.0; product=ScaprobeIntegrationTest")
    );
    assert!(port_event["error"].is_null());

    let summary = events
        .iter()
        .find(|event| event["event"] == "summary")
        .expect("summary event");
    assert_summary_event_schema(summary);
    assert_eq!(summary["scan_id"], "integration-open");
    assert_eq!(summary["total"].as_u64(), Some(1));
    assert_eq!(summary["open"].as_u64(), Some(1));
    assert_eq!(summary["closed"].as_u64(), Some(0));
    assert_eq!(summary["open_filtered"].as_u64(), Some(0));
    assert_eq!(summary["filtered"].as_u64(), Some(0));
    assert_eq!(summary["error"].as_u64(), Some(0));
    assert_eq!(summary["engine"], "rust");
}

#[test]
fn scan_accepts_targets_and_ports_from_files() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind file-input listener");
    let port = listener.local_addr().expect("listener addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept file-input scanner");
        stream
            .write_all(b"SSH-2.0-ScaprobeFileInputTest\r\n")
            .expect("write file-input banner");
    });
    let targets_file = write_temp_input("targets", "127.0.0.1\n");
    let ports_file = write_temp_input("ports", &format!("{port}\n"));
    let targets_arg = targets_file.to_string_lossy().into_owned();
    let ports_arg = ports_file.to_string_lossy().into_owned();

    let events = run_engine_scan(&[
        "--scan-id",
        "integration-file-input",
        "--targets-file",
        &targets_arg,
        "--ports-file",
        &ports_arg,
        "--timeout-ms",
        "1000",
        "--concurrency",
        "4",
        "--rate-limit-per-sec",
        "1000",
        "--service-probe",
    ]);

    let _ = fs::remove_file(&targets_file);
    let _ = fs::remove_file(&ports_file);
    server.join().expect("file-input server thread join");
    let port_event = events
        .iter()
        .find(|event| event["event"] == "port")
        .expect("file-input port event");
    assert_eq!(port_event["state"], "open");
    assert_eq!(port_event["service_name"], "ssh");
}

#[test]
fn scan_udp_open_response_emits_udp_event() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp listener");
    let port = socket.local_addr().expect("udp listener addr").port();
    let server = thread::spawn(move || {
        let mut buf = [0_u8; 512];
        let (size, peer) = socket.recv_from(&mut buf).expect("receive udp probe");
        assert!(size > 0);
        socket
            .send_to(b"scaprobe-udp-test", peer)
            .expect("send udp response");
    });
    let port_arg = port.to_string();

    let events = run_engine_scan(&[
        "--scan-id",
        "integration-udp",
        "--targets",
        "127.0.0.1",
        "--ports",
        &port_arg,
        "--protocol",
        "udp",
        "--timeout-ms",
        "1000",
        "--concurrency",
        "4",
        "--rate-limit-per-sec",
        "1000",
        "--service-probe",
    ]);

    server.join().expect("udp server thread join");
    let port_event = events
        .iter()
        .find(|event| event["event"] == "port")
        .expect("port event");
    assert_port_event_schema(port_event);
    assert_eq!(port_event["scan_id"], "integration-udp");
    assert_eq!(port_event["protocol"], "udp");
    assert_eq!(port_event["state"], "open");
    assert_eq!(port_event["service_name"], "unknown");
    assert!(port_event["evidence"]
        .as_str()
        .expect("evidence string")
        .contains("udp response received"));

    let summary = events
        .iter()
        .find(|event| event["event"] == "summary")
        .expect("summary event");
    assert_eq!(summary["total"].as_u64(), Some(1));
    assert_eq!(summary["open"].as_u64(), Some(1));
}

#[test]
fn scan_identifies_http_on_nonstandard_port() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind http listener");
    let port = listener.local_addr().expect("listener addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept http scanner connection");
        let mut buf = [0_u8; 256];
        let _ = stream.read(&mut buf);
        stream
            .write_all(
                b"HTTP/1.0 200 OK\r\nServer: ScaprobeTest\r\nContent-Type: text/html\r\n\r\n<html><title>Scaprobe &amp; Lab</title></html>",
            )
            .expect("write http response");
    });
    let port_arg = port.to_string();

    let events = run_engine_scan(&[
        "--scan-id",
        "integration-http",
        "--targets",
        "127.0.0.1",
        "--ports",
        &port_arg,
        "--timeout-ms",
        "300",
        "--concurrency",
        "4",
        "--rate-limit-per-sec",
        "1000",
        "--service-probe",
    ]);

    server.join().expect("http server thread join");
    let port_event = events
        .iter()
        .find(|event| event["event"] == "port")
        .expect("port event");
    assert_eq!(port_event["state"], "open");
    assert_eq!(port_event["service_name"], "http");
    assert!(port_event["service_confidence"].as_f64().unwrap() >= 0.98);
    assert!(port_event["banner"]
        .as_str()
        .expect("banner string")
        .starts_with("HTTP/1.0 200 OK"));
    assert!(port_event["banner"]
        .as_str()
        .expect("banner string")
        .contains("title=Scaprobe & Lab"));
}

#[test]
fn scan_identifies_tls_record_on_nonstandard_port() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls listener");
    let port = listener.local_addr().expect("listener addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept tls scanner connection");
        let mut buf = [0_u8; 256];
        let _ = stream.read(&mut buf);
        stream
            .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])
            .expect("write tls alert");
    });
    let port_arg = port.to_string();

    let events = run_engine_scan(&[
        "--scan-id",
        "integration-tls",
        "--targets",
        "127.0.0.1",
        "--ports",
        &port_arg,
        "--timeout-ms",
        "300",
        "--concurrency",
        "4",
        "--rate-limit-per-sec",
        "1000",
        "--service-probe",
    ]);

    server.join().expect("tls server thread join");
    let port_event = events
        .iter()
        .find(|event| event["event"] == "port")
        .expect("port event");
    assert_eq!(port_event["state"], "open");
    assert_eq!(port_event["service_name"], "tls");
    assert!(port_event["service_confidence"].as_f64().unwrap() >= 0.82);
    assert_eq!(
        port_event["banner"].as_str(),
        Some("TLS record type=alert version=3.3 length=2")
    );
}

#[test]
fn scan_respects_start_rate_limit_under_high_concurrency() {
    let mut ports = Vec::new();
    let mut servers = Vec::new();
    for _ in 0..4 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind rate-limit listener");
        ports.push(listener.local_addr().expect("listener addr").port());
        servers.push(thread::spawn(move || {
            let (mut stream, _) = listener
                .accept()
                .expect("accept rate-limit scanner connection");
            let _ = stream.write_all(b"SCAPROBE-RATE-TEST\r\n");
        }));
    }
    let ports_arg = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let start = Instant::now();
    let events = run_engine_scan(&[
        "--scan-id",
        "integration-rate",
        "--targets",
        "127.0.0.1",
        "--ports",
        &ports_arg,
        "--timeout-ms",
        "1000",
        "--concurrency",
        "16",
        "--rate-limit-per-sec",
        "2",
    ]);
    let elapsed = start.elapsed();
    for server in servers {
        server.join().expect("rate-limit server join");
    }

    let port_events = events
        .iter()
        .filter(|event| event["event"] == "port")
        .count();
    assert_eq!(
        port_events, 4,
        "expected one port event per scanned port: {events:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(1200),
        "scan finished too quickly for 4 starts at 2/sec: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "rate-limit integration test took unexpectedly long: {elapsed:?}"
    );
}

#[test]
fn scan_applies_runtime_tcp_banner_catalog() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind plugin listener");
    let port = listener.local_addr().expect("plugin listener addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept plugin scanner");
        stream
            .write_all(b"WELCOME X-PLUGIN-SERVICE\r\n")
            .expect("write plugin banner");
    });
    let catalog = write_temp_input(
        "plugin-catalog",
        &format!(
            r#"{{"schema_version":1,"tcp_services":{{"{port}":"mapped-service"}},"tcp_banner_rules":[{{"service":"catalog-service","confidence":0.97,"ports":[{port}],"contains":[88,45,80,76,85,71,73,78]}}]}}"#,
        ),
    );
    let port_arg = port.to_string();
    let catalog_arg = catalog.to_string_lossy().into_owned();

    let events = run_engine_scan(&[
        "--scan-id",
        "integration-plugin-tcp",
        "--targets",
        "127.0.0.1",
        "--ports",
        &port_arg,
        "--timeout-ms",
        "1000",
        "--service-probe",
        "--plugin-catalog-file",
        &catalog_arg,
    ]);

    let _ = fs::remove_file(&catalog);
    server.join().expect("plugin server join");
    let event = events
        .iter()
        .find(|event| event["event"] == "port")
        .expect("plugin port event");
    assert_eq!(event["service_name"], "catalog-service");
    assert_eq!(event["service_confidence"].as_f64(), Some(0.97));
}

#[test]
fn scan_applies_runtime_udp_hex_catalog() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind plugin udp listener");
    let port = socket
        .local_addr()
        .expect("plugin udp listener addr")
        .port();
    let server = thread::spawn(move || {
        let mut buf = [0_u8; 512];
        let (_, peer) = socket
            .recv_from(&mut buf)
            .expect("receive plugin udp probe");
        socket
            .send_to(&[0x02, 0xff, 0x10], peer)
            .expect("send plugin udp response");
    });
    let catalog = write_temp_input(
        "plugin-catalog-udp",
        &format!(
            r#"{{"schema_version":1,"udp_response_rules":[{{"service":"catalog-udp","confidence":0.94,"ports":[{port}],"starts_with_hex":[2,255]}}]}}"#,
        ),
    );
    let port_arg = port.to_string();
    let catalog_arg = catalog.to_string_lossy().into_owned();

    let events = run_engine_scan(&[
        "--scan-id",
        "integration-plugin-udp",
        "--targets",
        "127.0.0.1",
        "--ports",
        &port_arg,
        "--protocol",
        "udp",
        "--timeout-ms",
        "1000",
        "--service-probe",
        "--plugin-catalog-file",
        &catalog_arg,
    ]);

    let _ = fs::remove_file(&catalog);
    server.join().expect("plugin udp server join");
    let event = events
        .iter()
        .find(|event| event["event"] == "port")
        .expect("plugin udp port event");
    assert_eq!(event["service_name"], "catalog-udp");
    assert_eq!(event["service_confidence"].as_f64(), Some(0.94));
}

#[test]
fn scan_rejects_invalid_runtime_catalog() {
    let catalog = write_temp_input("invalid-plugin-catalog", r#"{"schema_version":2}"#);
    let catalog_arg = catalog.to_string_lossy().into_owned();

    let output = Command::new(engine_path())
        .arg("scan")
        .args([
            "--scan-id",
            "integration-invalid-plugin",
            "--targets",
            "127.0.0.1",
            "--ports",
            "9",
            "--plugin-catalog-file",
            &catalog_arg,
        ])
        .output()
        .expect("run engine with invalid catalog");

    let _ = fs::remove_file(&catalog);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("unsupported plugin catalog schema version"));
}

fn run_engine_scan(args: &[&str]) -> Vec<Value> {
    let output = Command::new(engine_path())
        .arg("scan")
        .args(args)
        .output()
        .expect("run scaprobe-engine");
    assert!(
        output.status.success(),
        "engine failed\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|err| panic!("invalid NDJSON line {line:?}: {err}"))
        })
        .collect()
}

fn write_temp_input(label: &str, contents: &str) -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "scaprobe-engine-{label}-{}-{id}.txt",
        std::process::id()
    ));
    fs::write(&path, contents).expect("write temporary engine input");
    path
}

fn assert_port_event_schema(event: &Value) {
    assert_eq!(event["event"], "port");
    assert!(event["scan_id"].is_string());
    assert!(event["host"].is_string());
    assert!(event["port"].is_u64());
    assert!(event["protocol"].is_string());
    assert!(matches!(
        event["state"].as_str(),
        Some("open" | "closed" | "open|filtered" | "filtered" | "error")
    ));
    assert!(event["latency_ms"].is_null() || event["latency_ms"].is_number());
    assert!(event["service_name"].is_null() || event["service_name"].is_string());
    assert!(event["service_confidence"].is_null() || event["service_confidence"].is_number());
    assert!(event["banner"].is_null() || event["banner"].is_string());
    assert!(event["evidence"].is_null() || event["evidence"].is_string());
    assert!(event["error"].is_null() || event["error"].is_string());
}

fn assert_summary_event_schema(event: &Value) {
    assert_eq!(event["event"], "summary");
    assert!(event["scan_id"].is_string());
    assert!(event["total"].is_u64());
    assert!(event["open"].is_u64());
    assert!(event["closed"].is_u64());
    assert!(event["open_filtered"].is_u64());
    assert!(event["filtered"].is_u64());
    assert!(event["error"].is_u64());
    assert!(event["engine"].is_string());
}
