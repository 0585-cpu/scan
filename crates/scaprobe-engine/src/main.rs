use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use futures::stream::{self, StreamExt};
use ipnet::IpNet;
use native_tls::TlsConnector;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{sleep_until, timeout, Duration, Instant};
use tokio_native_tls::TlsConnector as TokioTlsConnector;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::*;

#[derive(Parser)]
#[command(name = "scaprobe-engine")]
#[command(about = "High-throughput authorized scanner engine for Scaprobe")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Scan(ScanArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Protocol {
    Tcp,
    Udp,
}

#[derive(Parser)]
struct ScanArgs {
    #[arg(long)]
    scan_id: String,
    #[arg(
        long,
        conflicts_with = "targets_file",
        required_unless_present = "targets_file"
    )]
    targets: Option<String>,
    #[arg(long, conflicts_with = "targets", required_unless_present = "targets")]
    targets_file: Option<PathBuf>,
    #[arg(
        long,
        conflicts_with = "ports_file",
        required_unless_present = "ports_file"
    )]
    ports: Option<String>,
    #[arg(long, conflicts_with = "ports", required_unless_present = "ports")]
    ports_file: Option<PathBuf>,
    #[arg(long, default_value_t = 65536)]
    max_hosts: usize,
    #[arg(long, default_value_t = 800)]
    timeout_ms: u64,
    #[arg(long, default_value_t = 2000)]
    concurrency: usize,
    #[arg(long, default_value_t = 5000)]
    rate_limit_per_sec: u64,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(0..=3))]
    udp_retries: u8,
    #[arg(long, value_enum, default_value = "tcp")]
    protocol: Protocol,
    #[arg(long, default_value_t = false)]
    service_probe: bool,
    #[arg(long, hide = true)]
    plugin_catalog_file: Option<PathBuf>,
}

#[derive(Clone, Default, Deserialize)]
struct RuntimePluginCatalog {
    #[serde(default)]
    schema_version: u8,
    #[serde(default)]
    tcp_services: BTreeMap<u16, String>,
    #[serde(default)]
    udp_services: BTreeMap<u16, String>,
    #[serde(default)]
    tcp_banner_rules: Vec<RuntimeFingerprintRule>,
    #[serde(default)]
    udp_response_rules: Vec<RuntimeFingerprintRule>,
}

#[derive(Clone, Deserialize)]
struct RuntimeFingerprintRule {
    service: String,
    confidence: f64,
    #[serde(default)]
    ports: Vec<u16>,
    contains: Option<Vec<u8>>,
    starts_with: Option<Vec<u8>>,
    contains_hex: Option<Vec<u8>>,
    starts_with_hex: Option<Vec<u8>>,
}

impl RuntimeFingerprintRule {
    fn matches(&self, port: u16, data: &[u8]) -> bool {
        if !self.ports.is_empty() && !self.ports.contains(&port) {
            return false;
        }
        let lower = data.to_ascii_lowercase();
        self.contains
            .as_ref()
            .is_none_or(|value| contains_bytes(&lower, &value.to_ascii_lowercase()))
            && self
                .starts_with
                .as_ref()
                .is_none_or(|value| lower.starts_with(&value.to_ascii_lowercase()))
            && self
                .contains_hex
                .as_ref()
                .is_none_or(|value| contains_bytes(data, value))
            && self
                .starts_with_hex
                .as_ref()
                .is_none_or(|value| data.starts_with(value))
    }
}

impl RuntimePluginCatalog {
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(anyhow!("unsupported plugin catalog schema version"));
        }
        if self
            .tcp_services
            .values()
            .chain(self.udp_services.values())
            .any(|service| service.trim().is_empty())
        {
            return Err(anyhow!("plugin service map values must not be empty"));
        }
        for rule in self
            .tcp_banner_rules
            .iter()
            .chain(self.udp_response_rules.iter())
        {
            if rule.service.trim().is_empty() {
                return Err(anyhow!("plugin fingerprint service must not be empty"));
            }
            if !(0.0..=1.0).contains(&rule.confidence) {
                return Err(anyhow!(
                    "plugin fingerprint confidence must be between 0 and 1"
                ));
            }
            if rule.contains.is_none()
                && rule.starts_with.is_none()
                && rule.contains_hex.is_none()
                && rule.starts_with_hex.is_none()
            {
                return Err(anyhow!("plugin fingerprint requires a match field"));
            }
            if [
                rule.contains.as_deref(),
                rule.starts_with.as_deref(),
                rule.contains_hex.as_deref(),
                rule.starts_with_hex.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(<[u8]>::is_empty)
            {
                return Err(anyhow!("plugin fingerprint match fields must not be empty"));
            }
        }
        Ok(())
    }

    fn match_rule(
        &self,
        rules: &[RuntimeFingerprintRule],
        port: u16,
        data: &[u8],
    ) -> Option<ServiceFingerprint> {
        rules
            .iter()
            .find(|rule| rule.matches(port, data))
            .map(|rule| ServiceFingerprint {
                name: Some(rule.service.clone()),
                confidence: Some(rule.confidence),
                banner: Some(clean_banner(&String::from_utf8_lossy(data))),
            })
    }
}

#[derive(Serialize)]
struct PortEvent {
    event: &'static str,
    scan_id: String,
    host: String,
    port: u16,
    protocol: &'static str,
    state: String,
    latency_ms: Option<f64>,
    service_name: Option<String>,
    service_confidence: Option<f64>,
    banner: Option<String>,
    evidence: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct SummaryEvent {
    event: &'static str,
    scan_id: String,
    total: usize,
    open: usize,
    closed: usize,
    open_filtered: usize,
    filtered: usize,
    error: usize,
    engine: &'static str,
    elapsed_ms: f64,
    process_rss_bytes: Option<u64>,
    process_peak_rss_bytes: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => run_scan(args).await,
    }
}

fn load_runtime_plugin_catalog(path: Option<&Path>) -> Result<RuntimePluginCatalog> {
    let Some(path) = path else {
        return Ok(RuntimePluginCatalog::default());
    };
    let text = fs::read_to_string(path)
        .with_context(|| format!("could not read plugin catalog: {}", path.display()))?;
    let catalog: RuntimePluginCatalog = serde_json::from_str(&text)
        .with_context(|| format!("could not parse plugin catalog: {}", path.display()))?;
    catalog.validate()?;
    Ok(catalog)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

async fn run_scan(args: ScanArgs) -> Result<()> {
    let scan_started = Instant::now();
    if args.timeout_ms == 0 || args.timeout_ms > 60_000 {
        return Err(anyhow!("--timeout-ms must be between 1 and 60000"));
    }
    if args.concurrency == 0 || args.concurrency > 4_096 {
        return Err(anyhow!("--concurrency must be between 1 and 4096"));
    }
    if args.rate_limit_per_sec == 0 || args.rate_limit_per_sec > 100_000 {
        return Err(anyhow!("--rate-limit-per-sec must be between 1 and 100000"));
    }
    if args.max_hosts == 0 || args.max_hosts > 1_000_000 {
        return Err(anyhow!("--max-hosts must be between 1 and 1000000"));
    }
    let target_expr = load_scan_expression(
        args.targets.as_deref(),
        args.targets_file.as_deref(),
        "targets",
    )?;
    let port_expr =
        load_scan_expression(args.ports.as_deref(), args.ports_file.as_deref(), "ports")?;
    let targets = parse_targets(&target_expr, args.max_hosts)?;
    let ports = parse_ports(&port_expr)?;
    let plugin_catalog = Arc::new(load_runtime_plugin_catalog(
        args.plugin_catalog_file.as_deref(),
    )?);
    let planned_attempts = targets
        .len()
        .checked_mul(ports.len())
        .ok_or_else(|| anyhow!("planned scan attempts overflow"))?;
    if planned_attempts > 100_000_000 {
        return Err(anyhow!(
            "planned scan attempts exceed absolute safety limit (100000000)"
        ));
    }
    let timeout_duration = Duration::from_millis(args.timeout_ms.max(1));
    let rate_limiter = RateLimiter::new(args.rate_limit_per_sec);
    let scan_id: Arc<str> = Arc::from(args.scan_id);
    let protocol = args.protocol;
    let service_probe = args.service_probe;
    let concurrency = args.concurrency;
    let udp_retries = args.udp_retries;

    let mut summary = SummaryEvent {
        event: "summary",
        scan_id: scan_id.to_string(),
        engine: "rust",
        total: 0,
        open: 0,
        closed: 0,
        open_filtered: 0,
        filtered: 0,
        error: 0,
        elapsed_ms: 0.0,
        process_rss_bytes: None,
        process_peak_rss_bytes: None,
    };

    let scan_jobs = targets
        .into_iter()
        .flat_map(|target| ports.iter().copied().map(move |port| (target, port)));

    let mut stream = stream::iter(scan_jobs)
        .map(|(target, port)| {
            let scan_id = scan_id.clone();
            let rate_limiter = rate_limiter.clone();
            let plugin_catalog = plugin_catalog.clone();
            async move {
                rate_limiter.wait().await;
                scan_one(
                    target,
                    port,
                    &scan_id,
                    timeout_duration,
                    protocol,
                    service_probe,
                    udp_retries,
                    &plugin_catalog,
                )
                .await
            }
        })
        .buffer_unordered(concurrency);

    while let Some(event) = stream.next().await {
        observe(&mut summary, &event);
        emit(&event)?;
    }
    summary.elapsed_ms = round2(scan_started.elapsed().as_secs_f64() * 1000.0);
    (summary.process_rss_bytes, summary.process_peak_rss_bytes) = process_memory_bytes();
    emit(&summary)?;
    Ok(())
}

/// Sleeps shorter than this are not worth attempting: OS timers round up to a
/// tick (~1 ms at best, ~15 ms on stock Windows), so a 10 us sleep costs a full
/// tick and caps the real scan rate far below the configured one.
const MIN_RATE_LIMIT_SLEEP: Duration = Duration::from_millis(1);

/// How far the schedule may run behind the clock before it is pulled forward.
///
/// A sleep that overshoots by a timer tick leaves the schedule behind; keeping
/// that credit lets the attempts it owes start immediately instead of losing
/// the time for good. Bounded so a long stall cannot bank unlimited attempts:
/// the burst is at most this window times the configured rate.
const MAX_RATE_LIMIT_LAG: Duration = Duration::from_millis(20);

#[derive(Clone)]
struct RateLimiter {
    next_start: Arc<Mutex<Instant>>,
    spacing: Duration,
}

impl RateLimiter {
    fn new(rate_limit_per_sec: u64) -> Self {
        let nanos_per_start = (1_000_000_000_u64 / rate_limit_per_sec.max(1)).max(1);
        Self {
            next_start: Arc::new(Mutex::new(Instant::now())),
            spacing: Duration::from_nanos(nanos_per_start),
        }
    }

    /// Reserve this attempt's slot, then wait for it.
    ///
    /// Slots stay on one shared schedule that advances by exactly `spacing`
    /// per attempt, so the long-run rate is the configured one. Slots less
    /// than a timer tick away start immediately rather than oversleeping, and
    /// a slot already in the past starts immediately too - the schedule keeps
    /// its place instead of resetting, so the attempts an overshooting sleep
    /// owes are paid back as a bounded burst.
    async fn wait(&self) {
        let deadline = self.reserve_deadline();
        if deadline.saturating_duration_since(Instant::now()) >= MIN_RATE_LIMIT_SLEEP {
            sleep_until(deadline).await;
        }
    }

    fn reserve_deadline(&self) -> Instant {
        let mut next_start = self
            .next_start
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        let floor = now.checked_sub(MAX_RATE_LIMIT_LAG).unwrap_or(now);
        let deadline = if *next_start < floor {
            floor
        } else {
            *next_start
        };
        *next_start = deadline + self.spacing;
        deadline
    }
}

async fn scan_one(
    target: IpAddr,
    port: u16,
    scan_id: &str,
    timeout_duration: Duration,
    protocol: Protocol,
    service_probe: bool,
    udp_retries: u8,
    plugin_catalog: &RuntimePluginCatalog,
) -> PortEvent {
    match protocol {
        Protocol::Tcp => {
            scan_tcp_one(
                target,
                port,
                scan_id,
                timeout_duration,
                service_probe,
                plugin_catalog,
            )
            .await
        }
        Protocol::Udp => {
            scan_udp_one(
                target,
                port,
                scan_id,
                timeout_duration,
                service_probe,
                udp_retries,
                plugin_catalog,
            )
            .await
        }
    }
}

async fn scan_tcp_one(
    target: IpAddr,
    port: u16,
    scan_id: &str,
    timeout_duration: Duration,
    service_probe: bool,
    plugin_catalog: &RuntimePluginCatalog,
) -> PortEvent {
    let host = target.to_string();
    let start = Instant::now();
    let addr = SocketAddr::new(target, port);
    match timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            let fingerprint = if service_probe {
                identify_service(&mut stream, &host, port, timeout_duration, plugin_catalog).await
            } else {
                ServiceFingerprint::default()
            };
            PortEvent {
                event: "port",
                scan_id: scan_id.to_string(),
                host,
                port,
                protocol: "tcp",
                state: "open".to_string(),
                latency_ms: Some(round2(latency_ms)),
                service_name: fingerprint.name,
                service_confidence: fingerprint.confidence,
                banner: fingerprint.banner,
                evidence: None,
                error: None,
            }
        }
        Ok(Err(err)) => {
            let state = tcp_error_state(err.kind());
            PortEvent {
                event: "port",
                scan_id: scan_id.to_string(),
                host,
                port,
                protocol: "tcp",
                state: state.to_string(),
                latency_ms: Some(round2(start.elapsed().as_secs_f64() * 1000.0)),
                service_name: None,
                service_confidence: None,
                banner: None,
                evidence: None,
                // Keep the reason for filtered answers too: "host unreachable"
                // and "admin prohibited" are different findings for the analyst.
                error: if state == "closed" {
                    None
                } else {
                    Some(err.to_string())
                },
            }
        }
        Err(_) => PortEvent {
            event: "port",
            scan_id: scan_id.to_string(),
            host,
            port,
            protocol: "tcp",
            state: "filtered".to_string(),
            latency_ms: None,
            service_name: None,
            service_confidence: None,
            banner: None,
            evidence: None,
            error: Some("timeout".to_string()),
        },
    }
}

/// Map a failed TCP connect to a port state.
///
/// A refusal is a real RST from the host, so the port is closed. Unreachable
/// and administratively-prohibited answers come from a router or firewall on
/// the path, which is filtering rather than an engine failure - reporting them
/// as `error` hides real filtering inside the error bucket. Anything else
/// (out of file descriptors, ephemeral port exhaustion, ...) stays an error,
/// because it says nothing about the target.
fn tcp_error_state(kind: std::io::ErrorKind) -> &'static str {
    use std::io::ErrorKind;
    match kind {
        ErrorKind::ConnectionRefused => "closed",
        ErrorKind::HostUnreachable
        | ErrorKind::NetworkUnreachable
        | ErrorKind::PermissionDenied
        | ErrorKind::TimedOut => "filtered",
        _ => "error",
    }
}

async fn scan_udp_one(
    target: IpAddr,
    port: u16,
    scan_id: &str,
    timeout_duration: Duration,
    service_probe: bool,
    retries: u8,
    plugin_catalog: &RuntimePluginCatalog,
) -> PortEvent {
    let host = target.to_string();
    let start = Instant::now();
    let addr = SocketAddr::new(target, port);
    let bind_addr = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(err) => {
            return PortEvent {
                event: "port",
                scan_id: scan_id.to_string(),
                host,
                port,
                protocol: "udp",
                state: "error".to_string(),
                latency_ms: Some(round2(start.elapsed().as_secs_f64() * 1000.0)),
                service_name: None,
                service_confidence: None,
                banner: None,
                evidence: Some("socket bind error".to_string()),
                error: Some(err.to_string()),
            }
        }
    };
    if let Err(err) = socket.connect(addr).await {
        return udp_error_event(scan_id, host, port, start, err, "socket connect error");
    }
    let payload = udp_probe_payload(port);
    let mut buf = [0_u8; 2048];
    for attempt in 0..=retries {
        if let Err(err) = socket.send(&payload).await {
            return udp_error_or_closed_event(scan_id, host, port, start, err);
        }
        match timeout(timeout_duration, socket.recv(&mut buf)).await {
            Ok(Ok(size)) if udp_response_matches(port, &payload, &buf[..size]) => {
                let fingerprint = if service_probe {
                    classify_udp_response_with_catalog(port, &buf[..size], plugin_catalog)
                } else {
                    ServiceFingerprint::default()
                };
                return PortEvent {
                    event: "port",
                    scan_id: scan_id.to_string(),
                    host,
                    port,
                    protocol: "udp",
                    state: "open".to_string(),
                    latency_ms: Some(round2(start.elapsed().as_secs_f64() * 1000.0)),
                    service_name: fingerprint.name,
                    service_confidence: fingerprint.confidence,
                    banner: fingerprint.banner,
                    evidence: Some(format!(
                        "correlated udp response received ({size} bytes, attempt {})",
                        attempt + 1
                    )),
                    error: None,
                };
            }
            Ok(Ok(_)) | Err(_) if attempt < retries => {
                tokio::time::sleep(Duration::from_millis(50_u64 << attempt)).await;
            }
            Ok(Ok(_)) | Err(_) => break,
            Ok(Err(err)) => return udp_error_or_closed_event(scan_id, host, port, start, err),
        }
    }
    PortEvent {
        event: "port",
        scan_id: scan_id.to_string(),
        host,
        port,
        protocol: "udp",
        state: "open|filtered".to_string(),
        latency_ms: None,
        service_name: None,
        service_confidence: None,
        banner: None,
        evidence: Some(format!(
            "no UDP response after {} attempt(s) (open|filtered; correlated response required)",
            retries + 1
        )),
        error: None,
    }
}

fn udp_error_or_closed_event(
    scan_id: &str,
    host: String,
    port: u16,
    start: Instant,
    err: std::io::Error,
) -> PortEvent {
    if matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
    ) {
        PortEvent {
            event: "port",
            scan_id: scan_id.to_string(),
            host,
            port,
            protocol: "udp",
            state: "closed".to_string(),
            latency_ms: Some(round2(start.elapsed().as_secs_f64() * 1000.0)),
            service_name: None,
            service_confidence: None,
            banner: None,
            evidence: Some("icmp port unreachable reported by OS".to_string()),
            error: Some(err.to_string()),
        }
    } else {
        udp_error_event(scan_id, host, port, start, err, "socket error")
    }
}

fn udp_error_event(
    scan_id: &str,
    host: String,
    port: u16,
    start: Instant,
    err: std::io::Error,
    evidence: &str,
) -> PortEvent {
    PortEvent {
        event: "port",
        scan_id: scan_id.to_string(),
        host,
        port,
        protocol: "udp",
        state: "error".to_string(),
        latency_ms: Some(round2(start.elapsed().as_secs_f64() * 1000.0)),
        service_name: None,
        service_confidence: None,
        banner: None,
        evidence: Some(evidence.to_string()),
        error: Some(err.to_string()),
    }
}

#[derive(Default)]
struct ServiceFingerprint {
    name: Option<String>,
    confidence: Option<f64>,
    banner: Option<String>,
}

async fn identify_service(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    timeout_duration: Duration,
    plugin_catalog: &RuntimePluginCatalog,
) -> ServiceFingerprint {
    let known = effective_known_service(port, plugin_catalog);

    if is_tls_like_service(known) {
        let (record, plugin_matched) =
            probe_tls(stream, timeout_duration, known, port, plugin_catalog).await;
        if plugin_matched {
            return record.unwrap_or_default();
        }
        let endpoint = probe_tls_endpoint(host, port, timeout_duration, known).await;
        if let Some(mut fingerprint) = endpoint {
            if let Some(record_banner) = record.as_ref().and_then(|value| value.banner.as_ref()) {
                fingerprint.banner = Some(clean_banner(&format!(
                    "{record_banner}; {}",
                    fingerprint.banner.unwrap_or_default()
                )));
            }
            return fingerprint;
        }
        if let Some(fingerprint) = record {
            return fingerprint;
        }
        return fallback_known_service(known);
    }

    if matches!(known, Some("http" | "http-alt")) {
        if let Some(fingerprint) =
            probe_http(stream, host, port, timeout_duration, known, plugin_catalog).await
        {
            return fingerprint;
        }
        return fallback_known_service(known);
    }

    let passive = read_bytes(stream, timeout_duration).await;
    if let Some(fingerprint) =
        classify_passive_bytes_with_catalog(&passive, known, port, plugin_catalog)
    {
        return fingerprint;
    }

    if known.is_some() {
        return fallback_known_service(known);
    }

    if let Some(fingerprint) =
        probe_http(stream, host, port, timeout_duration, known, plugin_catalog).await
    {
        return fingerprint;
    }

    fallback_unknown_or_known(known)
}

async fn probe_http(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    timeout_duration: Duration,
    known: Option<&str>,
    plugin_catalog: &RuntimePluginCatalog,
) -> Option<ServiceFingerprint> {
    let request = http_request(host, port);
    if stream.write_all(request.as_bytes()).await.is_err() {
        return None;
    }
    let bytes = read_bounded(stream, timeout_duration, 16_384).await;
    if let Some(fingerprint) =
        plugin_catalog.match_rule(&plugin_catalog.tcp_banner_rules, port, &bytes)
    {
        return Some(fingerprint);
    }
    let text = String::from_utf8_lossy(&bytes).to_string();
    if text.starts_with("HTTP/") {
        return Some(ServiceFingerprint {
            name: Some(
                if known == Some("https") {
                    "https"
                } else {
                    "http"
                }
                .to_string(),
            ),
            confidence: Some(0.98),
            banner: Some(http_response_summary(&text)),
        });
    }
    if let Some(tls) = tls_record_summary(&bytes) {
        return Some(ServiceFingerprint {
            name: Some(tls_service_name_for(known).to_string()),
            confidence: Some(if is_tls_like_service(known) {
                0.92
            } else {
                0.82
            }),
            banner: Some(tls),
        });
    }
    None
}

async fn probe_tls_endpoint(
    host: &str,
    port: u16,
    timeout_duration: Duration,
    known: Option<&str>,
) -> Option<ServiceFingerprint> {
    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .ok()?;
    let stream = timeout(
        timeout_duration,
        TcpStream::connect(SocketAddr::new(host.parse().ok()?, port)),
    )
    .await
    .ok()?
    .ok()?;
    let mut tls = timeout(
        timeout_duration,
        TokioTlsConnector::from(connector).connect(host, stream),
    )
    .await
    .ok()?
    .ok()?;
    let certificate = tls
        .get_ref()
        .peer_certificate()
        .ok()
        .flatten()
        .and_then(|certificate| certificate.to_der().ok())
        .and_then(|der| x509_certificate_summary(&der));
    let mut parts = vec!["TLS".to_string()];
    if let Some(certificate) = certificate {
        parts.push(certificate);
    }
    if matches!(known, Some("https" | "winrm-https" | "docker-tls")) {
        let request = http_request(host, port);
        if tls.write_all(request.as_bytes()).await.is_ok() {
            let bytes = read_bounded(&mut tls, timeout_duration, 16_384).await;
            let text = String::from_utf8_lossy(&bytes);
            if text.starts_with("HTTP/") {
                parts.push(http_response_summary(&text));
            }
        }
    }
    Some(ServiceFingerprint {
        name: Some(tls_service_name_for(known).to_string()),
        confidence: Some(0.99),
        banner: Some(clean_banner(&parts.join("; "))),
    })
}

async fn probe_tls(
    stream: &mut TcpStream,
    timeout_duration: Duration,
    known: Option<&str>,
    port: u16,
    plugin_catalog: &RuntimePluginCatalog,
) -> (Option<ServiceFingerprint>, bool) {
    if stream.write_all(tls_client_hello()).await.is_err() {
        return (None, false);
    }
    let bytes = read_bytes(stream, timeout_duration).await;
    if let Some(fingerprint) =
        plugin_catalog.match_rule(&plugin_catalog.tcp_banner_rules, port, &bytes)
    {
        return (Some(fingerprint), true);
    }
    (
        tls_record_summary(&bytes).map(|summary| ServiceFingerprint {
            name: Some(tls_service_name_for(known).to_string()),
            confidence: Some(0.96),
            banner: Some(summary),
        }),
        false,
    )
}

fn classify_passive_bytes(bytes: &[u8], known: Option<&str>) -> Option<ServiceFingerprint> {
    if bytes.is_empty() {
        return None;
    }
    if let Some(tls) = tls_record_summary(bytes) {
        return Some(ServiceFingerprint {
            name: Some("tls".to_string()),
            confidence: Some(0.86),
            banner: Some(tls),
        });
    }
    let banner = String::from_utf8_lossy(bytes).to_string();
    let lower = banner.to_ascii_lowercase();
    if lower.starts_with("ssh-") {
        return Some(ServiceFingerprint {
            name: Some("ssh".to_string()),
            confidence: Some(0.98),
            banner: Some(normalize_service_banner("ssh", &banner)),
        });
    }
    if lower.starts_with("220") && lower.contains("ftp") {
        return Some(ServiceFingerprint {
            name: Some("ftp".to_string()),
            confidence: Some(0.92),
            banner: Some(normalize_service_banner("ftp", &banner)),
        });
    }
    if lower.contains("smtp")
        || (lower.starts_with("220 ") && matches!(known, Some("smtp" | "submission" | "smtps")))
    {
        return Some(ServiceFingerprint {
            name: Some("smtp".to_string()),
            confidence: Some(0.78),
            banner: Some(normalize_service_banner("smtp", &banner)),
        });
    }
    if lower.starts_with("rfb ") {
        return Some(ServiceFingerprint {
            name: Some("vnc".to_string()),
            confidence: Some(0.96),
            banner: Some(clean_banner(&banner)),
        });
    }
    if bytes.starts_with(&[0x03, 0x00]) && known == Some("rdp") {
        return Some(ServiceFingerprint {
            name: Some("rdp".to_string()),
            confidence: Some(0.88),
            banner: Some(format!("RDP TPKT response ({} bytes)", bytes.len())),
        });
    }
    if bytes.len() > 5 && bytes[3] == 0 && bytes[4] == 0x0a {
        let version_end = bytes[5..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|position| position + 5)
            .unwrap_or(bytes.len());
        let version = String::from_utf8_lossy(&bytes[5..version_end]);
        return Some(ServiceFingerprint {
            name: Some("mysql".to_string()),
            confidence: Some(0.96),
            banner: Some(format!(
                "MySQL handshake version={}",
                clean_banner(&version)
            )),
        });
    }
    if lower.starts_with("+ok") && matches!(known, Some("pop3" | "pop3s")) {
        return Some(ServiceFingerprint {
            name: Some("pop3".to_string()),
            confidence: Some(0.90),
            banner: Some(normalize_service_banner("pop3", &banner)),
        });
    }
    if lower.starts_with("* ok") && matches!(known, Some("imap" | "imaps")) {
        return Some(ServiceFingerprint {
            name: Some("imap".to_string()),
            confidence: Some(0.90),
            banner: Some(clean_banner(&banner)),
        });
    }
    if lower.starts_with("+pong") || lower.starts_with('$') || lower.starts_with("-noauth") {
        return Some(ServiceFingerprint {
            name: Some("redis".to_string()),
            confidence: Some(0.80),
            banner: Some(clean_banner(&banner)),
        });
    }
    if lower.starts_with("version ") && known == Some("memcached") {
        return Some(ServiceFingerprint {
            name: Some("memcached".to_string()),
            confidence: Some(0.85),
            banner: Some(clean_banner(&banner)),
        });
    }
    Some(ServiceFingerprint {
        name: Some(known.unwrap_or("unknown").to_string()),
        confidence: Some(if known.is_some() { 0.50 } else { 0.25 }),
        banner: Some(clean_banner(&banner)),
    })
}

fn classify_passive_bytes_with_catalog(
    bytes: &[u8],
    known: Option<&str>,
    port: u16,
    plugin_catalog: &RuntimePluginCatalog,
) -> Option<ServiceFingerprint> {
    if bytes.is_empty() {
        return None;
    }
    if let Some(fingerprint) =
        plugin_catalog.match_rule(&plugin_catalog.tcp_banner_rules, port, bytes)
    {
        return Some(fingerprint);
    }
    classify_passive_bytes(bytes, known)
}

async fn read_bytes(stream: &mut TcpStream, timeout_duration: Duration) -> Vec<u8> {
    let mut buf = [0_u8; 512];
    match timeout(
        timeout_duration.min(Duration::from_millis(1500)),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(size)) if size > 0 => buf[..size].to_vec(),
        _ => Vec::new(),
    }
}

async fn read_bounded<S>(stream: &mut S, timeout_duration: Duration, maximum: usize) -> Vec<u8>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let deadline = Instant::now() + timeout_duration;
    let mut output = Vec::with_capacity(maximum.min(4096));
    let mut buffer = [0_u8; 4096];
    while output.len() < maximum {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        let wanted = buffer.len().min(maximum - output.len());
        match timeout(remaining, stream.read(&mut buffer[..wanted])).await {
            Ok(Ok(size)) if size > 0 => output.extend_from_slice(&buffer[..size]),
            _ => break,
        }
    }
    output
}

fn fallback_known_service(known: Option<&str>) -> ServiceFingerprint {
    ServiceFingerprint {
        name: known.map(str::to_string),
        confidence: known.map(|name| match name {
            "https" | "dns" | "smtps" | "ldaps" | "dot" | "imaps" | "pop3s" | "ftps"
            | "docker-tls" | "winrm-https" => 0.70,
            _ => 0.55,
        }),
        banner: known.map(|_| "inferred from port mapping".to_string()),
    }
}

fn fallback_unknown_or_known(known: Option<&str>) -> ServiceFingerprint {
    fallback_known_service(known).or_unknown()
}

impl ServiceFingerprint {
    fn or_unknown(self) -> Self {
        if self.name.is_some() {
            self
        } else {
            ServiceFingerprint {
                name: Some("unknown".to_string()),
                confidence: Some(0.10),
                banner: None,
            }
        }
    }
}

fn tls_record_summary(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 5 || !matches!(bytes[0], 20..=23) || bytes[1] != 0x03 {
        return None;
    }
    let content_type = match bytes[0] {
        20 => "change_cipher_spec",
        21 => "alert",
        22 => "handshake",
        23 => "application_data",
        _ => "unknown",
    };
    let record_len = u16::from_be_bytes([bytes[3], bytes[4]]);
    if record_len > 18_432 {
        return None;
    }
    if bytes[0] == 22 && bytes.len() >= 11 && bytes[5] == 2 {
        if let Some(summary) = tls_server_hello_summary(bytes, record_len.into()) {
            return Some(summary);
        }
    }
    Some(format!(
        "TLS record type={content_type} version=3.{} length={record_len}",
        bytes[2]
    ))
}

fn tls_server_hello_summary(bytes: &[u8], record_len: usize) -> Option<String> {
    let end = bytes.len().min(5 + record_len);
    let mut position = 9_usize;
    if position + 35 > end {
        return None;
    }
    let mut negotiated = (bytes[position], bytes[position + 1]);
    position += 34;
    let session_id_len = bytes[position] as usize;
    position += 1 + session_id_len;
    if position + 3 > end {
        return None;
    }
    let cipher = u16::from_be_bytes([bytes[position], bytes[position + 1]]);
    position += 3;
    if position + 2 <= end {
        let extensions_len = u16::from_be_bytes([bytes[position], bytes[position + 1]]) as usize;
        position += 2;
        let extensions_end = end.min(position + extensions_len);
        while position + 4 <= extensions_end {
            let extension_type = u16::from_be_bytes([bytes[position], bytes[position + 1]]);
            let extension_len =
                u16::from_be_bytes([bytes[position + 2], bytes[position + 3]]) as usize;
            position += 4;
            if position + extension_len > extensions_end {
                break;
            }
            if extension_type == 43 && extension_len == 2 {
                negotiated = (bytes[position], bytes[position + 1]);
            }
            position += extension_len;
        }
    }
    let version = match negotiated {
        (3, 1) => "TLS1.0".to_string(),
        (3, 2) => "TLS1.1".to_string(),
        (3, 3) => "TLS1.2".to_string(),
        (3, 4) => "TLS1.3".to_string(),
        (_, minor) => format!("3.{minor}"),
    };
    Some(format!(
        "TLS ServerHello version={version} cipher=0x{cipher:04x} length={record_len}"
    ))
}

fn http_response_summary(value: &str) -> String {
    let normalized = value.replace("\r\n", "\n");
    let mut lines = normalized.lines();
    let status = lines.next().unwrap_or("HTTP response").trim().to_string();
    let mut details = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            break;
        }
        let Some((name, header_value)) = line.split_once(':') else {
            continue;
        };
        let lower = name.trim().to_ascii_lowercase();
        if matches!(lower.as_str(), "server" | "location" | "content-type")
            && !details
                .iter()
                .any(|item: &String| item.starts_with(&format!("{lower}=")))
        {
            let limit = match lower.as_str() {
                "server" => 128,
                "location" => 200,
                _ => 100,
            };
            let normalized = header_value
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(limit)
                .collect::<String>();
            details.push(format!("{lower}={normalized}"));
        }
    }
    if let Some(title) = html_title(value) {
        details.push(format!("title={title}"));
    }
    clean_banner(
        &std::iter::once(status)
            .chain(details)
            .collect::<Vec<_>>()
            .join("; "),
    )
}

fn html_title(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let content_start = lower[start..].find('>')? + start + 1;
    let content_end = lower[content_start..].find("</title")? + content_start;
    let raw = &value[content_start..content_end];
    let mut text = String::new();
    let mut inside_tag = false;
    for character in raw.chars() {
        match character {
            '<' => inside_tag = true,
            '>' => inside_tag = false,
            _ if !inside_tag => text.push(character),
            _ => {}
        }
    }
    let decoded = text
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");
    let normalized = decoded.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.chars().take(160).collect())
    }
}

fn http_request(host: &str, port: u16) -> String {
    let host_header = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    format!(
        "GET / HTTP/1.0\r\nHost: {host_header}:{port}\r\nUser-Agent: Scaprobe/0.1\r\nAccept: text/html,*/*;q=0.1\r\nConnection: close\r\n\r\n"
    )
}

fn normalize_service_banner(service: &str, value: &str) -> String {
    let first_line = value.lines().next().unwrap_or(value).trim();
    if service == "ssh" {
        if let Some(remainder) = first_line.strip_prefix("SSH-") {
            if let Some((protocol, software_and_platform)) = remainder.split_once('-') {
                let mut fields = software_and_platform.splitn(2, char::is_whitespace);
                let software = fields.next().unwrap_or("unknown");
                let mut parts = vec![format!("SSH protocol={protocol}")];
                if let Some((product, version)) = software.split_once('_') {
                    parts.push(format!("product={product}"));
                    parts.push(format!("version={version}"));
                } else {
                    parts.push(format!("product={software}"));
                }
                if let Some(platform) = fields.next() {
                    let normalized = platform.split_whitespace().collect::<Vec<_>>().join(" ");
                    if !normalized.is_empty() {
                        parts.push(format!("platform={normalized}"));
                    }
                }
                return clean_banner(&parts.join("; "));
            }
        }
    }
    let label = match service {
        "ftp" => Some("FTP greeting"),
        "smtp" => Some("SMTP greeting"),
        "pop3" => Some("POP3 greeting"),
        "imap" => Some("IMAP greeting"),
        _ => None,
    };
    match label {
        Some(label) => clean_banner(&format!(
            "{label}={}",
            first_line.split_whitespace().collect::<Vec<_>>().join(" ")
        )),
        None => clean_banner(value),
    }
}

fn x509_certificate_summary(der: &[u8]) -> Option<String> {
    let (_, certificate) = X509Certificate::from_der(der).ok()?;
    let mut parts = Vec::new();
    if let Some(common_name) = certificate
        .subject()
        .iter_common_name()
        .find_map(|attribute| attribute.as_str().ok())
    {
        parts.push(format!(
            "cert_cn={}",
            common_name.chars().take(160).collect::<String>()
        ));
    }
    if let Ok(Some(extension)) = certificate.subject_alternative_name() {
        let mut names = Vec::new();
        for name in &extension.value.general_names {
            let value = match name {
                GeneralName::DNSName(name) => Some((*name).to_string()),
                GeneralName::IPAddress(bytes) if bytes.len() == 4 => {
                    Some(IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string())
                }
                GeneralName::IPAddress(bytes) if bytes.len() == 16 => {
                    let octets: [u8; 16] = (*bytes).try_into().ok()?;
                    Some(IpAddr::from(octets).to_string())
                }
                _ => None,
            };
            if let Some(value) = value {
                names.push(value.chars().take(80).collect::<String>());
            }
        }
        if !names.is_empty() {
            let hidden = names.len().saturating_sub(5);
            names.truncate(5);
            let suffix = if hidden > 0 {
                format!(",+{hidden}")
            } else {
                String::new()
            };
            parts.push(format!("cert_san={}{}", names.join(","), suffix));
        }
    }
    let expiry = certificate.validity().not_after.to_datetime();
    parts.push(format!(
        "cert_expires={:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        expiry.year(),
        u8::from(expiry.month()),
        expiry.day(),
        expiry.hour(),
        expiry.minute(),
        expiry.second()
    ));
    if parts.is_empty() {
        None
    } else {
        Some(clean_banner(&parts.join("; ")))
    }
}

fn tls_client_hello() -> &'static [u8] {
    &[
        // TLS 1.2 ClientHello with broadly supported ECDHE-RSA suites and the
        // extensions modern servers require before returning a ServerHello.
        0x16, 0x03, 0x01, 0x00, 0x59, 0x01, 0x00, 0x00, 0x55, 0x03, 0x03, 0x53, 0x43, 0x41, 0x50,
        0x52, 0x4f, 0x42, 0x45, 0x54, 0x4c, 0x53, 0x50, 0x52, 0x4f, 0x42, 0x45, 0x43, 0x4c, 0x49,
        0x45, 0x4e, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x00, 0x00,
        0x08, 0xc0, 0x2f, 0xc0, 0x30, 0xcc, 0xa8, 0xcc, 0xa9, 0x01, 0x00, 0x00, 0x24, 0x00, 0x0a,
        0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x0b, 0x00, 0x02, 0x01,
        0x00, 0x00, 0x0d, 0x00, 0x0e, 0x00, 0x0c, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01,
        0x05, 0x01, 0x06, 0x01,
    ]
}

fn load_scan_expression(inline: Option<&str>, file: Option<&Path>, label: &str) -> Result<String> {
    match (inline, file) {
        (Some(value), None) => Ok(value.to_string()),
        (None, Some(path)) => fs::read_to_string(path)
            .with_context(|| format!("could not read {label} file: {}", path.display())),
        _ => Err(anyhow!(
            "provide exactly one of --{label} or --{label}-file"
        )),
    }
}

fn parse_targets(expr: &str, max_hosts: usize) -> Result<Vec<IpAddr>> {
    if max_hosts == 0 {
        return Err(anyhow!("max hosts must be at least 1"));
    }
    let mut result = BTreeSet::new();
    for part in scan_expression_tokens(expr) {
        if part.contains('/') {
            let net: IpNet = part
                .parse()
                .with_context(|| format!("invalid CIDR target: {part}"))?;
            match net {
                IpNet::V4(v4) => {
                    for addr in v4.hosts() {
                        insert_target(&mut result, IpAddr::V4(addr), max_hosts)?;
                    }
                }
                IpNet::V6(v6) => {
                    for addr in v6.hosts() {
                        insert_target(&mut result, IpAddr::V6(addr), max_hosts)?;
                    }
                }
            }
        } else {
            let address = part
                .parse()
                .with_context(|| format!("invalid IP target: {part}"))?;
            insert_target(&mut result, address, max_hosts)?;
        }
    }
    if result.is_empty() {
        return Err(anyhow!("no targets were provided"));
    }
    Ok(result.into_iter().collect())
}

fn insert_target(result: &mut BTreeSet<IpAddr>, address: IpAddr, max_hosts: usize) -> Result<()> {
    if result.insert(address) && result.len() > max_hosts {
        return Err(anyhow!("target expansion exceeds --max-hosts={max_hosts}"));
    }
    Ok(())
}

fn parse_ports(expr: &str) -> Result<Vec<u16>> {
    let mut result = BTreeSet::new();
    for part in scan_expression_tokens(expr) {
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start
                .parse()
                .with_context(|| format!("invalid port: {start}"))?;
            let end: u16 = end
                .parse()
                .with_context(|| format!("invalid port: {end}"))?;
            if start == 0 || end == 0 || start > end {
                return Err(anyhow!("invalid port range: {part}"));
            }
            for port in start..=end {
                result.insert(port);
            }
        } else {
            let port = part
                .parse()
                .with_context(|| format!("invalid port: {part}"))?;
            if port == 0 {
                return Err(anyhow!("port out of range: {part}"));
            }
            result.insert(port);
        }
    }
    if result.is_empty() {
        return Err(anyhow!("no ports were provided"));
    }
    Ok(result.into_iter().collect())
}

fn scan_expression_tokens(expr: &str) -> impl Iterator<Item = &str> {
    expr.lines()
        .flat_map(|line| line.split('#').next().unwrap_or("").split(','))
        .map(str::trim)
        .filter(|part| !part.is_empty())
}

fn observe(summary: &mut SummaryEvent, event: &PortEvent) {
    summary.total += 1;
    match event.state.as_str() {
        "open" => summary.open += 1,
        "closed" => summary.closed += 1,
        "open|filtered" => summary.open_filtered += 1,
        "filtered" => summary.filtered += 1,
        _ => summary.error += 1,
    }
}

fn emit<T: Serialize>(value: &T) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn known_service(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("ftp-data"),
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        80 => Some("http"),
        88 => Some("kerberos"),
        110 => Some("pop3"),
        135 => Some("msrpc"),
        139 => Some("netbios-ssn"),
        143 => Some("imap"),
        389 => Some("ldap"),
        443 => Some("https"),
        445 => Some("smb"),
        465 => Some("smtps"),
        554 => Some("rtsp"),
        587 => Some("smtp"),
        636 => Some("ldaps"),
        873 => Some("rsync"),
        990 => Some("ftps"),
        853 => Some("dot"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1433 => Some("mssql"),
        1521 => Some("oracle"),
        1883 => Some("mqtt"),
        2049 => Some("nfs"),
        2375 => Some("docker"),
        2376 => Some("docker-tls"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgresql"),
        5900 => Some("vnc"),
        5985 => Some("winrm"),
        5986 => Some("winrm-https"),
        6379 => Some("redis"),
        8080 => Some("http-alt"),
        8443 => Some("https"),
        9200 | 9300 => Some("elasticsearch"),
        11211 => Some("memcached"),
        27017 => Some("mongodb"),
        _ => None,
    }
}

fn effective_known_service<'a>(
    port: u16,
    plugin_catalog: &'a RuntimePluginCatalog,
) -> Option<&'a str> {
    plugin_catalog
        .tcp_services
        .get(&port)
        .map(String::as_str)
        .or_else(|| known_service(port))
}

fn known_udp_service(port: u16) -> Option<&'static str> {
    match port {
        53 => Some("dns"),
        67 | 68 => Some("dhcp"),
        69 => Some("tftp"),
        88 => Some("kerberos"),
        123 => Some("ntp"),
        137 => Some("netbios-ns"),
        138 => Some("netbios-dgm"),
        161 => Some("snmp"),
        162 => Some("snmptrap"),
        500 => Some("isakmp"),
        514 => Some("syslog"),
        520 => Some("rip"),
        1434 => Some("mssql-browser"),
        1900 => Some("ssdp"),
        3702 => Some("ws-discovery"),
        5060 => Some("sip"),
        5353 => Some("mdns"),
        5683 => Some("coap"),
        11211 => Some("memcached"),
        _ => None,
    }
}

fn effective_known_udp_service<'a>(
    port: u16,
    plugin_catalog: &'a RuntimePluginCatalog,
) -> Option<&'a str> {
    plugin_catalog
        .udp_services
        .get(&port)
        .map(String::as_str)
        .or_else(|| known_udp_service(port))
}

fn udp_probe_payload(port: u16) -> Vec<u8> {
    match port {
        53 => dns_query_payload("scaprobe.invalid"),
        69 => b"\x00\x01scaprobe-test\x00octet\x00".to_vec(),
        123 => {
            let mut payload = vec![0x1b];
            payload.resize(48, 0);
            if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                let seconds = now.as_secs().saturating_add(2_208_988_800) as u32;
                let fraction = ((u64::from(now.subsec_nanos()) << 32) / 1_000_000_000) as u32;
                payload[40..44].copy_from_slice(&seconds.to_be_bytes());
                payload[44..48].copy_from_slice(&fraction.to_be_bytes());
            }
            payload
        }
        137 => netbios_status_query_payload(),
        161 => vec![
            0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c',
            0xa0, 0x1c, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02,
            0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02,
            0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
        ],
        500 => isakmp_probe_payload(),
        520 => rip_request_payload(),
        1434 => b"\x02".to_vec(),
        1900 => b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
            .to_vec(),
        3702 => ws_discovery_probe_payload(),
        5060 => sip_options_payload(),
        5353 => dns_query_payload("_services._dns-sd._udp.local"),
        5683 => coap_core_query_payload(),
        11211 => b"version\r\n".to_vec(),
        _ => vec![0],
    }
}

fn udp_response_matches(port: u16, request: &[u8], response: &[u8]) -> bool {
    if response.is_empty() {
        return false;
    }
    match port {
        53 | 137 | 5353 => {
            request.len() >= 2 && response.len() >= 2 && response[..2] == request[..2]
        }
        123 => request.len() >= 48 && response.len() >= 48 && response[24..32] == request[40..48],
        161 | 162 => snmp_request_id(request)
            .zip(snmp_request_id(response))
            .is_some_and(|(request_id, response_id)| request_id == response_id),
        500 => request.len() >= 8 && response.len() >= 8 && response[..8] == request[..8],
        5683 => request.len() >= 4 && response.len() >= 4 && response[2..4] == request[2..4],
        5060 => String::from_utf8_lossy(response)
            .to_ascii_lowercase()
            .contains("call-id: scaprobe"),
        _ => true,
    }
}

fn snmp_request_id(payload: &[u8]) -> Option<&[u8]> {
    payload
        .windows(2)
        .position(|pair| matches!(pair, [0xa0 | 0xa2, _]))
        .and_then(|position| payload.get(position + 2..))
        .and_then(|tail| {
            if tail.len() >= 2 && tail[0] == 0x02 {
                let length = tail[1] as usize;
                tail.get(2..2 + length)
            } else {
                None
            }
        })
}

fn dns_query_payload(name: &str) -> Vec<u8> {
    let mut payload = vec![
        b'S', b'P', 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in name.trim_end_matches('.').split('.') {
        payload.push(label.len() as u8);
        payload.extend_from_slice(label.as_bytes());
    }
    payload.push(0);
    payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    payload
}

fn netbios_status_query_payload() -> Vec<u8> {
    let mut payload = vec![
        b'S', b'P', 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut name = [0_u8; 16];
    name[0] = b'*';
    let mut encoded = Vec::with_capacity(32);
    for byte in name {
        encoded.push(b'A' + ((byte >> 4) & 0x0f));
        encoded.push(b'A' + (byte & 0x0f));
    }
    payload.push(encoded.len() as u8);
    payload.extend_from_slice(&encoded);
    payload.extend_from_slice(&[0x00, 0x00, 0x21, 0x00, 0x01]);
    payload
}

fn isakmp_probe_payload() -> Vec<u8> {
    let mut payload = b"SCAPROBE".to_vec();
    payload.extend_from_slice(&[0; 8]);
    payload.extend_from_slice(&[0x00, 0x10, 0x02, 0x00]);
    payload.extend_from_slice(&[0; 4]);
    payload.extend_from_slice(&28_u32.to_be_bytes());
    payload
}

fn rip_request_payload() -> Vec<u8> {
    let mut payload = vec![0x01, 0x02, 0x00, 0x00];
    payload.extend_from_slice(&[0; 16]);
    payload.extend_from_slice(&16_u32.to_be_bytes());
    payload
}

fn ws_discovery_probe_payload() -> Vec<u8> {
    b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><e:Header><w:MessageID>uuid:00000000-0000-0000-0000-000000000000</w:MessageID><w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header><e:Body><d:Probe /></e:Body></e:Envelope>".to_vec()
}

fn sip_options_payload() -> Vec<u8> {
    b"OPTIONS sip:scaprobe.invalid SIP/2.0\r\nVia: SIP/2.0/UDP scaprobe.invalid;branch=z9hG4bK-scaprobe\r\nMax-Forwards: 1\r\nFrom: <sip:scaprobe@scaprobe.invalid>;tag=scaprobe\r\nTo: <sip:scaprobe.invalid>\r\nCall-ID: scaprobe\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n".to_vec()
}

fn coap_core_query_payload() -> Vec<u8> {
    b"\x40\x01SP\xbb.well-known\x04core".to_vec()
}

#[cfg(test)]
fn classify_udp_response(port: u16, bytes: &[u8]) -> ServiceFingerprint {
    classify_udp_response_with_catalog(port, bytes, &RuntimePluginCatalog::default())
}

fn classify_udp_response_with_catalog(
    port: u16,
    bytes: &[u8],
    plugin_catalog: &RuntimePluginCatalog,
) -> ServiceFingerprint {
    if let Some(fingerprint) =
        plugin_catalog.match_rule(&plugin_catalog.udp_response_rules, port, bytes)
    {
        return fingerprint;
    }
    if matches!(port, 53 | 5353) {
        if let Some(fingerprint) = classify_dns_response(port, bytes) {
            return fingerprint;
        }
    }
    if port == 69 {
        if let Some(fingerprint) = classify_tftp_response(bytes) {
            return fingerprint;
        }
    }
    if port == 123 {
        if let Some(fingerprint) = classify_ntp_response(bytes) {
            return fingerprint;
        }
    }
    if matches!(port, 137 | 138) {
        if let Some(fingerprint) = classify_netbios_response(port, bytes) {
            return fingerprint;
        }
    }
    if matches!(port, 161 | 162) {
        if let Some(fingerprint) = classify_snmp_response(bytes) {
            return fingerprint;
        }
    }
    if port == 500 {
        if let Some(fingerprint) = classify_isakmp_response(bytes) {
            return fingerprint;
        }
    }
    if port == 520 {
        if let Some(fingerprint) = classify_rip_response(bytes) {
            return fingerprint;
        }
    }
    if port == 1434 {
        if let Some(fingerprint) = classify_mssql_browser_response(bytes) {
            return fingerprint;
        }
    }
    if port == 5683 {
        if let Some(fingerprint) = classify_coap_response(bytes) {
            return fingerprint;
        }
    }
    if port == 11211 {
        if let Some(fingerprint) = classify_memcached_response(bytes) {
            return fingerprint;
        }
    }
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    if port == 1900
        && (lower.starts_with("http/") || lower.contains("ssdp") || lower.contains("upnp"))
    {
        return ServiceFingerprint {
            name: Some("ssdp".to_string()),
            confidence: Some(0.90),
            banner: Some(clean_banner(&String::from_utf8_lossy(bytes))),
        };
    }
    if port == 3702
        && (lower.contains("probematches")
            || lower.contains("schemas.xmlsoap.org/ws/2005/04/discovery"))
    {
        return ServiceFingerprint {
            name: Some("ws-discovery".to_string()),
            confidence: Some(0.90),
            banner: Some(clean_banner(&String::from_utf8_lossy(bytes))),
        };
    }
    if port == 5060
        && (lower.starts_with("sip/2.0")
            || lower.contains("\r\nvia:")
            || lower.contains("\r\ncseq:"))
    {
        return ServiceFingerprint {
            name: Some("sip".to_string()),
            confidence: Some(0.92),
            banner: Some(clean_banner(&String::from_utf8_lossy(bytes))),
        };
    }
    if let Some(name) = effective_known_udp_service(port, plugin_catalog) {
        return ServiceFingerprint {
            name: Some(name.to_string()),
            confidence: Some(0.55),
            banner: Some(format!(
                "{} bytes: {}",
                bytes.len(),
                bytes_hex_prefix(bytes)
            )),
        };
    }
    ServiceFingerprint {
        name: Some("unknown".to_string()),
        confidence: Some(0.20),
        banner: Some(format!(
            "{} bytes: {}",
            bytes.len(),
            bytes_hex_prefix(bytes)
        )),
    }
}

fn classify_dns_response(port: u16, bytes: &[u8]) -> Option<ServiceFingerprint> {
    if bytes.len() < 12 || bytes[2] & 0x80 == 0 {
        return None;
    }
    let rcode = bytes[3] & 0x0f;
    let answers = u16::from_be_bytes([bytes[6], bytes[7]]);
    let authorities = u16::from_be_bytes([bytes[8], bytes[9]]);
    let additionals = u16::from_be_bytes([bytes[10], bytes[11]]);
    let service = if port == 53 { "dns" } else { "mdns" };
    Some(ServiceFingerprint {
        name: Some(service.to_string()),
        confidence: Some(0.95),
        banner: Some(format!(
            "{service} response rcode={rcode} answers={answers} authorities={authorities} additionals={additionals}"
        )),
    })
}

fn classify_tftp_response(bytes: &[u8]) -> Option<ServiceFingerprint> {
    if bytes.len() < 4 {
        return None;
    }
    let opcode = u16::from_be_bytes([bytes[0], bytes[1]]);
    let opcode_name = match opcode {
        3 => "data",
        4 => "ack",
        5 => "error",
        6 => "option-ack",
        _ => return None,
    };
    if opcode == 5 {
        let code = u16::from_be_bytes([bytes[2], bytes[3]]);
        let message = bytes[4..]
            .split(|byte| *byte == 0)
            .next()
            .map(String::from_utf8_lossy)
            .unwrap_or_default();
        return Some(ServiceFingerprint {
            name: Some("tftp".to_string()),
            confidence: Some(0.92),
            banner: Some(format!(
                "tftp error code={code} message={}",
                clean_banner(&message)
            )),
        });
    }
    Some(ServiceFingerprint {
        name: Some("tftp".to_string()),
        confidence: Some(0.88),
        banner: Some(format!("tftp opcode={opcode_name}")),
    })
}

fn classify_ntp_response(bytes: &[u8]) -> Option<ServiceFingerprint> {
    if bytes.len() < 48 || !matches!(bytes[0] & 0x07, 4 | 5) {
        return None;
    }
    let leap = (bytes[0] >> 6) & 0x03;
    let version = (bytes[0] >> 3) & 0x07;
    let mode = bytes[0] & 0x07;
    let stratum = bytes[1];
    Some(ServiceFingerprint {
        name: Some("ntp".to_string()),
        confidence: Some(0.92),
        banner: Some(format!(
            "ntp response li={leap} version={version} mode={mode} stratum={stratum}"
        )),
    })
}

fn classify_netbios_response(port: u16, bytes: &[u8]) -> Option<ServiceFingerprint> {
    if bytes.len() < 12 {
        return None;
    }
    if port == 137 && bytes[2] & 0x80 != 0 {
        let rcode = bytes[3] & 0x0f;
        let answers = u16::from_be_bytes([bytes[6], bytes[7]]);
        return Some(ServiceFingerprint {
            name: Some("netbios-ns".to_string()),
            confidence: Some(0.88),
            banner: Some(format!(
                "netbios-ns response rcode={rcode} answers={answers}"
            )),
        });
    }
    if port == 138 {
        return Some(ServiceFingerprint {
            name: Some("netbios-dgm".to_string()),
            confidence: Some(0.72),
            banner: Some(format!("netbios-dgm message_type=0x{:02x}", bytes[0])),
        });
    }
    None
}

fn classify_snmp_response(bytes: &[u8]) -> Option<ServiceFingerprint> {
    let top = asn1_tlv(bytes, 0)?;
    if top.tag != 0x30 {
        return None;
    }
    let mut pos = top.value_start;
    let version_tlv = asn1_tlv(bytes, pos);
    let Some(version_tlv) = version_tlv else {
        return Some(ServiceFingerprint {
            name: Some("snmp".to_string()),
            confidence: Some(0.75),
            banner: Some(format!("snmp sequence bytes={}", bytes.len())),
        });
    };
    if version_tlv.tag != 0x02 {
        return Some(ServiceFingerprint {
            name: Some("snmp".to_string()),
            confidence: Some(0.75),
            banner: Some(format!("snmp sequence bytes={}", bytes.len())),
        });
    }
    let version = bytes[version_tlv.value_start..version_tlv.end]
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
    pos = version_tlv.end;
    let community_tlv = asn1_tlv(bytes, pos);
    let mut community_len = 0;
    if let Some(tlv) = community_tlv {
        if tlv.tag == 0x04 {
            community_len = tlv.end - tlv.value_start;
            pos = tlv.end;
        }
    }
    let Some(pdu_tlv) = asn1_tlv(bytes, pos) else {
        return Some(ServiceFingerprint {
            name: Some("snmp".to_string()),
            confidence: Some(0.80),
            banner: Some(format!(
                "snmp version={version} community_len={community_len}"
            )),
        });
    };
    if pdu_tlv.end > top.end {
        return Some(ServiceFingerprint {
            name: Some("snmp".to_string()),
            confidence: Some(0.80),
            banner: Some(format!(
                "snmp version={version} community_len={community_len}"
            )),
        });
    }
    let pdu = match pdu_tlv.tag {
        0xa0 => "get-request".to_string(),
        0xa1 => "get-next-request".to_string(),
        0xa2 => "get-response".to_string(),
        0xa3 => "set-request".to_string(),
        0xa4 => "trap".to_string(),
        0xa5 => "get-bulk-request".to_string(),
        0xa8 => "report".to_string(),
        tag => format!("0x{tag:02x}"),
    };
    Some(ServiceFingerprint {
        name: Some("snmp".to_string()),
        confidence: Some(0.92),
        banner: Some(format!(
            "snmp pdu={pdu} version={version} community_len={community_len}"
        )),
    })
}

fn classify_isakmp_response(bytes: &[u8]) -> Option<ServiceFingerprint> {
    if bytes.len() < 28 {
        return None;
    }
    let major = bytes[17] >> 4;
    let minor = bytes[17] & 0x0f;
    let length = u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]) as usize;
    if !matches!(major, 1 | 2) || length < 28 || length > bytes.len() {
        return None;
    }
    Some(ServiceFingerprint {
        name: Some("isakmp".to_string()),
        confidence: Some(0.88),
        banner: Some(format!(
            "isakmp version={major}.{minor} exchange={} flags=0x{:02x}",
            bytes[18], bytes[19]
        )),
    })
}

fn classify_rip_response(bytes: &[u8]) -> Option<ServiceFingerprint> {
    if bytes.len() < 4 || bytes[0] != 2 || !matches!(bytes[1], 1 | 2) {
        return None;
    }
    let routes = bytes.len().saturating_sub(4) / 20;
    Some(ServiceFingerprint {
        name: Some("rip".to_string()),
        confidence: Some(0.88),
        banner: Some(format!("rip response version={} routes={routes}", bytes[1])),
    })
}

fn classify_mssql_browser_response(bytes: &[u8]) -> Option<ServiceFingerprint> {
    let text = String::from_utf8_lossy(bytes);
    let lower = text.to_ascii_lowercase();
    if !lower.contains("servername;") && !lower.contains("instancename;") {
        return None;
    }
    Some(ServiceFingerprint {
        name: Some("mssql-browser".to_string()),
        confidence: Some(0.90),
        banner: Some(clean_banner(&text)),
    })
}

fn classify_coap_response(bytes: &[u8]) -> Option<ServiceFingerprint> {
    if bytes.len() < 4 || bytes[0] >> 6 != 1 {
        return None;
    }
    let code_class = bytes[1] >> 5;
    if !matches!(code_class, 2 | 4 | 5) {
        return None;
    }
    let message_id = u16::from_be_bytes([bytes[2], bytes[3]]);
    Some(ServiceFingerprint {
        name: Some("coap".to_string()),
        confidence: Some(0.88),
        banner: Some(format!(
            "coap response code={}.{:02} message_id={message_id}",
            code_class,
            bytes[1] & 0x1f
        )),
    })
}

fn classify_memcached_response(bytes: &[u8]) -> Option<ServiceFingerprint> {
    let payload = if bytes.len() >= 8 { &bytes[8..] } else { bytes };
    let text = String::from_utf8_lossy(payload);
    let lower = text.to_ascii_lowercase();
    if !(lower.starts_with("version ")
        || lower.starts_with("error")
        || lower.starts_with("server_error")
        || lower.starts_with("client_error"))
    {
        return None;
    }
    Some(ServiceFingerprint {
        name: Some("memcached".to_string()),
        confidence: Some(0.88),
        banner: Some(clean_banner(&text)),
    })
}

#[derive(Clone, Copy)]
struct Asn1Tlv {
    tag: u8,
    value_start: usize,
    end: usize,
}

fn asn1_tlv(bytes: &[u8], offset: usize) -> Option<Asn1Tlv> {
    if offset + 2 > bytes.len() {
        return None;
    }
    let tag = bytes[offset];
    let length_byte = bytes[offset + 1];
    let mut pos = offset + 2;
    let length = if length_byte & 0x80 != 0 {
        let length_len = usize::from(length_byte & 0x7f);
        if length_len == 0 || length_len > 4 || pos + length_len > bytes.len() {
            return None;
        }
        let length = bytes[pos..pos + length_len]
            .iter()
            .fold(0_usize, |value, byte| (value << 8) | usize::from(*byte));
        pos += length_len;
        length
    } else {
        usize::from(length_byte)
    };
    let end = pos.checked_add(length)?;
    if end > bytes.len() {
        return None;
    }
    Some(Asn1Tlv {
        tag,
        value_start: pos,
        end,
    })
}

fn bytes_hex_prefix(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(64)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn is_tls_like_service(known: Option<&str>) -> bool {
    matches!(
        known,
        Some(
            "https"
                | "smtps"
                | "ldaps"
                | "dot"
                | "imaps"
                | "pop3s"
                | "ftps"
                | "docker-tls"
                | "winrm-https"
        )
    )
}

fn tls_service_name_for(known: Option<&str>) -> &'static str {
    match known {
        Some("https") => "https",
        Some("smtps") => "smtps",
        Some("ldaps") => "ldaps",
        Some("dot") => "dot",
        Some("imaps") => "imaps",
        Some("pop3s") => "pop3s",
        Some("ftps") => "ftps",
        Some("docker-tls") => "docker-tls",
        Some("winrm-https") => "winrm-https",
        _ => "tls",
    }
}

fn clean_banner(value: &str) -> String {
    value
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .chars()
        .take(512)
        .collect()
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(windows)]
fn process_memory_bytes() -> (Option<u64>, Option<u64>) {
    use std::ffi::c_void;

    #[repr(C)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
    }
    #[link(name = "psapi")]
    extern "system" {
        fn GetProcessMemoryInfo(
            process: *mut c_void,
            counters: *mut ProcessMemoryCounters,
            size: u32,
        ) -> i32;
    }

    let mut counters = ProcessMemoryCounters {
        cb: std::mem::size_of::<ProcessMemoryCounters>() as u32,
        page_fault_count: 0,
        peak_working_set_size: 0,
        working_set_size: 0,
        quota_peak_paged_pool_usage: 0,
        quota_paged_pool_usage: 0,
        quota_peak_non_paged_pool_usage: 0,
        quota_non_paged_pool_usage: 0,
        pagefile_usage: 0,
        peak_pagefile_usage: 0,
    };
    let success = unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters,
            std::mem::size_of::<ProcessMemoryCounters>() as u32,
        )
    };
    if success == 0 {
        (None, None)
    } else {
        (
            Some(counters.working_set_size as u64),
            Some(counters.peak_working_set_size as u64),
        )
    }
}

#[cfg(target_os = "linux")]
fn process_memory_bytes() -> (Option<u64>, Option<u64>) {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return (None, None);
    };
    let mut current = None;
    let mut peak = None;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            current = value
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .map(|value| value * 1024);
        } else if let Some(value) = line.strip_prefix("VmHWM:") {
            peak = value
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .map(|value| value * 1024);
        }
    }
    (current, peak)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn process_memory_bytes() -> (Option<u64>, Option<u64>) {
    (None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_connect_errors_by_who_answered() {
        use std::io::ErrorKind;
        assert_eq!(tcp_error_state(ErrorKind::ConnectionRefused), "closed");
        assert_eq!(tcp_error_state(ErrorKind::HostUnreachable), "filtered");
        assert_eq!(tcp_error_state(ErrorKind::NetworkUnreachable), "filtered");
        assert_eq!(tcp_error_state(ErrorKind::PermissionDenied), "filtered");
        assert_eq!(tcp_error_state(ErrorKind::TimedOut), "filtered");
        assert_eq!(tcp_error_state(ErrorKind::OutOfMemory), "error");
    }

    #[tokio::test]
    async fn rate_limiter_keeps_the_long_run_rate() {
        // 2000/sec means 500 us spacing: below the sleep floor, so attempts
        // burst, but the shared schedule still paces the total.
        let limiter = RateLimiter::new(2_000);
        let started = Instant::now();
        for _ in 0..200 {
            limiter.wait().await;
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(90),
            "200 attempts at 2000/sec finished too fast: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(400),
            "sleep granularity dominated the schedule: {elapsed:?}"
        );
    }

    #[test]
    fn parses_ports_with_ranges_and_dedupe() {
        assert_eq!(
            parse_ports("80,443,8000-8002,80").unwrap(),
            vec![80, 443, 8000, 8001, 8002]
        );
    }

    #[test]
    fn rejects_invalid_port_range() {
        assert!(parse_ports("10-1").is_err());
    }

    #[test]
    fn rejects_port_zero() {
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("0-10").is_err());
    }

    #[test]
    fn runtime_catalog_service_maps_override_builtin_maps() {
        let catalog = RuntimePluginCatalog {
            schema_version: 1,
            tcp_services: BTreeMap::from([(80, "plugin-http".to_string())]),
            udp_services: BTreeMap::from([(53, "plugin-dns".to_string())]),
            ..RuntimePluginCatalog::default()
        };

        assert_eq!(effective_known_service(80, &catalog), Some("plugin-http"));
        assert_eq!(
            effective_known_udp_service(53, &catalog),
            Some("plugin-dns")
        );
        assert_eq!(effective_known_service(22, &catalog), Some("ssh"));
    }

    #[test]
    fn runtime_catalog_rules_use_manifest_order_and_support_text_and_hex() {
        let text_rule = |service: &str| RuntimeFingerprintRule {
            service: service.to_string(),
            confidence: 0.9,
            ports: vec![18080],
            contains: Some(b"hello".to_vec()),
            starts_with: None,
            contains_hex: None,
            starts_with_hex: None,
        };
        let catalog = RuntimePluginCatalog {
            schema_version: 1,
            tcp_banner_rules: vec![text_rule("first"), text_rule("second")],
            udp_response_rules: vec![RuntimeFingerprintRule {
                service: "hex-service".to_string(),
                confidence: 0.88,
                ports: vec![1812],
                contains: None,
                starts_with: None,
                contains_hex: None,
                starts_with_hex: Some(vec![0x02, 0xff]),
            }],
            ..RuntimePluginCatalog::default()
        };

        let tcp =
            classify_passive_bytes_with_catalog(b"HELLO from both rules", None, 18080, &catalog)
                .unwrap();
        assert_eq!(tcp.name.as_deref(), Some("first"));
        let udp = classify_udp_response_with_catalog(1812, &[0x02, 0xff, 0x10], &catalog);
        assert_eq!(udp.name.as_deref(), Some("hex-service"));
    }

    #[test]
    fn runtime_catalog_rule_precedes_builtin_udp_classifier() {
        let catalog = RuntimePluginCatalog {
            schema_version: 1,
            udp_response_rules: vec![RuntimeFingerprintRule {
                service: "custom-dns".to_string(),
                confidence: 0.99,
                ports: vec![53],
                contains: None,
                starts_with: Some(vec![0x12, 0x34]),
                contains_hex: None,
                starts_with_hex: None,
            }],
            ..RuntimePluginCatalog::default()
        };
        let dns_like = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];

        let fingerprint = classify_udp_response_with_catalog(53, &dns_like, &catalog);

        assert_eq!(fingerprint.name.as_deref(), Some("custom-dns"));
    }

    #[test]
    fn runtime_catalog_rejects_invalid_schema_and_rules() {
        let wrong_schema: RuntimePluginCatalog =
            serde_json::from_str(r#"{"schema_version":2,"tcp_services":{},"udp_services":{}}"#)
                .unwrap();
        assert!(wrong_schema.validate().is_err());

        let no_match: RuntimePluginCatalog = serde_json::from_str(
            r#"{"schema_version":1,"tcp_banner_rules":[{"service":"bad","confidence":0.8}]}"#,
        )
        .unwrap();
        assert!(no_match.validate().is_err());
    }

    #[test]
    fn expands_ipv4_cidr_hosts() {
        let targets = parse_targets("127.0.0.0/30", 10).unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].to_string(), "127.0.0.1");
        assert_eq!(targets[1].to_string(), "127.0.0.2");
    }

    #[test]
    fn enforces_target_limit_for_cidrs_and_individual_ips() {
        assert!(parse_targets("127.0.0.0/30", 1).is_err());
        assert!(parse_targets("127.0.0.1,127.0.0.2", 1).is_err());
    }

    #[test]
    fn parses_newline_separated_scan_inputs() {
        let targets = parse_targets("127.0.0.1 # loopback\n127.0.0.2", 2).unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(parse_ports("80 # http\n443").unwrap(), vec![80, 443]);
    }

    #[test]
    fn rate_limiter_reserves_staggered_deadlines() {
        let limiter = RateLimiter::new(100);
        let first = limiter.reserve_deadline();
        let second = limiter.reserve_deadline();
        let third = limiter.reserve_deadline();
        assert!(second.duration_since(first) >= Duration::from_millis(10));
        assert!(third.duration_since(second) >= Duration::from_millis(10));
    }

    #[test]
    fn tls_client_hello_lengths_are_consistent() {
        let hello = tls_client_hello();
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        let handshake_len = u32::from_be_bytes([0, hello[6], hello[7], hello[8]]) as usize;
        assert_eq!(record_len, hello.len() - 5);
        assert_eq!(handshake_len, hello.len() - 9);
    }

    #[test]
    fn fingerprint_validation_rejects_ambiguous_or_impossible_records() {
        let ftp = classify_passive_bytes(b"220 Welcome\r\n", Some("ftp")).unwrap();
        assert_eq!(ftp.name.as_deref(), Some("ftp"));

        assert!(tls_record_summary(&[0x16, 0x03, 0x03, 0xff, 0xff]).is_none());

        let mut malformed_isakmp = [0_u8; 28];
        malformed_isakmp[17] = 0x20;
        malformed_isakmp[24..28].copy_from_slice(&1000_u32.to_be_bytes());
        assert!(classify_isakmp_response(&malformed_isakmp).is_none());
    }

    #[test]
    fn udp_probe_payloads_are_service_specific() {
        assert!(udp_probe_payload(53).len() > 12);
        assert!(udp_probe_payload(69).starts_with(&[0x00, 0x01]));
        assert_eq!(udp_probe_payload(123).len(), 48);
        assert!(udp_probe_payload(137).len() > 40);
        assert!(udp_probe_payload(500).starts_with(b"SCAPROBE"));
        assert_eq!(&udp_probe_payload(520)[..2], &[0x01, 0x02]);
        assert_eq!(udp_probe_payload(1434), b"\x02");
        assert!(String::from_utf8_lossy(&udp_probe_payload(1900)).contains("M-SEARCH"));
        assert!(String::from_utf8_lossy(&udp_probe_payload(3702)).contains("Probe"));
        assert!(String::from_utf8_lossy(&udp_probe_payload(5060)).starts_with("OPTIONS "));
        assert!(udp_probe_payload(5353).len() > 12);
        assert!(udp_probe_payload(5683).starts_with(&[0x40, 0x01]));
        assert_eq!(udp_probe_payload(11211), b"version\r\n");
    }

    #[test]
    fn udp_response_correlation_checks_protocol_identifiers() {
        let dns = udp_probe_payload(53);
        assert!(udp_response_matches(
            53,
            &dns,
            &[dns[0], dns[1], 0x81, 0x80]
        ));
        assert!(!udp_response_matches(53, &dns, b"XX\x81\x80"));

        let ntp = udp_probe_payload(123);
        let mut ntp_response = [0_u8; 48];
        ntp_response[24..32].copy_from_slice(&ntp[40..48]);
        assert!(udp_response_matches(123, &ntp, &ntp_response));
        ntp_response[24] ^= 1;
        assert!(!udp_response_matches(123, &ntp, &ntp_response));

        let snmp = udp_probe_payload(161);
        let mut snmp_response = snmp.clone();
        snmp_response[13] = 0xa2;
        assert!(udp_response_matches(161, &snmp, &snmp_response));
        snmp_response[20] = 2;
        assert!(!udp_response_matches(161, &snmp, &snmp_response));
    }

    #[test]
    fn windows_udp_connection_reset_is_closed() {
        let event = udp_error_or_closed_event(
            "test",
            "127.0.0.1".to_string(),
            9,
            Instant::now(),
            std::io::Error::from(std::io::ErrorKind::ConnectionReset),
        );
        assert_eq!(event.state, "closed");
        assert_eq!(
            event.evidence.as_deref(),
            Some("icmp port unreachable reported by OS")
        );
    }

    #[test]
    fn service_metadata_summaries_keep_safe_high_value_fields() {
        let http = http_response_summary(
            "HTTP/1.1 302 Found\r\nServer: lab\r\nLocation: /login\r\nContent-Type: text/html\r\n\r\n<html><title>Lab &amp; Login</title>body</html>",
        );
        assert!(http.contains("server=lab"));
        assert!(http.contains("location=/login"));
        assert!(!http.contains("body"));
        assert!(http.contains("title=Lab & Login"));

        assert_eq!(
            normalize_service_banner("ssh", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"),
            "SSH protocol=2.0; product=OpenSSH; version=9.6p1; platform=Ubuntu-3ubuntu13"
        );
        assert_eq!(
            fallback_known_service(Some("ssh")).banner.as_deref(),
            Some("inferred from port mapping")
        );
        let vnc = classify_passive_bytes(b"RFB 003.008\n", Some("vnc")).unwrap();
        assert_eq!(vnc.banner.as_deref(), Some("RFB 003.008\\n"));
        let pop3 = classify_passive_bytes(b"+OK POP3 ready\r\n", Some("pop3")).unwrap();
        assert_eq!(pop3.banner.as_deref(), Some("POP3 greeting=+OK POP3 ready"));

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&[
            0x00, 0x13, 0x01, 0x00, 0x00, 0x06, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
        ]);
        let mut handshake = vec![0x02, 0x00, 0x00, body.len() as u8];
        handshake.extend_from_slice(&body);
        let mut record = vec![0x16, 0x03, 0x03, 0x00, handshake.len() as u8];
        record.extend_from_slice(&handshake);
        let summary = tls_record_summary(&record).unwrap();
        assert!(summary.contains("version=TLS1.3"));
        assert!(summary.contains("cipher=0x1301"));
    }

    #[test]
    fn udp_classifies_dns_fixture() {
        let query = dns_query_payload("scaprobe.invalid");
        let mut response = Vec::new();
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&[0x81, 0x80]);
        response.extend_from_slice(&query[4..6]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x7f, 0x00,
            0x00, 0x01,
        ]);

        let fingerprint = classify_udp_response(53, &response);

        assert_eq!(fingerprint.name.as_deref(), Some("dns"));
        assert!(fingerprint.confidence.unwrap() >= 0.95);
        assert!(fingerprint.banner.unwrap().contains("answers=1"));
    }

    #[test]
    fn udp_classifies_ntp_fixture() {
        let mut response = [0_u8; 48];
        response[0] = 0x24;
        response[1] = 2;

        let fingerprint = classify_udp_response(123, &response);

        assert_eq!(fingerprint.name.as_deref(), Some("ntp"));
        assert!(fingerprint.confidence.unwrap() >= 0.92);
        let banner = fingerprint.banner.unwrap();
        assert!(banner.contains("version=4"));
        assert!(banner.contains("stratum=2"));
    }

    #[test]
    fn udp_classifies_snmp_fixture() {
        let response = [
            0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa2,
            0x1c, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30,
            0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05,
            0x00,
        ];

        let fingerprint = classify_udp_response(161, &response);

        assert_eq!(fingerprint.name.as_deref(), Some("snmp"));
        assert!(fingerprint.confidence.unwrap() >= 0.92);
        let banner = fingerprint.banner.unwrap();
        assert!(banner.contains("pdu=get-response"));
        assert!(banner.contains("community_len=6"));
    }

    #[test]
    fn udp_classifies_ssdp_fixture() {
        let response = b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nUSN: uuid:scaprobe-test::upnp:rootdevice\r\n\r\n";

        let fingerprint = classify_udp_response(1900, response);

        assert_eq!(fingerprint.name.as_deref(), Some("ssdp"));
        assert!(fingerprint.confidence.unwrap() >= 0.90);
        assert!(fingerprint.banner.unwrap().contains("upnp:rootdevice"));
    }

    #[test]
    fn udp_classifies_tftp_fixture() {
        let response = b"\x00\x05\x00\x01File not found\x00";

        let fingerprint = classify_udp_response(69, response);

        assert_eq!(fingerprint.name.as_deref(), Some("tftp"));
        assert!(fingerprint.confidence.unwrap() >= 0.92);
        assert!(fingerprint.banner.unwrap().contains("error code=1"));
    }

    #[test]
    fn udp_classifies_expanded_service_fixtures() {
        let mut isakmp = b"SCAPROBE".to_vec();
        isakmp.extend_from_slice(&[0x01; 8]);
        isakmp.extend_from_slice(&[0x00, 0x10, 0x02, 0x00]);
        isakmp.extend_from_slice(&[0; 4]);
        isakmp.extend_from_slice(&28_u32.to_be_bytes());
        let fixtures: Vec<(u16, Vec<u8>, &str)> = vec![
            (500, isakmp, "isakmp"),
            (520, [b"\x02\x02\x00\x00".as_slice(), &[0; 20]].concat(), "rip"),
            (
                1434,
                b"\x05ServerName;SQL01;InstanceName;MSSQLSERVER;".to_vec(),
                "mssql-browser",
            ),
            (
                3702,
                b"<ProbeMatches xmlns='http://schemas.xmlsoap.org/ws/2005/04/discovery'></ProbeMatches>"
                    .to_vec(),
                "ws-discovery",
            ),
            (
                5060,
                b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP scaprobe\r\nCSeq: 1 OPTIONS\r\n\r\n"
                    .to_vec(),
                "sip",
            ),
            (5683, b"\x60\x45SP".to_vec(), "coap"),
            (
                11211,
                b"\x00\x01\x00\x00\x00\x01\x00\x00VERSION 1.6.22\r\n".to_vec(),
                "memcached",
            ),
        ];

        for (port, response, expected) in fixtures {
            let fingerprint = classify_udp_response(port, &response);
            assert_eq!(fingerprint.name.as_deref(), Some(expected), "port {port}");
            assert!(fingerprint.confidence.unwrap() >= 0.88, "port {port}");
        }
    }
}
