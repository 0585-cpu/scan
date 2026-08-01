# netroach

`netroach` is an authorization-first network diagnostics toolkit that combines:

- High-throughput TCP connect and UDP response-based scanning through the required `netroach-engine`
- Service fingerprinting for common TCP, TLS, and UDP services, including normalized greetings, HTTP metadata, and TLS certificate details
- Streaming PCAP/PCAPNG analysis with ARP, ICMP, DHCP, DNS, HTTP, TLS ClientHello, and conversation metadata
- Bounded live packet capture to PCAP with optional automatic analysis
- HTTP-only OAST callback sessions for authorized out-of-band diagnostics
- Template-based packet sending for lab and owned networks
- JSON data plugins for custom port profiles and service fingerprint rules
- Automatic image evidence: browser screenshots for web services and credential-free pre-authentication terminal transcripts for other services
- Local SQLite history, JSON/CSV/NDJSON/XLSX export with image evidence, and a FastAPI local REST API

Active network actions require both `--confirm-authorized` and at least one explicit `--scope` CIDR.
The API field `scope_from_targets` fills the scope in from the targets themselves; it saves typing but cannot reject anything, so `confirm_authorized` stays the operator's real authorization statement.
Live capture is passive but sensitive; it requires `--confirm-authorized` and either `--duration-s` or `--count`.

## Install

For a portable release artifact, see [docs/install.md](docs/install.md). For day-to-day usage, see [docs/user-guide.md](docs/user-guide.md). Windows artifacts use `.zip`; macOS/Linux artifacts use `.tar.gz`; each artifact is written with a `.sha256` checksum.

For the self-contained Windows installer and desktop development notes, see [docs/desktop-packaging.md](docs/desktop-packaging.md). The installed desktop app bundles Playwright headless Chromium and the WebView2 offline installer, so it does not require Python, Node.js, Rust, a separate browser, or a first-run internet connection.

To continue development on another PC, including the current implementation status, architecture, setup commands, validation steps, and known release limitations, see [docs/development-handoff-ko.md](docs/development-handoff-ko.md).

On another Windows x64 PC, extract the release ZIP and run `Start-Netroach.cmd`. Its menu can start Netroach, install screenshot support and start, install or update only, or run diagnostics. Normal start performs first-run setup automatically. For automation, use `Start-Netroach.cmd --start`, `--screenshots`, `--setup`, or `--diagnostics`. The lower-level `bin\setup.cmd` and `bin\start-desktop.cmd` scripts remain available for separate setup and launch steps. The destination PC needs Python 3.10+ and internet access during setup; TCP/UDP scanning itself does not require Npcap.

Alternatively, install the Windows NSIS desktop package for a Python-free deployment. Build it with `py -3 tools\build_desktop.py`; see the desktop packaging guide for build prerequisites.

For development:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

This registers the official command:

```powershell
netroach --help
netroach --version
```


## Rust Engine

Build the Rust engine when Cargo is available:

```powershell
cargo build --release -p netroach-engine
```

On Windows machines without Visual Studio Build Tools, use a GNU toolchain plus the `portable` profile:

```powershell
rustup toolchain install stable-x86_64-pc-windows-gnu --profile minimal
cargo +stable-x86_64-pc-windows-gnu build --profile portable -p netroach-engine
```

If local application-control policy blocks executables under the workspace `target/` directory, build into a user temp target directory:

```powershell
$env:CARGO_TARGET_DIR = Join-Path $env:TEMP 'netroach-cargo-target'
cargo +stable-x86_64-pc-windows-gnu build --profile portable -p netroach-engine
```

The Rust engine ships with the Python package and is required for scans. Without it, the REST API and dashboard remain available in degraded mode while scan submission is disabled; PCAP, capture, packet sending, OAST, and history features continue to work.

Check the engine version directly:

```powershell
netroach-engine --version
```

## Diagnostics

```powershell
netroach serve --check
```

Diagnostics report the Rust engine path/version, Scapy availability, packet driver, and raw packet privilege status. Windows packet sending generally needs Npcap and an elevated terminal. macOS/Linux raw packet sending may require elevated privileges or `CAP_NET_RAW`.

## Desktop Mode

Start Netroach as a local desktop-style app:

```powershell
netroach desktop
```

This starts the local API/dashboard on the fixed `127.0.0.1:8765` address and opens the dashboard. Pass `--port 0` only when an automatically selected free port is preferred. Use `netroach desktop --no-open` when a desktop wrapper or shortcut will open the URL itself.

## CLI Examples

Run an authorized scan:

```powershell
netroach scan --targets 192.168.1.10 --ports 22,80,443 --scope 192.168.1.0/24 --confirm-authorized
```

Scan a small subnet with JSON output:

```powershell
netroach scan --targets 192.168.1.0/28 --ports 1-1024 --scope 192.168.1.0/24 --json --confirm-authorized
```

Read targets and ports from files, exclude a host, and include a named profile:

```powershell
netroach scan --targets-file .\targets.txt --ports-file .\ports.txt --exclude 192.168.1.50/32 --profile web --scope 192.168.1.0/24 --confirm-authorized
```

Use built-in common ports:

```powershell
netroach scan --targets 192.168.1.10 --top-ports 20 --scope 192.168.1.0/24 --confirm-authorized
```

Use a configuration file for scan defaults, custom port profiles, excludes, scope, and environments:

```powershell
netroach scan --config .\netroach.toml --env lab --targets 192.168.1.10 --profile web-plus --confirm-authorized
netroach serve --config .\netroach.toml --env corp
```

If `--config` is omitted, Netroach checks `.\netroach.toml` and then the user config directory. Example config: `docs/netroach.example.toml`.
Built-in environments are `local`, `lab`, and `corp`; file environments can override them under `[environments.<name>.scan]`.
Config can provide `scope`, but active scans and packet sends still require `--confirm-authorized` or `confirm_authorized=true`.

Load JSON data plugins for owned lab service names, port profiles, and fingerprint rules:

```powershell
netroach plugins validate .\docs\netroach.plugin.example.json
netroach plugins list --plugin .\docs\netroach.plugin.example.json
netroach scan --plugin .\docs\netroach.plugin.example.json --targets 192.168.1.10 --profile lab-app --scope 192.168.1.0/24 --confirm-authorized
```

Plugins can also be listed in `netroach.toml` under `[plugins].paths`. Plugin manifests are JSON data only; Netroach does not execute plugin code. Python validates and merges runtime fingerprint rules, then passes a temporary schema-version-1 catalog to the Rust engine. Port profiles remain Python-side input presets.

Run a UDP scan for common infrastructure services:

```powershell
netroach scan --protocol udp --udp-retries 1 --targets 192.168.1.10 --ports 53,123,161 --scope 192.168.1.0/24 --confirm-authorized
```

UDP results use `open` when a protocol-correlated response is received, `closed` when the OS reports ICMP port unreachable, and `open|filtered` when no correlated response arrives after the configured attempts. DNS/mDNS, NetBIOS, NTP, SNMP, ISAKMP, SIP, and CoAP validate protocol identifiers; `--udp-retries` accepts 0 through 3 and defaults to 1.
Built-in UDP probes currently cover DNS/mDNS, NTP, SNMP, SSDP, TFTP, NetBIOS name service, ISAKMP, RIP, MSSQL Browser, WS-Discovery, SIP, CoAP, and Memcached.

Scans are bounded before execution. The defaults allow 1,000,000 host-port attempts, a 60-second maximum per-attempt timeout, 4,096 workers, 100,000 starts per second, and 1,000,000 expanded hosts. A scan above `--max-attempts` requires `--confirm-large-scan`; the absolute limit is 100,000,000 attempts. The dashboard shows the planned host, port, and attempt counts before submission.

```powershell
netroach scan --targets 192.168.1.0/24 --ports 1-1024 --max-attempts 100000 --confirm-large-scan --scope 192.168.1.0/24 --confirm-authorized
```

API/desktop scan results are streamed into SQLite in bounded batches instead of being retained as one in-memory list. If the local API stops while an API-created job is queued or running, the next startup claims that job and scans only host-port pairs that do not already have a stored result. If the Rust engine is unavailable, recovery leaves those jobs untouched until a later server restart. Job browsing, cancellation, deletion, annotations, evidence, and cleanup are available through the dashboard and `/v1/scans` REST endpoints.

Export stored scan results:

```powershell
netroach export <scan_id> --format json
netroach export <scan_id> --format csv --state open --output .\open-ports.csv
netroach export <scan_id> --format ndjson --protocol udp --output .\udp-results.ndjson
```

Generate a scan report:

```powershell
netroach report <scan_id> --format html --output .\scan-report.html
netroach report <scan_id> --format markdown --output .\scan-report.md
```

Analyze a PCAP/PCAPNG file:

```powershell
netroach pcap .\capture.pcapng --top 10
```

PCAP summaries include protocol counts, top talkers, conversation packet/byte/duration metrics, DNS queries/responses/NXDOMAIN counts, HTTP Host/User-Agent/status lines, TLS SNI/ALPN, ARP request/reply counts, ICMP type counts, and DHCP message types.

Run a bounded live capture and analyze the saved PCAP:

```powershell
netroach capture --output .\capture.pcap --duration-s 10 --filter "tcp port 80" --confirm-authorized
netroach capture --output .\sample.pcap --count 100 --iface "Ethernet" --confirm-authorized --json
```

Live capture requires Scapy plus platform packet capture privileges. Count-only captures are still protected by an internal timeout so the command does not wait forever on quiet links.

Start `netroach serve`, then use the dashboard or `/v1/oast/sessions` REST endpoints to create HTTP callback tokens and inspect interactions. OAST support records inbound HTTP metadata only; it does not generate exploit payloads or perform vulnerability checks.

Send template traffic:

```powershell
netroach send tcp --target 192.168.1.10 --dport 443 --scope 192.168.1.0/24 --confirm-authorized --dry-run --json
netroach send icmp --target 192.168.1.10 --scope 192.168.1.0/24 --count 3 --confirm-authorized
netroach send udp --target 192.168.1.20 --dport 9999 --payload-text "hello" --scope 192.168.1.0/24 --confirm-authorized
netroach send dns --target 192.168.1.1 --dns-name example.com --scope 192.168.1.0/24 --confirm-authorized
```

Packet send results include template-specific `details`. Dry runs validate scope and fields but record `sent=0`; HTTP sends record response status metadata; DNS sends record response summaries when a reply is received.

Packet audit history and database backup/restore are available through the dashboard and REST API.

Start the local REST API:

```powershell
netroach serve --host 127.0.0.1 --port 8765
```

Open the local dashboard:

```text
http://127.0.0.1:8765/dashboard
```

### API authentication

A loopback bind (`127.0.0.1`, `localhost`, `::1`) serves the API without a token, as before. Any other bind is reachable from the network, so the API is never served unauthenticated: supply `--api-token` or `NETROACH_API_TOKEN`, and one is generated and printed at startup when you do not.

When a token is active, every endpoint requires `Authorization: Bearer <token>`. Opening `/dashboard?token=<token>` once exchanges the token for an `HttpOnly` session cookie, so the browser keeps working without the token in later URLs. Only the `/oast/<token>` callback receiver stays open, because the scanned systems delivering those callbacks cannot present operator credentials.

```powershell
netroach serve --host 0.0.0.0 --port 8765 --api-token (python -c "import secrets;print(secrets.token_urlsafe(32))")
```

The token protects the API; it is not transport security. Anything beyond a trusted network should be fronted by TLS.

Print startup diagnostics directly:

```powershell
netroach diagnostics
```

Import `postman/netroach.postman_collection.json` into Postman and set `baseUrl` if needed.

Package a portable artifact with an existing engine build. `--archive-format auto` writes zip for Windows targets and tar.gz for macOS/Linux targets, plus a `.sha256` checksum:

```powershell
py -3 tools\package.py --cargo-target-dir $env:CARGO_TARGET_DIR --engine-profile portable --archive-format auto
py -3 tools\smoke_package.py .\dist
py -3 tools\smoke_package.py .\dist --require-engine
```

Run benchmark and soak helpers. They perform real scans, so they require explicit scope and `--confirm-authorized`.

```powershell
py -3 tools\benchmark_scan.py --targets 127.0.0.1 --top-ports 100 --scope 127.0.0.0/8 --confirm-authorized --warmup-runs 1 --runs 5 --output benchmark.json
py -3 tools\soak_scan.py --targets 127.0.0.1 --ports 80,443,8080 --iterations 20 --scope 127.0.0.0/8 --confirm-authorized --max-memory-growth-mb 32 --output soak.json
```

Benchmark reports include per-run completeness, state counts, latency percentiles, throughput distributions, controller CPU/RSS, and Rust-engine elapsed/RSS measurements. Soak reports additionally detect result-count failures, state drift, and controller memory growth. Both helpers use bounded streaming collection by default; use `--retain-results` only when the benchmark must include full result-list retention.

Scan reports preserve the compact Open Results table and add explicit included/total result counts, full-database aggregate summaries, per-host state totals, collapsible service identification and review sections, and a print-friendly evidence gallery. Sections longer than five items start collapsed, long text has an individual preview, and print output expands all details. If a report limit is reached, actionable results are prioritized and the omission is clearly marked.

## API

Primary endpoints:

- `GET /v1/health`
- `GET /`
- `GET /dashboard`
- `GET /v1/plugins`
- `POST /v1/oast/sessions`
- `GET /v1/oast/sessions`
- `GET /v1/oast/sessions/{session_id}`
- `GET /v1/oast/sessions/{session_id}/interactions`
- `DELETE /v1/oast/sessions/{session_id}`
- `/oast/{token}` callback route for inbound HTTP methods
- `POST /v1/scans`
- `GET /v1/scans`
- `GET /v1/scans/{scan_id}`
- `GET /v1/scans/{scan_id}/progress`
- `GET /v1/scans/{scan_id}/results`
- `PATCH /v1/scans/{scan_id}/results/{host}/{protocol}/{port}`
- `GET /v1/scans/{scan_id}/export`
- `GET /v1/scans/{scan_id}/report`
- `POST /v1/scans/{scan_id}/cancel`
- `POST /v1/scans/cleanup`
- `DELETE /v1/scans/{scan_id}`
- `POST /v1/pcaps/analyze`
- `POST /v1/captures/live`
- `GET /v1/pcaps/analyses`
- `GET /v1/pcaps/analyses/{analysis_id}`
- `POST /v1/packets/send`
- `GET /v1/packets/audits`
- `GET /v1/packets/audits/{audit_id}`
- `GET /v1/db/export`
- `POST /v1/db/import`

Scan results support `limit`, `offset`, `open_only`, `state`, `protocol`, and `service` query filters.
The export endpoint supports `format=json|csv|ndjson` plus the same result filters.
The report endpoint supports `format=html|markdown|json`.

Example scan request:

```json
{
  "targets": "127.0.0.1",
  "ports": "22,80,443",
  "exclude": ["127.0.0.2/32"],
  "port_profile": "web",
  "top_ports": 10,
  "config_env": "lab",
  "scope": ["127.0.0.0/8"],
  "confirm_authorized": true,
  "protocol": "tcp",
  "timeout_ms": 800,
  "concurrency": 2000,
  "rate_limit_per_sec": 5000,
  "udp_retries": 1,
  "max_hosts": 65536,
  "max_attempts": 1000000,
  "confirm_large_scan": false,
  "service_probe": true
}
```

Example plugin manifest:

```json
{
  "name": "lab-services",
  "version": "1.0.0",
  "port_profiles": {
    "lab-app": [18080, 18443]
  },
  "tcp_services": {
    "18080": "custom-http"
  },
  "udp_services": {
    "1812": "radius"
  },
  "tcp_banner_rules": [
    {
      "service": "custom-app",
      "ports": [18080],
      "contains": "X-Custom-App",
      "confidence": 0.93
    }
  ],
  "udp_response_rules": [
    {
      "service": "radius",
      "ports": [1812],
      "starts_with_hex": "02",
      "confidence": 0.88
    }
  ]
}
```

Example scan response:

```json
{
  "scan_id": "00000000-0000-0000-0000-000000000000",
  "status": "queued",
  "workload": {
    "hosts": 1,
    "ports": 16,
    "attempts": 16
  }
}
```

Example OAST session request:

```json
{
  "label": "lab callback",
  "base_url": "http://127.0.0.1:8765",
  "ttl_seconds": 3600,
  "confirm_authorized": true
}
```

Example filtered results request:

```text
GET /v1/scans/{scan_id}/results?state=open&protocol=udp&service=dns&limit=100&offset=0
```

Example progress and export requests:

```text
GET /v1/scans/{scan_id}/progress
GET /v1/scans/{scan_id}/export?format=csv&state=open
POST /v1/scans/{scan_id}/cancel
DELETE /v1/scans/{scan_id}
```

Example result annotation request:

```json
{
  "tags": ["review", "prod"],
  "note": "confirm service owner"
}
```

Example packet send request:

```json
{
  "template": "dns",
  "target": "127.0.0.1",
  "scope": ["127.0.0.0/8"],
  "confirm_authorized": true,
  "dns_name": "example.com",
  "count": 1,
  "interval_ms": 1000,
  "dry_run": false
}
```

Example live capture request:

```json
{
  "output": "capture.pcap",
  "duration_s": 10,
  "count": 100,
  "iface": "Ethernet",
  "bpf_filter": "tcp port 80",
  "confirm_authorized": true,
  "analyze": true
}
```

Example health response includes diagnostics:

```json
{
  "status": "ok",
  "db": "C:\\Users\\you\\AppData\\Roaming\\Netroach\\netroach.db",
  "diagnostics": {
    "app_version": "0.1.0",
    "rust_engine_available": true,
    "rust_engine_version": "netroach-engine 0.1.0",
    "scapy_available": true,
    "packet_driver": "Npcap",
    "packet_driver_available": true,
    "elevated": true,
    "raw_socket_privileged": true,
    "packet_driver_note": "Npcap detected and this process appears elevated; raw packet sending should be available."
  }
}
```

Application-level API errors use a consistent detail shape:

```json
{
  "detail": {
    "error": "state must be one of: open, closed, open|filtered, filtered, error"
  }
}
```

## Tests

```powershell
py -3 -m unittest discover -s tests
```

FastAPI API tests require the `dev` extra. Rust tests/builds require Cargo.

See `docs/release-checklist.md` before cutting a distributable artifact.

## Scope Boundaries

v1 intentionally excludes exploit checks, stealth/evasion features, authentication bypass, arbitrary Scapy expression execution, and raw byte packet injection. Live capture is bounded by duration/count, requires explicit authorization confirmation, and writes to PCAP for auditable analysis.
