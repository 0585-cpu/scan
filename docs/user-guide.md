# Scaprobe User Guide

Scaprobe is an authorization-first network diagnostics toolkit. Use it only on networks and systems you own or are explicitly allowed to test.

## 1. Install And Check

Development install:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
scaprobe --help
scaprobe serve --check
```

Portable release installs are covered in `docs/install.md`.

## 2. Run A Scan

Active scans require both scope and confirmation.

```powershell
scaprobe scan --targets 192.168.1.10 --ports 22,80,443 --scope 192.168.1.0/24 --confirm-authorized
scaprobe scan --protocol udp --udp-retries 1 --targets 192.168.1.10 --ports 53,123,161 --scope 192.168.1.0/24 --confirm-authorized
```

Targets accept IP addresses, CIDR ranges, and hostnames. A hostname is resolved before anything else runs, so the scope guard always checks the addresses that will actually be probed - a name can never carry a target past it. Every address a name resolves to is scanned, up to 16 per name, and the stored job records the resolved addresses.

```powershell
scaprobe scan --targets lab.example.internal --ports 22,80,443 --scope 10.0.0.0/8 --confirm-authorized
```

The scanner retries silent UDP probes once by default and accepts correlated replies for protocols that expose transaction IDs, cookies, request IDs, or message IDs. Use `--udp-retries 0` for one attempt or a value up to 3 for lossy networks.

With service probing enabled, Scaprobe normalizes SSH product/version/platform fields and common FTP, SMTP, POP3, and IMAP greetings. HTTP results include a bounded status line plus selected `Server`, `Location`, `Content-Type`, and HTML title metadata. TLS-like services use a real bounded handshake to collect the certificate common name, up to five SAN entries, and expiry time; HTTPS-like services also collect HTTP metadata through the encrypted connection. A service name derived only from its well-known port is marked `inferred` in the dashboard instead of being presented as a confirmed fingerprint.

The default workload guard allows 1,000,000 host-port attempts. Scans above that configured threshold require a separate `--confirm-large-scan` acknowledgement and can never exceed the 100,000,000-attempt absolute limit. Timeout, worker concurrency, rate, and expanded-host counts are bounded as well. The dashboard previews attempts and an estimated minimum duration before submission.

Use built-in or custom port profiles:

```powershell
scaprobe scan --targets 192.168.1.10 --profile web --scope 192.168.1.0/24 --confirm-authorized
scaprobe scan --config .\scaprobe.toml --env lab --targets 192.168.1.10 --confirm-authorized
```

To capture automatic image evidence for discovered services, enable it per scan. Web services use real browser screenshots. SSH, FTP, SMTP, DNS, SNMP, database, and other non-web services receive an 800 x 600 PowerShell terminal image containing the executed diagnostic command, its output, and the scan's service banner or protocol response:

```powershell
pip install -e ".[screenshots]"
playwright install chromium
scaprobe scan --targets 192.168.1.10 --ports 22,53,80,443 --scope 192.168.1.0/24 --confirm-authorized --capture-evidence
```

`--capture-evidence` captures browser or terminal evidence. Browser navigation is limited to the scanned host. For TCP services, the terminal evidence runs a bounded PowerShell `.NET TcpClient.ConnectAsync()` diagnostic. SSH and Telnet stop at the client login prompt; FTP, SMTP, POP3, IMAP, and Redis use only pre-authentication capability commands such as `FEAT`, `EHLO`, `CAPA`, `CAPABILITY`, or `PING`. Implicit TLS variants perform the TLS handshake first. No username, password, key, `AUTH`, database startup, bind, or login packet is sent. UDP terminal evidence displays the response already obtained by the authorized scanner because PowerShell has no generic UDP connection test. If Playwright or a web page is unavailable, Scaprobe stores terminal evidence instead. The default timeout is 8 seconds and the unified automatic evidence set is capped at 20 services; adjust these bounds with `--screenshot-timeout-ms` and `--screenshot-max`.

In the dashboard, port presets and configured port profiles are selected from the same **Presets** row. **Import TXT** accepts a plain-text profile containing comma-separated ports, ranges, and `#` comments; imported profiles are validated and saved in the local dashboard browser for reuse. Enable `Use targets as authorized scope` to derive scan scope from the target field. Single IP targets become `/32` or `/128`; CIDR targets are used as-is.

## 3. Track Jobs And Results

Long port inventories are condensed into ranges in the dashboard Jobs table. The selected job summary can be expanded to show the complete stored port list. Result sets containing multiple hosts are separated into horizontally scrollable host tabs, with state tabs and counts for each host. Search and filters run against the complete stored result set, and the table supports 25, 50, 100, 250, or 500 rows per page with server-side pagination.

API-created scans stream results into SQLite in batches. After an unexpected API/desktop restart, resumable queued or running jobs enter `recovering`, preserve existing results, and continue with only missing host-port pairs. Cancellation requests take precedence over recovery.

Use the dashboard or `/v1/scans` REST endpoints to browse jobs, inspect progress and results, cancel or delete scans, annotate results, and manage manual evidence.

PNG, JPEG, GIF, and WebP files up to 10 MB are accepted. Manual images, web screenshots, and PowerShell terminal transcripts appear in result JSON, exports, reports, and the dashboard through controlled download URLs; the image bytes remain in the scan artifact directory next to the database.

Export or report:

```powershell
scaprobe export <scan_id> --format csv --state open --output .\open.csv
scaprobe export <scan_id> --format csv --bundle-evidence --output .\scan-evidence.zip
scaprobe export <scan_id> --format xlsx --output .\scan-results.xlsx
scaprobe report <scan_id> --format html --output .\scan-report.html
scaprobe report <scan_id> --format html --embed-evidence --output .\scan-report-offline.html
```

The evidence bundle contains `results.csv`, `manifest.json`, and the attached image files under `evidence/`. Each CSV evidence entry includes its relative `bundle_path`.

The Excel export contains a filterable **Results** sheet and an **Evidence** sheet with the image files embedded directly in the workbook.

Dashboard **Report**, **JSON**, **CSV**, **Excel**, and evidence thumbnails all open inside the page instead of a new tab, because the packaged desktop window is a webview that drops new-window navigation. JSON and CSV are previewed as text, the Excel workbook reports its size, and the preview's **Save** button writes the real file - the CSV bundle zip for **CSV**, the workbook for **Excel**. Clicking an evidence thumbnail shows the full-size image in the same viewer. Close it with the Close button, a click outside, or Esc.

HTML, Markdown, and JSON reports disclose how many stored results are included. When `--limit` truncates report details, open ports, error or ambiguous states, and annotated results are selected before routine closed or filtered rows, while state, service, protocol, and per-host summaries are calculated from the complete stored scan. The HTML report keeps the compact **Open Results** columns and adds scan configuration, per-host state totals, service-identification details, a review queue, and a 320 x 240 non-cropping evidence gallery with print styling. Service details, review items, and the evidence gallery use native accessible disclosure controls: sections with more than five items start collapsed, long banner/error/note values have their own 160-character preview, and print output expands all content. `--embed-evidence` embeds up to 50 MB of image files in an HTML report so it remains viewable without the local API; the dashboard Report action enables this mode automatically.

## 4. Benchmark And Stability Checks

The benchmark and soak helpers execute real scans and therefore require the same explicit scope and authorization confirmation as normal scans:

```powershell
py -3 tools\benchmark_scan.py --targets 127.0.0.1 --ports 1-1024 --scope 127.0.0.1/32 --confirm-authorized --warmup-runs 1 --runs 5 --output benchmark.json
py -3 tools\soak_scan.py --targets 127.0.0.1 --ports 1-1024 --scope 127.0.0.1/32 --confirm-authorized --iterations 20 --max-memory-growth-mb 32 --output soak.json
```

The benchmark report verifies every planned result was emitted, then records state counts, latency percentiles, elapsed-time and checks-per-second distributions, controller CPU/RSS, and Rust-engine RSS when available. The soak assessment fails on incomplete iterations, engine errors, state-count drift, or memory growth above the configured threshold. Result objects are not retained by default, so the measurement exercises the bounded streaming path used by large scans.

## 5. Analyze PCAP Files

```powershell
scaprobe pcap .\capture.pcapng --top 10
```

PCAP summaries include protocols, top talkers, conversations, DNS, HTTP, TLS, ARP, ICMP, and DHCP metadata.

## 6. Live Capture

Live capture is bounded and requires confirmation.

```powershell
scaprobe capture --output .\capture.pcap --duration-s 10 --confirm-authorized
scaprobe capture --output .\sample.pcap --count 100 --iface "Ethernet" --confirm-authorized --json
```

Windows usually requires Npcap and an elevated terminal. macOS/Linux may require root or packet capture privileges.

## 7. Send Template Packets

Scaprobe allows template-based traffic only. Arbitrary Scapy expressions and raw byte injection are intentionally not supported.

```powershell
scaprobe send tcp --target 192.168.1.10 --dport 443 --scope 192.168.1.0/24 --confirm-authorized --dry-run --json
scaprobe send icmp --target 192.168.1.10 --scope 192.168.1.0/24 --count 3 --confirm-authorized
scaprobe send dns --target 192.168.1.1 --dns-name example.com --scope 192.168.1.0/24 --confirm-authorized
```

Packet audit history remains available in the dashboard and REST API.

## 8. Data Plugins

Plugins are JSON data files. They do not execute code.

```powershell
scaprobe plugins validate .\docs\scaprobe.plugin.example.json
scaprobe plugins list --plugin .\docs\scaprobe.plugin.example.json
scaprobe scan --plugin .\docs\scaprobe.plugin.example.json --targets 192.168.1.10 --profile lab-app --scope 192.168.1.0/24 --confirm-authorized
```

Plugins can add port profiles, TCP/UDP service names, and simple banner/response fingerprint rules.

## 9. HTTP OAST

OAST support records inbound HTTP callbacks. It does not generate exploit payloads.

Start the API on the DB you want to store callbacks in:

```powershell
scaprobe serve --host 127.0.0.1 --port 8765
```

Create callback tokens and inspect or delete interactions from the dashboard or `/v1/oast/sessions` REST endpoints. Use the generated `/oast/<token>` URL only in your authorized test.

Sensitive headers such as `Authorization` and `Cookie` are redacted before storage.

## 10. Local API And Dashboard

```powershell
scaprobe serve --host 127.0.0.1 --port 8765
```

Open:

```text
http://127.0.0.1:8765/dashboard
```

A loopback bind (`127.0.0.1`, `localhost`, `::1`) needs no token. Any other bind is reachable from the network and therefore always requires one: pass `--api-token`, set `SCAPROBE_API_TOKEN`, or let the startup print the token it generated.

```powershell
scaprobe serve --host 0.0.0.0 --port 8765 --api-token <token>
```

With a token active, every endpoint requires `Authorization: Bearer <token>`. Open `/dashboard?token=<token>` once and the browser keeps an `HttpOnly` session cookie, so later URLs no longer carry the token. Only the `/oast/<token>` callback receiver stays open, because the scanned systems that deliver those callbacks cannot present operator credentials. The token authenticates the API; it is not transport security, so put TLS in front of anything beyond a trusted network.

Import `postman/scaprobe.postman_collection.json` into Postman for API examples.

## 11. Desktop Mode

```powershell
scaprobe desktop
```

This starts the same local API/dashboard on the fixed `127.0.0.1:8765` address and opens the dashboard. Use `--port 0` only when a free ephemeral port is preferred:

```powershell
scaprobe desktop --host 127.0.0.1 --no-open
```

`desktop` accepts `--api-token` and follows the same rule as `serve`: loopback stays open, any other bind gets a token, and the opened URL carries it once.

Installer and Tauri wrapper notes are in `docs/desktop-packaging.md`.

## 12. Backup And Restore

Use the dashboard or `/v1/db/export` and `/v1/db/import` REST endpoints. Backups include scan history, annotations, attached image evidence, PCAP analyses, packet audits, and OAST sessions/interactions.
