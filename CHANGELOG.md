# Changelog

All notable Netroach changes are tracked here.

## 0.1.0 - Unreleased

- Added the authorization-first CLI, local REST API, SQLite storage, and Postman collection.
- Added the Rust `netroach-engine` TCP/UDP scanner with NDJSON streaming output.
- Added streaming PCAP/PCAPNG analysis for protocol counts, talkers, conversations, DNS queries, HTTP hosts, and TLS SNI/ALPN metadata.
- Added template-based packet sending for ICMP, TCP, UDP, DNS, and HTTP with scope and authorization checks.
- Added portable packaging and smoke tests for CLI startup diagnostics.
- Added self-contained Windows desktop packaging with a frozen Python backend, bundled Rust engine, automatic free-port startup, health readiness, logging, and child-process cleanup.
- Bundled Playwright headless Chromium and the WebView2 offline installer for browser screenshot evidence and fully offline destination-PC installation.
- Added API token authentication: loopback binds stay open, non-loopback binds always require a token (`--api-token`, `NETROACH_API_TOKEN`, or a generated one), and the dashboard exchanges `?token=` for an HttpOnly cookie. Only the `/oast/<token>` callback receiver stays unauthenticated.
- Fixed the engine rate limiter capping real throughput far below the configured rate: slots shorter than one OS timer tick no longer sleep, so the schedule paces the average instead of the timer granularity.
- TCP connect answers from routers and firewalls (host/network unreachable, administratively prohibited, connect timeout) are now reported as `filtered` with their reason, instead of being buried in `error`.
- Bounded the engine event queue and released the reader thread on cancellation, so a fast engine cannot grow memory without limit or leak a thread per cancelled scan.
- Moved the dashboard out of a Python string into `netroach/static/dashboard.html`.
- Result paging now uses a `(scan_id, host, port)` covering index instead of sorting the whole scan for every page, the database runs in WAL mode with `synchronous=NORMAL`, and the dashboard stops polling while its window is hidden - all of which matter most on low-end machines.
- Fixed reports, evidence images, and JSON/CSV/Excel exports doing nothing in the packaged desktop app: those actions relied on `target="_blank"`, which the desktop webview drops. Reports, evidence, and exports now open in an in-page viewer - JSON and CSV are previewed as text, workbooks report their size - and the viewer's Save button writes the real file, so both the browser and the desktop build behave the same.
- Scan targets accept hostnames as well as IP addresses and CIDR ranges. Names are resolved before parsing and scope checking, so the scope guard always sees the addresses that will be probed.
- Added ruff and mypy configuration plus a `requirements.lock.txt` with the exact runtime versions a release was built from. Fixed the loop-variable binding in the Playwright route handler that confines evidence capture to the scanned host.
- The frozen desktop backend turns on the uvicorn request log at `--log-level debug`, and the desktop shell forwards `NETROACH_LOG_LEVEL`, so a packaged app can be traced through `backend.log`. CI now runs ruff and builds the engine on its declared minimum Rust version.
- Renamed the project from Scaprobe to Netroach: CLI command, Python package, Rust engine crate, environment variables, desktop identifier, and artifact names. A database left in the old `Scaprobe` data directory is moved to the new location on first start, and the portable archive now also carries `requirements.lock.txt`.
- Reworked the dashboard: a refreshed light design system with a blue accent that no longer collides with the green/amber/red port states, grouped navigation, a one-line purpose under every view title, and a fully Korean interface. Technical vocabulary (open/filtered, CIDR, BPF, TCP flags) stays in English.
- HTML and Markdown scan reports are now written in Korean. The JSON report keeps machine-readable English keys and values so downstream tooling is unaffected, and report evidence images no longer sit inside a new-window link that the desktop viewer would drop.
