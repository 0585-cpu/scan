# Changelog

All notable Netroach changes are tracked here.

## 0.2.2 - 2026-09-11

- Offered SYN scanning in the dashboard only where the engine was built for it. The engine now answers a `capabilities` subcommand, and a build without SYN support no longer had every TCP scan it started rejected. Anything uncertain falls back to Connect, which works on every build.
- Rejected unsorted SYN target and port input instead of silently losing replies to it, which would have reported open ports as filtered with nothing to show the run went wrong.
- Reported what a SYN sweep is doing while it runs. A sweep publishes no result until its last retry settles, so a scan of millions of probes showed 0% for an hour and could not be told from one that never started.
- Reported the automatic evidence pass the same way. It runs after every result is stored, so the bar read 100% for as long as it took to photograph each open port.
- Added `tools/syn_crosscheck.py`, which judges a SYN sweep against a Connect scan of the same ports and refuses to compare scans that did not cover the same work.
- Recorded the real-LAN cross-check the sweep passes, including what a high `filtered` count means: the target rate-limiting its resets, not a fault.

## 0.2.1 - 2026-09-11

- Fixed Linux/macOS type checking of the Windows-only ctypes DLL and callback exports without changing Windows calls or calling conventions. DLL handle annotations now use the portable CDLL base type.
- Made the fake window-enumeration test independent of the Windows callback ABI, used host-native SDK paths in the build test, and included the Playwright test dependency in the development extra so clean CI environments can run evidence tests.
- Retained the SYN, service/evidence, and dashboard changes from 0.2.0 in the personal-use Npcap-inclusive Windows installer.

## 0.2.0 - 2026-09-11

- Added the optional Windows IPv4 TCP SYN scan runner, bounded retries and rate, adapter-specific route/capture handling, and CLI/API configuration. Loopback targets use TCP connect; SYN scanning rejects UDP and IPv6.
- Made SYN the default TCP mode in the desktop dashboard, with an explicit TCP Connect-only checkbox. Service detection enables SYN-open Connect rechecking, service/banner analysis, and automatic browser/console evidence; disabling it preserves the SYN result without a service connection.
- Preserved observed SYN-open results when follow-up Connect fails, and kept long-running scans alive through an independent heartbeat with cancellation and recovery support.
- Added personal-use NSIS packaging with signature-verified Npcap input and a Npcap 1.88+/AdminOnly=0 installation check. Npcap-containing bundles are not for external redistribution.
- Moved the searchable Jobs table above the selected job's summary, exports, results, and evidence, with an independently scrolling compact job list.
- Fixed stale job/search responses replacing current results, old port sources leaking into open-port rescans, missing saved port-profile restoration, recapture tracking changing with job selection, and hidden controls incorrectly displaying.
- Added isolated Chromium/API regression coverage for scan options, job selection, evidence previews, rescan scope, profile restoration, recapture controls, and out-of-order responses.

## 0.1.0 - 2026-09-08

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
- The package now type-checks clean under mypy, and CI enforces it alongside ruff. The fixes were annotations only: a `@contextmanager` that declared `Iterable` instead of `Iterator`, address types named concretely instead of through the private `ipaddress._BaseAddress`, and dynamic scapy/JSON values typed `Any` rather than `object`.
- Live capture can now run through pktmon, the packet monitor built into Windows 10 1809 and later, so a Windows capture needs no third-party driver and no Npcap redistribution licence. `--backend auto` prefers it and falls back to scapy, which is still chosen automatically for a full BPF filter or a specific interface. Diagnostics report `pktmon_available` and the reason.
- PCAP summaries now report `decoded_frames` and `undecoded_frames` next to `packet_count`. A pktmon capture on a Wi-Fi adapter holds a raw 802.11 copy of every Ethernet frame, so the total alone read as double; every statistic counts the decoded frames, and the capture file still keeps everything.
