# Changelog

All notable Netroach changes are tracked here.

## 0.2.7 - 2026-09-14

- Photograph the browser's own window for a web port, rather than the page alone. The window carries what the page cannot: the address actually arrived at, and the browser's judgement beside it - the padlock, the "not secure" on a plaintext management page, the warning on a certificate that does not match. It is moved off the visible desktop first, the way a console capture is, and where there is no desktop to draw on the capture stays headless and the page is the evidence as before.
- Record something for a page behind a login box, which had no evidence at all. A browser driven by the capture does not render a 401 - it fails the navigation - and the transcript it fell back to had no mode for a web port, so the record read only that the port answered. One unauthenticated request now keeps the response head, where the finding is: the status, the authentication scheme and realm the server offers, the server header.
- Stop writing a target's side of the conversation. The transcript prints replies under a label and a reader takes the unlabelled lines beside them for more of the same, but three were ours: "login as:" is PuTTY's wording and SSH never sends a prompt in the clear, "USER:" is a command a client sends rather than anything POP3 replied, and "User (host):" imitated the Windows ftp client with the real host name in it. The transcript now carries what the target said and what was sent, and nothing else.
- Name a service by what it says rather than by the port it says it on. Telnet is identified by its option negotiation, which nothing else opens with - a switch on a port no table maps went from unknown to telnet with its model name as the banner. POP3, IMAP and memcached are no longer recognised only where the port already agreed; the greeting names the service and the port decides how sure that is. A banner that merely mentions SMTP is no longer a mail server. Where a greeting states a product and version plainly, they are split out as fields a reader can check an advisory against.
- Bundle the browser that has a window. The headless shell can photograph a page and nothing else; only the full build ships, so the bundle is 430MB rather than 274MB, and not the 701MB both would cost.
- Keep the client beside the console for services that speak in lines. POP3, IMAP, SMTP and FTP lost the telnet client pane in 0.2.6 - the pane that photographs their actual exchange. TLS and binary protocols still get none, because pointing telnet at those photographs mojibake that looks like evidence and says nothing.

## 0.2.6 - 2026-09-14

- Start the SYN-enabled engine on a machine that has no Npcap. Linking Npcap's import library made `wpcap.dll` a load-time dependency, so the one binary that also carries connect and UDP scanning could not start at all without the driver - and said nothing, because the launcher sees a missing DLL rather than a message. The library is delay-loaded now, and the sweep asks for it before its first call so a forced SYN scan fails with a sentence naming Npcap instead of ending the process.
- Find Npcap where it actually installs. `System32\Npcap` is not on the loader's search path; only Npcap's optional WinPcap API-compatible mode also leaves a copy where a plain load finds it. That directory is tried by name too, so an ordinary install is no longer read as no install at all.
- Offer SYN only when the driver is present as well as the feature, and say which of the two is missing. The form told every operator that a build including Npcap was needed - true while the SYN build carried an installer, and exactly wrong for the fresh install that is now the ordinary case.
- Run the Chromium dashboard suite under the plain `pytest` the project documents. It skipped without an environment variable, and a skipped suite reads as a passing one - while carrying the fixture for the SYN-versus-Connect regression that reached users in 0.2.4.

## 0.2.5 - 2026-09-13

- Applied the scoped ControlDeck 2001 dashboard theme: Windows 2000-style title bars, raised controls, sunken inputs, charcoal readouts, grid tables, visible focus, forced-colors support, and compact mobile navigation without changing existing IDs or authorization states.
- Reduced the sidebar to the port-scan entry, made port scanning the initial view, and reflow the workspace when the rail expands instead of covering the form.
- Raised compact scan-button labels to at least 14px, improved disabled-label contrast, allowed long labels to wrap, and removed the nested raised-button styling that obscured preset names.
- Made job IDs, status labels, targets, and host-summary values easier to read with 15-16px semibold text while keeping the selected-row and status-dot cues.
- Replaced the three always-visible scan-mode explanations with accessible `(?)` help buttons that reveal the same text on mouse hover, keyboard focus, or touch focus without changing checkbox state.
- Fixed the SYN-capable Chromium regression fixture so the default SYN and optional TCP Connect modes are exercised in the real browser suite.
- Store the final same-host redirect URL with a web screenshot, so evidence records the page that was actually photographed.
- Stop exact console-window searches from falling back to a similarly titled window.
- Allow a SYN-enabled installer to use the Npcap SDK without embedding an Npcap installer; the user-direct official Npcap path is now the default packaging policy.
- Includes the post-0.2.4 scan load distribution, parallel route resolution, rate-limited SYN resets, compact resume spans, and per-host evidence allocation work.

## 0.2.4 - 2026-09-11

- Fixed a SYN-capable build defaulting to Connect scanning. The scan form read "health has not answered yet" as "this engine cannot SYN", ticked Connect-only on load, and never untied it, so every scan started from the dashboard was a Connect scan unless the operator noticed.
- Stopped sending frames to a host that never answered ARP. The incomplete neighbour entry is all zeroes, and a switch floods rather than drops an address it has never learned: a /24 with two hundred empty addresses and a thousand ports put two hundred thousand flooded frames on the segment. Those hosts are skipped and reported as not having answered ARP, which is a different thing from a filtered port.
- Refused to sweep a broadcast address, which reaches every host on the segment and cannot produce a result. The target is skipped with that reason; the rest of the scan proceeds.
- Closed the half-open connection a probe leaves on a target. The scanning host's firewall drops the unsolicited SYN-ACK rather than resetting it, so the target held the connection and retransmitted until its own timeout - measured, four SYN-ACKs and no reset. On a controller or a printer whose backlog is a slot or two, that slot was unavailable for the best part of a minute.
- Lowered the narrow sweep floor to 500 probes a second, where the measured answer stops depending on luck: over 512 ports at 1,000 the open port came back in two runs of three, and at 500 in five of five with nothing unanswered.
- Let a wide sweep use the greater of that floor and ten probes a second per host, capped by what the machine can send. Probes are shared across hosts, so a scan of thousands was paced as though aimed at one fragile device. A scan must raise its own rate limit above the floor for the budget to give it more.
- Sent SYN frames to the driver in batches rather than one call each, which was the ceiling rather than the rate limit: a subnet sweep measured 2,387 probes a second before and 5,010 after. The batch is capped by the host count, so a burst spreads across the subnet.
- Sent a sweep's bulk results as one summary per host instead of a line per probe. Storing twenty-five million results went from about an hour to under a second; the counts and port ranges are unchanged.
- Failed a sweep whose replies Npcap dropped for want of buffer, rather than reporting those probes as filtered.
- Showed why a scan failed, and what a SYN sweep and the evidence pass are doing while they run - neither stores a result while it works, so the bar sat at 0% for one and 100% for the other.
- Added `tools/syn_crosscheck.py` and `docs/testing-and-measurement-ko.md`.

## 0.2.3 - 2026-09-11

- Fixed a SYN scan of a subnet the scanning machine sits in failing entirely. The sweep cannot probe an address the machine answers to and refused one by failing the whole run, so a twelve-subnet scan died on the one subnet holding the scanner. Those addresses now join loopback on the connect path.
- Showed why a scan failed. The reason was recorded and never rendered, so diagnosing a refused target meant reading the database row by hand.
- Sent SYN frames to the driver in batches rather than one call each. The per-call cost, not the rate limit, was the ceiling: a subnet sweep measured 2,387 probes a second before and 5,010 after. Batches are capped by the host count, so a burst spreads across the subnet and a single-host sweep still sends one frame at a time.
- Allowed a wide sweep the greater of the flat rate limit and ten probes a second per host, capped by what the machine can send. The per-host budget only raises the ceiling, so narrow scans pace exactly as before. A scan must raise its own rate limit above 5,000 for the budget to give it more.
- Stopped a sweep storing millions of rows it would only fold away. Closed results carried a constant note that made them unfoldable; without it a 65,535 port sweep of a live host keeps three rows instead of 27,101. Result batches also grew from 250 to 5,000, with a one second ceiling on waiting, raising storage from about 16,500 results a second to 50,000.
- Failed a sweep whose replies Npcap dropped for want of buffer, rather than reporting the probes as filtered. Measured clean at the rates a sweep uses.
- Reported what a SYN sweep and the automatic evidence pass are doing while they run. Neither stores a result while it works, so the progress bar sat at 0% for the sweep and 100% through evidence capture.
- Offered SYN scanning in the dashboard only where the engine was built with it, and refused unsorted SYN input rather than silently losing replies to it.

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
