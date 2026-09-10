# SYN Sweep Personal Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an opt-in IPv4 SYN scanner and a private NSIS build that interactively installs Npcap when required.

**Architecture:** Keep packet construction pure, add fail-closed Windows adapter mapping and a focused Npcap runner, then pass an explicit `syn_sweep` setting through the existing Rust/Python boundary. Stage a user-supplied Npcap installer only for personal NSIS builds and verify the installed driver before modifying Netroach files.

**Tech Stack:** Rust 2021, Tokio, pcap 2.5, windows-sys 0.61, Python 3.10+, FastAPI, Tauri 2, NSIS

**Spec:** `docs/superpowers/specs/2026-09-10-syn-sweep-personal-installer-design.md`

## Global Constraints

- Active scans still require explicit authorization confirmation and scope.
- SYN probes are IPv4-only and capped at 5,000 packets per second.
- Default builds must not link Npcap.
- The private Npcap bundle must never be committed or externally published.
- Do not stage, commit, merge, push, or create a pull request without a separate request.
- Elevated, clean-VM, and real-network tests remain separate evidence gates.

---

### Task 1: Fail-closed Npcap device mapping

**Files:**
- Modify: `crates/netroach-engine/src/netlink.rs`

**Interfaces:**
- Consumes: Windows interface index from `Route.interface_index`
- Produces: `pcap_device_for_interface(interface_index: u32, devices: &[pcap::Device]) -> Result<pcap::Device, RouteError>`

- [x] Add failing unit tests for uppercase/lowercase GUID matching, no match, and ambiguous matches.
- [x] Run `cargo test --manifest-path crates/netroach-engine/Cargo.toml --features syn-sweep netlink` and confirm the new symbols are missing.
- [x] Implement index-to-LUID-to-GUID conversion, canonical GUID formatting, and exact case-insensitive device matching.
- [x] Re-run the targeted tests and the default no-feature Rust suite.

### Task 2: Compact probe state and retry planning

**Files:**
- Create: `crates/netroach-engine/src/syn_runner.rs`
- Modify: `crates/netroach-engine/src/main.rs`

**Interfaces:**
- Produces: `ProbeStates::new(len)`, `record(index, SynReply)`, `get(index)`, and `unanswered_indices()`
- Produces: `SynSweepConfig { timeout, rate_limit_per_sec, retries }`

- [x] Add failing tests proving four two-bit states fit in one byte, duplicates are idempotent, open wins over a later close, and retries select only unanswered probes.
- [x] Run the targeted feature test and confirm failure because the module/API is absent.
- [x] Implement only the packed state and deterministic `port-major` probe-index helpers.
- [x] Re-run targeted tests until green without adding I/O.

### Task 3: Npcap capture and send runner

**Files:**
- Modify: `crates/netroach-engine/src/syn_runner.rs`
- Modify: `crates/netroach-engine/src/main.rs`
- Modify: `crates/netroach-engine/examples/loopback_roundtrip.rs`

**Interfaces:**
- Consumes: `resolve_route`, `pcap_device_for_interface`, `build_syn_frame`, `parse_syn_reply`, and the existing `RateLimiter`
- Produces: `run_syn_sweep(targets, ports, config) -> Result<SynSweepOutcome>`

- [x] Add failing tests around pure adapter grouping, datalink rejection, rate capping, and reply-to-probe indexing.
- [x] Implement receiver readiness barriers, per-interface capture/send handles, the BPF filter, bounded response windows, and one retry by default.
- [x] Make every pcap, thread, route, and link-type failure abort rather than fabricate filtered results.
- [ ] Update the loopback example to exercise the runner boundary while retaining its explicit open/closed listener assertions.
- [x] Run feature tests; record the elevated example as `UNVERIFIED` unless UAC execution is completed.

### Task 4: Rust engine CLI integration

**Files:**
- Modify: `crates/netroach-engine/src/main.rs`
- Modify: `crates/netroach-engine/tests/engine_cli.rs`

**Interfaces:**
- Produces: `--syn-sweep` and `--syn-retries 0..2`
- Preserves: existing NDJSON `PortEvent` and `SummaryEvent` schemas

- [x] Add failing CLI tests for unavailable feature builds, UDP conflicts, retry bounds, and unchanged connect defaults.
- [x] Route TCP SYN scans through `run_syn_sweep`; emit closed/filtered once and pass open ports to the existing connect/service path.
- [x] Preserve SYN `open` when the follow-up connect fails, recording the follow-up error as evidence instead of changing state.
- [x] Run all default and feature Rust tests.

### Task 5: Python/API/dashboard setting propagation

**Files:**
- Modify: `netroach/models.py`
- Modify: `netroach/engine.py`
- Modify: `netroach/config.py`
- Modify: `netroach/cli.py`
- Modify: `netroach/api.py`
- Modify: `netroach/static/dashboard.html`
- Modify: `tests/test_engine.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_api.py`
- Modify: `tests/test_config.py`
- Modify: `tests/test_dashboard.py`

**Interfaces:**
- Produces: `EngineSettings.syn_sweep: bool` and request/config field `syn_sweep`

- [x] Add failing tests that opt-in TCP requests append `--syn-sweep`, UDP requests reject it, and default commands remain unchanged.
- [x] Add the CLI/API/config field and persist it in scan job parameters for recovery.
- [x] Add an explicit TCP-only dashboard checkbox and disable it for UDP.
- [x] Run the targeted Python tests, then the full Python suite.

### Task 6: Private Npcap-aware NSIS build

**Files:**
- Modify: `tools/build_desktop.py`
- Modify: `tests/test_build_desktop.py`
- Modify: `desktop/src-tauri/installer-hooks.nsh`
- Modify: `.gitignore`

**Interfaces:**
- Produces: build arguments `--syn-sweep`, `--npcap-sdk-lib PATH`, and `--npcap-installer PATH`
- Produces: ignored staging file `desktop/src-tauri/resources/installers/npcap-installer.exe`

- [x] Add failing tests for Cargo feature construction, required paired inputs, NSIS-only validation, staging, and SHA-256 reporting.
- [x] Extend the build tool to prepend the SDK directory to `LIB`, add `--features syn-sweep`, and stage only an explicitly supplied installer.
- [x] Add an NSIS compile-time conditional so ordinary builds remain unchanged when no staged installer exists.
- [x] Before browser cleanup, check Npcap driver version and `AdminOnly`; run the staged installer interactively when needed and abort unless Npcap 1.88+ with `AdminOnly=0` is observed afterward.
- [x] Do not add an uninstall action for Npcap.
- [x] Run build-tool tests and generate an NSIS bundle when a local installer file is available.

### Task 7: Documentation and complete verification

**Files:**
- Modify: `docs/syn-sweep-handoff.md`
- Modify: `docs/desktop-packaging.md`
- Modify: `docs/release-checklist.md`
- Modify: `README.md`

- [x] Correct “no per-probe state” to the two-bit bounded-state design and document the retry default.
- [x] Document the private-build command, manual Npcap UI step, `AdminOnly=0`, personal-use boundary, and non-removal behavior.
- [x] Run formatting, full Python tests, default Rust tests, feature Rust tests, and both default/feature builds.
- [x] Inspect `git diff --check`, `git status`, and the generated installer contents if an installer was built.
- [x] Report UAC loopback, clean-VM installation, real-network cross-validation, and final package acceptance as `UNVERIFIED` unless directly executed.
