# Default SYN and Service Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make dashboard TCP scans default to SYN, use service detection as the SYN-open connect/evidence gate, and retain an explicit connect-only choice.

**Architecture:** Reuse the existing `syn_sweep` and `service_probe` fields. The Rust SYN result branch emits open immediately when service probing is disabled; the dashboard maps one service checkbox to fingerprinting plus both automatic evidence flags.

**Tech Stack:** Rust 2021, Tokio, Python 3.10+, FastAPI, vanilla HTML/JavaScript

**Spec:** `docs/superpowers/specs/2026-09-11-default-syn-service-evidence-design.md`

## Global Constraints

- Keep authorization, scope, Npcap, rate, and retry gates unchanged.
- Preserve the existing API and CLI field names.
- Do not change UDP service-probe behavior.
- Do not stage, commit, merge, push, or publish.

---

### Task 1: SYN-open follow-up gate

**Files:**
- Modify: `crates/netroach-engine/src/main.rs`
- Test: `crates/netroach-engine/src/main.rs`

**Interfaces:**
- Consumes: `service_probe: bool` already passed to `run_syn_scan`
- Produces: a direct `PortEvent(state="open", evidence="SYN-ACK observed")` when false, or the existing connect/fingerprint follow-up when true

- [ ] Add a feature-gated unit test proving disabled service detection produces a direct SYN-open event without service fields.
- [ ] Run the focused test and confirm it fails because the direct-event helper is absent.
- [ ] Implement the direct-event helper and select it in the `ProbeState::Open` branch.
- [ ] Run focused and complete Rust feature tests.

### Task 2: Dashboard scan semantics

**Files:**
- Modify: `netroach/static/dashboard.html`
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: `tcp_connect_only` checkbox and the existing `service_probe` checkbox
- Produces: `syn_sweep = protocol is TCP and connect-only is false`; for TCP, `capture_screenshots` and `capture_console` equal `service_probe`

- [ ] Replace the old dashboard expectations with failing tests for default SYN, connect-only, and unified service evidence.
- [ ] Run the focused dashboard tests and confirm the old UI fails them.
- [ ] Replace the SYN opt-in control with connect-only and remove the redundant initial evidence checkboxes.
- [ ] Derive the request's service and evidence flags once and update preset handling.
- [ ] Run the complete dashboard and API tests.

### Task 3: Documentation, build, and runtime checks

**Files:**
- Modify: `docs/user-guide.md`
- Modify: `docs/syn-sweep-handoff.md`
- Modify: `README.md`

**Interfaces:**
- Documents the dashboard-only default while keeping direct CLI/API compatibility explicit.

- [ ] Update user-facing scan-mode and service-evidence behavior.
- [ ] Run all Python tests and both default and `syn-sweep` Rust tests.
- [ ] Build the SYN-enabled release engine and desktop installer.
- [ ] Replace the installed Netroach build and run a focused authorized local smoke test; record environmental limitations separately.
