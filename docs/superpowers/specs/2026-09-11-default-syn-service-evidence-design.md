# Default SYN and Service Evidence Design

## Approved behavior

- Dashboard TCP scans use IPv4 SYN scanning by default.
- A separate **TCP Connect scan only** checkbox bypasses SYN and scans every
  selected TCP port with the existing connect scanner.
- With **Service detection** off, a SYN scan emits the SYN result directly and
  does not connect to a SYN-open port.
- With **Service detection** on, only SYN-open ports enter the existing TCP
  connect and fingerprint path. A failed follow-up must not downgrade the
  observed SYN-open state.
- Dashboard service detection also enables automatic evidence collection.
  Web ports use browser images; other TCP services use the real-console capture
  path, with the existing terminal-render fallback.
- UDP behavior and the independent UDP service-probe checkbox do not change.
- Authorization, scope validation, SYN retry limits, and Npcap fail-closed
  behavior do not change.

## Compatibility boundary

The dashboard is the product default being changed. Existing API and CLI
fields remain compatible: `syn_sweep`, `service_probe`,
`capture_screenshots`, and `capture_console` are not renamed. Direct callers
can continue to select connect scanning or evidence behavior explicitly.

## Verification

- Dashboard contract tests cover the default SYN/connect-only choice and the
  service-detection-to-evidence mapping.
- Rust feature tests cover pure SYN-open emission when service detection is off
  and the preserved SYN observation after a requested follow-up.
- Python and Rust suites, a SYN-feature release build, and a focused local
  runtime smoke test are required before replacing the installed build.
