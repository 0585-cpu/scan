# SYN Sweep and Personal Npcap Installer Design

## Purpose

Netroach must perform IPv4 TCP SYN scanning on the owner's Windows PCs even
when Npcap was not installed before Netroach setup. The installed application
must retain the existing authorization and scope checks, and the normal TCP
connect scanner must remain available as an unchanged fallback implementation.

This is a private, personal-use build. It is not an externally redistributable
Npcap bundle.

## Confirmed baseline

- `syn_sweep.rs` already builds SYN frames, creates stateless cookies, and
  parses SYN-ACK/RST replies.
- `netlink.rs` already resolves the Windows route, source address, interface
  index, source MAC, and next-hop MAC.
- The missing engine work is interface-index-to-Npcap-device mapping plus the
  send, capture, retry, and result paths.
- The desktop build uses Tauri 2 and an NSIS installer hook. The installer is
  currently per-user, while the Npcap child installer requests its own UAC
  elevation.

## Engine design

The SYN path remains Windows-only and behind Cargo's `syn-sweep` feature. A
normal build does not link pcap or Windows packet-capture APIs.

`netlink.rs` maps the `GetBestRoute2` interface index through
`ConvertInterfaceIndexToLuid` and `ConvertInterfaceLuidToGuid`, then performs a
case-insensitive exact GUID match against `pcap::Device::list()`. Missing,
ambiguous, unsupported, or failed mappings stop the SYN scan rather than
silently selecting another adapter.

A focused `syn_runner.rs` module owns Npcap I/O. It prepares one sender and one
capture thread per interface, starts capture before transmission, applies a
`tcp and dst port <source_port>` BPF filter, and accepts only Ethernet or Npcap
loopback datalinks. Ports are traversed outside hosts so consecutive probes are
spread across targets. The effective rate is `min(requested_rate, 5000)`.

Replies are authenticated with the existing SYN cookie. Probe state uses two
bits per host-port pair (`unanswered`, `open`, `closed`) so duplicate replies
are idempotent and only unanswered probes are retried. This corrects the older
handoff's literal “no per-probe state” wording while preserving its real
requirement: no socket, task, timer, or heap object per probe. Sixteen million
probes use about 4 MiB; the 100-million absolute safety limit uses about 25 MiB.

The default is one retry. After the final response window, unanswered probes
are emitted as `filtered`, RST replies as `closed`, and SYN-ACK replies as
`open`. Open replies are verified through the existing TCP connect/service
probe path, but a failed follow-up connection must not overwrite the observed
SYN-ACK state.

Loopback, the selected source address itself, non-IPv4 targets, UDP scans, and
unsupported link types do not enter raw SYN I/O. Invalid combinations receive
an explicit error or use the existing connect path where documented.

## Application integration

The Rust engine accepts `--syn-sweep` and `--syn-retries 0..2`. Python carries
the same setting through CLI, API, saved scan parameters, recovery, and the
dashboard. Existing authorization confirmation and explicit scope validation
remain mandatory before Python launches the engine.

The SYN-enabled dashboard uses SYN for TCP by default and exposes an explicit
connect-only checkbox. Service detection gates the SYN-open connect/fingerprint
follow-up and enables automatic browser/console image evidence. Direct CLI/API
callers retain the explicit `syn_sweep` field for compatibility. The rate input
may be lower than 5,000 pps, but the engine enforces 5,000 pps as an absolute
SYN ceiling even if another caller bypasses the UI.

## Personal installer design

`tools/build_desktop.py` gains explicit inputs for the Npcap SDK library
directory and the locally downloaded Npcap installer. It never downloads Npcap
and never places credentials or the installer binary in Git. A personal SYN
installer build:

1. builds `netroach-engine` with `--features syn-sweep` and the supplied SDK
   library directory prepended to `LIB`;
2. copies the supplied installer to an ignored staging path with a fixed build
   name and prints its SHA-256;
3. permits only an NSIS bundle because the existing NSIS hook is the controlled
   prerequisite path;
4. embeds the Npcap installer into NSIS temporary storage, not the installed
   Netroach resource directory.

Before NSIS removes or replaces any Netroach files, the hook reads Npcap's
driver version and `AdminOnly` registry value. Npcap 1.88 or newer with
`AdminOnly=0` passes. Otherwise the bundled free installer runs interactively,
with a message instructing the owner to allow non-administrator access. The
hook then verifies the registry values again. Cancellation, failure, an older
driver, or `AdminOnly=1` aborts Netroach installation.

Npcap is machine-wide and may be shared by other tools. The Netroach
uninstaller therefore never removes or changes Npcap.

## Security and distribution boundaries

- The combined installer is for the owner's PCs only and must not be published
  or transferred to third parties.
- The Npcap installer must be downloaded manually from the official source and
  passed by explicit path at build time.
- Allowing non-administrator access exposes packet capture/injection to other
  local accounts. This design is accepted only for the owner's personal PCs.
- Active scans still require explicit authorization and scope.
- No exploit checks, evasion, spoofed-source scanning, or arbitrary raw packet
  injection is added.

## Verification gates

1. Unit tests cover GUID formatting/matching, compact state transitions,
   retries, CLI validation, Python command construction, and build inputs.
2. Default Rust tests and builds pass without Npcap SDK linkage.
3. Feature tests and builds pass with the Npcap SDK.
4. Generated NSIS source contains the prerequisite check and bundled installer.
5. An elevated loopback test observes both SYN-ACK and RST.
6. An owned lab subnet produces the same open-port set through SYN and connect
   scans before SYN is considered release-ready.
7. A clean Windows VM without Npcap proves interactive installation,
   `AdminOnly=0`, driver startup, application startup, and an authorized SYN
   scan.

Any gate requiring UAC, another machine, or a real authorized network remains
`UNVERIFIED` until it is executed and recorded.
