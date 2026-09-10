# SYN Sweep — Development Handoff

A stateless SYN pre-sweep for the scan engine, so a filtered-heavy range costs
one packet per port instead of one socket held for the whole timeout. Only the
foundations are built; this is where to pick it up on another machine.

## Why

A connect scan (`TcpStream::connect`, the current engine) holds a socket per
port for the timeout, so throughput on a range that mostly does not answer is
`concurrency / timeout`. On the customer's `/24 × 10,000` scan that was ~2
hours and thousands of live sockets on an 8 GB machine, which is what wedged
it. A SYN sweep sends one packet per port, keeps no per-probe state, and hands
only the *open* ports to the existing connect path for banners, service
identification and console evidence. Measured target: **15 M probes in ~53 min
at 5,000 pps**, with the memory pressure gone.

Speed is **not** the goal and the rate is deliberately capped — tens of
thousands of pps could knock over fragile OT/embedded gear. 5,000 pps is
2.5 Mbps of 64-byte frames; the constraint is the target's session handling,
not our link.

## Build environment (Windows)

SYN work needs Npcap (raw send is blocked on plain sockets since XP SP2) and
its SDK to build against.

1. **Npcap runtime** — https://npcap.com , installer signed by "Nmap Software
   LLC". Install with **WinPcap API-compatible Mode** and **loopback support**
   checked (loopback is how the round trip is tested without a network).
   Verify: `Get-Service npcap` is `Running`, `C:\Windows\System32\Npcap\wpcap.dll` exists.
2. **Npcap SDK** — unzip to `C:\npcap-sdk` (so `C:\npcap-sdk\Lib\x64\wpcap.lib`
   and `C:\npcap-sdk\Include\pcap.h` exist).
3. **Build** — the SDK lib dir must be on `LIB`:
   ```powershell
   $env:LIB = "C:\npcap-sdk\Lib\x64;$env:LIB"
   cargo build  --manifest-path crates\netroach-engine\Cargo.toml --features syn-sweep
   cargo test   --manifest-path crates\netroach-engine\Cargo.toml --features syn-sweep syn_sweep
   ```

`pcap` and `windows-sys` are **optional, behind the `syn-sweep` feature**. The
default build and the packaged installer link neither — confirm with a plain
`cargo build` / `cargo test` (no `--features`), which needs no SDK and stays
green. Never enable `syn-sweep` in the packaged desktop build.

Npcap's licence is free for personal and in-house use; the installer is **not**
redistributed with Netroach — it is installed separately on each machine.

## Done, and how it was verified

### `crates/netroach-engine/src/syn_sweep.rs` — packet layer (commit 5bbafe7)
Pure byte functions, no I/O, fully unit-tested (`cargo test --features syn-sweep syn_sweep`, 9 tests):
- `syn_cookie(secret, host, port, source_port) -> u32` — the keyed hash placed
  in the TCP sequence number. A reply is ours only if its ack returns
  `cookie + 1`; this is what lets the sweep hold **no per-probe state** and what
  stops a forged/foreign packet becoming a finding.
- `build_syn_frame(link, ...)` / `parse_syn_reply(link, frame, secret)` — build
  a SYN, read a SYN-ACK (open) / RST (closed).
- `LinkLayer` — `Ethernet { source_mac, next_hop_mac }` vs `Null` (loopback,
  DLT_NULL). The frame's framing differs by adapter; sending the wrong one gets
  no answers at all.

**End-to-end proof:** `examples/loopback_roundtrip.rs` injects SYNs over the
Npcap loopback adapter at a held-open port and an unbound one. The kernel
answered SYN-ACK and RST respectively and the parser sorted both — so the
built frame really transmits and a real stack accepts it. Run elevated:
`cargo run --features syn-sweep --example loopback_roundtrip`.

### `crates/netroach-engine/src/netlink.rs` — route resolution (commit 588c885)
Windows IP Helper via `windows-sys`. `resolve_route(dest) -> Route { source_ip,
link, interface_index }`:
- `GetBestRoute2` — next hop, interface, source address for a destination.
- `GetIfEntry2` — that interface's MAC (source MAC).
- `GetIpNetEntry2` / `ResolveIpNetEntry2` — the next hop's MAC, ARPing when the
  cache is cold. On-link targets (next hop reported unspecified) ARP the target
  itself; off-link ones ARP the gateway.

**Verified against the live table** (`examples/resolve_route.rs`, no elevation
needed): `8.8.8.8` (off-segment) and the default gateway both resolved to the
gateway's MAC, an on-link neighbour to its own — the same/other-subnet split a
mixed-subnet scan depends on. Run: `cargo run --features syn-sweep --example
resolve_route -- 8.8.8.8 <gateway-ip> <local-ip>`.

## Remaining work

3. **Send loop + receive thread.** Detect the adapter's datalink and pick the
   `LinkLayer` from it (loopback is DLT_NULL=0, wired is DLT_EN10MB=1). Send at
   a capped rate (5,000 pps ceiling). Receive on a second thread with a BPF
   filter (`tcp and dst port <our source port>`), feeding frames to
   `parse_syn_reply`. **Still needed:** map `interface_index` (from the route)
   to a pcap device name — `ConvertInterfaceIndexToLuid` → interface GUID →
   match the `\Device\NPF_{GUID}` pcap device. Without it we cannot pick the
   right adapter to send on.
4. **Retransmission.** A lost SYN or reply is a silent miss — connect scans do
   not have this because the OS retransmits. Re-send ports that got no answer
   1–2 times. This is what makes the sweep trustworthy for a diagnosis.
5. **Cross-check + integration.** Before it can be used: scan one range with
   both SYN and connect and confirm the **open-port lists match**. Any mismatch
   means raise the retransmit count. Then add a `--syn-sweep` flag: default
   stays the connect scan, and with it on, SYN-sweep first and pass only open
   ports to the connect path. Keeping it a flag means it can be turned off if
   anything is wrong, with nothing to revert.

## Design decisions already made

- **5,000 pps ceiling** — enough (53 min for 15 M) and safe for fragile gear.
  The win is no held sockets / no state, not raw speed.
- **Stateless matching** via the SYN cookie — there is nowhere to hold 15 M
  outstanding probes, and it doubles as forgery protection.
- **`LinkLayer` per adapter** — wired needs ethernet + next-hop MAC, loopback
  needs neither. Resolved once per target and cached.
- **Feature-gated** — the default build and packaged installer never link pcap
  or windows-sys.
- **IPv4 only** for now.

## Do not ship yet

The three unpushed commits (route resolver, packet layer, and the web viewport
fix `d53a4ee`) are on `main` but not in a release. SYN sweep is **incomplete** —
the packet and routing foundations only, no working sweep — so it must not go
into a packaged build until step 5 (cross-check) passes. The evidence fixes
earlier in the branch are release-ready; SYN sweep is not.
