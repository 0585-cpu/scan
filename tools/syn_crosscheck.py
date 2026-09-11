"""Compare a SYN sweep against a connect scan of the same targets.

This is the gate that decides whether the sweep can be used for an assessment.
A SYN sweep sends one packet per port and keeps no per-probe state, so a lost
SYN or a lost reply is a port that answers nothing and is reported filtered -
an open port missing from the report, with nothing to say it went missing.
Connect scanning cannot lose a port that way, because the OS retransmits. So
connect is the reference, and the question is whether SYN found what it found.

Usage:
    netroach scan ... --json > connect.json
    netroach scan ... --syn-sweep --syn-retries 1 --json > syn.json
    python tools/syn_crosscheck.py connect.json syn.json

Exits 0 when the sweep agrees on every open port, 1 when it does not.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# open|filtered is a UDP state; a TCP SYN sweep never emits it. Both scans are
# TCP here, so "open" is the only state that claims a reachable service.
OPEN = "open"


def open_ports(path: Path) -> set[tuple[str, int]]:
    """The (host, port) pairs a scan reported open."""
    report = json.loads(path.read_text(encoding="utf-8"))
    results = report.get("results")
    if results is None:
        raise SystemExit(f"{path} has no results; was it written with --json?")
    return {
        (str(row["host"]), int(row["port"]))
        for row in results
        if row.get("state") == OPEN and row.get("protocol") == "tcp"
    }


def probed_ports(path: Path) -> set[tuple[str, int]]:
    """Every (host, port) a scan looked at, open or not."""
    report = json.loads(path.read_text(encoding="utf-8"))
    return {
        (str(row["host"]), int(row["port"]))
        for row in report.get("results") or []
        if row.get("protocol") == "tcp"
    }


def render(label: str, ports: set[tuple[str, int]], limit: int = 40) -> str:
    listed = sorted(ports)
    shown = ", ".join(f"{host}:{port}" for host, port in listed[:limit])
    if len(listed) > limit:
        shown += f", ... (+{len(listed) - limit} more)"
    return f"{label} ({len(listed)}): {shown}" if listed else f"{label}: none"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("connect_json", type=Path, help="connect scan written with --json")
    parser.add_argument("syn_json", type=Path, help="SYN sweep written with --json")
    args = parser.parse_args(argv)

    connect_open = open_ports(args.connect_json)
    syn_open = open_ports(args.syn_json)

    # Comparing scans of different workloads would read as disagreement when it
    # is only a different question asked twice.
    connect_probed = probed_ports(args.connect_json)
    syn_probed = probed_ports(args.syn_json)
    if connect_probed != syn_probed:
        print("the two scans did not cover the same ports, so they cannot be compared")
        print(f"  connect probed {len(connect_probed)}, SYN probed {len(syn_probed)}")
        only_connect = len(connect_probed - syn_probed)
        only_syn = len(syn_probed - connect_probed)
        print(f"  {only_connect} only in connect, {only_syn} only in SYN")
        return 1

    missed = connect_open - syn_open
    extra = syn_open - connect_open

    print(f"probed {len(connect_probed)} ports on {len({host for host, _ in connect_probed})} hosts")
    print(f"connect found {len(connect_open)} open, SYN found {len(syn_open)} open")
    print()
    if missed:
        print("MISSED - connect found these open and the sweep did not:")
        print(f"  {render('ports', missed)}")
        print("  Raise --syn-retries, or the link is losing packets.")
    if extra:
        print("EXTRA - the sweep called these open and connect did not:")
        print(f"  {render('ports', extra)}")
        print("  A service that stopped between the two runs looks like this too;")
        print("  re-run connect before treating it as a sweep fault.")
    if not missed and not extra:
        print("PASS - the sweep agreed with connect on every open port.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
