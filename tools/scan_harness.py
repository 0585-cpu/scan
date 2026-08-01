from __future__ import annotations

import argparse
from typing import Any

from netroach.auth import require_active_authorization
from netroach.models import EngineSettings
from netroach.scan_inputs import PORT_PROFILES, TOP_PORTS, resolve_ports, resolve_targets, validate_scan_workload


def add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--targets", default="127.0.0.1", help="target IP/CIDR expression")
    parser.add_argument("--targets-file", help="file containing target expressions")
    parser.add_argument("--exclude", action="append", default=[], help="CIDR to exclude; repeatable")
    parser.add_argument("--ports", help="port expression")
    parser.add_argument("--ports-file", help="file containing port expressions")
    parser.add_argument("--profile", dest="port_profile", choices=sorted(PORT_PROFILES), help="named port profile")
    parser.add_argument("--top-ports", type=int, help=f"use first N top ports, up to {len(TOP_PORTS)}")
    parser.add_argument("--scope", action="append", default=[], help="authorized CIDR scope; repeatable")
    parser.add_argument("--confirm-authorized", action="store_true", help="confirm you are authorized to scan the scope")
    parser.add_argument("--protocol", choices=["tcp", "udp"], default="tcp")
    parser.add_argument("--timeout-ms", type=int, default=800)
    parser.add_argument("--concurrency", type=int, default=2000)
    parser.add_argument("--rate-limit-per-sec", type=int, default=5000)
    parser.add_argument("--udp-retries", type=int, choices=range(0, 4), default=1)
    parser.add_argument("--no-service-probe", action="store_true")
    parser.add_argument("--engine-path", help="path to netroach-engine")
    parser.add_argument("--max-hosts", type=int, default=65536)
    parser.add_argument("--max-attempts", type=int, default=1_000_000)
    parser.add_argument("--confirm-large-scan", action="store_true")


def prepare_scan(args: argparse.Namespace) -> tuple[list[Any], str, list[int], str, dict[str, int], EngineSettings]:
    guard = require_active_authorization(args.confirm_authorized, args.scope)
    targets, target_expr = resolve_targets(
        targets=args.targets,
        targets_file=args.targets_file,
        exclude=args.exclude,
        max_hosts=args.max_hosts,
    )
    guard.require_targets(targets)
    top_ports = args.top_ports
    if top_ports is None and not (args.ports or args.ports_file or args.port_profile):
        top_ports = 100
    ports, port_expr = resolve_ports(
        ports=args.ports,
        ports_file=args.ports_file,
        port_profile=args.port_profile,
        top_ports=top_ports,
    )
    workload = validate_scan_workload(
        targets,
        ports,
        max_attempts=args.max_attempts,
        confirm_large_scan=args.confirm_large_scan,
    )
    settings = EngineSettings(
        timeout_ms=args.timeout_ms,
        concurrency=args.concurrency,
        rate_limit_per_sec=args.rate_limit_per_sec,
        service_probe=not args.no_service_probe,
        protocol=args.protocol,
        udp_retries=args.udp_retries,
    )
    return targets, target_expr, ports, port_expr, workload, settings
