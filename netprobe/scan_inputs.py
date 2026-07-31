from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable, Mapping
from pathlib import Path

from .ports import parse_ports
from .scope import ScopeError, iter_target_tokens, parse_target_expr

ABSOLUTE_MAX_SCAN_ATTEMPTS = 100_000_000
MAX_ADDRESSES_PER_NAME = 16

PORT_PROFILES: dict[str, tuple[int, ...]] = {
    "web": (80, 443, 8000, 8080, 8443, 3000, 5000, 9000),
    "infra": (22, 53, 67, 68, 69, 123, 135, 139, 161, 389, 445, 514, 636, 3389, 5900),
}

TOP_PORTS: tuple[int, ...] = (
    80,
    443,
    22,
    21,
    25,
    53,
    110,
    111,
    135,
    139,
    143,
    389,
    445,
    465,
    587,
    993,
    995,
    1433,
    1521,
    1723,
    2049,
    2375,
    2376,
    3306,
    3389,
    5432,
    5900,
    5985,
    5986,
    6379,
    8000,
    8080,
    8443,
    9000,
    9200,
    9300,
    11211,
    27017,
    23,
    69,
    81,
    88,
    123,
    137,
    138,
    162,
    179,
    199,
    427,
    500,
    514,
    520,
    554,
    631,
    646,
    873,
    990,
    1025,
    1026,
    1027,
    1028,
    1029,
    1080,
    1194,
    1434,
    1701,
    1883,
    1900,
    2000,
    2121,
    2181,
    2483,
    2484,
    2888,
    3128,
    3268,
    3269,
    3690,
    3702,
    3888,
    4369,
    4786,
    5060,
    5061,
    5353,
    5601,
    5672,
    5683,
    5800,
    6000,
    6001,
    7000,
    7001,
    7002,
    8008,
    8081,
    8088,
    8090,
    8181,
    8222,
    8300,
    8500,
    8888,
    9090,
    9100,
    9418,
    10000,
    10050,
    10051,
    10250,
    10255,
    11311,
    15672,
    16379,
    27018,
    27019,
    28017,
    50070,
    50075,
    61616,
)


def resolve_host_names(expr: str) -> str:
    """Replace hostname tokens with the addresses they resolve to.

    Resolution happens here, before any parsing or scope checking, so the rest
    of the pipeline only ever sees literal addresses: a name can never smuggle
    a target past the scope guard, because the guard checks what was resolved.
    """
    parts: list[str] = []
    for token in iter_target_tokens(expr):
        if _is_address_or_network(token):
            parts.append(token)
            continue
        parts.extend(resolve_host_name(token))
    if not parts:
        raise ScopeError("no targets were provided")
    return ",".join(parts)


def resolve_host_name(name: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ScopeError(f"could not resolve target name: {name}") from exc
    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0]).split("%", 1)[0]
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ScopeError(f"could not resolve target name: {name}")
    return addresses[:MAX_ADDRESSES_PER_NAME]


def _is_address_or_network(token: str) -> bool:
    try:
        if "/" in token:
            ipaddress.ip_network(token, strict=False)
        else:
            ipaddress.ip_address(token)
    except ValueError:
        return False
    return True


def resolve_targets(
    *,
    targets: str | None,
    targets_file: str | None = None,
    exclude: Iterable[str] | None = None,
    max_hosts: int = 65536,
) -> tuple[list[ipaddress._BaseAddress], str]:
    target_expr = resolve_host_names(
        combine_expressions(
            direct=targets,
            file_path=targets_file,
            direct_label="--targets",
            file_label="--targets-file",
        )
    )
    resolved = parse_target_expr(target_expr, max_hosts=max_hosts)
    excluded = parse_exclude_networks(exclude)
    if excluded:
        resolved = [
            target
            for target in resolved
            if not any(target.version == network.version and target in network for network in excluded)
        ]
        if not resolved:
            raise ScopeError("all targets were excluded")
    return resolved, normalize_targets_expr(resolved)


def resolve_ports(
    *,
    ports: str | None,
    ports_file: str | None = None,
    port_profile: str | None = None,
    top_ports: int | None = None,
    port_profiles: Mapping[str, Iterable[int]] | None = None,
) -> tuple[list[int], str]:
    expressions: list[str] = []
    profiles = {**PORT_PROFILES, **{name: tuple(values) for name, values in (port_profiles or {}).items()}}
    if ports and ports.strip():
        expressions.append(ports)
    if ports_file:
        expressions.append(read_expression_file(ports_file, "--ports-file"))
    if port_profile:
        if port_profile not in profiles:
            names = ", ".join(sorted(profiles))
            raise ValueError(f"port_profile must be one of: {names}")
        expressions.append(",".join(str(port) for port in profiles[port_profile]))
    if top_ports is not None:
        if top_ports < 1 or top_ports > len(TOP_PORTS):
            raise ValueError(f"top_ports must be between 1 and {len(TOP_PORTS)}")
        expressions.append(",".join(str(port) for port in TOP_PORTS[:top_ports]))
    if not expressions:
        raise ValueError("provide at least one of --ports, --ports-file, --profile, or --top-ports")
    resolved = parse_ports(",".join(expressions))
    return resolved, normalize_ports_expr(resolved)


def validate_scan_workload(
    targets: Iterable[object],
    ports: Iterable[int],
    *,
    max_attempts: int,
    confirm_large_scan: bool = False,
) -> dict[str, int]:
    host_count = len(targets) if hasattr(targets, "__len__") else sum(1 for _ in targets)
    port_count = len(ports) if hasattr(ports, "__len__") else sum(1 for _ in ports)
    attempts = host_count * port_count
    if attempts > ABSOLUTE_MAX_SCAN_ATTEMPTS:
        raise ValueError(
            f"scan plans {attempts:,} attempts, exceeding the absolute safety limit "
            f"of {ABSOLUTE_MAX_SCAN_ATTEMPTS:,}"
        )
    if attempts > max_attempts and not confirm_large_scan:
        raise ValueError(
            f"scan plans {attempts:,} attempts, exceeding max_attempts={max_attempts:,}; "
            "reduce the targets/ports or explicitly confirm the large scan"
        )
    return {"hosts": host_count, "ports": port_count, "attempts": attempts}


def combine_expressions(*, direct: str | None, file_path: str | None, direct_label: str, file_label: str) -> str:
    expressions: list[str] = []
    if direct and direct.strip():
        expressions.append(direct)
    if file_path:
        expressions.append(read_expression_file(file_path, file_label))
    if not expressions:
        raise ValueError(f"provide {direct_label} or {file_label}")
    return ",".join(expressions)


def read_expression_file(file_path: str, label: str) -> str:
    path = Path(file_path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"could not read {label}: {path}") from exc
    parts: list[str] = []
    for line in text.splitlines():
        item = line.split("#", 1)[0].strip()
        if item:
            parts.append(item)
    if not parts:
        raise ValueError(f"{label} is empty: {path}")
    return ",".join(parts)


def parse_exclude_networks(exclude: Iterable[str] | None) -> tuple[ipaddress._BaseNetwork, ...]:
    return tuple(ipaddress.ip_network(value.strip(), strict=False) for value in exclude or () if value and value.strip())


def normalize_targets_expr(targets: Iterable[ipaddress._BaseAddress]) -> str:
    return ",".join(str(target) for target in targets)


def normalize_ports_expr(ports: Iterable[int]) -> str:
    return ",".join(str(port) for port in ports)
