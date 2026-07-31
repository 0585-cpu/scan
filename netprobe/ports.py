from __future__ import annotations


class PortParseError(ValueError):
    """Raised when a port expression cannot be parsed."""


def parse_ports(expr: str) -> list[int]:
    ports: set[int] = set()
    for raw_part in expr.split(","):
        part = raw_part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start = _parse_port(start_s)
            end = _parse_port(end_s)
            if start > end:
                raise PortParseError(f"invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_port(part))
    if not ports:
        raise PortParseError("no ports were provided")
    return sorted(ports)


def _parse_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise PortParseError(f"invalid port: {value}") from exc
    if port < 1 or port > 65535:
        raise PortParseError(f"port out of range: {port}")
    return port

