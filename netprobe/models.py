from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any


PUBLIC_RESULT_EXCLUDED_FIELDS = frozenset({"latency_ms", "service_confidence"})


def public_result_dict(result: Mapping[str, Any]) -> dict[str, Any]:
    """Return the stable user-facing projection of a stored scan result."""
    projected = {
        key: value
        for key, value in result.items()
        if key not in PUBLIC_RESULT_EXCLUDED_FIELDS
    }
    projected.setdefault("evidence_files", [])
    return projected


def public_result_dicts(results: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [public_result_dict(result) for result in results]


@dataclass(frozen=True)
class PortResult:
    host: str
    port: int
    state: str
    latency_ms: float | None
    protocol: str = "tcp"
    scan_id: str | None = None
    service_name: str | None = None
    service_confidence: float | None = None
    banner: str | None = None
    evidence: str | None = None
    error: str | None = None
    tags: list[str] = field(default_factory=list)
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_public_dict(self) -> dict[str, Any]:
        return public_result_dict(self.to_dict())


@dataclass(frozen=True)
class EngineSettings:
    timeout_ms: int = 800
    concurrency: int = 2000
    rate_limit_per_sec: int = 5000
    service_probe: bool = True
    protocol: str = "tcp"
    udp_retries: int = 1
    plugin_paths: tuple[str, ...] = ()


@dataclass
class ScanSummary:
    scan_id: str
    total: int = 0
    open: int = 0
    closed: int = 0
    open_filtered: int = 0
    filtered: int = 0
    error: int = 0

    def observe(self, result: PortResult) -> None:
        self.total += 1
        if result.state == "open":
            self.open += 1
        elif result.state == "closed":
            self.closed += 1
        elif result.state == "open|filtered":
            self.open_filtered += 1
        elif result.state == "filtered":
            self.filtered += 1
        else:
            self.error += 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PacketRequest:
    template: str
    target: str
    scope: list[str]
    confirm_authorized: bool
    count: int = 1
    interval_ms: int = 1000
    dport: int | None = None
    sport: int | None = None
    flags: str = "S"
    payload_text: str | None = None
    payload_base64: str | None = None
    dns_name: str | None = None
    http_method: str = "GET"
    http_path: str = "/"
    http_host: str | None = None
    dry_run: bool = False


@dataclass(frozen=True)
class SendResult:
    template: str
    target: str
    sent: int
    duration_s: float
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
