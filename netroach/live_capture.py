from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .pcap import analyze_pcap
from .pktmon import capture_to_pcapng, check_pktmon, parse_pktmon_filter

MAX_CAPTURE_COUNT = 1_000_000
MAX_CAPTURE_DURATION_S = 3600.0
DEFAULT_COUNT_ONLY_TIMEOUT_S = 60.0
MAX_CAPTURE_FILTER_LENGTH = 1024


CAPTURE_BACKENDS = ("auto", "scapy", "pktmon")


@dataclass(frozen=True)
class LiveCaptureRequest:
    output: str
    confirm_authorized: bool = False
    duration_s: float | None = None
    count: int | None = None
    iface: str | None = None
    bpf_filter: str | None = None
    analyze: bool = True
    top: int = 10
    backend: str = "auto"


@dataclass(frozen=True)
class LiveCaptureResult:
    file: str
    packet_count: int
    duration_s: float
    interface: str | None
    bpf_filter: str | None
    analyzed: bool
    analysis: dict[str, Any] | None = None
    analysis_error: str | None = None
    backend: str = "scapy"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def select_capture_backend(request: LiveCaptureRequest) -> str:
    """Pick the capture backend, preferring the one that needs no install.

    pktmon is part of Windows, so it is the default there; scapy/Npcap stays
    available for the finer-grained BPF filtering it alone supports.
    """
    if request.backend not in CAPTURE_BACKENDS:
        raise ValueError(f"backend must be one of: {', '.join(CAPTURE_BACKENDS)}")
    if request.backend != "auto":
        return request.backend
    if request.bpf_filter and not _is_pktmon_filter(request.bpf_filter):
        return "scapy"
    if request.iface:
        # pktmon captures every adapter; honour an explicit interface choice.
        return "scapy"
    return "pktmon" if check_pktmon().available else "scapy"


def _is_pktmon_filter(expression: str) -> bool:
    try:
        parse_pktmon_filter(expression)
    except ValueError:
        return False
    return True


def execute_live_capture(request: LiveCaptureRequest) -> LiveCaptureResult:
    output = validate_live_capture_request(request)
    chosen = select_capture_backend(request)
    if chosen == "pktmon":
        return _capture_with_pktmon(request, output)
    backend = _import_scapy_capture()
    output.parent.mkdir(parents=True, exist_ok=True)

    packet_count = 0
    writer = None
    started = time.monotonic()
    try:
        writer = backend["PcapWriter"](str(output), append=False, sync=True)

        def observe_packet(packet: object) -> None:
            nonlocal packet_count
            writer.write(packet)
            packet_count += 1

        sniff_kwargs: dict[str, Any] = {
            "store": False,
            "prn": observe_packet,
            "timeout": request.duration_s if request.duration_s is not None else DEFAULT_COUNT_ONLY_TIMEOUT_S,
        }
        if request.count is not None:
            sniff_kwargs["count"] = request.count
        if request.iface:
            sniff_kwargs["iface"] = request.iface
        if request.bpf_filter:
            sniff_kwargs["filter"] = request.bpf_filter

        backend["sniff"](**sniff_kwargs)
    except PermissionError as exc:
        raise RuntimeError("live capture requires packet capture privileges; run diagnostics for platform guidance") from exc
    except Exception as exc:  # noqa: BLE001 - Scapy raises platform/backend specific exceptions.
        raise RuntimeError(f"live capture failed: {exc}") from exc
    finally:
        if writer is not None:
            writer.close()

    elapsed = round(time.monotonic() - started, 6)
    analysis = None
    analysis_error = None
    analyzed = False
    if request.analyze:
        if packet_count == 0:
            analysis_error = "no packets captured"
        else:
            try:
                analysis = analyze_pcap(output, top=request.top).to_dict()
                analyzed = True
            except Exception as exc:  # noqa: BLE001 - capture succeeded; keep the result inspectable.
                analysis_error = str(exc)

    return LiveCaptureResult(
        file=str(output),
        packet_count=packet_count,
        duration_s=elapsed,
        interface=request.iface,
        bpf_filter=request.bpf_filter,
        analyzed=analyzed,
        analysis=analysis,
        analysis_error=analysis_error,
        backend="scapy",
    )


def _capture_with_pktmon(request: LiveCaptureRequest, output: Path) -> LiveCaptureResult:
    """Capture with the Windows built-in monitor and analyse the pcapng it writes.

    pktmon stops on time, never on a packet count, so a count-only request is
    given the same default window the scapy path uses.
    """
    duration = request.duration_s if request.duration_s is not None else DEFAULT_COUNT_ONLY_TIMEOUT_S
    started = time.monotonic()
    try:
        capture_to_pcapng(
            output=output,
            duration_s=duration,
            filter_expression=request.bpf_filter,
        )
    except PermissionError as exc:
        raise RuntimeError("pktmon capture requires an elevated terminal") from exc
    except Exception as exc:  # noqa: BLE001 - surface the pktmon message as-is.
        raise RuntimeError(f"live capture failed: {exc}") from exc
    elapsed = round(time.monotonic() - started, 6)

    analysis = None
    analysis_error = None
    analyzed = False
    packet_count = 0
    try:
        summary = analyze_pcap(output, top=request.top)
        packet_count = summary.packet_count
        if request.analyze:
            analysis = summary.to_dict()
            analyzed = True
    except Exception as exc:  # noqa: BLE001 - capture succeeded; keep the file inspectable.
        analysis_error = str(exc)
    if request.analyze and packet_count == 0 and analysis_error is None:
        analysis, analyzed, analysis_error = None, False, "no packets captured"

    return LiveCaptureResult(
        file=str(output),
        packet_count=packet_count,
        duration_s=elapsed,
        interface=request.iface,
        bpf_filter=request.bpf_filter,
        analyzed=analyzed,
        analysis=analysis,
        analysis_error=analysis_error,
        backend="pktmon",
    )


def validate_live_capture_request(request: LiveCaptureRequest) -> Path:
    if not request.confirm_authorized:
        raise ValueError("live capture requires confirm_authorized=true")
    if not request.output or not request.output.strip():
        raise ValueError("live capture requires an output pcap path")
    output = Path(request.output)
    if output.exists() and output.is_dir():
        raise ValueError(f"capture output path is a directory: {output}")
    if "\x00" in str(output):
        raise ValueError("capture output path contains an invalid NUL character")
    if request.duration_s is None and request.count is None:
        raise ValueError("live capture requires duration_s or count")
    if request.duration_s is not None:
        if request.duration_s <= 0:
            raise ValueError("duration_s must be greater than 0")
        if request.duration_s > MAX_CAPTURE_DURATION_S:
            raise ValueError(f"duration_s must be <= {MAX_CAPTURE_DURATION_S:g}")
    if request.count is not None:
        if request.count < 1:
            raise ValueError("count must be at least 1")
        if request.count > MAX_CAPTURE_COUNT:
            raise ValueError(f"count must be <= {MAX_CAPTURE_COUNT}")
    if request.top < 1:
        raise ValueError("top must be at least 1")
    if request.iface is not None and "\x00" in request.iface:
        raise ValueError("iface contains an invalid NUL character")
    if request.bpf_filter is not None:
        if "\x00" in request.bpf_filter:
            raise ValueError("bpf_filter contains an invalid NUL character")
        if len(request.bpf_filter) > MAX_CAPTURE_FILTER_LENGTH:
            raise ValueError(f"bpf_filter must be <= {MAX_CAPTURE_FILTER_LENGTH} characters")
    return output


def _import_scapy_capture() -> dict[str, Any]:
    try:
        from scapy.all import PcapWriter, sniff
    except ImportError as exc:
        raise RuntimeError("live capture requires scapy. Install with: pip install scapy") from exc
    return {"PcapWriter": PcapWriter, "sniff": sniff}
