"""Live capture through pktmon, the packet monitor built into Windows.

pktmon ships with Windows 10 1809 and later, so a capture needs no third-party
driver and no redistribution licence - which is what Npcap costs an
open-source build. It records to an ETL file and converts that to pcapng, and
pcapng is exactly what this project already analyses.

The capture itself still needs an elevated process, the same as Npcap.
"""
from __future__ import annotations

import hashlib
import platform
import re
import shutil
import subprocess
import tempfile
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

# pktmon writes a fresh ETL only if it is not already running; stopping an
# unrelated session would destroy someone else's capture, so we refuse instead.
_ALREADY_RUNNING = "another capture session is already running"
# Component copies of one packet land within ~10 frames of each other,
# so a small window catches them all without holding the capture in memory.
DEDUP_WINDOW_FRAMES = 64
STOP_TIMEOUT_S = 30.0
CONVERT_TIMEOUT_S = 120.0


@dataclass(frozen=True)
class PktmonAvailability:
    available: bool
    executable: str | None
    reason: str


def pktmon_path() -> str | None:
    if platform.system() != "Windows":
        return None
    return shutil.which("pktmon")


def check_pktmon(*, elevated: bool | None = None) -> PktmonAvailability:
    """Report whether pktmon can be used for a capture right now."""
    if platform.system() != "Windows":
        return PktmonAvailability(False, None, "pktmon is only available on Windows")
    executable = pktmon_path()
    if not executable:
        return PktmonAvailability(
            False,
            None,
            "pktmon was not found; it ships with Windows 10 1809 and later",
        )
    if elevated is False:
        return PktmonAvailability(
            False,
            executable,
            "pktmon capture requires an elevated terminal",
        )
    return PktmonAvailability(True, executable, "pktmon is available for driver-free capture")


def _run(executable: str, arguments: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [executable, *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def _fail(result: subprocess.CompletedProcess[str], action: str) -> str:
    detail = (result.stderr or result.stdout or "").strip().splitlines()
    message = detail[-1] if detail else f"exit status {result.returncode}"
    return f"pktmon {action} failed: {message}"


def build_filter_arguments(*, host: str | None = None, port: int | None = None) -> list[list[str]]:
    """Translate the two filter fields pktmon understands into filter commands.

    pktmon has its own filter grammar and does not accept BPF, so only the
    subset that maps cleanly is offered; anything else is rejected by the
    caller rather than silently ignored.
    """
    arguments: list[list[str]] = []
    if host:
        arguments.append(["filter", "add", "netroach-host", "-i", host])
    if port:
        arguments.append(["filter", "add", "netroach-port", "-p", str(port)])
    return arguments


def parse_pktmon_filter(expression: str | None) -> tuple[str | None, int | None]:
    """Accept a deliberately tiny filter syntax: `host <ip>` and `port <n>`.

    Returning a parse error rather than approximating a BPF expression keeps a
    capture from quietly recording more traffic than the operator asked for.
    """
    if not expression or not expression.strip():
        return None, None
    host: str | None = None
    port: int | None = None
    for term in re.split(r"\s+and\s+|\s*,\s*", expression.strip()):
        term = term.strip()
        if not term:
            continue
        match = re.fullmatch(r"host\s+(\S+)", term, flags=re.IGNORECASE)
        if match:
            host = match.group(1)
            continue
        match = re.fullmatch(r"port\s+(\d{1,5})", term, flags=re.IGNORECASE)
        if match:
            port = int(match.group(1))
            if not 1 <= port <= 65535:
                raise ValueError("pktmon filter port must be between 1 and 65535")
            continue
        raise ValueError(
            "pktmon filters accept only 'host <address>' and 'port <number>', "
            f"optionally joined by 'and'; got: {term}"
        )
    return host, port


def capture_to_pcapng(
    *,
    output: Path,
    duration_s: float,
    executable: str | None = None,
    filter_expression: str | None = None,
) -> int:
    """Capture for `duration_s` and write pcapng to `output`; return byte size.

    pktmon stops on time, never on a packet count, so a count-only request is
    bounded by the caller's duration instead.
    """
    engine = executable or pktmon_path()
    if not engine:
        raise RuntimeError("pktmon was not found; it ships with Windows 10 1809 and later")

    host, port = parse_pktmon_filter(filter_expression)
    status = _run(engine, ["status"], timeout=STOP_TIMEOUT_S)
    if status.returncode == 0 and _looks_running(status.stdout or ""):
        raise RuntimeError(_ALREADY_RUNNING)

    with tempfile.TemporaryDirectory(prefix="netroach-pktmon-") as tmp:
        etl = Path(tmp) / "capture.etl"
        _run(engine, ["filter", "remove"], timeout=STOP_TIMEOUT_S)
        for arguments in build_filter_arguments(host=host, port=port):
            result = _run(engine, arguments, timeout=STOP_TIMEOUT_S)
            if result.returncode != 0:
                raise RuntimeError(_fail(result, "filter add"))

        start_arguments = [
            "start",
            "--capture",
            # pktmon truncates to 128 bytes by default, which cuts off the HTTP
            # headers, TLS SNI and DNS names this project parses.
            "--pkt-size",
            "0",
            # Components are deliberately left at the default (all). Capturing
            # at the NIC only would avoid the duplication handled below, but on
            # a Wi-Fi adapter it yields raw 802.11 frames instead of the
            # Ethernet-shaped ones the analyser understands.
            "--file-name",
            str(etl),
        ]
        started = _run(engine, start_arguments, timeout=STOP_TIMEOUT_S)
        if started.returncode != 0:
            _run(engine, ["filter", "remove"], timeout=STOP_TIMEOUT_S)
            raise RuntimeError(_fail(started, "start"))

        try:
            time.sleep(duration_s)
        finally:
            stopped = _run(engine, ["stop"], timeout=STOP_TIMEOUT_S)
            _run(engine, ["filter", "remove"], timeout=STOP_TIMEOUT_S)
        if stopped.returncode != 0:
            raise RuntimeError(_fail(stopped, "stop"))
        if not etl.is_file():
            raise RuntimeError("pktmon produced no capture file")

        output.parent.mkdir(parents=True, exist_ok=True)
        converted = _run(
            engine,
            ["etl2pcap", str(etl), "--out", str(output)],
            timeout=CONVERT_TIMEOUT_S,
        )
        if converted.returncode != 0 or not output.is_file():
            raise RuntimeError(_fail(converted, "etl2pcap"))
        deduplicate_pcapng(output)
        return output.stat().st_size


def deduplicate_pcapng(path: Path, *, window_s: float = 0.001) -> int:
    """Drop the copies pktmon records of one packet at each stack component.

    pktmon logs a packet once per component it traverses, so a capture arrives
    with every frame repeated - about five times on the machine this was built
    against - which multiplies every count in the analysis. The copies share a
    timestamp to within microseconds but are interleaved with other packets
    rather than adjacent, so a short sliding window is needed: a frame is
    dropped when a byte-identical one was already kept within `window_s`.

    Real traffic survives this. A retransmission differs in at least its IP id
    or TCP timestamp option, and two genuinely identical frames a full window
    apart are both kept.

    Returns the number of packets removed. A failure here leaves the capture
    untouched: an inflated file still beats losing it.
    """
    try:
        from scapy.all import PcapNgReader, PcapNgWriter
    except ImportError:
        return 0

    if path.read_bytes()[:4] != b"\x0a\x0d\x0d\x0a":
        return 0  # not pcapng; nothing pktmon produced looks like this

    temporary = path.with_suffix(path.suffix + ".dedup")
    removed = 0
    written = 0
    failed = False
    reader = None
    writer = None
    try:
        reader = PcapNgReader(str(path))
        writer = PcapNgWriter(str(temporary))
        # Digests rather than frames: a jumbo frame is 64 KB and the window
        # would otherwise hold megabytes for no benefit.
        recent: OrderedDict[bytes, float] = OrderedDict()
        for packet in reader:
            stamp = float(getattr(packet, "time", 0.0))
            digest = hashlib.blake2b(bytes(packet), digest_size=16).digest()
            seen_at = recent.get(digest)
            if seen_at is not None and abs(stamp - seen_at) <= window_s:
                removed += 1
                continue
            recent[digest] = stamp
            recent.move_to_end(digest)
            while len(recent) > DEDUP_WINDOW_FRAMES:
                recent.popitem(last=False)
            writer.write(packet)
            written += 1
    except Exception:  # noqa: BLE001 - keep the original capture on any failure.
        failed = True
    finally:
        # Close explicitly: on Windows a handle scapy still holds would stop the
        # rewritten file from replacing the original.
        for closeable in (reader, writer):
            try:
                if closeable is not None:
                    closeable.close()
            except Exception:  # noqa: BLE001 - closing must not mask the outcome.
                pass

    # Never trade a capture for an empty file: if the rewrite produced nothing,
    # something went wrong in the reader and the original is the better answer.
    if failed or written == 0:
        temporary.unlink(missing_ok=True)
        return 0
    temporary.replace(path)
    return removed


def _looks_running(status_output: str) -> bool:
    lowered = status_output.lower()
    return "running" in lowered and "not running" not in lowered
