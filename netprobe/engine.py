from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import TextIO

from .config import MAX_CONCURRENCY, MAX_RATE_LIMIT_PER_SEC, MAX_TIMEOUT_MS
from .models import EngineSettings, PortResult, ScanSummary
from .plugins import PluginCatalog, load_plugins
from .scan_inputs import ABSOLUTE_MAX_SCAN_ATTEMPTS

EngineEventCallback = Callable[[dict[str, object]], None]
StopCallback = Callable[[], bool]
ENGINE_INLINE_INPUT_LIMIT = 16_000 if os.name == "nt" else 120_000
ENGINE_EVENT_QUEUE_SIZE = 10_000


class EngineError(RuntimeError):
    """Raised when the external scan engine fails."""


class EngineUnavailableError(EngineError):
    """Raised when the required Rust scan engine cannot be found."""


class ScanCancelled(RuntimeError):
    """Raised when a scan job is cancelled by the user."""


def run_scan(
    *,
    scan_id: str,
    targets: Iterable[object],
    ports: Iterable[int],
    settings: EngineSettings,
    target_expr: str,
    port_expr: str,
    on_event: EngineEventCallback | None = None,
    engine_path: str | None = None,
    collect_results: bool = True,
    should_stop: StopCallback | None = None,
) -> tuple[list[PortResult], ScanSummary]:
    target_list = list(targets)
    port_list = list(ports)
    _validate_engine_settings(settings, len(target_list) * len(port_list))
    engine = resolve_engine_path(engine_path)
    if engine is None:
        raise EngineUnavailableError("Rust scan engine is unavailable")
    plugin_catalog = load_plugins(settings.plugin_paths)
    return _run_rust_engine(
        engine=engine,
        scan_id=scan_id,
        target_expr=target_expr,
        port_expr=port_expr,
        settings=settings,
        on_event=on_event,
        plugin_catalog=plugin_catalog,
        max_hosts=max(1, len(target_list)),
        collect_results=collect_results,
        should_stop=should_stop,
    )


def _validate_engine_settings(settings: EngineSettings, planned_attempts: int) -> None:
    if not 1 <= settings.timeout_ms <= MAX_TIMEOUT_MS:
        raise ValueError(f"timeout_ms must be between 1 and {MAX_TIMEOUT_MS}")
    if not 1 <= settings.concurrency <= MAX_CONCURRENCY:
        raise ValueError(f"concurrency must be between 1 and {MAX_CONCURRENCY}")
    if not 1 <= settings.rate_limit_per_sec <= MAX_RATE_LIMIT_PER_SEC:
        raise ValueError(f"rate_limit_per_sec must be between 1 and {MAX_RATE_LIMIT_PER_SEC}")
    if settings.protocol not in {"tcp", "udp"}:
        raise ValueError("protocol must be 'tcp' or 'udp'")
    if not 0 <= settings.udp_retries <= 3:
        raise ValueError("udp_retries must be between 0 and 3")
    if planned_attempts > ABSOLUTE_MAX_SCAN_ATTEMPTS:
        raise ValueError(
            f"planned scan attempts exceed absolute safety limit ({ABSOLUTE_MAX_SCAN_ATTEMPTS})"
        )


def resolve_engine_path(explicit: str | None = None) -> str | None:
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    if os.environ.get("SCAPROBE_ENGINE"):
        candidates.append(os.environ["SCAPROBE_ENGINE"])
    which = shutil.which("scaprobe-engine")
    if which:
        candidates.append(which)
    suffix = ".exe" if os.name == "nt" else ""
    root = Path(__file__).resolve().parent.parent
    engine_name = f"scaprobe-engine{suffix}"
    candidates.append(str(root / "bin" / engine_name))
    candidates.extend(
        str(root / "target" / profile / engine_name)
        for profile in ("release", "portable", "debug")
    )
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file():
            return str(path)
    return None


def _run_rust_engine(
    *,
    engine: str,
    scan_id: str,
    target_expr: str,
    port_expr: str,
    settings: EngineSettings,
    on_event: EngineEventCallback | None,
    plugin_catalog: PluginCatalog | None = None,
    max_hosts: int = 65536,
    collect_results: bool = True,
    should_stop: StopCallback | None = None,
) -> tuple[list[PortResult], ScanSummary]:
    with tempfile.TemporaryDirectory(prefix="scaprobe-engine-inputs-") as tmp:
        input_dir = Path(tmp)
        plugin_catalog_file = None
        if plugin_catalog is not None and plugin_catalog.has_runtime_fingerprints:
            plugin_catalog_file = input_dir / "plugin-catalog.json"
            plugin_catalog_file.write_text(
                json.dumps(plugin_catalog.runtime_catalog_dict(), separators=(",", ":")),
                encoding="utf-8",
            )
        if _should_use_engine_input_files(target_expr, port_expr):
            targets_file = input_dir / "targets.txt"
            ports_file = input_dir / "ports.txt"
            targets_file.write_text(target_expr, encoding="utf-8")
            ports_file.write_text(port_expr, encoding="utf-8")
            command = _build_rust_engine_command(
                engine=engine,
                scan_id=scan_id,
                settings=settings,
                targets_file=targets_file,
                ports_file=ports_file,
                plugin_catalog_file=plugin_catalog_file,
                max_hosts=max_hosts,
            )
            return _run_rust_engine_command(
                command,
                scan_id=scan_id,
                on_event=on_event,
                collect_results=collect_results,
                should_stop=should_stop,
            )

        command = _build_rust_engine_command(
            engine=engine,
            scan_id=scan_id,
            settings=settings,
            target_expr=target_expr,
            port_expr=port_expr,
            plugin_catalog_file=plugin_catalog_file,
            max_hosts=max_hosts,
        )
        return _run_rust_engine_command(
            command,
            scan_id=scan_id,
            on_event=on_event,
            collect_results=collect_results,
            should_stop=should_stop,
        )


def _should_use_engine_input_files(target_expr: str, port_expr: str) -> bool:
    return len(target_expr) + len(port_expr) > ENGINE_INLINE_INPUT_LIMIT


def _build_rust_engine_command(
    *,
    engine: str,
    scan_id: str,
    settings: EngineSettings,
    target_expr: str | None = None,
    port_expr: str | None = None,
    targets_file: Path | None = None,
    ports_file: Path | None = None,
    plugin_catalog_file: Path | None = None,
    max_hosts: int = 65536,
) -> list[str]:
    command = [
        engine,
        "scan",
        "--scan-id",
        scan_id,
    ]
    inline_inputs = target_expr is not None and port_expr is not None
    file_inputs = targets_file is not None and ports_file is not None
    if inline_inputs == file_inputs:
        raise ValueError("provide exactly one complete set of inline engine inputs or input files")
    if file_inputs:
        assert targets_file is not None and ports_file is not None
        command.extend(["--targets-file", str(targets_file), "--ports-file", str(ports_file)])
    else:
        assert target_expr is not None and port_expr is not None
        command.extend(["--targets", target_expr, "--ports", port_expr])
    command.extend(
        [
            "--timeout-ms",
            str(settings.timeout_ms),
            "--concurrency",
            str(settings.concurrency),
            "--rate-limit-per-sec",
            str(settings.rate_limit_per_sec),
            "--udp-retries",
            str(settings.udp_retries),
        ]
    )
    if max_hosts > 65536:
        command.extend(["--max-hosts", str(max_hosts)])
    if settings.protocol != "tcp":
        command.extend(["--protocol", settings.protocol])
    if settings.service_probe:
        command.append("--service-probe")
    if plugin_catalog_file is not None:
        command.extend(["--plugin-catalog-file", str(plugin_catalog_file)])
    return command


def _run_rust_engine_command(
    command: list[str],
    *,
    scan_id: str,
    on_event: EngineEventCallback | None,
    collect_results: bool = True,
    should_stop: StopCallback | None = None,
) -> tuple[list[PortResult], ScanSummary]:
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    results: list[PortResult] = []
    summary = ScanSummary(scan_id=scan_id)
    stderr_parts: list[str] = []
    stderr_thread: threading.Thread | None = None
    if process.stderr is not None:
        stderr_thread = threading.Thread(
            target=_drain_engine_stderr,
            args=(process.stderr, stderr_parts),
            daemon=True,
        )
        stderr_thread.start()
    assert process.stdout is not None
    # Bounded so a fast engine cannot outrun the consumer and grow this queue
    # without limit; a full queue blocks the reader thread, which backpressures
    # the engine through the OS pipe.
    stdout_queue: queue.Queue[str | None] = queue.Queue(maxsize=ENGINE_EVENT_QUEUE_SIZE)
    stdout_thread = threading.Thread(
        target=_drain_engine_stdout,
        args=(process.stdout, stdout_queue),
        daemon=True,
    )
    stdout_thread.start()
    try:
        while True:
            if should_stop is not None and should_stop():
                raise ScanCancelled(f"scan cancelled: {scan_id}")
            try:
                line = stdout_queue.get(timeout=0.2)
            except queue.Empty:
                if process.poll() is not None and not stdout_thread.is_alive():
                    break
                continue
            if line is None:
                break
            if not line.strip():
                continue
            event = json.loads(line)
            if on_event:
                on_event(event)
            if event.get("event") == "port":
                result = _port_result_from_event(event)
                if collect_results:
                    results.append(result)
                summary.observe(result)
    except Exception:
        _terminate_process(process)
        if stderr_thread is not None:
            stderr_thread.join(timeout=3)
        # The reader thread may be blocked on a full queue; drain it so the
        # thread can finish instead of leaking for the life of the process.
        _release_reader(stdout_thread, stdout_queue)
        raise
    code = process.wait()
    stdout_thread.join(timeout=3)
    if stderr_thread is not None:
        stderr_thread.join(timeout=3)
    stderr = "".join(stderr_parts)
    if code != 0:
        raise EngineError(stderr.strip() or f"scaprobe-engine exited with status {code}")
    return results, summary


def _release_reader(
    thread: threading.Thread,
    events: queue.Queue[str | None],
    timeout: float = 3.0,
) -> None:
    deadline = time.monotonic() + timeout
    while thread.is_alive() and time.monotonic() < deadline:
        try:
            events.get_nowait()
        except queue.Empty:
            thread.join(timeout=0.05)


def _drain_engine_stdout(stream: TextIO, output: queue.Queue[str | None]) -> None:
    try:
        for line in stream:
            output.put(line)
    finally:
        output.put(None)


def _drain_engine_stderr(stream: TextIO, parts: list[str]) -> None:
    try:
        parts.append(stream.read())
    except Exception as exc:  # noqa: BLE001 - preserve the engine result even if stderr collection fails.
        parts.append(f"could not read engine stderr: {exc}")


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def _port_result_from_event(event: dict[str, object]) -> PortResult:
    return PortResult(
        scan_id=_string_or_none(event.get("scan_id")),
        host=str(event["host"]),
        port=int(event["port"]),
        protocol=str(event.get("protocol", "tcp")),
        state=str(event["state"]),
        latency_ms=_float_or_none(event.get("latency_ms")),
        service_name=_string_or_none(event.get("service_name")),
        service_confidence=_float_or_none(event.get("service_confidence")),
        banner=_string_or_none(event.get("banner")),
        evidence=_string_or_none(event.get("evidence")),
        error=_string_or_none(event.get("error")),
    )


def _string_or_none(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _float_or_none(value: object) -> float | None:
    if value is None:
        return None
    return float(value)
