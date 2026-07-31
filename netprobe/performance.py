from __future__ import annotations

import ctypes
import os
import statistics
import time
import tracemalloc
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProcessMeasurement:
    elapsed_s: float
    cpu_s: float
    rss_before_bytes: int | None
    rss_after_bytes: int | None
    rss_delta_bytes: int | None
    process_peak_rss_bytes: int | None
    python_current_bytes: int
    python_peak_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "elapsed_s": round(self.elapsed_s, 6),
            "cpu_s": round(self.cpu_s, 6),
            "rss_before_bytes": self.rss_before_bytes,
            "rss_after_bytes": self.rss_after_bytes,
            "rss_delta_bytes": self.rss_delta_bytes,
            "process_peak_rss_bytes": self.process_peak_rss_bytes,
            "python_current_bytes": self.python_current_bytes,
            "python_peak_bytes": self.python_peak_bytes,
        }


class ProcessMeter:
    def __init__(self) -> None:
        self._started = 0.0
        self._cpu_started = 0.0
        self._rss_started: int | None = None
        self._owned_tracemalloc = False

    def __enter__(self) -> ProcessMeter:
        self._started = time.perf_counter()
        self._cpu_started = time.process_time()
        self._rss_started, _ = process_memory_bytes()
        if not tracemalloc.is_tracing():
            tracemalloc.start()
            self._owned_tracemalloc = True
        tracemalloc.reset_peak()
        return self

    def finish(self) -> ProcessMeasurement:
        elapsed = time.perf_counter() - self._started
        cpu = time.process_time() - self._cpu_started
        rss_after, peak_rss = process_memory_bytes()
        python_current, python_peak = tracemalloc.get_traced_memory()
        measurement = ProcessMeasurement(
            elapsed_s=elapsed,
            cpu_s=cpu,
            rss_before_bytes=self._rss_started,
            rss_after_bytes=rss_after,
            rss_delta_bytes=(
                rss_after - self._rss_started
                if rss_after is not None and self._rss_started is not None
                else None
            ),
            process_peak_rss_bytes=peak_rss,
            python_current_bytes=python_current,
            python_peak_bytes=python_peak,
        )
        if self._owned_tracemalloc:
            tracemalloc.stop()
        return measurement

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        if self._owned_tracemalloc and tracemalloc.is_tracing():
            tracemalloc.stop()


class StreamingScanMetrics:
    def __init__(self, *, sample_limit: int = 20, latency_limit: int = 20_000) -> None:
        self.result_count = 0
        self.states: dict[str, int] = {}
        self.latencies_ms: list[float] = []
        self.sample_results: list[dict[str, object]] = []
        self.sample_limit = max(0, sample_limit)
        self.latency_limit = max(0, latency_limit)
        self.engine_summary: dict[str, object] | None = None

    def observe(self, event: dict[str, object]) -> None:
        if event.get("event") == "summary":
            self.engine_summary = dict(event)
            return
        if event.get("event") != "port":
            return
        self.result_count += 1
        state = str(event.get("state", "error"))
        self.states[state] = self.states.get(state, 0) + 1
        latency = event.get("latency_ms")
        if latency is not None and len(self.latencies_ms) < self.latency_limit:
            self.latencies_ms.append(float(latency))
        if len(self.sample_results) < self.sample_limit:
            self.sample_results.append({key: value for key, value in event.items() if key != "event"})

    def latency_summary(self) -> dict[str, float | int | None]:
        if not self.latencies_ms:
            return {"samples": 0, "min_ms": None, "p50_ms": None, "p95_ms": None, "max_ms": None}
        return {
            "samples": len(self.latencies_ms),
            "min_ms": round(min(self.latencies_ms), 3),
            "p50_ms": round(percentile(self.latencies_ms, 50), 3),
            "p95_ms": round(percentile(self.latencies_ms, 95), 3),
            "max_ms": round(max(self.latencies_ms), 3),
        }


def percentile(values: list[float], percent: float) -> float:
    if not values:
        raise ValueError("percentile requires at least one value")
    if not 0 <= percent <= 100:
        raise ValueError("percent must be between 0 and 100")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * (percent / 100)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + ((ordered[upper] - ordered[lower]) * fraction)


def distribution(values: list[float], *, digits: int = 3) -> dict[str, float | int | None]:
    if not values:
        return {"count": 0, "min": None, "p50": None, "p95": None, "max": None, "mean": None, "stdev": None}
    return {
        "count": len(values),
        "min": round(min(values), digits),
        "p50": round(percentile(values, 50), digits),
        "p95": round(percentile(values, 95), digits),
        "max": round(max(values), digits),
        "mean": round(statistics.fmean(values), digits),
        "stdev": round(statistics.pstdev(values), digits) if len(values) > 1 else 0.0,
    }


def process_memory_bytes() -> tuple[int | None, int | None]:
    if os.name == "nt":
        return _windows_process_memory_bytes()
    status_path = "/proc/self/status"
    if os.path.isfile(status_path):
        current = None
        peak = None
        try:
            with open(status_path, encoding="ascii") as status:
                for line in status:
                    if line.startswith("VmRSS:"):
                        current = int(line.split()[1]) * 1024
                    elif line.startswith("VmHWM:"):
                        peak = int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            return None, None
        return current, peak
    return None, None


def _windows_process_memory_bytes() -> tuple[int | None, int | None]:
    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    try:
        kernel32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        psapi.GetProcessMemoryInfo.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ProcessMemoryCounters),
            ctypes.c_ulong,
        ]
        psapi.GetProcessMemoryInfo.restype = ctypes.c_bool
        handle = kernel32.GetCurrentProcess()
        success = psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)
    except (AttributeError, OSError):
        return None, None
    if not success:
        return None, None
    return int(counters.WorkingSetSize), int(counters.PeakWorkingSetSize)
