from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netprobe.engine import run_scan
from netprobe.performance import ProcessMeter, StreamingScanMetrics, distribution
from tools.scan_harness import add_scan_arguments, prepare_scan


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = run_soak(args)
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run repeated authorized Scaprobe scans and emit a soak JSON report.")
    add_scan_arguments(parser)
    parser.add_argument("--iterations", type=int, default=10, help="maximum scan iterations")
    parser.add_argument("--duration-s", type=float, help="optional wall-clock duration limit")
    parser.add_argument("--sleep-ms", type=int, default=250, help="pause between iterations")
    parser.add_argument(
        "--max-memory-growth-mb",
        type=float,
        default=64.0,
        help="fail assessment when controller RSS grows beyond this amount",
    )
    parser.add_argument("--output", help="write JSON report to this path")
    return parser


def run_soak(args: argparse.Namespace) -> dict[str, object]:
    if args.iterations < 1:
        raise ValueError("--iterations must be at least 1")
    if args.duration_s is not None and args.duration_s <= 0:
        raise ValueError("--duration-s must be greater than 0")
    if args.sleep_ms < 0:
        raise ValueError("--sleep-ms cannot be negative")
    if args.max_memory_growth_mb < 0:
        raise ValueError("--max-memory-growth-mb cannot be negative")

    targets, target_expr, ports, port_expr, workload, settings = prepare_scan(args)

    started_at = datetime.now(timezone.utc).isoformat()
    started = time.perf_counter()
    deadline = started + args.duration_s if args.duration_s else None
    iterations: list[dict[str, object]] = []

    for index in range(args.iterations):
        if deadline is not None and time.perf_counter() >= deadline:
            break
        scan_id = f"soak-{index + 1}-{uuid.uuid4().hex[:8]}"
        metrics = StreamingScanMetrics(sample_limit=0)
        try:
            with ProcessMeter() as meter:
                results, summary = run_scan(
                    scan_id=scan_id,
                    targets=targets,
                    ports=ports,
                    settings=settings,
                    target_expr=target_expr,
                    port_expr=port_expr,
                    engine_path=args.engine_path,
                    on_event=metrics.observe,
                    collect_results=False,
                )
                process = meter.finish()
            complete = metrics.result_count == workload["attempts"] == summary.total
            iterations.append(
                {
                    "scan_id": scan_id,
                    "ok": True,
                    "complete": complete,
                    "observed_results": metrics.result_count,
                    "checks_per_sec": (
                        round(workload["attempts"] / process.elapsed_s, 2)
                        if process.elapsed_s
                        else workload["attempts"]
                    ),
                    "latency": metrics.latency_summary(),
                    "states": metrics.states,
                    "process": process.to_dict(),
                    "engine_process": metrics.engine_summary,
                    "retained_results": len(results),
                    "summary": summary.to_dict(),
                }
            )
        except Exception as exc:
            iterations.append(
                {
                    "scan_id": scan_id,
                    "ok": False,
                    "complete": False,
                    "error": str(exc),
                }
            )
        if index + 1 < args.iterations and args.sleep_ms > 0:
            time.sleep(args.sleep_ms / 1000)

    elapsed_s = round(time.perf_counter() - started, 3)
    successful = [item for item in iterations if item["ok"]]
    complete_iterations = [item for item in successful if item["complete"]]
    completed_checks = workload["attempts"] * len(complete_iterations)
    durations = [float(item["process"]["elapsed_s"]) for item in successful]
    throughputs = [float(item["checks_per_sec"]) for item in successful]
    rss_values = [
        int(item["process"]["rss_after_bytes"])
        for item in successful
        if item["process"]["rss_after_bytes"] is not None
    ]
    memory_growth = rss_values[-1] - rss_values[0] if len(rss_values) >= 2 else None
    allowed_growth = int(args.max_memory_growth_mb * 1024 * 1024)
    memory_within_limit = memory_growth is None or memory_growth <= allowed_growth
    state_signatures = {json.dumps(item["states"], sort_keys=True) for item in successful}
    state_stable = len(state_signatures) <= 1
    engine_peak_rss_values = [
        float(item["engine_process"]["process_peak_rss_bytes"])
        for item in successful
        if item.get("engine_process") and item["engine_process"].get("process_peak_rss_bytes") is not None
    ]
    passed = (
        bool(iterations)
        and len(successful) == len(iterations)
        and len(complete_iterations) == len(iterations)
        and memory_within_limit
        and state_stable
    )
    return {
        "tool": "soak_scan",
        "started_at": started_at,
        "protocol": args.protocol,
        "workload": workload,
        "iteration_count": len(iterations),
        "failed_iterations": sum(1 for item in iterations if not item["ok"]),
        "elapsed_s": elapsed_s,
        "completed_checks_per_sec": round(completed_checks / elapsed_s, 2) if elapsed_s > 0 else completed_checks,
        "settings": {
            "timeout_ms": settings.timeout_ms,
            "concurrency": settings.concurrency,
            "rate_limit_per_sec": settings.rate_limit_per_sec,
            "service_probe": settings.service_probe,
            "udp_retries": settings.udp_retries,
            "sleep_ms": args.sleep_ms,
        },
        "aggregate": {
            "elapsed_s": distribution(durations),
            "checks_per_sec": distribution(throughputs, digits=2),
            "controller_rss_growth_bytes": memory_growth,
            "engine_peak_rss_bytes": distribution(engine_peak_rss_values, digits=0),
        },
        "assessment": {
            "passed": passed,
            "incomplete_iterations": len(successful) - len(complete_iterations),
            "memory_growth_limit_bytes": allowed_growth,
            "memory_growth_measured": memory_growth is not None,
            "memory_growth_within_limit": memory_within_limit,
            "state_drift_detected": not state_stable,
        },
        "measurement_scope": {
            "controller_rss_and_cpu": "Python controller process",
            "engine_process": "Rust summary includes elapsed time and end/peak RSS on Windows and Linux",
            "streaming_results": True,
        },
        "iterations": iterations,
    }


if __name__ == "__main__":
    raise SystemExit(main())
