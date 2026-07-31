from __future__ import annotations

import argparse
import json
import sys
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
    report = run_benchmark(args)
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run an authorized Scaprobe scan benchmark and emit a JSON report.")
    add_scan_arguments(parser)
    parser.add_argument("--warmup-runs", type=int, default=1, help="unmeasured warmup runs")
    parser.add_argument("--runs", type=int, default=3, help="measured benchmark runs")
    parser.add_argument(
        "--retain-results",
        action="store_true",
        help="retain all PortResult objects; default exercises bounded streaming mode",
    )
    parser.add_argument("--output", help="write JSON report to this path")
    return parser


def run_benchmark(args: argparse.Namespace) -> dict[str, object]:
    if args.runs < 1:
        raise ValueError("--runs must be at least 1")
    if args.warmup_runs < 0:
        raise ValueError("--warmup-runs cannot be negative")
    targets, target_expr, ports, port_expr, workload, settings = prepare_scan(args)
    started_at = datetime.now(timezone.utc).isoformat()
    for index in range(args.warmup_runs):
        run_scan(
            scan_id=f"benchmark-warmup-{index + 1}-{uuid.uuid4().hex[:8]}",
            targets=targets,
            ports=ports,
            settings=settings,
            target_expr=target_expr,
            port_expr=port_expr,
            engine_path=args.engine_path,
            collect_results=False,
        )

    runs: list[dict[str, object]] = []
    for index in range(args.runs):
        scan_id = f"benchmark-{index + 1}-{uuid.uuid4().hex[:8]}"
        metrics = StreamingScanMetrics()
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
                    collect_results=args.retain_results,
                )
                process = meter.finish()
            elapsed_s = process.elapsed_s
            complete = metrics.result_count == workload["attempts"] == summary.total
            runs.append(
                {
                    "run": index + 1,
                    "scan_id": scan_id,
                    "ok": True,
                    "complete": complete,
                    "observed_results": metrics.result_count,
                    "checks_per_sec": round(workload["attempts"] / elapsed_s, 2) if elapsed_s else workload["attempts"],
                    "latency": metrics.latency_summary(),
                    "states": metrics.states,
                    "summary": summary.to_dict(),
                    "process": process.to_dict(),
                    "engine_process": metrics.engine_summary,
                    "retained_results": len(results),
                    "sample_results": metrics.sample_results,
                }
            )
        except Exception as exc:  # noqa: BLE001 - benchmark reports failures instead of hiding prior runs.
            runs.append({"run": index + 1, "scan_id": scan_id, "ok": False, "complete": False, "error": str(exc)})

    successful = [run for run in runs if run["ok"]]
    elapsed_values = [float(run["process"]["elapsed_s"]) for run in successful]
    throughput_values = [float(run["checks_per_sec"]) for run in successful]
    rss_delta_values = [
        float(run["process"]["rss_delta_bytes"])
        for run in successful
        if run["process"]["rss_delta_bytes"] is not None
    ]
    engine_peak_rss_values = [
        float(run["engine_process"]["process_peak_rss_bytes"])
        for run in successful
        if run.get("engine_process") and run["engine_process"].get("process_peak_rss_bytes") is not None
    ]
    passed = len(successful) == args.runs and all(bool(run["complete"]) for run in successful)
    return {
        "tool": "benchmark_scan",
        "started_at": started_at,
        "protocol": args.protocol,
        "workload": workload,
        "warmup_runs": args.warmup_runs,
        "measured_runs": args.runs,
        "streaming_mode": not args.retain_results,
        "settings": {
            "timeout_ms": settings.timeout_ms,
            "concurrency": settings.concurrency,
            "rate_limit_per_sec": settings.rate_limit_per_sec,
            "service_probe": settings.service_probe,
            "udp_retries": settings.udp_retries,
        },
        "aggregate": {
            "elapsed_s": distribution(elapsed_values),
            "checks_per_sec": distribution(throughput_values, digits=2),
            "rss_delta_bytes": distribution(rss_delta_values, digits=0),
            "engine_peak_rss_bytes": distribution(engine_peak_rss_values, digits=0),
        },
        "measurement_scope": {
            "controller_rss_and_cpu": "Python controller process",
            "engine_process": "Rust summary includes elapsed time and end/peak RSS on Windows and Linux",
            "python_allocations": "tracemalloc allocations in the Python controller process",
            "latency_samples_cap": 20_000,
        },
        "assessment": {
            "passed": passed,
            "failed_runs": args.runs - len(successful),
            "incomplete_runs": sum(1 for run in successful if not run["complete"]),
        },
        "runs": runs,
    }


if __name__ == "__main__":
    raise SystemExit(main())
