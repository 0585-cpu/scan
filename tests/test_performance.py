import unittest
from unittest.mock import patch

from netroach.models import ScanSummary
from netroach.performance import ProcessMeter, StreamingScanMetrics, distribution, percentile, process_memory_bytes
from tools import benchmark_scan, soak_scan


class PerformanceTests(unittest.TestCase):
    def test_percentiles_distribution_and_process_meter(self):
        self.assertEqual(percentile([1.0, 2.0, 3.0], 50), 2.0)
        self.assertEqual(percentile([1.0, 3.0], 50), 2.0)
        self.assertEqual(distribution([1.0, 2.0, 3.0])["p95"], 2.9)
        with ProcessMeter() as meter:
            sum(range(1000))
            measurement = meter.finish()
        self.assertGreaterEqual(measurement.elapsed_s, 0)
        self.assertGreaterEqual(measurement.python_peak_bytes, 0)
        current, peak = process_memory_bytes()
        if current is not None and peak is not None:
            self.assertGreater(current, 0)
            self.assertGreaterEqual(peak, current)

    def test_streaming_scan_metrics_are_bounded(self):
        metrics = StreamingScanMetrics(sample_limit=2, latency_limit=3)
        for port in range(10):
            metrics.observe(
                {
                    "event": "port",
                    "host": "127.0.0.1",
                    "port": port + 1,
                    "state": "closed",
                    "latency_ms": float(port),
                }
            )
        self.assertEqual(metrics.result_count, 10)
        self.assertEqual(metrics.states, {"closed": 10})
        self.assertEqual(len(metrics.sample_results), 2)
        self.assertEqual(metrics.latency_summary()["samples"], 3)

    def test_benchmark_uses_streaming_and_checks_completeness(self):
        args = benchmark_scan.build_parser().parse_args(
            [
                "--targets",
                "127.0.0.1",
                "--ports",
                "80",
                "--scope",
                "127.0.0.0/8",
                "--confirm-authorized",
                "--warmup-runs",
                "0",
                "--runs",
                "2",
            ]
        )

        def fake_run_scan(**kwargs):
            kwargs["on_event"](
                {
                    "event": "port",
                    "scan_id": kwargs["scan_id"],
                    "host": "127.0.0.1",
                    "port": 80,
                    "protocol": "tcp",
                    "state": "closed",
                    "latency_ms": 1.0,
                }
            )
            return [], ScanSummary(scan_id=kwargs["scan_id"], total=1, closed=1)

        with patch("tools.benchmark_scan.run_scan", side_effect=fake_run_scan):
            report = benchmark_scan.run_benchmark(args)

        self.assertTrue(report["streaming_mode"])
        self.assertTrue(report["assessment"]["passed"])
        self.assertEqual(report["aggregate"]["checks_per_sec"]["count"], 2)
        self.assertTrue(all(run["retained_results"] == 0 for run in report["runs"]))

    def test_soak_assesses_completeness_and_memory_growth(self):
        args = soak_scan.build_parser().parse_args(
            [
                "--targets",
                "127.0.0.1",
                "--ports",
                "80",
                "--scope",
                "127.0.0.0/8",
                "--confirm-authorized",
                "--iterations",
                "3",
                "--sleep-ms",
                "0",
            ]
        )

        def fake_run_scan(**kwargs):
            kwargs["on_event"](
                {
                    "event": "port",
                    "scan_id": kwargs["scan_id"],
                    "host": "127.0.0.1",
                    "port": 80,
                    "protocol": "tcp",
                    "state": "closed",
                    "latency_ms": 1.0,
                }
            )
            return [], ScanSummary(scan_id=kwargs["scan_id"], total=1, closed=1)

        with patch("tools.soak_scan.run_scan", side_effect=fake_run_scan):
            report = soak_scan.run_soak(args)

        self.assertEqual(report["iteration_count"], 3)
        self.assertTrue(report["assessment"]["passed"])
        self.assertFalse(report["assessment"]["state_drift_detected"])
        self.assertTrue(all(item["complete"] for item in report["iterations"]))

    def test_soak_fails_assessment_when_state_counts_drift(self):
        args = soak_scan.build_parser().parse_args(
            [
                "--targets",
                "127.0.0.1",
                "--ports",
                "80",
                "--scope",
                "127.0.0.0/8",
                "--confirm-authorized",
                "--iterations",
                "2",
                "--sleep-ms",
                "0",
            ]
        )
        call_count = 0

        def fake_run_scan(**kwargs):
            nonlocal call_count
            call_count += 1
            state = "closed" if call_count == 1 else "open"
            kwargs["on_event"](
                {
                    "event": "port",
                    "scan_id": kwargs["scan_id"],
                    "host": "127.0.0.1",
                    "port": 80,
                    "protocol": "tcp",
                    "state": state,
                    "latency_ms": 1.0,
                }
            )
            summary = ScanSummary(scan_id=kwargs["scan_id"], total=1)
            setattr(summary, state, 1)
            return [], summary

        with patch("tools.soak_scan.run_scan", side_effect=fake_run_scan):
            report = soak_scan.run_soak(args)

        self.assertFalse(report["assessment"]["passed"])
        self.assertTrue(report["assessment"]["state_drift_detected"])


if __name__ == "__main__":
    unittest.main()
