import importlib.util
import io
import ipaddress
import json
import sqlite3
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

PNG_HEADER = bytes([137, 80, 78, 71, 13, 10, 26, 10]) + b"shot"


def has_fastapi_testclient() -> bool:
    if importlib.util.find_spec("fastapi") is None:
        return False
    try:
        from fastapi.testclient import TestClient  # noqa: F401
    except RuntimeError:
        return False
    return True


@unittest.skipUnless(has_fastapi_testclient(), "fastapi TestClient dependencies are not installed")
class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        from netroach.version import __version__

        diagnostics = {
            "app_version": __version__,
            "platform": "test",
            "python": "test",
            "rust_engine": "netroach-engine",
            "rust_engine_available": True,
            "rust_engine_version": "netroach-engine test",
            "scapy_available": True,
            "database_path": "",
        }
        self.engine_patch = patch("netroach.api.resolve_engine_path", return_value="netroach-engine")
        self.diagnostics_patch = patch("netroach.api.collect_diagnostics")
        self.engine_patch.start()
        diagnostics_mock = self.diagnostics_patch.start()
        diagnostics_mock.return_value.to_dict.return_value = diagnostics
        self.addCleanup(self.engine_patch.stop)
        self.addCleanup(self.diagnostics_patch.stop)

    def test_startup_recovery_scans_only_missing_host_port_pairs(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import PortResult, ScanSummary
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="80,81",
                scope=["127.0.0.0/8"],
                params={
                    "resumable": True,
                    "max_hosts": 10,
                    "protocol": "tcp",
                    "timeout_ms": 50,
                    "concurrency": 10,
                    "rate_limit_per_sec": 100,
                    "service_probe": False,
                },
            )
            repo.mark_scan_started(scan_id)
            repo.add_port_result(
                PortResult(
                    scan_id=scan_id,
                    host="127.0.0.1",
                    port=80,
                    protocol="tcp",
                    state="open",
                    latency_ms=1.0,
                )
            )
            calls: list[tuple[list[str], list[int]]] = []

            def fake_run_scan(**kwargs):
                targets = [str(target) for target in kwargs["targets"]]
                ports = list(kwargs["ports"])
                calls.append((targets, ports))
                for target in targets:
                    for port in ports:
                        kwargs["on_event"](
                            {
                                "event": "port",
                                "scan_id": scan_id,
                                "host": target,
                                "port": port,
                                "protocol": "tcp",
                                "state": "closed",
                                "latency_ms": 1.0,
                            }
                        )
                return [], ScanSummary(scan_id=scan_id, total=len(targets) * len(ports))

            with patch("netroach.api.run_scan", side_effect=fake_run_scan):
                with TestClient(create_app(str(db_path))) as client:
                    self.assertEqual(client.get("/v1/health").status_code, 200)
                    deadline = time.monotonic() + 3
                    while repo.get_job(scan_id)["status"] not in {"completed", "failed"} and time.monotonic() < deadline:
                        time.sleep(0.02)

            self.assertEqual(repo.get_job(scan_id)["status"], "completed")
            self.assertEqual(calls, [(["127.0.0.1"], [81])])
            self.assertEqual(repo.count_results(scan_id), 2)

    def test_health(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.version import __version__

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/netroach.db"))
            response = client.get("/v1/health")
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["status"], "ok")
            self.assertTrue(payload["rust_engine_available"])
            self.assertEqual(Path(payload["db"]), Path(tmp) / "netroach.db")
            self.assertIn("diagnostics", payload)
            self.assertEqual(payload["diagnostics"]["app_version"], __version__)
            self.assertIn("platform", payload["diagnostics"])
            self.assertIn("rust_engine_available", payload["diagnostics"])
            self.assertIn("rust_engine_version", payload["diagnostics"])
            self.assertIn("scapy_available", payload["diagnostics"])
            self.assertEqual(Path(payload["diagnostics"]["database_path"]), Path(tmp) / "netroach.db")
            self.assertIn("web", payload["plugins"]["port_profiles"])
            self.assertIn("infra", payload["plugins"]["port_profiles"])

    def test_health_is_degraded_and_scan_is_rejected_when_engine_is_missing(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            with patch("netroach.api.resolve_engine_path", return_value=None):
                with patch("netroach.api.collect_diagnostics") as collect:
                    collect.return_value.to_dict.return_value = {
                        "rust_engine": None,
                        "rust_engine_available": False,
                        "rust_engine_version": None,
                    }
                    with TestClient(create_app(str(db_path))) as client:
                        health = client.get("/v1/health")
                        rejected = client.post(
                            "/v1/scans",
                            json={
                                "targets": "127.0.0.1",
                                "ports": "80",
                                "scope": ["127.0.0.0/8"],
                                "confirm_authorized": True,
                            },
                        )
                        plugins = client.get("/v1/plugins")
                        dashboard = client.get("/dashboard")
                        pcaps = client.get("/v1/pcaps/analyses")
                        audits = client.get("/v1/packets/audits")
                        oast = client.get("/v1/oast/sessions")

            self.assertEqual(health.status_code, 200)
            self.assertEqual(health.json()["status"], "degraded")
            self.assertFalse(health.json()["rust_engine_available"])
            self.assertEqual(rejected.status_code, 503)
            self.assertEqual(rejected.json(), {"detail": {"error": "Rust scan engine is unavailable"}})
            self.assertEqual(SQLiteRepository(db_path).list_jobs(), [])
            self.assertEqual(plugins.status_code, 200)
            self.assertEqual(dashboard.status_code, 200)
            self.assertEqual(pcaps.status_code, 200)
            self.assertEqual(audits.status_code, 200)
            self.assertEqual(oast.status_code, 200)

    def test_startup_preserves_recoverable_jobs_when_engine_is_missing(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="80",
                scope=["127.0.0.0/8"],
                params={"resumable": True},
            )
            repo.mark_scan_started(scan_id)
            with patch("netroach.api.resolve_engine_path", return_value=None):
                with TestClient(create_app(str(db_path))) as client:
                    self.assertEqual(client.get("/v1/scans").status_code, 200)

            # The job is kept for a later start that has an engine, but it must
            # not keep claiming to be running: the dashboard reads that as live
            # work and holds its progress strip and fast poll open forever.
            job = repo.get_job(scan_id)
            self.assertEqual(job["status"], "recovering")
            self.assertIn("engine", job["summary"]["interrupted"])
            self.assertIn(scan_id, [str(item["id"]) for item in repo.list_recoverable_scan_jobs()])

    def test_evidence_capture_failures_are_recorded_on_the_job(self):
        """A screenshot that fails has to leave a trace somewhere.

        The CLI prints these warnings; the API path dropped the summary, so a
        capture that failed produced no log line, no field in the response and
        nothing in the database - the operator saw a scan with less evidence
        than they asked for and no way to learn why.
        """
        from netroach.api import _run_scan_job
        from netroach.engine import EngineSettings
        from netroach.evidence import ScreenshotCaptureSummary
        from netroach.models import ScanSummary
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1", ports="80", scope=["127.0.0.1/32"], params={"protocol": "tcp"}
            )

            def fake_run_scan(**kwargs):
                kwargs["on_event"](
                    {
                        "event": "port",
                        "scan_id": scan_id,
                        "host": "127.0.0.1",
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "latency_ms": 1.0,
                        "service_name": "http",
                    }
                )
                return [], ScanSummary(scan_id=scan_id, total=1)

            failure = ScreenshotCaptureSummary(
                candidates=1, captured=0, failed=1, errors=("http://127.0.0.1/: net::ERR_FAILED",)
            )
            with (
                patch("netroach.api.run_scan", side_effect=fake_run_scan),
                patch("netroach.api.capture_automatic_evidence", return_value=failure),
            ):
                _run_scan_job(
                    str(db_path),
                    scan_id,
                    [ipaddress.ip_address("127.0.0.1")],
                    [80],
                    EngineSettings(protocol="tcp"),
                    True,
                )

            summary = repo.get_job(scan_id)["summary"]
            self.assertEqual(repo.get_job(scan_id)["status"], "completed")
            evidence = summary["evidence"]
            self.assertEqual(evidence["candidates"], 1)
            self.assertEqual(evidence["captured"], 0)
            self.assertEqual(evidence["without_evidence"], 1)
            self.assertIn("net::ERR_FAILED", evidence["errors"][0])
            self.assertNotIn("failed", evidence)

    def test_a_recovered_capture_reads_as_recovered_not_failed(self):
        """A web screenshot that failed but fell back to a transcript.

        The stored count was `failed: 0` beside a populated `errors` list,
        because the candidate did end up with evidence - correct, and it read
        as a contradiction. The number now says what it counts: candidates
        left with no evidence at all.
        """
        from netroach.api import _run_scan_job
        from netroach.engine import EngineSettings
        from netroach.evidence import ScreenshotCaptureSummary
        from netroach.models import ScanSummary
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1", ports="80", scope=["127.0.0.1/32"], params={"protocol": "tcp"}
            )

            def fake_run_scan(**kwargs):
                kwargs["on_event"](
                    {
                        "event": "port",
                        "scan_id": scan_id,
                        "host": "127.0.0.1",
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "latency_ms": 1.0,
                        "service_name": "http",
                    }
                )
                return [], ScanSummary(scan_id=scan_id, total=1)

            recovered = ScreenshotCaptureSummary(
                candidates=1,
                captured=1,
                failed=0,
                terminal_transcripts=1,
                errors=("http://127.0.0.1/: Protocol error (Page.captureScreenshot)",),
            )
            with (
                patch("netroach.api.run_scan", side_effect=fake_run_scan),
                patch("netroach.api.capture_automatic_evidence", return_value=recovered),
            ):
                _run_scan_job(
                    str(db_path),
                    scan_id,
                    [ipaddress.ip_address("127.0.0.1")],
                    [80],
                    EngineSettings(protocol="tcp"),
                    True,
                )

            evidence = repo.get_job(scan_id)["summary"]["evidence"]
            self.assertEqual(evidence["captured"], 1)
            self.assertEqual(evidence["without_evidence"], 0)
            self.assertIn("captureScreenshot", evidence["errors"][0])

    def test_a_clean_capture_records_no_failures(self):
        from netroach.api import _run_scan_job
        from netroach.engine import EngineSettings
        from netroach.evidence import ScreenshotCaptureSummary
        from netroach.models import ScanSummary
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1", ports="80", scope=["127.0.0.1/32"], params={"protocol": "tcp"}
            )

            def fake_run_scan(**kwargs):
                kwargs["on_event"](
                    {
                        "event": "port",
                        "scan_id": scan_id,
                        "host": "127.0.0.1",
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "latency_ms": 1.0,
                    }
                )
                return [], ScanSummary(scan_id=scan_id, total=1)

            clean = ScreenshotCaptureSummary(candidates=1, captured=1, failed=0)
            with (
                patch("netroach.api.run_scan", side_effect=fake_run_scan),
                patch("netroach.api.capture_automatic_evidence", return_value=clean),
            ):
                _run_scan_job(
                    str(db_path),
                    scan_id,
                    [ipaddress.ip_address("127.0.0.1")],
                    [80],
                    EngineSettings(protocol="tcp"),
                    True,
                )

            self.assertNotIn("evidence", repo.get_job(scan_id)["summary"])

    def test_recovery_leaves_a_job_another_instance_is_running(self):
        """Two instances can share the default database.

        `worker_token` is NULL during a normal run, so it cannot tell a corpse
        from a peer - both instances used to resume the same scan and collide.
        A recent heartbeat now means "someone else owns this".
        """
        from netroach.api import _start_scan_recovery
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1", ports="80", scope=["127.0.0.1/32"], params={"resumable": True}
            )
            repo.mark_scan_started(scan_id)
            repo.record_scan_heartbeat(scan_id)

            with patch("netroach.api.run_scan") as run:
                threads = _start_scan_recovery(str(db_path))

            for thread in threads:
                thread.join(timeout=3)
            self.assertEqual(threads, [])
            run.assert_not_called()
            self.assertEqual(repo.get_job(scan_id)["status"], "running")

    def test_a_silent_engine_keeps_the_scan_heartbeat_alive(self):
        """A SYN sweep can run for minutes before it emits its first result."""
        from netroach.api import _run_scan_job
        from netroach.engine import EngineSettings
        from netroach.models import ScanSummary
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="192.0.2.1", ports="1-100", scope=["192.0.2.1/32"], params={"protocol": "tcp"}
            )
            heartbeats = []
            heartbeat_ready = threading.Event()
            real_heartbeat = SQLiteRepository.record_scan_heartbeat

            def counting_heartbeat(self, sid):
                result = real_heartbeat(self, sid)
                heartbeats.append(time.monotonic())
                if len(heartbeats) >= 3:
                    heartbeat_ready.set()
                return result

            def silent_run_scan(**_kwargs):
                # SQLite writes and Windows scheduling can exceed a 60 ms sleep.
                self.assertTrue(heartbeat_ready.wait(2), "silent engine received no periodic heartbeat")
                return [], ScanSummary(scan_id=scan_id, total=100)

            with (
                patch("netroach.api.SCAN_HEARTBEAT_INTERVAL_S", 0.01),
                patch("netroach.api.run_scan", side_effect=silent_run_scan),
                patch.object(SQLiteRepository, "record_scan_heartbeat", counting_heartbeat),
            ):
                _run_scan_job(
                    str(db_path),
                    scan_id,
                    [ipaddress.ip_address("192.0.2.1")],
                    list(range(1, 101)),
                    EngineSettings(protocol="tcp", syn_sweep=True),
                )

            self.assertGreaterEqual(len(heartbeats), 3)
            self.assertEqual(repo.get_job(scan_id)["status"], "completed")

    def test_a_silent_engine_is_terminated_when_the_live_job_is_cancelled(self):
        from netroach.api import _run_scan_job
        from netroach.engine import EngineSettings, ScanCancelled
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="192.0.2.1", ports="1-100", scope=["192.0.2.1/32"], params={"protocol": "tcp"}
            )
            engine_started = threading.Event()
            engine_stopped = threading.Event()

            def silent_run_scan(**kwargs):
                engine_started.set()
                while not kwargs["should_stop"]():
                    time.sleep(0.005)
                engine_stopped.set()
                raise ScanCancelled("cancelled by test")

            with patch("netroach.api.run_scan", side_effect=silent_run_scan):
                worker = threading.Thread(
                    target=_run_scan_job,
                    args=(
                        str(db_path),
                        scan_id,
                        [ipaddress.ip_address("192.0.2.1")],
                        list(range(1, 101)),
                        EngineSettings(protocol="tcp", syn_sweep=True),
                    ),
                )
                worker.start()
                self.assertTrue(engine_started.wait(timeout=2))
                repo.request_scan_cancel(scan_id)
                worker.join(timeout=3)

            self.assertFalse(worker.is_alive())
            self.assertTrue(engine_stopped.is_set())
            self.assertEqual(repo.get_job(scan_id)["status"], "cancelled")

    def test_recovery_takes_over_a_job_whose_worker_stopped_beating(self):
        from netroach.api import _start_scan_recovery
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1", ports="80", scope=["127.0.0.1/32"], params={"resumable": True, "max_hosts": 4}
            )
            repo.mark_scan_started(scan_id)
            repo.record_scan_heartbeat(scan_id)
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    "UPDATE scan_jobs SET heartbeat_at=datetime(CURRENT_TIMESTAMP, '-600 seconds') WHERE id=?",
                    (scan_id,),
                )
                conn.commit()
            finally:
                conn.close()

            with patch("netroach.api.run_scan") as run:
                threads = _start_scan_recovery(str(db_path))
                for thread in threads:
                    thread.join(timeout=5)

            self.assertEqual(len(threads), 1)
            run.assert_called()

    def test_the_cancel_check_does_not_run_once_per_probe(self):
        """Checking for cancellation opened a SQLite connection per probe.

        `session()` opens a connection, runs three PRAGMAs, queries and closes
        - about 1.24ms, against 0.004ms for the same query on a live
        connection. It ran once in on_event and once per engine read loop
        iteration, so two of them sat in front of every single probe and
        capped a scan at a few hundred ports per second no matter what
        concurrency, timeout or rate limit were set to.
        """
        from netroach.api import _run_scan_job
        from netroach.engine import EngineSettings
        from netroach.models import ScanSummary
        from netroach.storage import SQLiteRepository

        probes = 2000
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports=f"1-{probes}",
                scope=["127.0.0.1/32"],
                params={"protocol": "tcp"},
            )
            calls = {"count": 0}
            real_check = SQLiteRepository.is_scan_cancel_requested

            def counting_check(self, sid):
                calls["count"] += 1
                return real_check(self, sid)

            def fake_run_scan(**kwargs):
                stop = kwargs.get("should_stop")
                for port in range(1, probes + 1):
                    if stop is not None:
                        stop()
                    kwargs["on_event"](
                        {
                            "event": "port",
                            "scan_id": scan_id,
                            "host": "127.0.0.1",
                            "port": port,
                            "protocol": "tcp",
                            "state": "filtered",
                            "latency_ms": 1.0,
                        }
                    )
                return [], ScanSummary(scan_id=scan_id, total=probes)

            with (
                patch("netroach.api.run_scan", side_effect=fake_run_scan),
                patch.object(SQLiteRepository, "is_scan_cancel_requested", counting_check),
            ):
                _run_scan_job(
                    str(db_path),
                    scan_id,
                    [ipaddress.ip_address("127.0.0.1")],
                    list(range(1, probes + 1)),
                    EngineSettings(protocol="tcp"),
                )

            # Bulk states are stored as a count, so ask for the recorded total
            # rather than the row count.
            self.assertEqual(sum(repo.count_results_by_state(scan_id).values()), probes)
            # A handful of polls plus the cold checks around the scan, not one
            # per probe and certainly not two.
            self.assertLess(calls["count"], 50, f"{calls['count']} cancel checks for {probes} probes")

    def test_a_cancel_is_still_noticed_promptly(self):
        from netroach.api import _run_scan_job
        from netroach.engine import EngineSettings
        from netroach.models import ScanSummary
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1", ports="1-500", scope=["127.0.0.1/32"], params={"protocol": "tcp"}
            )
            repo.request_scan_cancel(scan_id)

            def fake_run_scan(**kwargs):
                for port in range(1, 501):
                    kwargs["on_event"](
                        {
                            "event": "port",
                            "scan_id": scan_id,
                            "host": "127.0.0.1",
                            "port": port,
                            "protocol": "tcp",
                            "state": "filtered",
                            "latency_ms": 1.0,
                        }
                    )
                return [], ScanSummary(scan_id=scan_id, total=500)

            with patch("netroach.api.run_scan", side_effect=fake_run_scan):
                _run_scan_job(
                    str(db_path),
                    scan_id,
                    [ipaddress.ip_address("127.0.0.1")],
                    list(range(1, 501)),
                    EngineSettings(protocol="tcp"),
                )

            self.assertEqual(repo.get_job(scan_id)["status"], "cancelled")

    def test_a_failing_final_flush_still_marks_the_job(self):
        """A dying scan thread must never leave the job reading 'running'.

        The error handler used to flush before marking the job. When that flush
        raised - which it did, because a failed batch was left in the pending
        list and retried - the thread died with the job still 'running', and the
        dashboard treated the corpse as live work indefinitely.
        """
        from netroach.api import _run_scan_job
        from netroach.engine import EngineSettings
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1", ports="80", scope=["127.0.0.1/32"], params={"protocol": "tcp"}
            )

            def explode(*_args, **_kwargs):
                raise RuntimeError("engine exploded")

            with (
                patch("netroach.api.run_scan", side_effect=explode),
                patch.object(SQLiteRepository, "add_port_results", side_effect=OSError("disk gone")),
            ):
                _run_scan_job(
                    str(db_path),
                    scan_id,
                    [ipaddress.ip_address("127.0.0.1")],
                    [80],
                    EngineSettings(protocol="tcp"),
                )

            job = repo.get_job(scan_id)
            self.assertEqual(job["status"], "failed")
            self.assertIn("engine exploded", job["summary"]["error"])

    def test_dashboard_routes(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/netroach.db"))

            root = client.get("/")
            dashboard = client.get("/dashboard")

            self.assertEqual(root.status_code, 200)
            self.assertIn("text/html", root.headers["content-type"])
            self.assertIn("Netroach 콘솔", root.text)
            self.assertIn("/v1/scans", root.text)
            self.assertIn("data-view-target=\"overview\"", root.text)
            self.assertIn("패킷 전송", root.text)
            self.assertIn("진단", root.text)
            self.assertIn("대상을 그대로 승인 범위로 사용", root.text)
            self.assertIn("scope_from_targets", root.text)
            self.assertIn("/v1/pcaps/analyze", root.text)
            self.assertIn("/v1/packets/send", root.text)
            self.assertNotIn("<th>Latency</th>", root.text)
            self.assertNotIn("result.latency_ms", root.text)
            self.assertIn("capture_screenshots", root.text)
            self.assertIn("data-evidence-target", root.text)
            self.assertIn("data-evidence-delete", root.text)
            self.assertIn("bundle_evidence=true", root.text)
            self.assertNotIn("CSV + Images", root.text)
            self.assertNotIn("Excel + Images", root.text)
            self.assertIn('id="scanExportCsv"', root.text)
            self.assertIn('id="scanExportXlsx"', root.text)
            self.assertIn('id="scanJobSearch"', root.text)
            self.assertIn('id="scanJobStatus"', root.text)
            self.assertIn('id="scanResultSearch"', root.text)
            self.assertIn('id="scanResultPageSize"', root.text)
            self.assertIn('id="scanHostTabs"', root.text)
            self.assertIn('id="scanStateTabs"', root.text)
            self.assertIn('id="scanResultPagination"', root.text)
            self.assertNotIn('id="scanOpenOnly"', root.text)
            self.assertIn('id="scanAdvanced"', root.text)
            self.assertIn('id="scanPortProfileFile"', root.text)
            # The imported-profile list was replaced by the preset chips; the
            # TXT import control it fed still applies straight into the form.
            self.assertIn('id="scanPresetChips"', root.text)
            self.assertIn("compactPortsHtml(job.ports", root.text)
            self.assertIn("const formElement = event.currentTarget", root.text)
            self.assertIn("formElement.elements.confirm_authorized.checked = false", root.text)
            self.assertIn("Rust 엔진 없음", root.text)
            self.assertNotIn('<label for="scanProfile">Port Profile</label>', root.text)
            self.assertIn("format=xlsx", root.text)
            self.assertIn("width: 80px;", root.text)
            self.assertEqual(dashboard.status_code, 200)
            self.assertIn("스캔 시작", dashboard.text)

    def test_scan_requires_scope(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/netroach.db"))
            response = client.post(
                "/v1/scans",
                json={"targets": "127.0.0.1", "ports": "80", "confirm_authorized": True},
            )
            self.assertEqual(response.status_code, 400)
            self.assertIn("error", response.json()["detail"])

    def test_scan_create_response_fields(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import ScanSummary

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/netroach.db"))
            with patch("netroach.api.run_scan") as run_scan:
                run_scan.side_effect = lambda **kwargs: ([], ScanSummary(scan_id=kwargs["scan_id"]))
                response = client.post(
                    "/v1/scans",
                    json={
                        "targets": "127.0.0.1",
                        "ports": "80",
                        "scope": ["127.0.0.0/8"],
                        "confirm_authorized": True,
                        "timeout_ms": 50,
                    },
                )

            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(set(payload), {"scan_id", "status", "workload"})
            self.assertEqual(payload["status"], "queued")
            self.assertEqual(payload["workload"], {"hosts": 1, "ports": 1, "attempts": 1})

    def test_scan_can_derive_scope_from_targets(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import ScanSummary

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/netroach.db"))
            with patch("netroach.api.run_scan") as run_scan:
                run_scan.side_effect = lambda **kwargs: ([], ScanSummary(scan_id=kwargs["scan_id"]))
                response = client.post(
                    "/v1/scans",
                    json={
                        "targets": "127.0.0.1\n127.0.0.0/30",
                        "ports": "80",
                        "scope_from_targets": True,
                        "confirm_authorized": True,
                    },
                )

            self.assertEqual(response.status_code, 200)
            scan_id = response.json()["scan_id"]
            job = client.get(f"/v1/scans/{scan_id}").json()
            self.assertEqual(job["scope"], ["127.0.0.1/32", "127.0.0.0/30"])

    def test_scan_supports_exclude_profile_and_top_ports(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import ScanSummary

        captured: dict[str, object] = {}

        def fake_run_scan(**kwargs):
            captured.update(kwargs)
            return [], ScanSummary(scan_id=kwargs["scan_id"])

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/netroach.db"))
            with patch("netroach.api.run_scan", side_effect=fake_run_scan):
                response = client.post(
                    "/v1/scans",
                    json={
                        "targets": "127.0.0.1,127.0.0.2",
                        "scope": ["127.0.0.0/8"],
                        "confirm_authorized": True,
                        "exclude": ["127.0.0.2/32"],
                        "port_profile": "web",
                        "top_ports": 3,
                    },
                )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(captured["target_expr"], "127.0.0.1")
            self.assertEqual(captured["port_expr"], "22,80,443,3000,5000,8000,8080,8443,9000")

    def test_scan_requires_explicit_confirmation_above_max_attempts(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import ScanSummary

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/netroach.db"))
            request = {
                "targets": "127.0.0.1,127.0.0.2",
                "ports": "80,443",
                "scope": ["127.0.0.0/8"],
                "confirm_authorized": True,
                "max_attempts": 3,
            }
            rejected = client.post("/v1/scans", json=request)
            self.assertEqual(rejected.status_code, 400)
            self.assertIn("4 attempts", rejected.json()["detail"]["error"])

            with patch("netroach.api.run_scan", return_value=([], ScanSummary(scan_id="ignored"))):
                accepted = client.post("/v1/scans", json={**request, "confirm_large_scan": True})
            self.assertEqual(accepted.status_code, 200)
            self.assertEqual(accepted.json()["workload"], {"hosts": 2, "ports": 2, "attempts": 4})

    def test_scan_uses_app_config_scope_defaults_and_custom_port_profile(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import ScanSummary

        captured: dict[str, object] = {}

        def fake_run_scan(**kwargs):
            captured.update(kwargs)
            return [], ScanSummary(scan_id=kwargs["scan_id"])

        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "netroach.toml"
            config_path.write_text(
                """
[scan]
scope = ["127.0.0.0/8"]
exclude = ["127.0.0.2/32"]
port_profile = "custom"

[port_profiles]
custom = [8081, 8444]

[environments.local.scan]
timeout_ms = 111
concurrency = 12
rate_limit_per_sec = 13
""",
                encoding="utf-8",
            )
            client = TestClient(create_app(f"{tmp}/netroach.db", config_path=str(config_path), config_env="local"))
            with patch("netroach.api.run_scan", side_effect=fake_run_scan):
                response = client.post(
                    "/v1/scans",
                    json={
                        "targets": "127.0.0.1,127.0.0.2",
                        "confirm_authorized": True,
                    },
                )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(captured["target_expr"], "127.0.0.1")
            self.assertEqual(captured["port_expr"], "8081,8444")
            settings = captured["settings"]
            self.assertEqual(settings.timeout_ms, 111)
            self.assertEqual(settings.concurrency, 12)
            self.assertEqual(settings.rate_limit_per_sec, 13)

    def test_scan_api_passes_syn_sweep_options_to_the_engine(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import ScanSummary

        captured: dict[str, object] = {}

        def fake_run_scan(**kwargs):
            captured.update(kwargs)
            return [], ScanSummary(scan_id=kwargs["scan_id"])

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/netroach.db"))
            with patch("netroach.api.run_scan", side_effect=fake_run_scan):
                response = client.post(
                    "/v1/scans",
                    json={
                        "targets": "127.0.0.1",
                        "ports": "80",
                        "scope": ["127.0.0.0/8"],
                        "confirm_authorized": True,
                        "protocol": "tcp",
                        "syn_sweep": True,
                        "syn_retries": 2,
                    },
                )

        self.assertEqual(response.status_code, 200)
        settings = captured["settings"]
        self.assertIs(settings.syn_sweep, True)
        self.assertEqual(settings.syn_retries, 2)

    def test_sweep_progress_is_reported_while_a_scan_runs_and_dropped_after(self):
        """A sweep stores no result until it settles, so this is its only sign of life.

        Without it a scan of millions of probes is indistinguishable from one
        that never started, which is exactly how a real run read.
        """
        from netroach.api import _run_scan_job, _scan_activity
        from netroach.models import EngineSettings, ScanSummary
        from netroach.storage import SQLiteRepository

        seen: list[dict[str, object]] = []

        def fake_run_scan(**kwargs):
            kwargs["on_event"](
                {
                    "event": "sweep_progress",
                    "scan_id": kwargs["scan_id"],
                    "round": 1,
                    "sent": 4_000,
                    "round_total": 10_000,
                    "answered": 61_000,
                    "total": 65_535,
                }
            )
            seen.append(dict(_scan_activity[kwargs["scan_id"]]))
            # A port event means the sweep has settled and the job has moved on
            # to storing results. The sweep reading must not survive it, or the
            # progress bar stays parked on a finished round while real work runs.
            kwargs["on_event"](
                {
                    "event": "port",
                    "scan_id": kwargs["scan_id"],
                    "host": "127.0.0.1",
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                }
            )
            seen.append(_scan_activity.get(kwargs["scan_id"]))
            return [], ScanSummary(scan_id=kwargs["scan_id"])

        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(f"{tmp}/netroach.db")
            scan_id = repo.create_scan_job(
                targets="127.0.0.1", ports="80", scope=["127.0.0.0/8"], params={}
            )
            # Left queued on purpose: _run_scan_job starts the job itself,
            # and only a queued job starts.
            with patch("netroach.api.run_scan", side_effect=fake_run_scan):
                _run_scan_job(
                    f"{tmp}/netroach.db",
                    scan_id,
                    [ipaddress.ip_address("127.0.0.1")],
                    [80],
                    EngineSettings(protocol="tcp", syn_sweep=True),
                )

        self.assertEqual(len(seen), 2, "progress was not recorded while the scan ran")
        self.assertEqual(seen[0]["sent"], 4_000)
        self.assertEqual(seen[0]["round_total"], 10_000)
        self.assertEqual(seen[0]["answered"], 61_000)
        self.assertEqual(seen[0]["round"], 1)
        self.assertEqual(seen[0]["phase"], "sweep")
        self.assertIsNone(seen[1], "the first stored result must hand progress back")
        # Kept only for the life of the job: a finished scan is described by its
        # stored results, and leaving the entry would grow the dictionary for the
        # life of the process.
        self.assertNotIn(scan_id, _scan_activity)

    def test_scan_api_rejects_syn_sweep_for_udp(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/netroach.db"))
            response = client.post(
                "/v1/scans",
                json={
                    "targets": "127.0.0.1",
                    "ports": "53",
                    "scope": ["127.0.0.0/8"],
                    "confirm_authorized": True,
                    "protocol": "udp",
                    "syn_sweep": True,
                },
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("TCP", response.json()["detail"]["error"])

    def test_scan_uses_plugin_profile_and_lists_plugins(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import ScanSummary

        captured: dict[str, object] = {}

        def fake_run_scan(**kwargs):
            captured.update(kwargs)
            return [], ScanSummary(scan_id=kwargs["scan_id"])

        with tempfile.TemporaryDirectory() as tmp:
            plugin_path = Path(tmp) / "lab-plugin.json"
            plugin_path.write_text(
                json.dumps(
                    {
                        "name": "lab",
                        "version": "1.0.0",
                        "port_profiles": {"lab-app": [18080, 18443]},
                        "tcp_services": {"18080": "custom-http"},
                    }
                ),
                encoding="utf-8",
            )
            client = TestClient(create_app(f"{tmp}/netroach.db", plugin_paths=[str(plugin_path)]))

            plugins = client.get("/v1/plugins")
            self.assertEqual(plugins.status_code, 200)
            self.assertEqual(plugins.json()["plugins"][0]["name"], "lab")

            with patch("netroach.api.run_scan", side_effect=fake_run_scan):
                response = client.post(
                    "/v1/scans",
                    json={
                        "targets": "127.0.0.1",
                        "port_profile": "lab-app",
                        "scope": ["127.0.0.0/8"],
                        "confirm_authorized": True,
                    },
                )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(captured["port_expr"], "18080,18443")
            settings = captured["settings"]
            self.assertEqual(settings.plugin_paths, (str(plugin_path.resolve()),))

    def test_scan_list_endpoint(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="80",
                scope=["127.0.0.0/8"],
                params={},
            )
            client = TestClient(create_app(str(db_path)))

            response = client.get("/v1/scans", params={"limit": 10})

            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["count"], 1)
            self.assertEqual(payload["scans"][0]["id"], scan_id)

    def test_scan_rejects_invalid_protocol(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/netroach.db"))
            response = client.post(
                "/v1/scans",
                json={
                    "targets": "127.0.0.1",
                    "ports": "80",
                    "scope": ["127.0.0.0/8"],
                    "confirm_authorized": True,
                    "protocol": "icmp",
                },
            )
            self.assertEqual(response.status_code, 400)
            self.assertIn("protocol", response.json()["detail"]["error"])

    def test_scan_results_support_filters_and_pagination(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import PortResult
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="53,80",
                scope=["127.0.0.0/8"],
                params={"protocol": "udp"},
            )
            repo.add_port_results(
                [
                    PortResult(
                        scan_id=scan_id,
                        host="127.0.0.1",
                        port=53,
                        protocol="udp",
                        state="open",
                        latency_ms=1.0,
                        service_name="dns",
                        service_confidence=0.99,
                    ),
                    PortResult(
                        scan_id=scan_id,
                        host="127.0.0.1",
                        port=80,
                        protocol="tcp",
                        state="closed",
                        latency_ms=2.0,
                    ),
                ]
            )
            client = TestClient(create_app(str(db_path)))

            response = client.get(
                f"/v1/scans/{scan_id}/results",
                params={"state": "open", "protocol": "udp", "service": "dns", "limit": 1, "offset": 0},
            )

            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["count"], 1)
            self.assertEqual(payload["total"], 1)
            self.assertEqual(payload["hosts"], [{"host": "127.0.0.1", "total": 2, "states": {"closed": 1, "open": 1}}])
            self.assertEqual(payload["results"][0]["port"], 53)
            self.assertNotIn("latency_ms", payload["results"][0])
            self.assertNotIn("service_confidence", payload["results"][0])

    def test_scan_results_support_host_search_and_server_paging(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import PortResult
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1,127.0.0.2",
                ports="22,80,443",
                scope=["127.0.0.0/8"],
                params={},
            )
            repo.add_port_results(
                [
                    PortResult(scan_id=scan_id, host="127.0.0.1", port=22, protocol="tcp", state="open", latency_ms=1.0, banner="OpenSSH"),
                    PortResult(scan_id=scan_id, host="127.0.0.1", port=80, protocol="tcp", state="closed", latency_ms=1.0),
                    PortResult(scan_id=scan_id, host="127.0.0.2", port=443, protocol="tcp", state="open", latency_ms=1.0, service_name="https"),
                ]
            )
            client = TestClient(create_app(str(db_path)))

            first = client.get(
                f"/v1/scans/{scan_id}/results",
                params={"host": "127.0.0.1", "limit": 1, "offset": 0},
            ).json()
            second = client.get(
                f"/v1/scans/{scan_id}/results",
                params={"host": "127.0.0.1", "limit": 1, "offset": 1},
            ).json()
            searched = client.get(
                f"/v1/scans/{scan_id}/results",
                params={"search": "https", "limit": 50},
            ).json()

            self.assertEqual(first["total"], 2)
            self.assertEqual(first["results"][0]["port"], 22)
            self.assertEqual(second["results"][0]["port"], 80)
            self.assertEqual(searched["total"], 1)
            self.assertEqual(searched["results"][0]["host"], "127.0.0.2")
            self.assertEqual(len(first["hosts"]), 2)

    def test_scan_progress_cancel_delete_and_export(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import PortResult
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1,127.0.0.2",
                ports="53,80",
                scope=["127.0.0.0/8"],
                params={"protocol": "udp"},
            )
            repo.mark_scan_started(scan_id)
            repo.add_port_results(
                [
                    PortResult(
                        scan_id=scan_id,
                        host="127.0.0.1",
                        port=53,
                        protocol="udp",
                        state="open",
                        latency_ms=1.0,
                        service_name="dns",
                        service_confidence=0.99,
                    ),
                    PortResult(
                        scan_id=scan_id,
                        host="127.0.0.2",
                        port=80,
                        protocol="tcp",
                        state="closed",
                        latency_ms=2.0,
                    ),
                ]
            )
            client = TestClient(create_app(str(db_path)))

            progress = client.get(f"/v1/scans/{scan_id}/progress")
            self.assertEqual(progress.status_code, 200)
            self.assertEqual(progress.json()["planned_total"], 4)
            self.assertEqual(progress.json()["completed_results"], 2)

            annotated = client.patch(
                f"/v1/scans/{scan_id}/results/127.0.0.1/udp/53",
                json={"tags": ["review", "dns"], "note": "check resolver"},
            )
            self.assertEqual(annotated.status_code, 200)
            self.assertEqual(annotated.json()["tags"], ["dns", "review"])
            self.assertEqual(annotated.json()["note"], "check resolver")
            self.assertNotIn("latency_ms", annotated.json())
            self.assertNotIn("service_confidence", annotated.json())

            exported = client.get(f"/v1/scans/{scan_id}/export", params={"format": "csv", "state": "open"})
            self.assertEqual(exported.status_code, 200)
            self.assertIn("scan_id,host,port,protocol,state", exported.text)
            self.assertNotIn("latency_ms", exported.text.splitlines()[0])
            self.assertNotIn("service_confidence", exported.text.splitlines()[0])
            self.assertIn(",53,udp,open,", exported.text)
            self.assertNotIn(",80,tcp,closed,", exported.text)

            ndjson = client.get(f"/v1/scans/{scan_id}/export", params={"format": "ndjson", "limit": 1})
            self.assertEqual(ndjson.status_code, 200)
            lines = [json.loads(line) for line in ndjson.text.splitlines()]
            self.assertEqual(lines[0]["type"], "job")
            self.assertEqual(lines[1]["type"], "result")
            self.assertNotIn("latency_ms", lines[1]["result"])
            self.assertNotIn("service_confidence", lines[1]["result"])

            report_json = client.get(f"/v1/scans/{scan_id}/report", params={"format": "json"})
            self.assertEqual(report_json.status_code, 200)
            self.assertEqual(report_json.json()["counts"]["services"], {"dns": 1})
            self.assertNotIn("latency_ms", report_json.json()["open_results"][0])
            self.assertNotIn("service_confidence", report_json.json()["open_results"][0])

            limited_report = client.get(
                f"/v1/scans/{scan_id}/report",
                params={"format": "json", "limit": 1},
            )
            self.assertEqual(limited_report.status_code, 200)
            limited_payload = limited_report.json()
            self.assertEqual(limited_payload["completeness"]["included_results"], 1)
            self.assertEqual(limited_payload["completeness"]["total_stored_results"], 2)
            self.assertTrue(limited_payload["completeness"]["truncated"])
            self.assertEqual(limited_payload["open_results"][0]["port"], 53)

            report_html = client.get(f"/v1/scans/{scan_id}/report", params={"format": "html"})
            self.assertEqual(report_html.status_code, 200)
            self.assertIn("text/html", report_html.headers["content-type"])
            self.assertIn("Netroach 스캔 보고서", report_html.text)
            self.assertNotIn("<th>Latency</th>", report_html.text)

            cancelled = client.post(f"/v1/scans/{scan_id}/cancel")
            self.assertEqual(cancelled.status_code, 200)
            self.assertEqual(cancelled.json()["status"], "cancel_requested")

            deleted = client.delete(f"/v1/scans/{scan_id}")
            self.assertEqual(deleted.status_code, 200)
            self.assertTrue(deleted.json()["deleted"])
            self.assertEqual(client.get(f"/v1/scans/{scan_id}").status_code, 404)

    def test_result_image_evidence_upload_download_and_delete(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import PortResult
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="80",
                scope=["127.0.0.0/8"],
                params={},
            )
            repo.add_port_result(
                PortResult(
                    scan_id=scan_id,
                    host="127.0.0.1",
                    port=80,
                    state="open",
                    latency_ms=1.0,
                    service_name="http",
                )
            )
            client = TestClient(create_app(str(db_path)))
            endpoint = f"/v1/scans/{scan_id}/results/127.0.0.1/tcp/80/evidence"
            from PIL import Image

            image_buffer = io.BytesIO()
            Image.new("RGB", (800, 600), "teal").save(image_buffer, format="PNG")
            image = image_buffer.getvalue()

            invalid = client.post(endpoint, params={"filename": "bad.txt"}, content=b"plain text")
            self.assertEqual(invalid.status_code, 400)

            uploaded = client.post(
                endpoint,
                params={"filename": "proof.png"},
                content=image,
                headers={"Content-Type": "image/png"},
            )

            self.assertEqual(uploaded.status_code, 200)
            evidence = uploaded.json()
            self.assertEqual(evidence["type"], "manual")
            results = client.get(f"/v1/scans/{scan_id}/results").json()["results"]
            self.assertEqual(results[0]["evidence_files"][0]["id"], evidence["id"])
            downloaded = client.get(evidence["download_url"])
            self.assertEqual(downloaded.status_code, 200)
            self.assertEqual(downloaded.content, image)
            self.assertEqual(downloaded.headers["content-type"], "image/png")
            report = client.get(f"/v1/scans/{scan_id}/report", params={"format": "html"})
            self.assertIn(evidence["download_url"], report.text)
            self.assertEqual(report.headers["cache-control"], "no-store")
            embedded_report = client.get(
                f"/v1/scans/{scan_id}/report",
                params={"format": "html", "embed_evidence": True},
            )
            self.assertEqual(embedded_report.status_code, 200)
            self.assertIn("data:image/png;base64,", embedded_report.text)
            bundle_response = client.get(
                f"/v1/scans/{scan_id}/export",
                params={"format": "csv", "bundle_evidence": True},
            )
            self.assertEqual(bundle_response.status_code, 200)
            self.assertEqual(bundle_response.headers["content-type"], "application/zip")
            with zipfile.ZipFile(io.BytesIO(bundle_response.content)) as archive:
                self.assertIn("results.csv", archive.namelist())
                self.assertIn(f"evidence/{evidence['id']}.png", archive.namelist())
            excel_response = client.get(
                f"/v1/scans/{scan_id}/export",
                params={"format": "xlsx"},
            )
            self.assertEqual(excel_response.status_code, 200)
            self.assertIn(
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                excel_response.headers["content-type"],
            )
            with zipfile.ZipFile(io.BytesIO(excel_response.content)) as archive:
                self.assertTrue(any(name.startswith("xl/media/") for name in archive.namelist()))

            deleted = client.delete(f"/v1/evidence/{evidence['id']}")
            self.assertEqual(deleted.status_code, 200)
            self.assertTrue(deleted.json()["deleted"])
            self.assertEqual(client.get(evidence["download_url"]).status_code, 404)

    def test_background_scan_can_capture_automatic_service_evidence(self):
        from netroach.api import _run_scan_job
        from netroach.evidence import ScreenshotCaptureSummary
        from netroach.models import EngineSettings, PortResult, ScanSummary
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="80",
                scope=["127.0.0.0/8"],
                params={"capture_screenshots": True},
            )

            def fake_run_scan(**kwargs):
                result = PortResult(
                    scan_id=scan_id,
                    host="127.0.0.1",
                    port=80,
                    state="open",
                    latency_ms=1.0,
                    service_name="http",
                )
                kwargs["on_event"]({"event": "port", **result.to_dict()})
                summary = ScanSummary(scan_id=scan_id)
                summary.observe(result)
                return [result], summary

            def fake_capture(results, *, store, timeout_ms, maximum, should_stop, capture_console, on_examined=None):
                result = list(results)[0]
                self.assertFalse(should_stop())
                # Photographing a real console needs a desktop, so it is opt-in.
                self.assertFalse(capture_console)
                store(
                    result,
                    b"\x89PNG\r\n\x1a\napi automatic",
                    "web.png",
                    "http://127.0.0.1/",
                    "web_screenshot",
                )
                self.assertEqual(timeout_ms, 5_000)
                self.assertEqual(maximum, 2)
                return ScreenshotCaptureSummary(candidates=1, captured=1, failed=0, web_screenshots=1)

            with patch("netroach.api.run_scan", side_effect=fake_run_scan):
                with patch("netroach.api.capture_automatic_evidence", side_effect=fake_capture):
                    _run_scan_job(
                        str(db_path),
                        scan_id,
                        ["127.0.0.1"],
                        [80],
                        EngineSettings(),
                        True,
                        5_000,
                        2,
                    )

            stored = repo.get_result(scan_id, host="127.0.0.1", port=80)
            self.assertEqual(repo.get_job(scan_id)["status"], "completed")
            self.assertEqual(stored["evidence_files"][0]["type"], "web_screenshot")

    def test_scan_cleanup_endpoint(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="80",
                scope=["127.0.0.0/8"],
                params={},
            )
            with repo.session() as conn:
                conn.execute(
                    "UPDATE scan_jobs SET status='completed', completed_at='2000-01-01 00:00:00' WHERE id=?",
                    (scan_id,),
                )
            client = TestClient(create_app(str(db_path)))

            response = client.post("/v1/scans/cleanup", json={"older_than_days": 1, "dry_run": True})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["scan_ids"], [scan_id])
            self.assertIsNotNone(repo.get_job(scan_id))

            response = client.post("/v1/scans/cleanup", json={"older_than_days": 1})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["scan_ids"], [scan_id])
            self.assertIsNone(repo.get_job(scan_id))

    def test_scan_results_reject_invalid_filter(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="80",
                scope=["127.0.0.0/8"],
                params={},
            )
            client = TestClient(create_app(str(db_path)))

            response = client.get(f"/v1/scans/{scan_id}/results", params={"state": "unknown"})

            self.assertEqual(response.status_code, 400)
            self.assertIn("state", response.json()["detail"]["error"])

    def test_pcap_analyze_response_fields(self):
        if importlib.util.find_spec("scapy") is None:
            self.skipTest("scapy is not installed")
        from fastapi.testclient import TestClient
        from scapy.all import IP, TCP, Raw, wrpcap

        from netroach.api import create_app

        with tempfile.TemporaryDirectory() as tmp:
            pcap_path = Path(tmp) / "fixture.pcap"
            wrpcap(str(pcap_path), [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2) / Raw(b"x")])
            client = TestClient(create_app(f"{tmp}/netroach.db"))

            response = client.post("/v1/pcaps/analyze", json={"file": str(pcap_path), "top": 10})

            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(set(payload), {"analysis_id", "summary"})
            self.assertIn("packet_count", payload["summary"])
            self.assertIn("protocols", payload["summary"])
            self.assertIn("arp_summary", payload["summary"])
            self.assertIn("dns_responses", payload["summary"])
            self.assertIn("conversation_metrics", payload["summary"])

    def test_live_capture_endpoint_validates_and_persists_analysis(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.live_capture import LiveCaptureResult
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            output = Path(tmp) / "capture.pcap"
            client = TestClient(create_app(str(db_path)))

            rejected = client.post(
                "/v1/captures/live",
                json={"output": str(output), "duration_s": 1, "confirm_authorized": False},
            )
            self.assertEqual(rejected.status_code, 400)
            self.assertIn("confirm_authorized", rejected.json()["detail"]["error"])

            with patch(
                "netroach.api.execute_live_capture",
                return_value=LiveCaptureResult(
                    file=str(output),
                    packet_count=3,
                    duration_s=0.02,
                    interface="lo",
                    bpf_filter="udp",
                    analyzed=True,
                    analysis={"file": str(output), "packet_count": 3},
                ),
            ):
                response = client.post(
                    "/v1/captures/live",
                    json={
                        "output": str(output),
                        "duration_s": 1,
                        "count": 3,
                        "iface": "lo",
                        "bpf_filter": "udp",
                        "confirm_authorized": True,
                    },
                )

            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["capture"]["packet_count"], 3)
            self.assertIsNotNone(payload["analysis_id"])
            analysis = SQLiteRepository(db_path).get_pcap_analysis(payload["analysis_id"])
            self.assertEqual(analysis["summary"]["packet_count"], 3)

    def test_packet_send_response_fields_match_cli_shape(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import SendResult

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/netroach.db"))
            with patch(
                "netroach.api.execute_packet_request",
                return_value=SendResult(
                    template="icmp",
                    target="127.0.0.1",
                    sent=1,
                    duration_s=0.01,
                    details={"payload_bytes": 0},
                ),
            ):
                response = client.post(
                    "/v1/packets/send",
                    json={
                        "template": "icmp",
                        "target": "127.0.0.1",
                        "scope": ["127.0.0.0/8"],
                        "confirm_authorized": True,
                        "count": 1,
                        "interval_ms": 1000,
                    },
                )

            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertIn("audit_id", payload)
            self.assertEqual(set(payload["result"]), {"template", "target", "sent", "duration_s", "details"})
            self.assertEqual(payload["result"]["template"], "icmp")

    def test_packet_send_persists_full_audit_request_and_result(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import SendResult
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            client = TestClient(create_app(str(db_path)))
            with patch(
                "netroach.api.execute_packet_request",
                return_value=SendResult(
                    template="http",
                    target="127.0.0.1",
                    sent=1,
                    duration_s=0.02,
                    details={"dport": 8080, "method": "POST", "path": "/probe"},
                ),
            ):
                response = client.post(
                    "/v1/packets/send",
                    json={
                        "template": "http",
                        "target": "127.0.0.1",
                        "scope": ["127.0.0.0/8"],
                        "confirm_authorized": True,
                        "count": 1,
                        "interval_ms": 50,
                        "dport": 8080,
                        "payload_text": "ping",
                        "http_method": "POST",
                        "http_path": "/probe",
                        "http_host": "local.test",
                    },
                )

            self.assertEqual(response.status_code, 200)
            audit = SQLiteRepository(db_path).get_packet_audit(response.json()["audit_id"])
            self.assertIsNotNone(audit)
            self.assertEqual(audit["request"]["template"], "http")
            self.assertEqual(audit["request"]["scope"], ["127.0.0.0/8"])
            self.assertTrue(audit["request"]["confirm_authorized"])
            self.assertEqual(audit["request"]["interval_ms"], 50)
            self.assertEqual(audit["request"]["dport"], 8080)
            self.assertEqual(audit["request"]["payload_text"], "ping")
            self.assertEqual(audit["request"]["http_method"], "POST")
            self.assertEqual(audit["request"]["http_path"], "/probe")
            self.assertEqual(audit["request"]["http_host"], "local.test")
            self.assertEqual(audit["result"]["sent"], 1)
            self.assertEqual(audit["result"]["details"]["path"], "/probe")

    def test_packet_send_dry_run_preview_is_audited(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            client = TestClient(create_app(str(db_path)))
            response = client.post(
                "/v1/packets/send",
                json={
                    "template": "udp",
                    "target": "127.0.0.1",
                    "scope": ["127.0.0.0/8"],
                    "confirm_authorized": True,
                    "dport": 53,
                    "payload_text": "hello",
                    "dry_run": True,
                },
            )

            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["result"]["sent"], 0)
            self.assertTrue(payload["result"]["details"]["dry_run"])
            self.assertEqual(payload["result"]["details"]["payload_bytes"], 5)
            audit = SQLiteRepository(db_path).get_packet_audit(payload["audit_id"])
            self.assertTrue(audit["request"]["dry_run"])

    def test_history_and_database_endpoints(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import SendResult
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            audit_id = repo.save_packet_audit(
                request={"template": "icmp", "target": "127.0.0.1"},
                result=SendResult(template="icmp", target="127.0.0.1", sent=1, duration_s=0.1),
            )
            analysis_id = repo.save_pcap_analysis("capture.pcap", {"packet_count": 1})
            client = TestClient(create_app(str(db_path)))

            audits = client.get("/v1/packets/audits", params={"template": "icmp"})
            self.assertEqual(audits.status_code, 200)
            self.assertEqual(audits.json()["audits"][0]["id"], audit_id)
            audit = client.get(f"/v1/packets/audits/{audit_id}")
            self.assertEqual(audit.status_code, 200)
            self.assertEqual(audit.json()["request"]["template"], "icmp")

            analyses = client.get("/v1/pcaps/analyses")
            self.assertEqual(analyses.status_code, 200)
            self.assertEqual(analyses.json()["analyses"][0]["id"], analysis_id)
            analysis = client.get(f"/v1/pcaps/analyses/{analysis_id}")
            self.assertEqual(analysis.status_code, 200)
            self.assertEqual(analysis.json()["summary"]["packet_count"], 1)

            backup = client.get("/v1/db/export")
            self.assertEqual(backup.status_code, 200)
            imported_db = Path(tmp) / "imported.db"
            imported = TestClient(create_app(str(imported_db)))
            response = imported.post("/v1/db/import", json={"data": backup.json(), "replace": True})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["packet_audit"], 1)

    def test_oast_session_callback_and_history(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/netroach.db"))

            rejected = client.post(
                "/v1/oast/sessions",
                json={"base_url": "http://testserver", "ttl_seconds": 3600},
            )
            self.assertEqual(rejected.status_code, 400)
            self.assertIn("confirm_authorized", rejected.json()["detail"]["error"])

            created = client.post(
                "/v1/oast/sessions",
                json={
                    "label": "lab",
                    "base_url": "http://testserver",
                    "ttl_seconds": 3600,
                    "confirm_authorized": True,
                },
            )
            self.assertEqual(created.status_code, 200)
            session = created.json()["session"]
            self.assertIn("/oast/", created.json()["callback_url"])

            callback = client.post(
                f"/oast/{session['token']}?x=1",
                headers={"authorization": "secret", "user-agent": "api-test"},
                content=b"hello",
            )
            self.assertEqual(callback.status_code, 200)
            self.assertEqual(callback.json()["session_id"], session["id"])

            interactions = client.get(f"/v1/oast/sessions/{session['id']}/interactions")
            self.assertEqual(interactions.status_code, 200)
            stored = interactions.json()["interactions"][0]
            self.assertEqual(stored["method"], "POST")
            self.assertEqual(stored["query_string"], "x=1")
            self.assertEqual(stored["headers"]["authorization"], "[redacted]")
            self.assertEqual(stored["body_preview"], "hello")

            listed = client.get("/v1/oast/sessions")
            self.assertEqual(listed.status_code, 200)
            self.assertEqual(listed.json()["sessions"][0]["id"], session["id"])

            deleted = client.delete(f"/v1/oast/sessions/{session['id']}")
            self.assertEqual(deleted.status_code, 200)
            self.assertEqual(client.get(f"/v1/oast/sessions/{session['id']}").status_code, 404)

    def test_api_token_guards_every_endpoint_except_oast_callbacks(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app

        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "netroach.db")
            app = create_app(db_path, api_token="s3cret")
            with TestClient(app) as client:
                self.assertEqual(client.get("/v1/health").status_code, 401)
                self.assertEqual(client.get("/v1/scans").status_code, 401)
                self.assertEqual(
                    client.get("/v1/health", headers={"Authorization": "Bearer wrong"}).status_code,
                    401,
                )
                authorized = client.get("/v1/health", headers={"Authorization": "Bearer s3cret"})
                self.assertEqual(authorized.status_code, 200)
                # Targets deliver OAST callbacks and cannot present the operator token.
                self.assertEqual(client.get("/oast/unknown-token").status_code, 404)

    def test_dashboard_token_query_sets_cookie_session(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app

        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "netroach.db")
            app = create_app(db_path, api_token="s3cret")
            with TestClient(app) as client:
                self.assertEqual(client.get("/dashboard").status_code, 401)
                landing = client.get("/dashboard?token=s3cret")
                self.assertEqual(landing.status_code, 200)
                self.assertIn("netroach_api_token", client.cookies)
                self.assertEqual(client.get("/v1/health").status_code, 200)


@unittest.skipUnless(has_fastapi_testclient(), "fastapi TestClient dependencies are not installed")
class DatabaseMergeEndpointTests(unittest.TestCase):
    def test_merging_another_database_reports_what_it_loaded(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import PortResult
        from netroach.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            source = SQLiteRepository(Path(tmp) / "other" / "netroach.db")
            scan_id = source.create_scan_job(targets="10.0.0.1", ports="80", scope=[], params={})
            source.add_port_results(
                [
                    PortResult(
                        scan_id=scan_id, host="10.0.0.1", port=80, protocol="tcp",
                        state="open", latency_ms=1.0,
                    )
                ]
            )
            client = TestClient(create_app(str(Path(tmp) / "netroach.db")))

            response = client.post("/v1/db/merge", json={"path": str(source.path)})

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["scan_jobs"], 1)
            listed = client.get("/v1/scans").json()
            self.assertEqual([job["id"] for job in listed["scans"]], [scan_id])

    def test_merging_something_that_is_not_a_database_is_a_bad_request(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app

        with tempfile.TemporaryDirectory() as tmp:
            junk = Path(tmp) / "notes.txt"
            junk.write_text("nope", encoding="utf-8")
            client = TestClient(create_app(str(Path(tmp) / "netroach.db")))

            response = client.post("/v1/db/merge", json={"path": str(junk)})

            self.assertEqual(response.status_code, 400)


@unittest.skipUnless(has_fastapi_testclient(), "fastapi TestClient dependencies are not installed")
class RescanAndRecaptureTests(unittest.TestCase):
    """Finishing a scan whose evidence limit was set too low."""

    def _client_with_open_results(self, tmp):
        from fastapi.testclient import TestClient

        from netroach.api import create_app
        from netroach.models import PortResult
        from netroach.storage import SQLiteRepository

        db_path = Path(tmp) / "netroach.db"
        repo = SQLiteRepository(db_path)
        scan_id = repo.create_scan_job(targets="10.0.0.0/24", ports="1-100", scope=[], params={})
        repo.mark_scan_started(scan_id)
        results = [
            PortResult(scan_id=scan_id, host="10.0.0.2", port=80, protocol="tcp",
                       state="open", latency_ms=1.0),
            PortResult(scan_id=scan_id, host="10.0.0.1", port=443, protocol="tcp",
                       state="open", latency_ms=1.0),
        ]
        repo.add_port_results(results)
        repo.complete_scan(scan_id, repo.summarize_scan_results(scan_id))
        return TestClient(create_app(str(db_path))), repo, scan_id

    def test_the_open_results_come_back_as_scan_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            client, _repo, scan_id = self._client_with_open_results(tmp)

            payload = client.get(f"/v1/scans/{scan_id}/open-targets").json()

            self.assertEqual(payload["targets"], "10.0.0.1" + chr(10) + "10.0.0.2")
            self.assertEqual(payload["ports"], "80,443")
            self.assertEqual(payload["hosts"], 2)
            # Two hosts crossed with two ports, which is more than the two open
            # ports that produced them - the caller is told so.
            self.assertEqual(payload["probes"], 4)

    def test_a_udp_scans_ports_come_back_as_udp(self):
        """The form holds one protocol for the whole scan. Leaving it out of
        the inputs re-scanned a UDP scan's open ports over TCP, which finds
        nothing and gives no reason."""
        with tempfile.TemporaryDirectory() as tmp:
            from fastapi.testclient import TestClient

            from netroach.api import create_app
            from netroach.models import PortResult
            from netroach.storage import SQLiteRepository

            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="10.0.0.1", ports="161", scope=[], params={"protocol": "udp"}
            )
            repo.mark_scan_started(scan_id)
            repo.add_port_results([
                PortResult(scan_id=scan_id, host="10.0.0.1", port=161, protocol="udp",
                           state="open", latency_ms=1.0),
            ])
            repo.complete_scan(scan_id, repo.summarize_scan_results(scan_id))
            client = TestClient(create_app(str(db_path)))

            payload = client.get(f"/v1/scans/{scan_id}/open-targets").json()

            self.assertEqual(payload["protocol"], "udp")

    def test_a_recapture_can_be_stopped_once_it_has_started(self):
        """Console capture costs a second or two a port, so a thousand ports
        runs for the better part of an hour and holds the one recapture slot
        the whole time. Started on the wrong scan, it could only be escaped by
        closing the application."""
        with tempfile.TemporaryDirectory() as tmp:
            client, repo, scan_id = self._client_with_open_results(tmp)
            started = threading.Event()
            seen: list[bool] = []

            def paced(results, *, store, timeout_ms, maximum, capture_console, should_stop=None, on_examined=None):
                from netroach.evidence import ScreenshotCaptureSummary

                captured = 0
                for result in list(results):
                    started.set()
                    for _ in range(200):
                        if should_stop is not None and should_stop():
                            break
                        time.sleep(0.01)
                    if should_stop is not None and should_stop():
                        seen.append(True)
                        break
                    store(result, PNG_HEADER, "shot.png", None, "web_screenshot", "test")
                    captured += 1
                return ScreenshotCaptureSummary(candidates=1, captured=captured, failed=0)

            with patch("netroach.api.capture_automatic_evidence", side_effect=paced):
                client.post(f"/v1/scans/{scan_id}/evidence/recapture",
                            json={"screenshot_max": 50, "capture_console": False})
                self.assertTrue(started.wait(timeout=10))
                stopped = client.delete(f"/v1/scans/{scan_id}/evidence/recapture")
                for thread in threading.enumerate():
                    if thread.name.startswith("netroach-evidence-"):
                        thread.join(timeout=30)

            self.assertEqual(stopped.status_code, 200)
            self.assertTrue(stopped.json()["cancelled"])
            self.assertEqual(seen, [True], "the capture never saw the stop")
            progress = client.get(f"/v1/scans/{scan_id}/evidence/recapture").json()
            self.assertFalse(progress["running"])
            self.assertTrue(progress["cancelled"])
            # The slot is free again, so another scan can be captured.
            self.assertEqual(
                client.delete(f"/v1/scans/{scan_id}/evidence/recapture").status_code, 400
            )

    def test_a_store_that_fails_does_not_take_the_old_evidence_with_it(self):
        """The old pictures were dropped before the new one was stored, so a
        store that raised left the port with nothing - and a store can raise on
        a malformed image, a scan deleted mid-run, or a full disk. The picture
        in the report is the deliverable; losing it to a failed retry is worse
        than the retry not happening."""
        with tempfile.TemporaryDirectory() as tmp:
            client, repo, scan_id = self._client_with_open_results(tmp)
            repo.add_result_evidence(
                scan_id, host="10.0.0.2", port=80, data=PNG_HEADER,
                file_name="good.png", evidence_type="terminal_transcript",
                capture_agent="windows console capture",
            )

            def broken(results, *, store, timeout_ms, maximum, capture_console,
                       should_stop=None, on_examined=None):
                from netroach.evidence import ScreenshotCaptureSummary

                for result in list(results):
                    try:
                        store(result, b"not an image", "bad.png", None,
                              "terminal_transcript", "test")
                    except Exception:  # noqa: BLE001 - the run records and moves on.
                        pass
                return ScreenshotCaptureSummary(candidates=1, captured=0, failed=1)

            with patch("netroach.api.capture_automatic_evidence", side_effect=broken):
                client.post(f"/v1/scans/{scan_id}/evidence/recapture", json={})
                for thread in threading.enumerate():
                    if thread.name.startswith("netroach-evidence-"):
                        thread.join(timeout=30)

            kept = repo.list_result_evidence(scan_id, host="10.0.0.2", port=80)
            self.assertEqual(len(kept), 1, "the failed store destroyed the evidence")
            self.assertEqual(kept[0]["capture_agent"], "windows console capture")

            # A store that works still replaces rather than piling up.
            def works(results, *, store, timeout_ms, maximum, capture_console,
                      should_stop=None, on_examined=None):
                from netroach.evidence import ScreenshotCaptureSummary

                for result in list(results):
                    store(result, PNG_HEADER, "new.png", None, "terminal_transcript", "new")
                return ScreenshotCaptureSummary(candidates=1, captured=1, failed=0)

            with patch("netroach.api.capture_automatic_evidence", side_effect=works):
                client.post(f"/v1/scans/{scan_id}/evidence/recapture", json={})
                for thread in threading.enumerate():
                    if thread.name.startswith("netroach-evidence-"):
                        thread.join(timeout=30)

            replaced = repo.list_result_evidence(scan_id, host="10.0.0.2", port=80)
            self.assertEqual([row["capture_agent"] for row in replaced], ["new"])

    def test_a_scan_that_stopped_reporting_can_be_cancelled_and_deleted(self):
        """Recovery looks for an interrupted scan only when the backend starts,
        and skips one whose heartbeat is still recent because another instance
        may own it. A backend that died and came back inside that window
        therefore leaves the job running and idle - and while it read as
        running the dashboard offered no way to be rid of it."""
        import datetime
        import sqlite3

        from netroach.api import SCAN_HEARTBEAT_STALE_S

        with tempfile.TemporaryDirectory() as tmp:
            from fastapi.testclient import TestClient

            from netroach.api import create_app
            from netroach.storage import SQLiteRepository

            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(
                targets="10.0.0.1", ports="1-10", scope=[], params={"resumable": True}
            )
            repo.mark_scan_started(scan_id)
            client = TestClient(create_app(str(repo.path)))

            # A scan that is reporting is not stalled and keeps its guard rails.
            self.assertFalse(client.get(f"/v1/scans/{scan_id}").json()["stalled"])

            stopped = (
                datetime.datetime.now(datetime.timezone.utc)
                - datetime.timedelta(seconds=SCAN_HEARTBEAT_STALE_S + 60)
            ).strftime("%Y-%m-%d %H:%M:%S")
            connection = sqlite3.connect(repo.path, isolation_level=None)
            try:
                connection.execute(
                    "UPDATE scan_jobs SET heartbeat_at=? WHERE id=?", (stopped, scan_id)
                )
            finally:
                connection.close()

            self.assertTrue(client.get(f"/v1/scans/{scan_id}").json()["stalled"])

            # Cancelling settles it rather than asking a worker that is not
            # there to notice, which would have left it running for ever.
            cancelled = client.post(f"/v1/scans/{scan_id}/cancel").json()
            self.assertEqual(cancelled["status"], "cancelled")
            self.assertEqual(client.get(f"/v1/scans/{scan_id}").json()["status"], "cancelled")
            self.assertTrue(client.delete(f"/v1/scans/{scan_id}").json()["deleted"])

    def test_a_port_both_passes_look_at_is_counted_once(self):
        """A port the web pass could not photograph is handed to the console
        pass, which examines it again. Counting both put the tally above the
        number of ports there are - 22 examined of 19 planned - which reads as
        a mistake because it is one."""
        with tempfile.TemporaryDirectory() as tmp:
            client, _repo, scan_id = self._client_with_open_results(tmp)

            def both_passes(results, *, store, timeout_ms, maximum, capture_console,
                            should_stop=None, on_examined=None):
                from netroach.evidence import ScreenshotCaptureSummary

                rows = list(results)
                # The web pass sees every candidate and stores nothing.
                for result in rows:
                    on_examined(result)
                # The console pass then sees the same ports again.
                for result in rows:
                    on_examined(result)
                return ScreenshotCaptureSummary(candidates=len(rows), captured=0, failed=len(rows))

            with patch("netroach.api.capture_automatic_evidence", side_effect=both_passes):
                started = client.post(f"/v1/scans/{scan_id}/evidence/recapture", json={}).json()
                for thread in threading.enumerate():
                    if thread.name.startswith("netroach-evidence-"):
                        thread.join(timeout=30)

            progress = client.get(f"/v1/scans/{scan_id}/evidence/recapture").json()
            self.assertEqual(progress["examined"], started["pending"])
            self.assertLessEqual(progress["examined"], progress["total"])

    def test_a_folded_scan_does_not_blame_the_report_limit(self):
        """A port folded into a count has no row, so it is not something the
        report left out. Counting it as omitted made a scan five thousand rows
        inside the limit report that the limit had dropped results - and told
        the reader to raise a limit that would change nothing. Coverage lives
        in the state counts, which still carry every folded port."""
        with tempfile.TemporaryDirectory() as tmp:
            from fastapi.testclient import TestClient

            from netroach.api import create_app
            from netroach.models import PortResult
            from netroach.storage import SQLiteRepository

            db_path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="10.0.0.1", ports="1-199", scope=[], params={"protocol": "tcp"}
            )
            repo.mark_scan_started(scan_id)
            repo.add_port_results(
                [PortResult(scan_id=scan_id, host="10.0.0.1", port=80, protocol="tcp",
                            state="open", latency_ms=1.0)]
                + [PortResult(scan_id=scan_id, host="10.0.0.1", port=port, protocol="tcp",
                              state="closed", latency_ms=1.0)
                   for port in range(1, 200) if port != 80]
            )
            repo.complete_scan(scan_id, repo.summarize_scan_results(scan_id))
            client = TestClient(create_app(str(db_path)))

            report = client.get(f"/v1/scans/{scan_id}/report?format=json").json()

            self.assertFalse(report["completeness"]["truncated"])
            self.assertEqual(report["completeness"]["omitted_results"], 0)
            # The 198 folded ports are still reported - as coverage, not as loss.
            self.assertEqual(report["counts"]["states"]["closed"], 198)

    def test_evidence_can_be_collected_without_scanning_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            client, repo, scan_id = self._client_with_open_results(tmp)
            captured = []

            def fake_capture(results, *, store, timeout_ms, maximum, capture_console, should_stop=None, on_examined=None):
                for result in list(results):
                    captured.append((result["host"], result["port"]))
                    store(result, PNG_HEADER, "shot.png", None, "web_screenshot", "test")
                from netroach.evidence import ScreenshotCaptureSummary

                return ScreenshotCaptureSummary(
                    candidates=len(captured), captured=len(captured), failed=0
                )

            with patch("netroach.api.capture_automatic_evidence", side_effect=fake_capture):
                response = client.post(
                    f"/v1/scans/{scan_id}/evidence/recapture",
                    json={"screenshot_max": 50, "capture_console": False},
                )
                for thread in threading.enumerate():
                    if thread.name.startswith("netroach-evidence-"):
                        thread.join(timeout=30)

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["pending"], 2)
            self.assertEqual(sorted(captured), [("10.0.0.1", 443), ("10.0.0.2", 80)])
            self.assertEqual(len(repo.list_result_evidence(scan_id, host="10.0.0.2", port=80)), 1)

    def test_a_second_recapture_is_refused_while_the_first_runs(self):
        """A candidate stops being one only once its evidence is stored, so two
        runs started together photograph the same ports twice."""
        with tempfile.TemporaryDirectory() as tmp:
            client, _repo, scan_id = self._client_with_open_results(tmp)
            started = threading.Event()
            release = threading.Event()

            def blocking_capture(results, *, store, timeout_ms, maximum, capture_console, should_stop=None, on_examined=None):
                from netroach.evidence import ScreenshotCaptureSummary

                started.set()
                release.wait(timeout=30)
                return ScreenshotCaptureSummary(candidates=0, captured=0, failed=0)

            with patch("netroach.api.capture_automatic_evidence", side_effect=blocking_capture):
                first = client.post(f"/v1/scans/{scan_id}/evidence/recapture", json={})
                self.assertTrue(started.wait(timeout=30))
                second = client.post(f"/v1/scans/{scan_id}/evidence/recapture", json={})
                release.set()
                for thread in threading.enumerate():
                    if thread.name.startswith("netroach-evidence-"):
                        thread.join(timeout=30)

            self.assertEqual(first.status_code, 200)
            self.assertEqual(second.status_code, 400)
            # And the guard is released, so a later run is allowed.
            with patch("netroach.api.capture_automatic_evidence", side_effect=blocking_capture):
                release.set()
                third = client.post(f"/v1/scans/{scan_id}/evidence/recapture", json={})
                for thread in threading.enumerate():
                    if thread.name.startswith("netroach-evidence-"):
                        thread.join(timeout=30)
            self.assertEqual(third.status_code, 200)

    def test_a_capture_limit_above_a_hundred_is_honoured(self):
        """The limit was checked twice - once at the request and once inside
        the capture - and only one of them was raised."""
        from netroach.evidence import automatic_evidence_candidates, web_screenshot_candidates

        results = [
            {"host": "10.0.0.1", "port": 8000 + offset, "protocol": "tcp",
             "state": "open", "service_name": "http"}
            for offset in range(150)
        ]

        self.assertEqual(len(automatic_evidence_candidates(results, maximum=1200)), 150)
        self.assertEqual(len(web_screenshot_candidates(results, maximum=1200)), 150)

    def test_a_capture_that_throws_says_so_on_the_scan(self):
        """It runs on its own thread, where a traceback goes nowhere."""
        with tempfile.TemporaryDirectory() as tmp:
            client, repo, scan_id = self._client_with_open_results(tmp)

            with patch("netroach.api.capture_automatic_evidence", side_effect=RuntimeError("boom")):
                client.post(f"/v1/scans/{scan_id}/evidence/recapture", json={})
                for thread in threading.enumerate():
                    if thread.name.startswith("netroach-evidence-"):
                        thread.join(timeout=30)

            evidence = repo.get_job(scan_id)["summary"]["evidence"]
            self.assertTrue(any("boom" in reason for reason in evidence["errors"]))

    def test_progress_can_be_read_while_a_recapture_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            client, _repo, scan_id = self._client_with_open_results(tmp)
            first_stored = threading.Event()
            release = threading.Event()

            def paced_capture(results, *, store, timeout_ms, maximum, capture_console, should_stop=None, on_examined=None):
                from netroach.evidence import ScreenshotCaptureSummary

                rows = list(results)
                store(rows[0], PNG_HEADER, "one.png", None, "web_screenshot", "test")
                first_stored.set()
                release.wait(timeout=30)
                store(rows[1], PNG_HEADER, "two.png", None, "web_screenshot", "test")
                return ScreenshotCaptureSummary(candidates=2, captured=2, failed=0)

            with patch("netroach.api.capture_automatic_evidence", side_effect=paced_capture):
                client.post(f"/v1/scans/{scan_id}/evidence/recapture", json={})
                self.assertTrue(first_stored.wait(timeout=30))
                mid = client.get(f"/v1/scans/{scan_id}/evidence/recapture").json()
                release.set()
                for thread in threading.enumerate():
                    if thread.name.startswith("netroach-evidence-"):
                        thread.join(timeout=30)
                done = client.get(f"/v1/scans/{scan_id}/evidence/recapture").json()

            self.assertTrue(mid["running"])
            self.assertEqual(mid["total"], 2)
            self.assertEqual(mid["captured"], 1)
            self.assertFalse(done["running"])
            self.assertEqual(done["captured"], 2)
            self.assertIsNone(done["error"])

    def test_a_failed_recapture_shows_up_in_its_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            client, _repo, scan_id = self._client_with_open_results(tmp)

            with patch("netroach.api.capture_automatic_evidence", side_effect=RuntimeError("boom")):
                client.post(f"/v1/scans/{scan_id}/evidence/recapture", json={})
                for thread in threading.enumerate():
                    if thread.name.startswith("netroach-evidence-"):
                        thread.join(timeout=30)

            state = client.get(f"/v1/scans/{scan_id}/evidence/recapture").json()
            self.assertFalse(state["running"])
            self.assertIn("boom", state["error"])

    def test_a_scan_that_never_recaptured_reports_nothing_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            client, _repo, scan_id = self._client_with_open_results(tmp)

            state = client.get(f"/v1/scans/{scan_id}/evidence/recapture").json()

            self.assertFalse(state["running"])
            self.assertEqual(state["captured"], 0)

    def test_only_one_recapture_runs_at_a_time_across_scans(self):
        """Two runs share the desktop the console capture drives, and two scans
        of the same range hold the same host and port."""
        from netroach.models import PortResult

        with tempfile.TemporaryDirectory() as tmp:
            client, repo, first = self._client_with_open_results(tmp)
            second = repo.create_scan_job(targets="10.0.0.2", ports="80", scope=[], params={})
            repo.mark_scan_started(second)
            repo.add_port_results([
                PortResult(scan_id=second, host="10.0.0.2", port=80, protocol="tcp",
                           state="open", latency_ms=1.0),
            ])
            repo.complete_scan(second, repo.summarize_scan_results(second))
            started = threading.Event()
            release = threading.Event()

            def blocking(results, *, store, timeout_ms, maximum, capture_console, should_stop=None, on_examined=None):
                from netroach.evidence import ScreenshotCaptureSummary

                started.set()
                release.wait(timeout=30)
                return ScreenshotCaptureSummary(candidates=0, captured=0, failed=0)

            with patch("netroach.api.capture_automatic_evidence", side_effect=blocking):
                one = client.post(f"/v1/scans/{first}/evidence/recapture", json={})
                self.assertTrue(started.wait(timeout=30))
                two = client.post(f"/v1/scans/{second}/evidence/recapture", json={})
                release.set()
                for thread in threading.enumerate():
                    if thread.name.startswith("netroach-evidence-"):
                        thread.join(timeout=30)

            self.assertEqual(one.status_code, 200)
            self.assertEqual(two.status_code, 400)
            self.assertIn(first[:8], two.json()["detail"]["error"])

    def test_a_port_that_already_has_evidence_is_photographed_again(self):
        """The reason to run a recapture is that what is there was taken with
        the wrong settings, so a port with a picture needs a new one most."""
        with tempfile.TemporaryDirectory() as tmp:
            client, repo, scan_id = self._client_with_open_results(tmp)
            for host, port in (("10.0.0.2", 80), ("10.0.0.1", 443)):
                repo.add_result_evidence(
                    scan_id, host=host, port=port, data=PNG_HEADER,
                    file_name="old.png", evidence_type="web_screenshot",
                )
            captured = []

            def fake_capture(results, *, store, timeout_ms, maximum, capture_console, should_stop=None, on_examined=None):
                from netroach.evidence import ScreenshotCaptureSummary

                for result in list(results):
                    captured.append((result["host"], result["port"]))
                    store(result, PNG_HEADER, "new.png", None, "web_screenshot", "test")
                return ScreenshotCaptureSummary(
                    candidates=len(captured), captured=len(captured), failed=0
                )

            with patch("netroach.api.capture_automatic_evidence", side_effect=fake_capture):
                payload = client.post(f"/v1/scans/{scan_id}/evidence/recapture", json={}).json()
                for thread in threading.enumerate():
                    if thread.name.startswith("netroach-evidence-"):
                        thread.join(timeout=30)

            self.assertEqual(payload["pending"], 2)
            self.assertEqual(sorted(captured), [("10.0.0.1", 443), ("10.0.0.2", 80)])
            # Replaced rather than added to: one picture per port, the new one.
            stored = repo.list_result_evidence(scan_id, host="10.0.0.2", port=80)
            self.assertEqual([item["file_name"] for item in stored], ["new.png"])

    def test_a_file_the_operator_attached_survives_a_recapture(self):
        with tempfile.TemporaryDirectory() as tmp:
            client, repo, scan_id = self._client_with_open_results(tmp)
            repo.add_result_evidence(
                scan_id, host="10.0.0.2", port=80, data=PNG_HEADER,
                file_name="by-hand.png", evidence_type="manual",
            )

            def fake_capture(results, *, store, timeout_ms, maximum, capture_console, should_stop=None, on_examined=None):
                from netroach.evidence import ScreenshotCaptureSummary

                for result in list(results):
                    store(result, PNG_HEADER, "new.png", None, "web_screenshot", "test")
                return ScreenshotCaptureSummary(candidates=1, captured=1, failed=0)

            with patch("netroach.api.capture_automatic_evidence", side_effect=fake_capture):
                client.post(f"/v1/scans/{scan_id}/evidence/recapture", json={})
                for thread in threading.enumerate():
                    if thread.name.startswith("netroach-evidence-"):
                        thread.join(timeout=30)

            names = sorted(
                item["file_name"]
                for item in repo.list_result_evidence(scan_id, host="10.0.0.2", port=80)
            )
            self.assertEqual(names, ["by-hand.png", "new.png"])

    def test_a_running_scan_is_not_recaptured_underneath_itself(self):
        with tempfile.TemporaryDirectory() as tmp:
            client, repo, scan_id = self._client_with_open_results(tmp)
            with repo.session() as conn:
                conn.execute("UPDATE scan_jobs SET status='running' WHERE id=?", (scan_id,))

            response = client.post(f"/v1/scans/{scan_id}/evidence/recapture", json={})

            self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
