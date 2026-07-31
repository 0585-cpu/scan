import json
import importlib.util
import io
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


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
        from netprobe.version import __version__

        diagnostics = {
            "app_version": __version__,
            "platform": "test",
            "python": "test",
            "rust_engine": "scaprobe-engine",
            "rust_engine_available": True,
            "rust_engine_version": "scaprobe-engine test",
            "scapy_available": True,
            "database_path": "",
        }
        self.engine_patch = patch("netprobe.api.resolve_engine_path", return_value="scaprobe-engine")
        self.diagnostics_patch = patch("netprobe.api.collect_diagnostics")
        self.engine_patch.start()
        diagnostics_mock = self.diagnostics_patch.start()
        diagnostics_mock.return_value.to_dict.return_value = diagnostics
        self.addCleanup(self.engine_patch.stop)
        self.addCleanup(self.diagnostics_patch.stop)

    def test_startup_recovery_scans_only_missing_host_port_pairs(self):
        from fastapi.testclient import TestClient

        from netprobe.api import create_app
        from netprobe.models import PortResult, ScanSummary
        from netprobe.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
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

            with patch("netprobe.api.run_scan", side_effect=fake_run_scan):
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

        from netprobe.api import create_app
        from netprobe.version import __version__

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/scaprobe.db"))
            response = client.get("/v1/health")
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["status"], "ok")
            self.assertTrue(payload["rust_engine_available"])
            self.assertEqual(Path(payload["db"]), Path(tmp) / "scaprobe.db")
            self.assertIn("diagnostics", payload)
            self.assertEqual(payload["diagnostics"]["app_version"], __version__)
            self.assertIn("platform", payload["diagnostics"])
            self.assertIn("rust_engine_available", payload["diagnostics"])
            self.assertIn("rust_engine_version", payload["diagnostics"])
            self.assertIn("scapy_available", payload["diagnostics"])
            self.assertEqual(Path(payload["diagnostics"]["database_path"]), Path(tmp) / "scaprobe.db")
            self.assertIn("web", payload["plugins"]["port_profiles"])
            self.assertIn("infra", payload["plugins"]["port_profiles"])

    def test_health_is_degraded_and_scan_is_rejected_when_engine_is_missing(self):
        from fastapi.testclient import TestClient

        from netprobe.api import create_app
        from netprobe.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
            with patch("netprobe.api.resolve_engine_path", return_value=None):
                with patch("netprobe.api.collect_diagnostics") as collect:
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

        from netprobe.api import create_app
        from netprobe.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
            repo = SQLiteRepository(db_path)
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="80",
                scope=["127.0.0.0/8"],
                params={"resumable": True},
            )
            repo.mark_scan_started(scan_id)
            with patch("netprobe.api.resolve_engine_path", return_value=None):
                with TestClient(create_app(str(db_path))) as client:
                    self.assertEqual(client.get("/v1/scans").status_code, 200)

            self.assertEqual(repo.get_job(scan_id)["status"], "running")

    def test_dashboard_routes(self):
        from fastapi.testclient import TestClient

        from netprobe.api import create_app

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/scaprobe.db"))

            root = client.get("/")
            dashboard = client.get("/dashboard")

            self.assertEqual(root.status_code, 200)
            self.assertIn("text/html", root.headers["content-type"])
            self.assertIn("Scaprobe Dashboard", root.text)
            self.assertIn("/v1/scans", root.text)
            self.assertIn("data-view-target=\"overview\"", root.text)
            self.assertIn("Packet Send", root.text)
            self.assertIn("Diagnostics", root.text)
            self.assertIn("Use exact targets as scope", root.text)
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
            self.assertIn('id="scanCustomProfiles"', root.text)
            self.assertIn("compactPortsHtml(job.ports", root.text)
            self.assertIn("const formElement = event.currentTarget", root.text)
            self.assertIn("formElement.elements.confirm_authorized.checked = false", root.text)
            self.assertIn("Rust Engine Unavailable", root.text)
            self.assertNotIn('<label for="scanProfile">Port Profile</label>', root.text)
            self.assertIn("format=xlsx", root.text)
            self.assertIn("width: 80px; height: 60px", root.text)
            self.assertEqual(dashboard.status_code, 200)
            self.assertIn("Start Scan", dashboard.text)

    def test_scan_requires_scope(self):
        from fastapi.testclient import TestClient

        from netprobe.api import create_app

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/scaprobe.db"))
            response = client.post(
                "/v1/scans",
                json={"targets": "127.0.0.1", "ports": "80", "confirm_authorized": True},
            )
            self.assertEqual(response.status_code, 400)
            self.assertIn("error", response.json()["detail"])

    def test_scan_create_response_fields(self):
        from fastapi.testclient import TestClient

        from netprobe.api import create_app
        from netprobe.models import ScanSummary

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/scaprobe.db"))
            with patch("netprobe.api.run_scan") as run_scan:
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

        from netprobe.api import create_app
        from netprobe.models import ScanSummary

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/scaprobe.db"))
            with patch("netprobe.api.run_scan") as run_scan:
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

        from netprobe.api import create_app
        from netprobe.models import ScanSummary

        captured: dict[str, object] = {}

        def fake_run_scan(**kwargs):
            captured.update(kwargs)
            return [], ScanSummary(scan_id=kwargs["scan_id"])

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/scaprobe.db"))
            with patch("netprobe.api.run_scan", side_effect=fake_run_scan):
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

        from netprobe.api import create_app
        from netprobe.models import ScanSummary

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/scaprobe.db"))
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

            with patch("netprobe.api.run_scan", return_value=([], ScanSummary(scan_id="ignored"))):
                accepted = client.post("/v1/scans", json={**request, "confirm_large_scan": True})
            self.assertEqual(accepted.status_code, 200)
            self.assertEqual(accepted.json()["workload"], {"hosts": 2, "ports": 2, "attempts": 4})

    def test_scan_uses_app_config_scope_defaults_and_custom_port_profile(self):
        from fastapi.testclient import TestClient

        from netprobe.api import create_app
        from netprobe.models import ScanSummary

        captured: dict[str, object] = {}

        def fake_run_scan(**kwargs):
            captured.update(kwargs)
            return [], ScanSummary(scan_id=kwargs["scan_id"])

        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "scaprobe.toml"
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
            client = TestClient(create_app(f"{tmp}/scaprobe.db", config_path=str(config_path), config_env="local"))
            with patch("netprobe.api.run_scan", side_effect=fake_run_scan):
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

    def test_scan_uses_plugin_profile_and_lists_plugins(self):
        from fastapi.testclient import TestClient

        from netprobe.api import create_app
        from netprobe.models import ScanSummary

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
            client = TestClient(create_app(f"{tmp}/scaprobe.db", plugin_paths=[str(plugin_path)]))

            plugins = client.get("/v1/plugins")
            self.assertEqual(plugins.status_code, 200)
            self.assertEqual(plugins.json()["plugins"][0]["name"], "lab")

            with patch("netprobe.api.run_scan", side_effect=fake_run_scan):
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

        from netprobe.api import create_app
        from netprobe.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
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

        from netprobe.api import create_app

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/scaprobe.db"))
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

        from netprobe.api import create_app
        from netprobe.models import PortResult
        from netprobe.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
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

        from netprobe.api import create_app
        from netprobe.models import PortResult
        from netprobe.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
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

        from netprobe.api import create_app
        from netprobe.models import PortResult
        from netprobe.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
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
            self.assertIn("Scaprobe Scan Report", report_html.text)
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

        from netprobe.api import create_app
        from netprobe.models import PortResult
        from netprobe.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
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
        from netprobe.api import _run_scan_job
        from netprobe.evidence import ScreenshotCaptureSummary
        from netprobe.models import EngineSettings, PortResult, ScanSummary
        from netprobe.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
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

            def fake_capture(results, *, store, timeout_ms, maximum, should_stop):
                result = list(results)[0]
                self.assertFalse(should_stop())
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

            with patch("netprobe.api.run_scan", side_effect=fake_run_scan):
                with patch("netprobe.api.capture_automatic_evidence", side_effect=fake_capture):
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

        from netprobe.api import create_app
        from netprobe.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
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

        from netprobe.api import create_app
        from netprobe.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
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
        from scapy.all import IP, Raw, TCP, wrpcap

        from netprobe.api import create_app

        with tempfile.TemporaryDirectory() as tmp:
            pcap_path = Path(tmp) / "fixture.pcap"
            wrpcap(str(pcap_path), [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2) / Raw(b"x")])
            client = TestClient(create_app(f"{tmp}/scaprobe.db"))

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

        from netprobe.api import create_app
        from netprobe.live_capture import LiveCaptureResult
        from netprobe.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
            output = Path(tmp) / "capture.pcap"
            client = TestClient(create_app(str(db_path)))

            rejected = client.post(
                "/v1/captures/live",
                json={"output": str(output), "duration_s": 1, "confirm_authorized": False},
            )
            self.assertEqual(rejected.status_code, 400)
            self.assertIn("confirm_authorized", rejected.json()["detail"]["error"])

            with patch(
                "netprobe.api.execute_live_capture",
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

        from netprobe.api import create_app
        from netprobe.models import SendResult

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/scaprobe.db"))
            with patch(
                "netprobe.api.execute_packet_request",
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

        from netprobe.api import create_app
        from netprobe.models import SendResult
        from netprobe.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
            client = TestClient(create_app(str(db_path)))
            with patch(
                "netprobe.api.execute_packet_request",
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

        from netprobe.api import create_app
        from netprobe.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
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

        from netprobe.api import create_app
        from netprobe.models import SendResult
        from netprobe.storage import SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
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

        from netprobe.api import create_app

        with tempfile.TemporaryDirectory() as tmp:
            client = TestClient(create_app(f"{tmp}/scaprobe.db"))

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

        from netprobe.api import create_app

        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "scaprobe.db")
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

        from netprobe.api import create_app

        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "scaprobe.db")
            app = create_app(db_path, api_token="s3cret")
            with TestClient(app) as client:
                self.assertEqual(client.get("/dashboard").status_code, 401)
                landing = client.get("/dashboard?token=s3cret")
                self.assertEqual(landing.status_code, 200)
                self.assertIn("scaprobe_api_token", client.cookies)
                self.assertEqual(client.get("/v1/health").status_code, 200)


if __name__ == "__main__":
    unittest.main()
