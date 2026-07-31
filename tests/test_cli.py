import io
import importlib.util
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from netprobe.cli import RESULT_EXPORT_FIELDS, main
from netprobe.evidence import ScreenshotCaptureSummary
from netprobe.models import PortResult, ScanSummary, SendResult
from netprobe.storage import SQLiteRepository
from netprobe.version import __version__


class CliTests(unittest.TestCase):
    def test_version_flag(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as exc:
                main(["--version"])

        self.assertEqual(exc.exception.code, 0)
        self.assertEqual(stdout.getvalue().strip(), f"scaprobe {__version__}")

    def test_removed_history_commands_and_legacy_evidence_flag_are_not_recognized(self):
        commands = [
            ["jobs"],
            ["audits"],
            ["pcaps"],
            ["oast"],
            ["db"],
            ["scan", "--capture-" + "screenshots"],
        ]
        for command in commands:
            with self.subTest(command=command):
                with redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as exc:
                        main(command)
                self.assertEqual(exc.exception.code, 2)

    def test_scan_requires_scope(self):
        code = main(["scan", "--targets", "127.0.0.1", "--ports", "80", "--confirm-authorized"])
        self.assertEqual(code, 2)

    def test_serve_check_succeeds(self):
        code = main(["serve", "--check"])
        self.assertEqual(code, 0)

    def test_diagnostics_command_succeeds(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = main(["diagnostics"])

        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertIn("app_version", payload)
        self.assertIn("database_path", payload)

    def test_scan_json_response_fields(self):
        def fake_run_scan(**kwargs):
            result = PortResult(
                scan_id=kwargs["scan_id"],
                host="127.0.0.1",
                port=80,
                protocol="tcp",
                state="open",
                latency_ms=1.0,
                service_name="http",
                service_confidence=0.99,
            )
            summary = ScanSummary(scan_id=kwargs["scan_id"])
            summary.observe(result)
            return [result], summary

        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            with patch("netprobe.cli.run_scan", side_effect=fake_run_scan):
                with redirect_stdout(stdout):
                    code = main(
                        [
                            "scan",
                            "--db",
                            str(Path(tmp) / "scaprobe.db"),
                            "--targets",
                            "127.0.0.1",
                            "--ports",
                            "80",
                            "--scope",
                            "127.0.0.0/8",
                            "--confirm-authorized",
                            "--json",
                        ]
                    )

            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(set(payload), {"scan_id", "summary", "results"})
            self.assertEqual(payload["summary"]["total"], 1)
            self.assertEqual(payload["results"][0]["state"], "open")
            self.assertNotIn("latency_ms", payload["results"][0])
            self.assertNotIn("service_confidence", payload["results"][0])

    def test_scan_text_output_omits_latency(self):
        def fake_run_scan(**kwargs):
            result = PortResult(
                scan_id=kwargs["scan_id"],
                host="127.0.0.1",
                port=80,
                protocol="tcp",
                state="open",
                latency_ms=1.0,
                service_name="http",
            )
            summary = ScanSummary(scan_id=kwargs["scan_id"])
            summary.observe(result)
            return [result], summary

        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            with patch("netprobe.cli.run_scan", side_effect=fake_run_scan):
                with redirect_stdout(stdout):
                    code = main(
                        [
                            "scan",
                            "--db",
                            str(Path(tmp) / "scaprobe.db"),
                            "--targets",
                            "127.0.0.1",
                            "--ports",
                            "80",
                            "--scope",
                            "127.0.0.0/8",
                            "--confirm-authorized",
                        ]
                    )

            self.assertEqual(code, 0)
            self.assertIn("OPEN 127.0.0.1:80/tcp http", stdout.getvalue())
            self.assertNotIn("1.0 ms", stdout.getvalue())

    def test_scan_can_capture_automatic_service_evidence(self):
        def fake_run_scan(**kwargs):
            result = PortResult(
                scan_id=kwargs["scan_id"],
                host="127.0.0.1",
                port=80,
                protocol="tcp",
                state="open",
                latency_ms=1.0,
                service_name="http",
            )
            summary = ScanSummary(scan_id=kwargs["scan_id"])
            summary.observe(result)
            return [result], summary

        def fake_capture(results, *, store, timeout_ms, maximum):
            result = list(results)[0]
            store(
                result,
                b"\x89PNG\r\n\x1a\nautomatic",
                "127.0.0.1_80.png",
                "http://127.0.0.1/",
                "web_screenshot",
            )
            self.assertEqual(timeout_ms, 4_000)
            self.assertEqual(maximum, 3)
            return ScreenshotCaptureSummary(candidates=1, captured=1, failed=0, web_screenshots=1)

        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            with patch("netprobe.cli.run_scan", side_effect=fake_run_scan):
                with patch("netprobe.cli.capture_automatic_evidence", side_effect=fake_capture):
                    with redirect_stdout(stdout):
                        code = main(
                            [
                                "scan",
                                "--db",
                                str(Path(tmp) / "scaprobe.db"),
                                "--targets",
                                "127.0.0.1",
                                "--ports",
                                "80",
                                "--scope",
                                "127.0.0.0/8",
                                "--confirm-authorized",
                                "--capture-evidence",
                                "--screenshot-timeout-ms",
                                "4000",
                                "--screenshot-max",
                                "3",
                                "--json",
                            ]
                        )

            self.assertEqual(code, 0)
            evidence = json.loads(stdout.getvalue())["results"][0]["evidence_files"][0]
            self.assertEqual(evidence["type"], "web_screenshot")
            self.assertEqual(evidence["source_url"], "http://127.0.0.1/")

    def test_scan_accepts_target_file_exclude_and_port_profile(self):
        captured: dict[str, object] = {}

        def fake_run_scan(**kwargs):
            captured.update(kwargs)
            return [], ScanSummary(scan_id=kwargs["scan_id"])

        with tempfile.TemporaryDirectory() as tmp:
            targets_file = Path(tmp) / "targets.txt"
            targets_file.write_text("127.0.0.2\n127.0.0.3\n", encoding="utf-8")
            stdout = io.StringIO()
            with patch("netprobe.cli.run_scan", side_effect=fake_run_scan):
                with redirect_stdout(stdout):
                    code = main(
                        [
                            "scan",
                            "--db",
                            str(Path(tmp) / "scaprobe.db"),
                            "--targets",
                            "127.0.0.1",
                            "--targets-file",
                            str(targets_file),
                            "--exclude",
                            "127.0.0.2/32",
                            "--profile",
                            "web",
                            "--top-ports",
                            "2",
                            "--scope",
                            "127.0.0.0/8",
                            "--confirm-authorized",
                            "--json",
                        ]
                    )

            self.assertEqual(code, 0)
            self.assertEqual(captured["target_expr"], "127.0.0.1,127.0.0.3")
            self.assertEqual(captured["port_expr"], "80,443,3000,5000,8000,8080,8443,9000")

    def test_scan_uses_config_scope_defaults_and_custom_port_profile(self):
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
timeout_ms = 123
concurrency = 7
rate_limit_per_sec = 9
port_profile = "custom"

[port_profiles]
custom = [8081, 8444]
""",
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with patch("netprobe.cli.run_scan", side_effect=fake_run_scan):
                with redirect_stdout(stdout):
                    code = main(
                        [
                            "scan",
                            "--db",
                            str(Path(tmp) / "scaprobe.db"),
                            "--config",
                            str(config_path),
                            "--targets",
                            "127.0.0.1,127.0.0.2",
                            "--confirm-authorized",
                            "--json",
                        ]
                    )

            self.assertEqual(code, 0)
            self.assertEqual(captured["target_expr"], "127.0.0.1")
            self.assertEqual(captured["port_expr"], "8081,8444")
            settings = captured["settings"]
            self.assertEqual(settings.timeout_ms, 123)
            self.assertEqual(settings.concurrency, 7)
            self.assertEqual(settings.rate_limit_per_sec, 9)

    def test_scan_uses_plugin_port_profile_and_records_plugin_paths(self):
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
                        "port_profiles": {"lab-app": [18080, 18443]},
                        "tcp_services": {"18080": "custom-http"},
                    }
                ),
                encoding="utf-8",
            )
            config_path = Path(tmp) / "scaprobe.toml"
            config_path.write_text(
                """
[plugins]
paths = ["lab-plugin.json"]
""",
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with patch("netprobe.cli.run_scan", side_effect=fake_run_scan):
                with redirect_stdout(stdout):
                    code = main(
                        [
                            "scan",
                            "--db",
                            str(Path(tmp) / "scaprobe.db"),
                            "--config",
                            str(config_path),
                            "--targets",
                            "127.0.0.1",
                            "--profile",
                            "lab-app",
                            "--scope",
                            "127.0.0.0/8",
                            "--confirm-authorized",
                            "--json",
                        ]
                    )

            self.assertEqual(code, 0)
            self.assertEqual(captured["port_expr"], "18080,18443")
            settings = captured["settings"]
            self.assertEqual(settings.plugin_paths, (str(plugin_path.resolve()),))

    def test_plugins_list_and_validate_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_path = Path(tmp) / "lab-plugin.json"
            plugin_path.write_text(
                json.dumps({"name": "lab", "version": "1.0.0", "port_profiles": {"lab-app": [8080]}}),
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(["plugins", "validate", str(plugin_path), "--json"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout.getvalue())["name"], "lab")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(["plugins", "list", "--plugin", str(plugin_path), "--json"])
            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["count"], 1)
            self.assertEqual(payload["port_profiles"]["lab-app"], [8080])

    def test_export_csv_filters_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path, scan_id = create_scan_with_results(tmp)
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                code = main(
                    [
                        "export",
                        "--db",
                        str(db_path),
                        scan_id,
                        "--format",
                        "csv",
                        "--state",
                        "open",
                        "--protocol",
                        "udp",
                    ]
                )

            self.assertEqual(code, 0)
            text = stdout.getvalue()
            self.assertEqual(text.splitlines()[0], ",".join(RESULT_EXPORT_FIELDS))
            self.assertNotIn("latency_ms", text.splitlines()[0])
            self.assertNotIn("service_confidence", text.splitlines()[0])
            self.assertIn(",53,udp,open,", text)
            self.assertNotIn(",80,tcp,closed,", text)

    def test_export_ndjson_includes_job_and_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path, scan_id = create_scan_with_results(tmp)
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                code = main(["export", "--db", str(db_path), scan_id, "--format", "ndjson", "--limit", "1"])

            self.assertEqual(code, 0)
            lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
            self.assertEqual(lines[0]["type"], "job")
            self.assertEqual(lines[1]["type"], "result")
            self.assertEqual(lines[1]["result"]["port"], 53)
            self.assertNotIn("latency_ms", lines[1]["result"])
            self.assertNotIn("service_confidence", lines[1]["result"])

    def test_pcap_json_response_fields(self):
        if importlib.util.find_spec("scapy") is None:
            self.skipTest("scapy is not installed")
        from scapy.all import IP, TCP, Raw, wrpcap

        with tempfile.TemporaryDirectory() as tmp:
            pcap_path = Path(tmp) / "fixture.pcap"
            wrpcap(str(pcap_path), [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2) / Raw(b"x")])
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                code = main(["pcap", "--db", str(Path(tmp) / "scaprobe.db"), str(pcap_path), "--json"])

            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(set(payload), {"analysis_id", "summary"})
            self.assertIn("packet_count", payload["summary"])
            self.assertIn("protocols", payload["summary"])
            self.assertIn("arp_summary", payload["summary"])
            self.assertIn("dns_responses", payload["summary"])
            self.assertIn("conversation_metrics", payload["summary"])

    def test_capture_json_response_fields_and_persists_analysis(self):
        from netprobe.live_capture import LiveCaptureResult

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
            output = Path(tmp) / "capture.pcap"
            stdout = io.StringIO()
            with patch(
                "netprobe.cli.execute_live_capture",
                return_value=LiveCaptureResult(
                    file=str(output),
                    packet_count=2,
                    duration_s=0.01,
                    interface="lo",
                    bpf_filter="tcp",
                    analyzed=True,
                    analysis={"file": str(output), "packet_count": 2},
                ),
            ):
                with redirect_stdout(stdout):
                    code = main(
                        [
                            "capture",
                            "--db",
                            str(db_path),
                            "--output",
                            str(output),
                            "--duration-s",
                            "1",
                            "--count",
                            "2",
                            "--iface",
                            "lo",
                            "--filter",
                            "tcp",
                            "--confirm-authorized",
                            "--json",
                        ]
                    )

            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertIsNotNone(payload["analysis_id"])
            self.assertEqual(payload["capture"]["packet_count"], 2)
            analysis = SQLiteRepository(db_path).get_pcap_analysis(payload["analysis_id"])
            self.assertEqual(analysis["summary"]["packet_count"], 2)

    def test_send_json_response_fields_match_api_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            with patch(
                "netprobe.cli.execute_packet_request",
                return_value=SendResult(
                    template="icmp",
                    target="127.0.0.1",
                    sent=1,
                    duration_s=0.01,
                    details={"payload_bytes": 0},
                ),
            ):
                with redirect_stdout(stdout):
                    code = main(
                        [
                            "send",
                            "icmp",
                            "--db",
                            str(Path(tmp) / "scaprobe.db"),
                            "--target",
                            "127.0.0.1",
                            "--scope",
                            "127.0.0.0/8",
                            "--confirm-authorized",
                            "--json",
                        ]
                    )

            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertIn("audit_id", payload)
            self.assertEqual(set(payload["result"]), {"template", "target", "sent", "duration_s", "details"})
            self.assertEqual(payload["result"]["template"], "icmp")

    def test_send_persists_full_audit_request_and_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
            stdout = io.StringIO()
            with patch(
                "netprobe.cli.execute_packet_request",
                return_value=SendResult(
                    template="udp",
                    target="127.0.0.1",
                    sent=2,
                    duration_s=0.02,
                    details={"dport": 53, "payload_bytes": 5},
                ),
            ):
                with redirect_stdout(stdout):
                    code = main(
                        [
                            "send",
                            "udp",
                            "--db",
                            str(db_path),
                            "--target",
                            "127.0.0.1",
                            "--scope",
                            "127.0.0.0/8",
                            "--confirm-authorized",
                            "--count",
                            "2",
                            "--interval-ms",
                            "25",
                            "--dport",
                            "53",
                            "--sport",
                            "53530",
                            "--payload-text",
                            "hello",
                            "--json",
                        ]
                    )

            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            audit = SQLiteRepository(db_path).get_packet_audit(payload["audit_id"])
            self.assertIsNotNone(audit)
            self.assertEqual(audit["request"]["template"], "udp")
            self.assertEqual(audit["request"]["scope"], ["127.0.0.0/8"])
            self.assertTrue(audit["request"]["confirm_authorized"])
            self.assertEqual(audit["request"]["count"], 2)
            self.assertEqual(audit["request"]["interval_ms"], 25)
            self.assertEqual(audit["request"]["dport"], 53)
            self.assertEqual(audit["request"]["sport"], 53530)
            self.assertEqual(audit["request"]["payload_text"], "hello")
            self.assertEqual(audit["result"]["sent"], 2)
            self.assertEqual(audit["result"]["details"]["dport"], 53)

    def test_send_dry_run_preview_is_audited(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scaprobe.db"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(
                    [
                        "send",
                        "tcp",
                        "--db",
                        str(db_path),
                        "--target",
                        "127.0.0.1",
                        "--scope",
                        "127.0.0.0/8",
                        "--confirm-authorized",
                        "--dport",
                        "443",
                        "--flags",
                        "S",
                        "--payload-text",
                        "hello",
                        "--dry-run",
                        "--json",
                    ]
                )

            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["result"]["sent"], 0)
            self.assertTrue(payload["result"]["details"]["dry_run"])
            audit = SQLiteRepository(db_path).get_packet_audit(payload["audit_id"])
            self.assertTrue(audit["request"]["dry_run"])
            self.assertEqual(audit["result"]["details"]["payload_bytes"], 5)

    def test_report_markdown_writes_scan_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path, scan_id = create_scan_with_results(tmp)
            output = Path(tmp) / "report.md"
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                code = main(
                    [
                        "report",
                        "--db",
                        str(db_path),
                        scan_id,
                        "--format",
                        "markdown",
                        "--output",
                        str(output),
                    ]
                )

            self.assertEqual(code, 0)
            self.assertEqual(stdout.getvalue(), "")
            text = output.read_text(encoding="utf-8")
            self.assertIn("# Scaprobe Scan Report", text)
            self.assertIn("| 127.0.0.1 | 53 | udp | dns |", text)
            self.assertNotIn("Latency", text)


def create_scan_with_results(tmp: str) -> tuple[Path, str]:
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
    return db_path, scan_id


if __name__ == "__main__":
    unittest.main()
