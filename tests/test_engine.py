import io
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from netroach.engine import (
    EngineUnavailableError,
    ScanCancelled,
    _build_rust_engine_command,
    _run_rust_engine,
    _run_rust_engine_command,
    engine_process_environment,
    resolve_engine_path,
    run_scan,
)
from netroach.models import EngineSettings
from netroach.plugins import load_plugins


class EngineTests(unittest.TestCase):
    def test_windows_engine_process_can_find_npcap_dlls_without_compatibility_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            windows = Path(tmp) / "Windows"
            npcap = windows / "System32" / "Npcap"
            npcap.mkdir(parents=True)

            environment = engine_process_environment(
                {"PATH": r"C:\existing"},
                system="Windows",
                windows_dir=windows,
            )

        self.assertEqual(environment["PATH"].split(os.pathsep)[0], str(npcap))
        self.assertIn(r"C:\existing", environment["PATH"])

    def test_syn_sweep_settings_append_explicit_engine_flags(self):
        command = _build_rust_engine_command(
            engine="netroach-engine",
            scan_id="syn-test",
            target_expr="192.0.2.1",
            port_expr="80,443",
            settings=EngineSettings(syn_sweep=True, syn_retries=2),
        )

        self.assertIn("--syn-sweep", command)
        self.assertEqual(command[command.index("--syn-retries") + 1], "2")

    def test_default_engine_command_does_not_enable_syn_sweep(self):
        command = _build_rust_engine_command(
            engine="netroach-engine",
            scan_id="connect-test",
            target_expr="192.0.2.1",
            port_expr="80",
            settings=EngineSettings(),
        )

        self.assertNotIn("--syn-sweep", command)
        self.assertNotIn("--syn-retries", command)

    def test_direct_engine_call_rejects_invalid_syn_settings(self):
        for settings, message in (
            (EngineSettings(syn_sweep=True, protocol="udp"), "TCP"),
            (EngineSettings(syn_sweep=True, syn_retries=3), "syn_retries"),
        ):
            with self.subTest(settings=settings):
                with self.assertRaisesRegex(ValueError, message):
                    run_scan(
                        scan_id="invalid-syn",
                        targets=["127.0.0.1"],
                        ports=[80],
                        target_expr="127.0.0.1",
                        port_expr="80",
                        settings=settings,
                    )

    def test_engine_discovery_supports_explicit_and_canonical_environment_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = Path(tmp) / "netroach-engine"
            engine.touch()
            self.assertEqual(resolve_engine_path(str(engine)), str(engine))
            with patch.dict(os.environ, {"NETROACH_ENGINE": str(engine)}, clear=True):
                with patch("netroach.engine.shutil.which", return_value=None):
                    self.assertEqual(resolve_engine_path(), str(engine))

    def test_rust_engine_process_is_terminated_on_external_cancel(self):
        class BlockingStdout:
            def __init__(self) -> None:
                self.released = threading.Event()

            def __iter__(self):
                return self

            def __next__(self):
                self.released.wait(timeout=3)
                raise StopIteration

        class FakeProcess:
            def __init__(self) -> None:
                self.stdout = BlockingStdout()
                self.stderr = io.StringIO("")
                self.returncode = None
                self.terminated = False

            def poll(self):
                return self.returncode

            def terminate(self):
                self.terminated = True
                self.returncode = -15
                self.stdout.released.set()

            def kill(self):
                self.returncode = -9
                self.stdout.released.set()

            def wait(self, timeout=None):
                if self.returncode is None and timeout is not None:
                    raise TimeoutError
                return self.returncode or 0

        process = FakeProcess()
        with patch("netroach.engine.subprocess.Popen", return_value=process):
            with self.assertRaisesRegex(ScanCancelled, "cancelled"):
                _run_rust_engine_command(
                    ["netroach-engine", "scan"],
                    scan_id="cancel-rust",
                    on_event=None,
                    should_stop=lambda: True,
                )
        self.assertTrue(process.terminated)

    def test_cancelling_a_flooding_engine_does_not_leak_the_reader_thread(self):
        from netroach.engine import ENGINE_EVENT_QUEUE_SIZE

        class FloodingStdout:
            """Emits far more events than the bounded queue can hold."""

            def __init__(self) -> None:
                self.remaining = ENGINE_EVENT_QUEUE_SIZE * 3

            def __iter__(self):
                return self

            def __next__(self):
                if self.remaining <= 0:
                    raise StopIteration
                self.remaining -= 1
                return json.dumps({"event": "port", "host": "127.0.0.1", "port": 80, "state": "open"}) + "\n"

        class FakeProcess:
            def __init__(self) -> None:
                self.stdout = FloodingStdout()
                self.stderr = io.StringIO("")
                self.returncode = None

            def poll(self):
                return self.returncode

            def terminate(self):
                self.returncode = -15

            def kill(self):
                self.returncode = -9

            def wait(self, timeout=None):
                return self.returncode or 0

        before = threading.active_count()
        with patch("netroach.engine.subprocess.Popen", return_value=FakeProcess()):
            with self.assertRaises(ScanCancelled):
                _run_rust_engine_command(
                    ["netroach-engine", "scan"],
                    scan_id="flood-cancel",
                    on_event=None,
                    should_stop=lambda: True,
                )
        self.assertLessEqual(threading.active_count(), before)

    def test_runtime_plugins_are_serialized_for_rust_and_temporary_file_is_removed(self):
        captured: dict[str, object] = {}

        class FakeProcess:
            def __init__(self) -> None:
                self.stdout = io.StringIO("")
                self.stderr = io.StringIO("")

            def wait(self, timeout=None) -> int:
                return 0

            def poll(self) -> int:
                return 0

        def fake_popen(command: list[str], **_kwargs) -> FakeProcess:
            captured["command"] = command
            catalog_path = Path(command[command.index("--plugin-catalog-file") + 1])
            captured["catalog_path"] = catalog_path
            captured["catalog"] = json.loads(catalog_path.read_text(encoding="utf-8"))
            return FakeProcess()

        with tempfile.TemporaryDirectory() as tmp:
            plugin_path = Path(tmp) / "plugin.json"
            plugin_path.write_text(
                json.dumps(
                    {
                        "name": "lab",
                        "tcp_services": {"18080": "custom-http"},
                        "tcp_banner_rules": [
                            {
                                "service": "custom-http",
                                "contains": "X-Lab",
                                "confidence": 0.91,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with patch("netroach.engine.subprocess.Popen", side_effect=fake_popen):
                results, summary = _run_rust_engine(
                    engine="netroach-engine",
                    scan_id="plugin-scan",
                    target_expr="127.0.0.1",
                    port_expr="18080",
                    settings=EngineSettings(plugin_paths=(str(plugin_path),)),
                    on_event=None,
                    plugin_catalog=load_plugins([plugin_path]),
                )

        command = captured["command"]
        catalog = captured["catalog"]
        self.assertIn("--plugin-catalog-file", command)
        self.assertEqual(catalog["schema_version"], 1)
        self.assertEqual(catalog["tcp_services"]["18080"], "custom-http")
        self.assertEqual(catalog["tcp_banner_rules"][0]["contains"], [88, 45, 76, 97, 98])
        self.assertFalse(captured["catalog_path"].exists())
        self.assertEqual(results, [])
        self.assertEqual(summary.scan_id, "plugin-scan")

    def test_missing_rust_engine_raises_unavailable_error(self):
        with patch("netroach.engine.resolve_engine_path", return_value=None):
            with self.assertRaisesRegex(EngineUnavailableError, "Rust scan engine is unavailable"):
                run_scan(
                    scan_id="missing-engine",
                    targets=["127.0.0.1"],
                    ports=[80],
                    target_expr="127.0.0.1",
                    port_expr="80",
                    settings=EngineSettings(),
                )

    def test_large_rust_engine_inputs_are_transferred_through_temporary_files(self):
        captured: dict[str, object] = {}

        class FakeProcess:
            def __init__(self) -> None:
                self.stdout = io.StringIO("")
                self.stderr = io.StringIO("")

            def wait(self, timeout=None) -> int:
                return 0

            def poll(self) -> int:
                return 0

        def fake_popen(command: list[str], **_kwargs) -> FakeProcess:
            captured["command"] = command
            targets_path = Path(command[command.index("--targets-file") + 1])
            ports_path = Path(command[command.index("--ports-file") + 1])
            captured["targets_path"] = targets_path
            captured["ports_path"] = ports_path
            captured["targets"] = targets_path.read_text(encoding="utf-8")
            captured["ports"] = ports_path.read_text(encoding="utf-8")
            return FakeProcess()

        target_expr = ",".join(["127.0.0.1"] * 15_000)
        port_expr = ",".join(str(port) for port in range(1, 10_000))
        with patch("netroach.engine.subprocess.Popen", side_effect=fake_popen):
            results, summary = _run_rust_engine(
                engine="netroach-engine",
                scan_id="large-input",
                target_expr=target_expr,
                port_expr=port_expr,
                settings=EngineSettings(service_probe=False),
                on_event=None,
            )

        command = captured["command"]
        self.assertIn("--targets-file", command)
        self.assertIn("--ports-file", command)
        self.assertNotIn(target_expr, command)
        self.assertNotIn(port_expr, command)
        self.assertEqual(captured["targets"], target_expr)
        self.assertEqual(captured["ports"], port_expr)
        self.assertFalse(captured["targets_path"].exists())
        self.assertFalse(captured["ports_path"].exists())
        self.assertEqual(results, [])
        self.assertEqual(summary.total, 0)


class HostDiscoveryCommandTests(unittest.TestCase):
    """Discovery is on unless the operator says otherwise.

    Addresses on the scanner's own segment that answer no ARP have nothing to
    probe, and probing them is where a wide scan spends its time: measured on a
    real segment, ten such addresses over twenty ports took 22.6s where the
    same scan with discovery took 3.0s, and none of the difference reached
    anything. Ethernet cannot deliver to an on-link address without its MAC, so
    the skip is sound there - and only there, which is why the engine decides
    per address rather than the caller deciding per scan.

    It stays defeatable, for a segment holding a device that will not answer an
    ARP from an unknown source.
    """

    def _command(self, settings):
        return _build_rust_engine_command(
            engine="netroach-engine",
            scan_id="discovery-test",
            target_expr="10.0.0.0/24",
            port_expr="22",
            settings=settings,
        )

    def test_discovery_is_on_without_asking(self):
        self.assertNotIn("--no-host-discovery", self._command(EngineSettings()))

    def test_turning_it_off_reaches_the_engine(self):
        command = self._command(EngineSettings(host_discovery=False))
        self.assertIn("--no-host-discovery", command)


if __name__ == "__main__":
    unittest.main()
