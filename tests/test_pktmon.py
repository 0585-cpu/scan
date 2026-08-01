import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from netroach.live_capture import LiveCaptureRequest, select_capture_backend
from netroach.pktmon import build_filter_arguments, capture_to_pcapng, check_pktmon, parse_pktmon_filter


class PktmonFilterTests(unittest.TestCase):
    def test_supported_terms_are_parsed(self):
        self.assertEqual(parse_pktmon_filter("host 10.0.0.5"), ("10.0.0.5", None))
        self.assertEqual(parse_pktmon_filter("port 443"), (None, 443))
        self.assertEqual(parse_pktmon_filter("host 10.0.0.5 and port 80"), ("10.0.0.5", 80))
        self.assertEqual(parse_pktmon_filter(None), (None, None))

    def test_unsupported_expression_is_rejected_rather_than_approximated(self):
        # Silently widening a filter would capture more than the operator asked for.
        with self.assertRaisesRegex(ValueError, "host <address>"):
            parse_pktmon_filter("tcp and not port 22")
        with self.assertRaisesRegex(ValueError, "between 1 and 65535"):
            parse_pktmon_filter("port 70000")

    def test_filter_arguments_cover_only_requested_terms(self):
        self.assertEqual(build_filter_arguments(), [])
        self.assertEqual(
            build_filter_arguments(host="10.0.0.5", port=80),
            [
                ["filter", "add", "netroach-host", "-i", "10.0.0.5"],
                ["filter", "add", "netroach-port", "-p", "80"],
            ],
        )


class PktmonAvailabilityTests(unittest.TestCase):
    def test_non_windows_is_reported_unavailable(self):
        with patch("platform.system", return_value="Linux"):
            availability = check_pktmon()
        self.assertFalse(availability.available)
        self.assertIn("Windows", availability.reason)

    def test_missing_executable_is_reported(self):
        with patch("platform.system", return_value="Windows"), patch("shutil.which", return_value=None):
            availability = check_pktmon()
        self.assertFalse(availability.available)
        self.assertIn("not found", availability.reason)

    def test_unelevated_process_cannot_capture(self):
        with patch("platform.system", return_value="Windows"), patch("shutil.which", return_value="pktmon.exe"):
            availability = check_pktmon(elevated=False)
        self.assertFalse(availability.available)
        self.assertIn("elevated", availability.reason)

    def test_available_when_present_and_elevated(self):
        with patch("platform.system", return_value="Windows"), patch("shutil.which", return_value="pktmon.exe"):
            self.assertTrue(check_pktmon(elevated=True).available)


class BackendSelectionTests(unittest.TestCase):
    def _request(self, **overrides) -> LiveCaptureRequest:
        values = {"output": "capture.pcap", "confirm_authorized": True, "duration_s": 1.0}
        values.update(overrides)
        return LiveCaptureRequest(**values)

    def test_auto_prefers_pktmon_when_available(self):
        with patch("netroach.live_capture.check_pktmon") as check:
            check.return_value.available = True
            self.assertEqual(select_capture_backend(self._request()), "pktmon")

    def test_auto_falls_back_to_scapy_without_pktmon(self):
        with patch("netroach.live_capture.check_pktmon") as check:
            check.return_value.available = False
            self.assertEqual(select_capture_backend(self._request()), "scapy")

    def test_bpf_filter_pktmon_cannot_express_keeps_scapy(self):
        self.assertEqual(select_capture_backend(self._request(bpf_filter="tcp and not port 22")), "scapy")

    def test_explicit_interface_keeps_scapy(self):
        # pktmon captures every adapter, so an interface choice must be honoured.
        self.assertEqual(select_capture_backend(self._request(iface="Ethernet")), "scapy")

    def test_explicit_backend_wins_and_is_validated(self):
        self.assertEqual(select_capture_backend(self._request(backend="scapy")), "scapy")
        self.assertEqual(select_capture_backend(self._request(backend="pktmon")), "pktmon")
        with self.assertRaisesRegex(ValueError, "backend must be one of"):
            select_capture_backend(self._request(backend="tcpdump"))


class PktmonCaptureTests(unittest.TestCase):
    def test_capture_starts_stops_converts_and_clears_filters(self):
        calls: list[list[str]] = []

        def fake_run(arguments, **_kwargs):
            calls.append(list(arguments[1:]))
            if arguments[1] == "etl2pcap":
                Path(arguments[4]).write_bytes(b"pcapng")
            if arguments[1] == "start":
                Path(arguments[4]).write_bytes(b"etl")
            stdout = "Packet capture is not running." if arguments[1] == "status" else ""
            return subprocess.CompletedProcess(arguments, 0, stdout, "")

        with patch("netroach.pktmon.subprocess.run", side_effect=fake_run), patch("time.sleep"):
            size = capture_to_pcapng(
                output=Path("out.pcapng"),
                duration_s=0.01,
                executable="pktmon.exe",
                filter_expression="port 53",
            )

        self.assertEqual(size, 6)
        verbs = [call[0] for call in calls]
        self.assertEqual(verbs.count("start"), 1)
        self.assertEqual(verbs.count("stop"), 1)
        self.assertEqual(verbs.count("etl2pcap"), 1)
        # Filters are cleared before and after so a capture never inherits ours.
        self.assertGreaterEqual(verbs.count("filter"), 3)
        Path("out.pcapng").unlink(missing_ok=True)

    def test_running_session_is_not_hijacked(self):
        def fake_run(arguments, **_kwargs):
            return subprocess.CompletedProcess(arguments, 0, "Packet capture is running.", "")

        with patch("netroach.pktmon.subprocess.run", side_effect=fake_run):
            with self.assertRaisesRegex(RuntimeError, "already running"):
                capture_to_pcapng(output=Path("out.pcapng"), duration_s=0.01, executable="pktmon.exe")

    def test_failed_start_surfaces_the_pktmon_message(self):
        def fake_run(arguments, **_kwargs):
            if arguments[1] == "start":
                return subprocess.CompletedProcess(arguments, 1, "", "Access is denied.")
            return subprocess.CompletedProcess(arguments, 0, "not running", "")

        with patch("netroach.pktmon.subprocess.run", side_effect=fake_run):
            with self.assertRaisesRegex(RuntimeError, "Access is denied"):
                capture_to_pcapng(output=Path("out.pcapng"), duration_s=0.01, executable="pktmon.exe")


if __name__ == "__main__":
    unittest.main()
