import subprocess
import unittest
from unittest.mock import patch

from netprobe.diagnostics import collect_packet_capability, read_engine_version


class DiagnosticsTests(unittest.TestCase):
    def test_read_engine_version(self):
        completed = subprocess.CompletedProcess(
            args=["scaprobe-engine", "--version"],
            returncode=0,
            stdout="scaprobe-engine 0.1.0\n",
            stderr="",
        )
        with patch("netprobe.diagnostics.subprocess.run", return_value=completed):
            self.assertEqual(read_engine_version("scaprobe-engine"), "scaprobe-engine 0.1.0")

    def test_read_engine_version_returns_none_on_failure(self):
        completed = subprocess.CompletedProcess(
            args=["scaprobe-engine", "--version"],
            returncode=1,
            stdout="",
            stderr="failed",
        )
        with patch("netprobe.diagnostics.subprocess.run", return_value=completed):
            self.assertIsNone(read_engine_version("scaprobe-engine"))

    def test_windows_packet_capability_reports_npcap_and_elevation(self):
        with (
            patch("netprobe.diagnostics.detect_npcap", return_value=True),
            patch("netprobe.diagnostics.is_windows_elevated", return_value=False),
        ):
            capability = collect_packet_capability("Windows")

        self.assertEqual(capability.driver, "Npcap")
        self.assertTrue(capability.driver_available)
        self.assertFalse(capability.raw_socket_privileged)
        self.assertIn("elevated", capability.note)

    def test_linux_packet_capability_reports_cap_net_raw(self):
        with (
            patch("netprobe.diagnostics.is_root_user", return_value=False),
            patch("netprobe.diagnostics.has_cap_net_raw", return_value=True),
        ):
            capability = collect_packet_capability("Linux")

        self.assertEqual(capability.driver, "raw-socket")
        self.assertTrue(capability.raw_socket_privileged)
        self.assertIn("CAP_NET_RAW", capability.note)


if __name__ == "__main__":
    unittest.main()
