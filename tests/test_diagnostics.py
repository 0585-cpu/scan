import subprocess
import unittest
from unittest.mock import patch

from netroach.diagnostics import (
    collect_packet_capability,
    read_engine_syn_sweep,
    read_engine_version,
)


class EngineSynSweepCapabilityTests(unittest.TestCase):
    """Only the binary knows whether it was compiled with SYN support.

    Every uncertain answer is False: a build that cannot SYN rejects the scan
    outright, so claiming support that is not there breaks every TCP scan, while
    falling back to connect always works.
    """

    def _engine_says(self, stdout: str, returncode: int = 0):
        return subprocess.CompletedProcess(
            args=["netroach-engine", "capabilities"],
            returncode=returncode,
            stdout=stdout,
            stderr="",
        )

    def test_a_syn_capable_engine_reports_support(self):
        completed = self._engine_says('{"event":"capabilities","syn_sweep":true,"version":"0.2.4"}\n')
        with patch("netroach.diagnostics.subprocess.run", return_value=completed):
            self.assertIs(read_engine_syn_sweep("netroach-engine"), True)

    def test_a_connect_only_engine_reports_no_support(self):
        completed = self._engine_says('{"event":"capabilities","syn_sweep":false,"version":"0.2.4"}\n')
        with patch("netroach.diagnostics.subprocess.run", return_value=completed):
            self.assertIs(read_engine_syn_sweep("netroach-engine"), False)

    def test_an_engine_without_the_subcommand_reports_no_support(self):
        # An older engine does not know "capabilities" and exits non-zero.
        completed = self._engine_says("", returncode=2)
        with patch("netroach.diagnostics.subprocess.run", return_value=completed):
            self.assertIs(read_engine_syn_sweep("netroach-engine"), False)

    def test_unreadable_output_reports_no_support(self):
        with patch("netroach.diagnostics.subprocess.run", return_value=self._engine_says("not json")):
            self.assertIs(read_engine_syn_sweep("netroach-engine"), False)

    def test_an_engine_that_cannot_be_run_reports_no_support(self):
        with patch("netroach.diagnostics.subprocess.run", side_effect=OSError("boom")):
            self.assertIs(read_engine_syn_sweep("netroach-engine"), False)

    def test_a_missing_engine_reports_no_support(self):
        self.assertIs(read_engine_syn_sweep(None), False)


class DiagnosticsTests(unittest.TestCase):
    def test_read_engine_version(self):
        completed = subprocess.CompletedProcess(
            args=["netroach-engine", "--version"],
            returncode=0,
            stdout="netroach-engine 0.1.0\n",
            stderr="",
        )
        with patch("netroach.diagnostics.subprocess.run", return_value=completed):
            self.assertEqual(read_engine_version("netroach-engine"), "netroach-engine 0.1.0")

    def test_read_engine_version_returns_none_on_failure(self):
        completed = subprocess.CompletedProcess(
            args=["netroach-engine", "--version"],
            returncode=1,
            stdout="",
            stderr="failed",
        )
        with patch("netroach.diagnostics.subprocess.run", return_value=completed):
            self.assertIsNone(read_engine_version("netroach-engine"))

    def test_windows_packet_capability_reports_npcap_and_elevation(self):
        with (
            patch("netroach.diagnostics.detect_npcap", return_value=True),
            patch("netroach.diagnostics.is_windows_elevated", return_value=False),
        ):
            capability = collect_packet_capability("Windows")

        self.assertEqual(capability.driver, "Npcap")
        self.assertTrue(capability.driver_available)
        self.assertFalse(capability.raw_socket_privileged)
        self.assertIn("elevated", capability.note)

    def test_linux_packet_capability_reports_cap_net_raw(self):
        with (
            patch("netroach.diagnostics.is_root_user", return_value=False),
            patch("netroach.diagnostics.has_cap_net_raw", return_value=True),
        ):
            capability = collect_packet_capability("Linux")

        self.assertEqual(capability.driver, "raw-socket")
        self.assertTrue(capability.raw_socket_privileged)
        self.assertIn("CAP_NET_RAW", capability.note)


if __name__ == "__main__":
    unittest.main()
