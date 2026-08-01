import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netroach.scan_inputs import (
    TOP_PORTS,
    resolve_host_names,
    resolve_ports,
    resolve_targets,
    validate_scan_workload,
)
from netroach.scope import ScopeError


def _addrinfo(*addresses: str) -> list[tuple]:
    return [
        (
            socket.AF_INET6 if ":" in address else socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            (address, 0),
        )
        for address in addresses
    ]


class HostNameTargetTests(unittest.TestCase):
    def test_literal_targets_are_untouched(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("must not resolve")):
            self.assertEqual(
                resolve_host_names("127.0.0.1, 10.0.0.0/30 # comment"),
                "127.0.0.1,10.0.0.0/30",
            )

    def test_names_are_replaced_by_their_addresses(self):
        with patch("socket.getaddrinfo", return_value=_addrinfo("10.1.1.5", "10.1.1.6", "10.1.1.5")):
            self.assertEqual(resolve_host_names("lab.example"), "10.1.1.5,10.1.1.6")

    def test_names_and_literals_mix(self):
        with patch("socket.getaddrinfo", return_value=_addrinfo("10.1.1.5")):
            self.assertEqual(resolve_host_names("10.0.0.1,lab.example"), "10.0.0.1,10.1.1.5")

    def test_unresolvable_name_is_rejected(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("nope")):
            with self.assertRaisesRegex(ScopeError, "could not resolve target name: nowhere.invalid"):
                resolve_host_names("nowhere.invalid")

    def test_resolved_targets_still_face_the_scope_guard(self):
        from netroach.scope import ScopeGuard

        with patch("socket.getaddrinfo", return_value=_addrinfo("203.0.113.9")):
            targets, expr = resolve_targets(targets="lab.example", max_hosts=16)
        self.assertEqual(expr, "203.0.113.9")
        guard = ScopeGuard.from_strings(["10.0.0.0/8"])
        with self.assertRaises(ScopeError):
            guard.require_targets(targets)


class ScanInputTests(unittest.TestCase):
    def test_resolve_targets_combines_file_and_excludes(self):
        with tempfile.TemporaryDirectory() as tmp:
            targets_file = Path(tmp) / "targets.txt"
            targets_file.write_text(
                "\n".join(
                    [
                        "# lab targets",
                        "127.0.0.1",
                        "127.0.0.2,127.0.0.3",
                    ]
                ),
                encoding="utf-8",
            )

            targets, expr = resolve_targets(
                targets="127.0.0.4",
                targets_file=str(targets_file),
                exclude=["127.0.0.2/32"],
                max_hosts=10,
            )

            self.assertEqual([str(target) for target in targets], ["127.0.0.4", "127.0.0.1", "127.0.0.3"])
            self.assertEqual(expr, "127.0.0.4,127.0.0.1,127.0.0.3")

    def test_resolve_targets_rejects_when_all_excluded(self):
        with self.assertRaisesRegex(ValueError, "all targets were excluded"):
            resolve_targets(targets="127.0.0.1", exclude=["127.0.0.0/8"])

    def test_resolve_ports_combines_file_profile_and_top_ports(self):
        with tempfile.TemporaryDirectory() as tmp:
            ports_file = Path(tmp) / "ports.txt"
            ports_file.write_text("8080\n# comment\n8443\n", encoding="utf-8")

            ports, expr = resolve_ports(
                ports="443",
                ports_file=str(ports_file),
                port_profile="web",
                top_ports=3,
            )

            self.assertIn(22, ports)
            self.assertIn(80, ports)
            self.assertIn(443, ports)
            self.assertIn(8080, ports)
            self.assertEqual(expr, ",".join(str(port) for port in ports))

    def test_top_ports_profile_has_expanded_unique_inventory(self):
        self.assertGreaterEqual(len(TOP_PORTS), 100)
        self.assertEqual(len(TOP_PORTS), len(set(TOP_PORTS)))
        self.assertEqual(TOP_PORTS[:3], (80, 443, 22))

        ports, _expr = resolve_ports(ports=None, top_ports=100)

        self.assertEqual(len(ports), 100)
        self.assertIn(5060, ports)
        self.assertIn(5683, ports)
        all_top_ports, _expr = resolve_ports(ports=None, top_ports=len(TOP_PORTS))
        self.assertIn(10250, all_top_ports)

    def test_resolve_ports_rejects_missing_source(self):
        with self.assertRaisesRegex(ValueError, "provide at least one"):
            resolve_ports(ports=None)

    def test_resolve_ports_rejects_unknown_profile(self):
        with self.assertRaisesRegex(ValueError, "port_profile"):
            resolve_ports(ports=None, port_profile="unknown")

    def test_scan_workload_requires_confirmation_above_limit(self):
        with self.assertRaisesRegex(ValueError, "6 attempts"):
            validate_scan_workload(["a", "b"], [1, 2, 3], max_attempts=5)

        workload = validate_scan_workload(
            ["a", "b"],
            [1, 2, 3],
            max_attempts=5,
            confirm_large_scan=True,
        )
        self.assertEqual(workload, {"hosts": 2, "ports": 3, "attempts": 6})


if __name__ == "__main__":
    unittest.main()
