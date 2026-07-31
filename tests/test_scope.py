import ipaddress
import unittest

from netprobe.scope import ScopeError, ScopeGuard, parse_target_expr, scope_values_from_targets


class ScopeTests(unittest.TestCase):
    def test_parse_target_expr_expands_cidr_hosts(self):
        self.assertEqual(
            parse_target_expr("192.168.1.0/30"),
            [
                ipaddress.ip_address("192.168.1.1"),
                ipaddress.ip_address("192.168.1.2"),
            ],
        )

    def test_parse_target_expr_dedupes_addresses(self):
        self.assertEqual(parse_target_expr("192.168.1.1,192.168.1.1"), [ipaddress.ip_address("192.168.1.1")])

    def test_parse_target_expr_accepts_newlines(self):
        self.assertEqual(
            parse_target_expr("192.168.1.1\n192.168.1.2"),
            [ipaddress.ip_address("192.168.1.1"), ipaddress.ip_address("192.168.1.2")],
        )

    def test_parse_target_expr_enforces_max_hosts_for_individual_ips(self):
        with self.assertRaisesRegex(ScopeError, "max-hosts=1"):
            parse_target_expr("192.168.1.1,192.168.1.2", max_hosts=1)

    def test_parse_target_expr_rejects_non_positive_max_hosts(self):
        with self.assertRaisesRegex(ScopeError, "max_hosts"):
            parse_target_expr("192.168.1.1", max_hosts=0)

    def test_scope_values_from_targets_handles_ips_and_cidr(self):
        self.assertEqual(
            scope_values_from_targets("192.168.1.10\n192.168.1.0/28\n::1"),
            ["192.168.1.10/32", "192.168.1.0/28", "::1/128"],
        )

    def test_scope_guard_allows_explicit_scope(self):
        guard = ScopeGuard.from_strings(["192.168.1.0/24"])
        guard.require_ip("192.168.1.10")

    def test_scope_guard_rejects_out_of_scope_target(self):
        guard = ScopeGuard.from_strings(["192.168.1.0/24"])
        with self.assertRaises(ScopeError):
            guard.require_ip("192.168.2.10")


if __name__ == "__main__":
    unittest.main()
