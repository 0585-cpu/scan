import unittest
from unittest.mock import patch

from netroach.auth import (
    AuthorizationError,
    is_loopback_host,
    require_active_authorization,
    resolve_api_token,
)


class AuthTests(unittest.TestCase):
    def test_active_authorization_requires_confirmation(self):
        with self.assertRaises(AuthorizationError):
            require_active_authorization(False, ["127.0.0.0/8"])

    def test_active_authorization_requires_explicit_scope(self):
        with self.assertRaises(AuthorizationError):
            require_active_authorization(True, [])

    def test_active_authorization_returns_scope_guard(self):
        guard = require_active_authorization(True, ["127.0.0.0/8"])
        guard.require_ip("127.0.0.1")


class ApiTokenTests(unittest.TestCase):
    def test_loopback_hosts_are_recognized(self):
        for host in ("127.0.0.1", "127.5.5.5", "localhost", "::1", "[::1]"):
            self.assertTrue(is_loopback_host(host), host)
        for host in ("0.0.0.0", "192.168.1.10", "::", "example.internal", ""):
            self.assertFalse(is_loopback_host(host), host)

    def test_loopback_bind_stays_open_by_default(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertIsNone(resolve_api_token(None, "127.0.0.1"))

    def test_non_loopback_bind_generates_token(self):
        with patch.dict("os.environ", {}, clear=True):
            token = resolve_api_token(None, "0.0.0.0")
        self.assertTrue(token)
        self.assertGreaterEqual(len(token), 32)

    def test_explicit_token_wins(self):
        self.assertEqual(resolve_api_token("  secret  ", "127.0.0.1"), "secret")

    def test_environment_token_is_used(self):
        with patch.dict("os.environ", {"NETROACH_API_TOKEN": "env-secret"}):
            self.assertEqual(resolve_api_token(None, "127.0.0.1"), "env-secret")


if __name__ == "__main__":
    unittest.main()

