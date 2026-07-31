import unittest

from netprobe.oast import (
    OastSessionRequest,
    body_preview,
    build_callback_url,
    build_interaction_payload,
    sanitized_headers,
    validate_oast_session_request,
)


class OastTests(unittest.TestCase):
    def test_session_validation_requires_authorization_and_bounds(self):
        with self.assertRaisesRegex(ValueError, "confirm_authorized"):
            validate_oast_session_request(OastSessionRequest(confirm_authorized=False))

        with self.assertRaisesRegex(ValueError, "ttl_seconds"):
            validate_oast_session_request(OastSessionRequest(confirm_authorized=True, ttl_seconds=10))

        with self.assertRaisesRegex(ValueError, "base_url"):
            validate_oast_session_request(
                OastSessionRequest(confirm_authorized=True, base_url="ftp://example.test", ttl_seconds=60)
            )

    def test_callback_url_and_redaction_helpers(self):
        self.assertEqual(build_callback_url(None, "abc"), "/oast/abc")
        self.assertEqual(build_callback_url("http://127.0.0.1:8765/api", "abc"), "http://127.0.0.1:8765/api/oast/abc")

        headers = sanitized_headers({"Authorization": "secret", "User-Agent": "tester"})
        self.assertEqual(headers["Authorization"], "[redacted]")
        self.assertEqual(headers["User-Agent"], "tester")

        preview, truncated = body_preview(b"x" * 5000, limit=10)
        self.assertEqual(preview, "x" * 10)
        self.assertTrue(truncated)

    def test_interaction_payload_is_sanitized(self):
        payload = build_interaction_payload(
            method="post",
            path="/oast/token",
            query_string="a=1",
            client_host="127.0.0.1",
            headers=[("cookie", "session=secret"), ("x-test", "ok")],
            body=b"hello",
        )

        self.assertEqual(payload["method"], "POST")
        self.assertEqual(payload["headers"]["cookie"], "[redacted]")
        self.assertEqual(payload["headers"]["x-test"], "ok")
        self.assertEqual(payload["body_preview"], "hello")
        self.assertFalse(payload["body_truncated"])


if __name__ == "__main__":
    unittest.main()
