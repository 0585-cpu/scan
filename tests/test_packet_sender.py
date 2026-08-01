import importlib.util
import socket
import threading
import unittest

from netroach.models import PacketRequest
from netroach.packet_sender import (
    MAX_PAYLOAD_BYTES,
    _summarize_dns_response,
    decode_payload,
    execute_packet_request,
    send_http,
    validate_packet_request,
)


class PacketSenderTests(unittest.TestCase):
    def test_validate_rejects_unsupported_template(self):
        request = PacketRequest(
            template="raw",
            target="127.0.0.1",
            scope=["127.0.0.0/8"],
            confirm_authorized=True,
        )
        with self.assertRaises(ValueError):
            validate_packet_request(request)

    def test_validate_requires_dport_for_udp(self):
        request = PacketRequest(
            template="udp",
            target="127.0.0.1",
            scope=["127.0.0.0/8"],
            confirm_authorized=True,
        )
        with self.assertRaises(ValueError):
            validate_packet_request(request)

    def test_validate_accepts_supported_templates(self):
        requests = [
            make_request("icmp"),
            make_request("udp", dport=53),
            make_request("tcp", dport=443),
            make_request("dns", dns_name="example.com"),
            make_request("http", http_method="GET", http_path="/"),
        ]

        for request in requests:
            with self.subTest(template=request.template):
                validate_packet_request(request)

    def test_validate_caps_count(self):
        request = PacketRequest(
            template="icmp",
            target="127.0.0.1",
            scope=["127.0.0.0/8"],
            confirm_authorized=True,
            count=1001,
        )
        with self.assertRaises(ValueError):
            validate_packet_request(request)

    def test_validate_rejects_low_interval(self):
        with self.assertRaisesRegex(ValueError, "interval_ms"):
            validate_packet_request(make_request("icmp", interval_ms=9))

    def test_validate_rejects_oversized_payload(self):
        with self.assertRaisesRegex(ValueError, "payload"):
            validate_packet_request(make_request("udp", dport=53, payload_text="x" * (MAX_PAYLOAD_BYTES + 1)))

    def test_validate_rejects_conflicting_payload_fields(self):
        with self.assertRaisesRegex(ValueError, "only one"):
            validate_packet_request(make_request("icmp", payload_text="x", payload_base64="eA=="))

    def test_validate_rejects_invalid_ports(self):
        with self.assertRaisesRegex(ValueError, "port out of range"):
            validate_packet_request(make_request("tcp", dport=70000))
        with self.assertRaisesRegex(ValueError, "port out of range"):
            validate_packet_request(make_request("udp", dport=53, sport=0))

    def test_validate_rejects_dns_without_name_and_long_name(self):
        with self.assertRaisesRegex(ValueError, "dns_name"):
            validate_packet_request(make_request("dns", dns_name=None))
        with self.assertRaisesRegex(ValueError, "253"):
            validate_packet_request(make_request("dns", dns_name=("a" * 254)))

    def test_validate_rejects_invalid_http_options(self):
        with self.assertRaisesRegex(ValueError, "http_method"):
            validate_packet_request(make_request("http", http_method="TRACE"))
        with self.assertRaisesRegex(ValueError, "http_path"):
            validate_packet_request(make_request("http", http_path="relative"))

    def test_validate_rejects_invalid_tcp_flags(self):
        with self.assertRaisesRegex(ValueError, "flags"):
            validate_packet_request(make_request("tcp", dport=80, flags="SZ"))

    def test_decode_payload_base64(self):
        self.assertEqual(decode_payload(None, "aGVsbG8="), b"hello")

    def test_decode_payload_invalid_base64(self):
        with self.assertRaisesRegex(ValueError, "base64"):
            decode_payload(None, "not base64!!!")

    def test_execute_requires_confirmation_before_sending(self):
        request = make_request("icmp", confirm_authorized=False)

        with self.assertRaisesRegex(Exception, "confirm_authorized"):
            execute_packet_request(request)

    def test_execute_rejects_out_of_scope_target_before_sending(self):
        request = make_request("icmp", target="192.0.2.10", scope=["127.0.0.0/8"])

        with self.assertRaisesRegex(Exception, "outside authorized scope"):
            execute_packet_request(request)

    def test_execute_dry_run_returns_preview_without_sending(self):
        request = make_request("tcp", dport=443, flags="S", dry_run=True, payload_text="hello")

        result = execute_packet_request(request)

        self.assertEqual(result.template, "tcp")
        self.assertEqual(result.sent, 0)
        self.assertEqual(result.duration_s, 0.0)
        self.assertTrue(result.details["dry_run"])
        self.assertEqual(result.details["dport"], 443)
        self.assertEqual(result.details["payload_bytes"], 5)
        self.assertEqual(result.details["layers"], ["IP", "TCP"])

    def test_send_http_records_status_code(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve_once() -> None:
            try:
                conn, _addr = listener.accept()
                with conn:
                    conn.recv(512)
                    conn.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            finally:
                listener.close()

        server = threading.Thread(target=serve_once)
        server.start()
        try:
            result = send_http("127.0.0.1", dport=port, method="POST", path="/probe", payload=b"ping")
        finally:
            server.join(timeout=3)

        self.assertEqual(result.sent, 1)
        self.assertEqual(result.details["status_code"], 204)
        self.assertEqual(result.details["status_line"], "HTTP/1.1 204 No Content")
        self.assertEqual(result.details["payload_bytes"], 4)

    @unittest.skipUnless(importlib.util.find_spec("scapy") is not None, "scapy is not installed")
    def test_dns_response_summary(self):
        import scapy.all as scapy
        from scapy.all import DNS, DNSQR, DNSRR, IP, UDP

        response = (
            IP(src="127.0.0.1", dst="127.0.0.1")
            / UDP(sport=53, dport=53535)
            / DNS(
                id=1,
                qr=1,
                aa=1,
                qd=DNSQR(qname="example.com"),
                an=DNSRR(rrname="example.com", rdata="127.0.0.1"),
            )
        )

        summary = _summarize_dns_response(response, scapy)

        self.assertTrue(summary["response_received"])
        self.assertEqual(summary["rcode_name"], "NOERROR")
        self.assertEqual(summary["answers"], 1)
        self.assertIn("127.0.0.1", summary["answer_values"])


def make_request(template: str, **overrides: object) -> PacketRequest:
    values = {
        "template": template,
        "target": "127.0.0.1",
        "scope": ["127.0.0.0/8"],
        "confirm_authorized": True,
    }
    values.update(overrides)
    return PacketRequest(**values)


if __name__ == "__main__":
    unittest.main()
