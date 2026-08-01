import importlib.util
import struct
import tempfile
import tracemalloc
import unittest
from pathlib import Path

from netroach.pcap import analyze_pcap


def has_scapy() -> bool:
    return importlib.util.find_spec("scapy") is not None


@unittest.skipUnless(has_scapy(), "scapy is not installed")
class PcapAnalysisTests(unittest.TestCase):
    def test_pcap_golden_dns_http_tls_conversations(self):
        from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, wrpcap

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.pcap"
            wrpcap(str(path), fixture_packets(IP, TCP, UDP, DNS, DNSQR, Raw))

            summary = analyze_pcap(path, top=10).to_dict()

        self.assertEqual(summary["packet_count"], 4)
        self.assertEqual(summary["protocols"]["IPv4"], 4)
        self.assertEqual(summary["protocols"]["TCP"], 2)
        self.assertEqual(summary["protocols"]["UDP"], 2)
        self.assertEqual(summary["dns_queries"], ["example.test"])
        self.assertEqual(summary["http_hosts"], ["app.example.test"])
        self.assertIn(("10.0.0.10:53000 -> 10.0.0.53:53 UDP", 1), summary["conversations"])
        self.assertIn(("10.0.0.20:49152 -> 10.0.0.30:80 TCP", 1), summary["conversations"])
        self.assertIn({"sni": "tls.example.test", "alpn": ["h2", "http/1.1"]}, summary["tls_metadata"])

    def test_pcapng_golden_dns_http_tls_conversations(self):
        from scapy.all import DNS, DNSQR, IP, TCP, UDP, PcapNgWriter, Raw

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.pcapng"
            writer = PcapNgWriter(str(path))
            try:
                for packet in fixture_packets(IP, TCP, UDP, DNS, DNSQR, Raw):
                    writer.write(packet)
            finally:
                writer.close()

            summary = analyze_pcap(path, top=10).to_dict()

        self.assertEqual(summary["packet_count"], 4)
        self.assertEqual(summary["dns_queries"], ["example.test"])
        self.assertEqual(summary["http_hosts"], ["app.example.test"])
        self.assertIn({"sni": "tls.example.test", "alpn": ["h2", "http/1.1"]}, summary["tls_metadata"])

    def test_pcap_v11_extracts_l2_l3_http_dns_and_conversation_metrics(self):
        from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "v11.pcap"
            wrpcap(str(path), v11_packets(ARP, BOOTP, DHCP, DNS, DNSQR, Ether, ICMP, IP, Raw, TCP, UDP))

            summary = analyze_pcap(path, top=10).to_dict()

        self.assertEqual(summary["packet_count"], 8)
        self.assertEqual(summary["protocols"]["ARP"], 2)
        self.assertEqual(summary["protocols"]["ICMP"], 1)
        self.assertEqual(summary["protocols"]["DHCP"], 1)
        self.assertEqual(summary["arp_summary"], {"requests": 1, "replies": 1})
        self.assertEqual(summary["icmp_summary"], {"echo_request": 1})
        self.assertEqual(summary["dhcp_messages"], {"discover": 1})
        self.assertEqual(summary["dns_responses"]["total"], 1)
        self.assertEqual(summary["dns_responses"]["nxdomain"], 1)
        self.assertEqual(summary["dns_responses"]["rcode_counts"]["NXDOMAIN"], 1)
        self.assertEqual(summary["http_hosts"], ["app.example.test"])
        self.assertEqual(summary["http_user_agents"], ["NetroachTest/1.0"])
        self.assertEqual(summary["http_status_lines"], ["HTTP/1.1 404 Not Found"])
        metric = next(
            item
            for item in summary["conversation_metrics"]
            if item["conversation"] == "10.10.0.10:51000 -> 10.10.0.20:80 TCP"
        )
        self.assertEqual(metric["packets"], 2)
        self.assertGreater(metric["bytes"], 0)
        self.assertAlmostEqual(metric["duration"], 1.0, places=3)

    def test_large_pcap_is_processed_streaming_style(self):
        from scapy.all import IP, UDP, Raw, wrpcap

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "large.pcap"
            packets = [
                IP(src=f"10.1.{index // 250}.{index % 250 + 1}", dst="10.2.0.1")
                / UDP(sport=20000 + (index % 1000), dport=9999)
                / Raw(b"x")
                for index in range(1500)
            ]
            wrpcap(str(path), packets)

            tracemalloc.start()
            try:
                summary = analyze_pcap(path, top=5)
                _current, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()

        self.assertEqual(summary.packet_count, 1500)
        self.assertEqual(summary.protocols["UDP"], 1500)
        self.assertEqual(summary.protocols["IPv4"], 1500)
        self.assertLessEqual(len(summary.top_talkers), 5)
        self.assertLessEqual(len(summary.conversations), 5)
        self.assertLess(peak, 64 * 1024 * 1024)

    def test_rejects_missing_empty_corrupt_and_unsupported_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, "not found"):
                analyze_pcap(root / "missing.pcap")

            empty = root / "empty.pcap"
            empty.write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "empty"):
                analyze_pcap(empty)

            corrupt = root / "corrupt.pcap"
            corrupt.write_bytes(b"not a pcap")
            with self.assertRaisesRegex(ValueError, "could not read pcap"):
                analyze_pcap(corrupt)

            unsupported = root / "unsupported.pcap"
            unsupported.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 999))
            with self.assertRaisesRegex(ValueError, "unsupported pcap link type"):
                analyze_pcap(unsupported)


def fixture_packets(IP, TCP, UDP, DNS, DNSQR, Raw):
    return [
        IP(src="10.0.0.10", dst="10.0.0.53")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.test.")),
        IP(src="10.0.0.20", dst="10.0.0.30")
        / TCP(sport=49152, dport=80)
        / Raw(b"GET / HTTP/1.1\r\nHost: app.example.test\r\nUser-Agent: Netroach\r\n\r\n"),
        IP(src="10.0.0.20", dst="10.0.0.40")
        / TCP(sport=49153, dport=443)
        / Raw(tls_client_hello("tls.example.test", ["h2", "http/1.1"])),
        IP(src="10.0.0.50", dst="10.0.0.60") / UDP(sport=40000, dport=9999) / Raw(b"udp payload"),
    ]


def v11_packets(ARP, BOOTP, DHCP, DNS, DNSQR, Ether, ICMP, IP, Raw, TCP, UDP):
    packets = [
        Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, psrc="10.10.0.10", pdst="10.10.0.1"),
        Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
        / ARP(op=2, psrc="10.10.0.1", pdst="10.10.0.10"),
        Ether()
        / IP(src="10.10.0.10", dst="10.10.0.1")
        / ICMP(type=8, code=0),
        Ether()
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=b"\xaa\xbb\xcc\xdd\xee\xff")
        / DHCP(options=[("message-type", "discover"), "end"]),
        Ether()
        / IP(src="10.10.0.53", dst="10.10.0.10")
        / UDP(sport=53, dport=53000)
        / DNS(id=1, qr=1, rcode=3, qd=DNSQR(qname="missing.example.")),
        Ether()
        / IP(src="10.10.0.10", dst="10.10.0.20")
        / TCP(sport=51000, dport=80)
        / Raw(b"GET /one HTTP/1.1\r\nHost: app.example.test\r\nUser-Agent: NetroachTest/1.0\r\n\r\n"),
        Ether()
        / IP(src="10.10.0.10", dst="10.10.0.20")
        / TCP(sport=51000, dport=80)
        / Raw(b"GET /two HTTP/1.1\r\nHost: app.example.test\r\nUser-Agent: NetroachTest/1.0\r\n\r\n"),
        Ether()
        / IP(src="10.10.0.20", dst="10.10.0.10")
        / TCP(sport=80, dport=51000)
        / Raw(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"),
    ]
    for index, packet in enumerate(packets):
        packet.time = 1_700_000_000 + index
    packets[6].time = packets[5].time + 1
    return packets


def tls_client_hello(sni: str, alpn: list[str]) -> bytes:
    sni_name = sni.encode("idna")
    sni_entry = b"\x00" + len(sni_name).to_bytes(2, "big") + sni_name
    sni_ext_data = len(sni_entry).to_bytes(2, "big") + sni_entry

    alpn_protocols = b"".join(bytes([len(protocol.encode("ascii"))]) + protocol.encode("ascii") for protocol in alpn)
    alpn_ext_data = len(alpn_protocols).to_bytes(2, "big") + alpn_protocols

    extensions = (
        b"\x00\x00" + len(sni_ext_data).to_bytes(2, "big") + sni_ext_data
        + b"\x00\x10" + len(alpn_ext_data).to_bytes(2, "big") + alpn_ext_data
    )
    body = (
        b"\x03\x03"
        + (b"\x11" * 32)
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


if __name__ == "__main__":
    unittest.main()


class DecodedFrameCountTests(unittest.TestCase):
    def test_frames_the_analyser_cannot_read_are_counted_separately(self):
        # pktmon records raw 802.11 copies next to the Ethernet ones on a Wi-Fi
        # adapter; every statistic counts the decoded frames, so the totals have
        # to be reported apart rather than letting packet_count look inflated.
        from scapy.all import IP, UDP, Ether, PcapWriter, Raw

        from netroach.pcap import analyze_pcap

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mixed.pcap"
            with PcapWriter(str(path), sync=True) as writer:
                writer.write(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=53))
                writer.write(Ether() / Raw(load=b"\x88\x02" + b"\x00" * 40))

            summary = analyze_pcap(path)

        self.assertEqual(summary.packet_count, 2)
        self.assertEqual(summary.decoded_frames, 1)
        self.assertEqual(summary.undecoded_frames, 1)
        self.assertEqual(summary.protocols.get("IPv4"), 1)
