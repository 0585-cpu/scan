import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netroach.live_capture import LiveCaptureRequest, execute_live_capture, validate_live_capture_request


class FakePcapWriter:
    def __init__(self, path: str, append: bool = False, sync: bool = True):
        self.path = Path(path)
        self.append = append
        self.sync = sync
        self.packets: list[object] = []
        self.closed = False
        self.path.write_bytes(b"")

    def write(self, packet: object) -> None:
        self.packets.append(packet)
        self.path.write_bytes(self.path.read_bytes() + b"pkt")

    def close(self) -> None:
        self.closed = True


class FakeSummary:
    def __init__(self, path: Path):
        self.path = path

    def to_dict(self) -> dict[str, object]:
        return {"file": str(self.path), "packet_count": 2, "protocols": {"IPv4": 2}}


class LiveCaptureTests(unittest.TestCase):
    def test_live_capture_requires_authorization_and_bounds(self):
        with self.assertRaisesRegex(ValueError, "confirm_authorized"):
            validate_live_capture_request(LiveCaptureRequest(output="capture.pcap", duration_s=1))

        with self.assertRaisesRegex(ValueError, "duration_s or count"):
            validate_live_capture_request(LiveCaptureRequest(output="capture.pcap", confirm_authorized=True))

        with self.assertRaisesRegex(ValueError, "count must be <= 1000000"):
            validate_live_capture_request(
                LiveCaptureRequest(output="capture.pcap", confirm_authorized=True, count=1_000_001)
            )

        with self.assertRaisesRegex(ValueError, "duration_s must be <= 3600"):
            validate_live_capture_request(
                LiveCaptureRequest(output="capture.pcap", confirm_authorized=True, duration_s=3600.1)
            )

    def test_live_capture_streams_to_pcap_and_analyzes(self):
        sniff_kwargs: dict[str, object] = {}

        def fake_sniff(**kwargs):
            sniff_kwargs.update(kwargs)
            kwargs["prn"]("packet-1")
            kwargs["prn"]("packet-2")

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "capture.pcap"
            with (
                patch(
                    "netroach.live_capture._import_scapy_capture",
                    return_value={"PcapWriter": FakePcapWriter, "sniff": fake_sniff},
                ),
                patch("netroach.live_capture.analyze_pcap", side_effect=lambda path, top=10: FakeSummary(Path(path))),
            ):
                result = execute_live_capture(
                    LiveCaptureRequest(
                        output=str(output),
                        confirm_authorized=True,
                        duration_s=0.1,
                        count=2,
                        iface="lo",
                        bpf_filter="tcp",
                    )
                )

        self.assertEqual(result.packet_count, 2)
        self.assertTrue(result.analyzed)
        self.assertEqual(result.analysis["packet_count"], 2)
        self.assertEqual(sniff_kwargs["store"], False)
        self.assertEqual(sniff_kwargs["timeout"], 0.1)
        self.assertEqual(sniff_kwargs["count"], 2)
        self.assertEqual(sniff_kwargs["iface"], "lo")
        self.assertEqual(sniff_kwargs["filter"], "tcp")

    def test_count_only_capture_gets_default_timeout(self):
        sniff_kwargs: dict[str, object] = {}

        def fake_sniff(**kwargs):
            sniff_kwargs.update(kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "capture.pcap"
            with patch(
                "netroach.live_capture._import_scapy_capture",
                return_value={"PcapWriter": FakePcapWriter, "sniff": fake_sniff},
            ):
                result = execute_live_capture(
                    LiveCaptureRequest(
                        output=str(output),
                        confirm_authorized=True,
                        count=5,
                        analyze=False,
                        backend="scapy",
                    )
                )

        self.assertEqual(result.packet_count, 0)
        self.assertFalse(result.analyzed)
        self.assertEqual(sniff_kwargs["timeout"], 60.0)
        self.assertEqual(sniff_kwargs["count"], 5)


if __name__ == "__main__":
    unittest.main()
