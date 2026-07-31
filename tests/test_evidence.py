import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from PIL import Image

from netprobe.evidence import (
    SCREENSHOT_HEIGHT,
    SCREENSHOT_WIDTH,
    ScreenshotCaptureSummary,
    TerminalTranscript,
    automatic_evidence_candidates,
    capture_automatic_evidence,
    detect_image_media_type,
    preauth_mode_for_result,
    render_terminal_transcript,
    run_powershell_diagnostic,
    web_result_url,
    web_screenshot_candidates,
)


class EvidenceTests(unittest.TestCase):
    def test_screenshot_viewport_is_800_by_600(self):
        self.assertEqual((SCREENSHOT_WIDTH, SCREENSHOT_HEIGHT), (800, 600))

    def test_image_detection_accepts_supported_signatures_and_rejects_text(self):
        self.assertEqual(detect_image_media_type(b"\x89PNG\r\n\x1a\npayload"), "image/png")
        self.assertEqual(detect_image_media_type(b"\xff\xd8\xffpayload"), "image/jpeg")
        self.assertEqual(detect_image_media_type(b"GIF89apayload"), "image/gif")
        self.assertEqual(detect_image_media_type(b"RIFF\x00\x00\x00\x00WEBPpayload"), "image/webp")
        with self.assertRaisesRegex(ValueError, "PNG, JPEG, GIF, or WebP"):
            detect_image_media_type(b"not an image")

    def test_web_candidates_are_bounded_and_urls_handle_https_and_ipv6(self):
        results = [
            {"host": "127.0.0.1", "port": 80, "protocol": "tcp", "state": "open", "service_name": "http"},
            {"host": "127.0.0.2", "port": 443, "protocol": "tcp", "state": "open", "service_name": "tls"},
            {"host": "127.0.0.3", "port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh"},
        ]

        candidates = web_screenshot_candidates(results, maximum=1)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(web_result_url(candidates[0]), "http://127.0.0.1/")
        self.assertEqual(
            web_result_url({"host": "2001:db8::1", "port": 443, "service_name": "https"}),
            "https://[2001:db8::1]/",
        )

    def test_automatic_candidates_include_open_tcp_and_udp_services(self):
        results = [
            {"host": "127.0.0.1", "port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh"},
            {
                "host": "127.0.0.1",
                "port": 53,
                "protocol": "udp",
                "state": "open|filtered",
                "service_name": "dns",
            },
            {"host": "127.0.0.1", "port": 25, "protocol": "tcp", "state": "closed", "service_name": "smtp"},
        ]

        candidates = automatic_evidence_candidates(results)

        self.assertEqual([(item["port"], item["protocol"]) for item in candidates], [(22, "tcp"), (53, "udp")])

    def test_terminal_transcript_is_800_by_600_png(self):
        result = {
            "scan_id": "scan-1",
            "host": "192.0.2.10",
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service_name": "ssh",
            "banner": "SSH-2.0-OpenSSH_9.6",
            "evidence": "SSH protocol banner received",
        }
        image_bytes = render_terminal_transcript(
            result,
            TerminalTranscript(
                shell="Windows PowerShell",
                command="$tcp = [Net.Sockets.TcpClient]::new(); $tcp.ConnectAsync('192.0.2.10', 22).Wait(6000)",
                output="ComputerName : 192.0.2.10\nRemotePort : 22\nTcpTestSucceeded : True",
                exit_code=0,
            ),
        )

        self.assertEqual(detect_image_media_type(image_bytes), "image/png")
        with Image.open(io.BytesIO(image_bytes)) as image:
            self.assertEqual(image.size, (800, 600))

    def test_pre_authentication_modes_use_service_and_secure_port_hints(self):
        self.assertEqual(preauth_mode_for_result({"port": 22, "protocol": "tcp"}), "ssh")
        self.assertEqual(
            preauth_mode_for_result({"port": 2222, "protocol": "tcp", "service_name": "ssh"}),
            "ssh",
        )
        self.assertEqual(
            preauth_mode_for_result({"port": 465, "protocol": "tcp", "service_name": "smtp"}),
            "smtps",
        )
        self.assertEqual(
            preauth_mode_for_result({"port": 53, "protocol": "udp", "service_name": "dns"}),
            "none",
        )

    def test_powershell_diagnostic_passes_target_through_environment(self):
        dangerous_host = "127.0.0.1'; Remove-Item *; '"
        completed = SimpleNamespace(stdout="TcpTestSucceeded : True\n", stderr="", returncode=0)
        with patch("netprobe.evidence.shutil.which", return_value="powershell.exe"):
            with patch("netprobe.evidence.subprocess.run", return_value=completed) as run:
                transcript = run_powershell_diagnostic(
                    {
                        "host": dangerous_host,
                        "port": 22,
                        "protocol": "tcp",
                        "state": "open",
                        "service_name": "ssh",
                    }
                )

        arguments = run.call_args.args[0]
        self.assertNotIn(dangerous_host, arguments)
        self.assertEqual(run.call_args.kwargs["env"]["SCAPROBE_TARGET"], dangerous_host)
        self.assertEqual(run.call_args.kwargs["env"]["SCAPROBE_PREAUTH_MODE"], "ssh")
        self.assertNotIn("SCAPROBE_USERNAME", run.call_args.kwargs["env"])
        self.assertNotIn("SCAPROBE_PASSWORD", run.call_args.kwargs["env"])
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertIn("TcpTestSucceeded", transcript.output)

    def test_automatic_evidence_falls_back_to_terminal_transcripts(self):
        results = [
            {"host": "127.0.0.1", "port": 80, "protocol": "tcp", "state": "open", "service_name": "http"},
            {"host": "127.0.0.1", "port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh"},
        ]
        stored: list[tuple[int, str, tuple[int, int]]] = []

        def store(result, data, file_name, source_url, evidence_type):
            self.assertTrue(file_name.endswith(".png"))
            with Image.open(io.BytesIO(data)) as image:
                stored.append((result["port"], evidence_type, image.size))

        failed_web = ScreenshotCaptureSummary(
            candidates=1,
            captured=0,
            failed=1,
            errors=("browser unavailable",),
        )
        transcript = TerminalTranscript(
            shell="Windows PowerShell",
            command="$tcp.ConnectAsync()",
            output="TcpTestSucceeded : True",
            exit_code=0,
        )
        with patch("netprobe.evidence.capture_web_screenshots", return_value=failed_web):
            with patch("netprobe.evidence.run_powershell_diagnostic", return_value=transcript):
                summary = capture_automatic_evidence(results, store=store)

        self.assertEqual(
            stored,
            [(80, "terminal_transcript", (800, 600)), (22, "terminal_transcript", (800, 600))],
        )
        self.assertEqual(summary.candidates, 2)
        self.assertEqual(summary.captured, 2)
        self.assertEqual(summary.failed, 0)
        self.assertEqual(summary.web_screenshots, 0)
        self.assertEqual(summary.protocol_snapshots, 0)
        self.assertEqual(summary.terminal_transcripts, 2)
        self.assertIn("browser unavailable", summary.errors)


if __name__ == "__main__":
    unittest.main()
