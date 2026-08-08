import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from PIL import Image

from netroach.evidence import (
    SCREENSHOT_HEIGHT,
    SCREENSHOT_WIDTH,
    ScreenshotCaptureSummary,
    TerminalTranscript,
    automatic_evidence_candidates,
    capture_automatic_evidence,
    detect_image_media_type,
    host_route_filter,
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
        with patch("netroach.evidence.shutil.which", return_value="powershell.exe"):
            with patch("netroach.evidence.subprocess.run", return_value=completed) as run:
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
        self.assertEqual(run.call_args.kwargs["env"]["NETROACH_TARGET"], dangerous_host)
        self.assertEqual(run.call_args.kwargs["env"]["NETROACH_PREAUTH_MODE"], "ssh")
        self.assertNotIn("NETROACH_USERNAME", run.call_args.kwargs["env"])
        self.assertNotIn("NETROACH_PASSWORD", run.call_args.kwargs["env"])
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertIn("TcpTestSucceeded", transcript.output)

    def test_automatic_evidence_falls_back_to_terminal_transcripts(self):
        results = [
            {"host": "127.0.0.1", "port": 80, "protocol": "tcp", "state": "open", "service_name": "http"},
            {"host": "127.0.0.1", "port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh"},
        ]
        stored: list[tuple[int, str, tuple[int, int], str | None]] = []

        def store(result, data, file_name, source_url, evidence_type, capture_agent=None):
            self.assertTrue(file_name.endswith(".png"))
            with Image.open(io.BytesIO(data)) as image:
                stored.append((result["port"], evidence_type, image.size, capture_agent))

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
        with patch("netroach.evidence.capture_web_screenshots", return_value=failed_web):
            with patch("netroach.evidence.run_powershell_diagnostic", return_value=transcript):
                summary = capture_automatic_evidence(results, store=store)

        # The renderer identifies itself so a transcript can say what drew it,
        # the same way a screenshot names the browser that rendered it.
        agent = "netroach transcript renderer 800x600"
        self.assertEqual(
            stored,
            [
                (80, "terminal_transcript", (800, 600), agent),
                (22, "terminal_transcript", (800, 600), agent),
            ],
        )
        self.assertEqual(summary.candidates, 2)
        self.assertEqual(summary.captured, 2)
        self.assertEqual(summary.failed, 0)
        self.assertEqual(summary.web_screenshots, 0)
        self.assertEqual(summary.protocol_snapshots, 0)
        self.assertEqual(summary.terminal_transcripts, 2)
        self.assertIn("browser unavailable", summary.errors)


class FakePage:
    def __init__(self, screenshot_failures: int, goto_failures: int = 0):
        self.screenshot_failures = screenshot_failures
        self.goto_failures = goto_failures
        self.goto_calls = 0
        self.screenshot_calls = 0

    def goto(self, *_args, **_kwargs):
        self.goto_calls += 1
        if self.goto_calls <= self.goto_failures:
            raise RuntimeError("net::ERR_CONNECTION_REFUSED")

    def add_style_tag(self, **_kwargs):
        pass

    def screenshot(self, **_kwargs):
        self.screenshot_calls += 1
        if self.screenshot_calls <= self.screenshot_failures:
            raise RuntimeError("Protocol error (Page.captureScreenshot): Unable to capture screenshot")
        return b"\x89PNG\r\n\x1a\nimage"


class FakeContext:
    def __init__(self, page):
        self._page = page

    def route(self, *_args, **_kwargs):
        pass

    def new_page(self):
        return self._page

    def close(self):
        pass


class FakeBrowser:
    version = "151.0.0.0"

    def __init__(self, page):
        self._page = page

    def new_context(self, **_kwargs):
        return FakeContext(self._page)

    def close(self):
        pass


class FakePlaywright:
    def __init__(self, page):
        self.chromium = SimpleNamespace(launch=lambda **_kwargs: FakeBrowser(page))

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class ScreenshotRetryTests(unittest.TestCase):
    """One retry of the capture step, and only of the capture step.

    `Protocol error (Page.captureScreenshot): Unable to capture screenshot`
    was observed on a loaded page whose fonts had already resolved - the
    renderer failed to composite, not the navigation. Falling straight back to
    a terminal transcript silently downgrades the evidence, so the capture is
    worth one more attempt. Navigation failures are not retried: an unreachable
    host is deterministic and a second attempt only burns another full timeout.
    """

    def _capture(self, page):
        from netroach.evidence import capture_web_screenshots

        stored = []
        with patch("playwright.sync_api.sync_playwright", return_value=FakePlaywright(page)):
            summary = capture_web_screenshots(
                [{"host": "127.0.0.1", "port": 80, "protocol": "tcp", "state": "open", "service_name": "http"}],
                store=lambda *args: stored.append(args),
            )
        return summary, stored

    def test_a_transient_capture_failure_is_retried(self):
        page = FakePage(screenshot_failures=1)

        summary, stored = self._capture(page)

        self.assertEqual(summary.captured, 1)
        self.assertEqual(summary.failed, 0)
        self.assertEqual(page.screenshot_calls, 2)
        self.assertEqual(len(stored), 1)

    def test_a_capture_that_keeps_failing_is_reported(self):
        page = FakePage(screenshot_failures=5)

        summary, _ = self._capture(page)

        self.assertEqual(summary.captured, 0)
        self.assertEqual(summary.failed, 1)
        self.assertEqual(page.screenshot_calls, 2)
        self.assertIn("captureScreenshot", summary.errors[0])

    def test_navigation_failures_are_not_retried(self):
        page = FakePage(screenshot_failures=0, goto_failures=5)

        summary, _ = self._capture(page)

        self.assertEqual(summary.failed, 1)
        self.assertEqual(page.goto_calls, 1)
        self.assertEqual(page.screenshot_calls, 0)


class HostRouteFilterTests(unittest.TestCase):
    """The filter that confines a capture to the scanned host.

    It once used an `allowed_host=host` default parameter. Playwright passes the
    Request as a second argument to any handler that accepts one, so the default
    was replaced by a Request, every comparison failed, and the navigation
    itself was aborted - automatic screenshots failed for every target while the
    per-target `except` reported it only as a capture error.
    """

    def _route(self, url: str):
        calls: list[str] = []
        route = SimpleNamespace(
            request=SimpleNamespace(url=url),
            continue_=lambda: calls.append("continue"),
            abort=lambda: calls.append("abort"),
        )
        return route, calls

    def test_handler_takes_exactly_one_argument(self):
        import inspect

        parameters = inspect.signature(host_route_filter("127.0.0.1")).parameters
        self.assertEqual(len(parameters), 1)

    def test_the_scanned_host_is_allowed(self):
        handler = host_route_filter("127.0.0.1")
        route, calls = self._route("http://127.0.0.1:8080/app.css")

        handler(route)

        self.assertEqual(calls, ["continue"])

    def test_another_host_is_blocked(self):
        handler = host_route_filter("127.0.0.1")
        route, calls = self._route("http://example.com/tracker.js")

        handler(route)

        self.assertEqual(calls, ["abort"])

    def test_inline_schemes_are_allowed(self):
        handler = host_route_filter("127.0.0.1")
        for url in ("data:text/css,body{}", "blob:http://127.0.0.1/x", "about:blank"):
            route, calls = self._route(url)

            handler(route)

            self.assertEqual(calls, ["continue"], url)


if __name__ == "__main__":
    unittest.main()
