import io
import unittest
from pathlib import Path
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


class ConsoleCaptureTests(unittest.TestCase):
    """A photograph of a console, with a drawing behind it when there is none."""

    def _png_bytes(self, size, colour):
        buffer = io.BytesIO()
        Image.new("RGB", size, colour).save(buffer, format="PNG")
        return buffer.getvalue()

    def test_two_windows_become_one_picture(self):
        from netroach.console_capture import COMPOSED_PANE_GAP, compose_side_by_side

        left = self._png_bytes((700, 300), (10, 20, 30))
        right = self._png_bytes((280, 120), (200, 10, 10))

        composed = compose_side_by_side([left, right])

        image = Image.open(io.BytesIO(composed))
        self.assertEqual(image.size, (700 + COMPOSED_PANE_GAP + 280, 300))
        self.assertEqual(image.getpixel((10, 10)), (10, 20, 30))
        self.assertEqual(image.getpixel((700 + COMPOSED_PANE_GAP + 10, 10)), (200, 10, 10))

    def test_a_missing_telnet_pane_leaves_the_console_alone(self):
        from netroach.console_capture import compose_side_by_side

        left = self._png_bytes((700, 300), (10, 20, 30))

        composed = compose_side_by_side([left, b""])

        self.assertEqual(composed, left)

    def test_a_client_window_too_wide_for_the_cell_is_scaled_down(self):
        """The terminal will not open below a few hundred pixels, so the client
        arrives wider than there is room for beside the console."""
        from netroach.console_capture import _fit_pane_width

        wide = self._png_bytes((480, 300), (20, 20, 20))

        fitted = Image.open(io.BytesIO(_fit_pane_width(wide, 190)))

        self.assertEqual(fitted.width, 190)
        # Scaled, not cropped: it is the same window, smaller.
        self.assertAlmostEqual(fitted.width / fitted.height, 480 / 300, places=1)

    def test_a_pane_that_already_fits_is_left_alone(self):
        from netroach.console_capture import _fit_pane_width

        narrow = self._png_bytes((150, 90), (20, 20, 20))

        self.assertEqual(_fit_pane_width(narrow, 190), narrow)

    def test_nothing_captured_composes_to_nothing(self):
        from netroach.console_capture import compose_side_by_side

        self.assertIsNone(compose_side_by_side([b"", b""]))

    def test_the_session_shows_the_connection_still_open(self):
        from netroach.console_capture import build_connection_script

        script = build_connection_script("192.0.2.4", 111, done_path=Path("C:/tmp/done"))

        # netstat runs while the socket is still held: the ESTABLISHED line
        # naming this host and port is the whole evidence.
        self.assertIn("TcpClient", script)
        self.assertIn("netstat -an", script)
        self.assertLess(script.index("TcpClient"), script.index("netstat -an"))
        # Narrowed to this port. Every other socket on the host is height the
        # picture pays for and nobody reads. The trailing space keeps port 111
        # from matching 1110.
        self.assertIn("'192.0.2.4:111 '", script)
        self.assertIn("Stopped before username, password, key, AUTH, or login.", script)

    def test_a_host_cannot_break_out_of_the_quoted_string(self):
        from netroach.console_capture import build_connection_script

        script = build_connection_script("10.0.0.1'; calc; '", 80, done_path=Path("C:/tmp/done"))

        # PowerShell escapes a quote inside a single-quoted string by doubling
        # it, so the payload stays a value and never becomes a statement.
        self.assertIn("10.0.0.1''; calc; ''", script)
        self.assertNotIn("10.0.0.1'; calc; '", script)

    def test_the_console_option_covers_web_ports_too(self):
        """A browser screenshot is the better picture of a page, but it is not
        the netstat line, and the operator asked for the console."""
        from netroach import evidence as evidence_module

        agents = []

        def store(result, data, file_name, source_url, evidence_type, capture_agent=None):
            agents.append((result["port"], evidence_type, capture_agent))

        results = [
            {"host": "10.0.0.1", "port": 80, "protocol": "tcp", "state": "open",
             "service_name": "http", "banner": None},
        ]
        with patch.object(evidence_module, "capture_web_screenshots") as web:
            with patch.object(evidence_module, "capture_console_session", return_value=b"PNG"):
                evidence_module.capture_automatic_evidence(
                    results, store=store, capture_console=True, maximum=5
                )

        web.assert_not_called()
        self.assertEqual(agents, [(80, "terminal_transcript", "windows console capture")])

    def test_a_web_port_still_gets_its_screenshot_by_default(self):
        from netroach import evidence as evidence_module

        results = [
            {"host": "10.0.0.1", "port": 80, "protocol": "tcp", "state": "open",
             "service_name": "http", "banner": None},
        ]
        with patch.object(evidence_module, "capture_web_screenshots") as web:
            web.return_value = evidence_module.ScreenshotCaptureSummary(
                candidates=1, captured=0, failed=0
            )
            evidence_module.capture_automatic_evidence(
                results, store=lambda *a, **k: None, maximum=5
            )

        web.assert_called_once()

    def test_a_failed_capture_falls_back_to_the_drawing(self):
        from netroach import evidence as evidence_module

        stored = []

        def store(result, data, file_name, source_url, capture_agent=None):
            stored.append((file_name, capture_agent))

        results = [{"host": "10.0.0.1", "port": 22, "protocol": "tcp", "state": "open",
                    "service_name": "ssh", "banner": None}]
        with patch.object(evidence_module, "capture_console_session", return_value=None):
            summary = evidence_module.capture_terminal_transcripts(
                results, store=store, capture_console=True
            )

        self.assertEqual(summary.captured, 1)
        self.assertEqual(len(stored), 1)
        self.assertIn("transcript renderer", stored[0][1])

    def test_a_successful_capture_is_recorded_as_one(self):
        from netroach import evidence as evidence_module

        stored = []

        def store(result, data, file_name, source_url, capture_agent=None):
            stored.append((data, capture_agent))

        results = [{"host": "10.0.0.1", "port": 22, "protocol": "tcp", "state": "open",
                    "service_name": "ssh", "banner": None}]
        with patch.object(evidence_module, "capture_console_session", return_value=b"PNGDATA"):
            evidence_module.capture_terminal_transcripts(results, store=store, capture_console=True)

        self.assertEqual(stored[0][0], b"PNGDATA")
        self.assertEqual(stored[0][1], "windows console capture")

    def test_the_drawing_is_used_when_the_option_is_off(self):
        from netroach import evidence as evidence_module

        stored = []

        def store(result, data, file_name, source_url, capture_agent=None):
            stored.append(capture_agent)

        results = [{"host": "10.0.0.1", "port": 22, "protocol": "tcp", "state": "open",
                    "service_name": "ssh", "banner": None}]
        with patch.object(evidence_module, "capture_console_session") as capture:
            evidence_module.capture_terminal_transcripts(results, store=store)

        capture.assert_not_called()
        self.assertIn("transcript renderer", stored[0])


if __name__ == "__main__":
    unittest.main()
