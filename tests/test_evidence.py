import io
import time
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
                # These ports are fictional; the reachability check that guards
                # against photographing a connection that never opened would
                # otherwise skip them.
                with patch("netroach.evidence.port_still_answers", return_value=True):
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
        self.url = "http://127.0.0.1/"
        self.goto_calls = 0
        self.screenshot_calls = 0
        self.timeouts: list[float] = []
        self.evaluated: list[str] = []

    def set_default_timeout(self, timeout_ms):
        self.timeouts.append(float(timeout_ms))

    def goto(self, *_args, **_kwargs):
        self.goto_calls += 1
        if self.goto_calls <= self.goto_failures:
            raise RuntimeError("net::ERR_CONNECTION_REFUSED")

    def add_style_tag(self, **_kwargs):
        raise AssertionError("add_style_tag never returns on a page with no head")

    def evaluate(self, script, *_args):
        self.evaluated.append(script)
        return True

    def screenshot(self, **_kwargs):
        self.screenshot_calls += 1
        if self.screenshot_calls <= self.screenshot_failures:
            raise RuntimeError("Protocol error (Page.captureScreenshot): Unable to capture screenshot")
        return b"\x89PNG\r\n\x1a\nimage"


class FakeContext:
    def __init__(self, page):
        self._page = page
        self.default_timeout_ms = None

    def route(self, *_args, **_kwargs):
        pass

    def set_default_timeout(self, timeout_ms):
        self.default_timeout_ms = timeout_ms

    def new_page(self):
        return self._page

    def close(self):
        pass


class FakeBrowser:
    version = "151.0.0.0"

    def __init__(self, page):
        self._page = page
        self.last_context = None
        self.context_kwargs = {}

    def new_context(self, **kwargs):
        self.context_kwargs = kwargs
        self.last_context = FakeContext(self._page)
        return self.last_context

    def close(self):
        pass


class FakePlaywright:
    def __init__(self, page):
        self.browser = FakeBrowser(page)
        self.chromium = SimpleNamespace(launch=lambda **_kwargs: self.browser)

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

    def test_the_capture_never_takes_a_file_off_the_target(self):
        """The pass wants a picture. A navigation that turns into a download
        already fails, but a page can start one after it has loaded, and
        Playwright saves those by default - and taking a file off a system
        under assessment is not a library default's decision to make."""
        from netroach.evidence import capture_web_screenshots

        playwright = FakePlaywright(FakePage(screenshot_failures=0))
        with patch("playwright.sync_api.sync_playwright", return_value=playwright):
            capture_web_screenshots(
                [{"host": "127.0.0.1", "port": 80, "protocol": "tcp", "state": "open",
                  "service_name": "http"}],
                store=lambda *args: None,
            )

        self.assertIs(playwright.browser.context_kwargs["accept_downloads"], False)

    def test_an_exhausted_budget_never_becomes_an_unlimited_wait(self):
        """Playwright reads a timeout of zero as "no timeout". A port whose
        budget ran out would then wait for ever - the failure the budget was
        added to prevent, arrived at from the other side."""
        from netroach.evidence import capture_web_screenshots

        class Exhausting(FakePage):
            def goto(self, _url, **kwargs):
                self.timeouts.append(float(kwargs.get("timeout", 0)))
                # Spend more than the whole port budget navigating.
                time.sleep(2.2)

        page = Exhausting(screenshot_failures=0)
        with patch("playwright.sync_api.sync_playwright", return_value=FakePlaywright(page)):
            capture_web_screenshots(
                [{"host": "127.0.0.1", "port": 80, "protocol": "tcp", "state": "open",
                  "service_name": "http"}],
                store=lambda *args: None,
                timeout_ms=1000,
            )

        self.assertNotIn(0, page.timeouts)
        self.assertNotIn(0.0, page.timeouts)
        self.assertTrue(all(value > 0 for value in page.timeouts), page.timeouts)

    def test_the_browser_viewport_is_the_width_of_the_report_cell(self):
        """Both kinds of evidence land in the same cell of the assessment
        workbook and are scaled to fit it. A console capture is that cell's
        width and arrives at full size; an 800 by 600 page came in at 0.43 and
        filled a third of the width, so one report showed the page's text at
        less than half the size of the console's. The viewport is that width
        now. It is still taller than the cell, so it is scaled down to fit -
        the height is what a page needs to be worth reading, and the cell is
        the shape the report asks for."""
        from netroach.evidence import WEB_SCREENSHOT_HEIGHT, WEB_SCREENSHOT_WIDTH
        from netroach.exporters import _REPORT_EVIDENCE_BOX

        self.assertEqual(WEB_SCREENSHOT_WIDTH, _REPORT_EVIDENCE_BOX[0])
        self.assertGreater(WEB_SCREENSHOT_HEIGHT, _REPORT_EVIDENCE_BOX[1])

        # What that comes to in the cell: better than half its width, where
        # the old size managed under a third.
        scale = min(_REPORT_EVIDENCE_BOX[0] / WEB_SCREENSHOT_WIDTH,
                    _REPORT_EVIDENCE_BOX[1] / WEB_SCREENSHOT_HEIGHT)
        self.assertGreater(WEB_SCREENSHOT_WIDTH * scale, _REPORT_EVIDENCE_BOX[0] / 2)

        # The transcript renderer draws its own canvas and is not this.
        self.assertNotEqual(
            (WEB_SCREENSHOT_WIDTH, WEB_SCREENSHOT_HEIGHT),
            (SCREENSHOT_WIDTH, SCREENSHOT_HEIGHT),
        )

    def test_a_page_with_no_head_cannot_stop_the_run(self):
        """add_style_tag appends the element to document.head and waits for it
        to load. An XML document - a feed, a SOAP endpoint, a config file
        served as application/xml - has no head, so that wait never ends, and
        it does not end on the timeout either: the call is outside every
        deadline Playwright honours. One such port stopped a whole run, and the
        cancel with it, because the stop is only read between ports."""
        from netroach.evidence import capture_web_screenshots

        page = FakePage(screenshot_failures=0)
        with patch("playwright.sync_api.sync_playwright", return_value=FakePlaywright(page)):
            summary = capture_web_screenshots(
                [{"host": "127.0.0.1", "port": 80, "protocol": "tcp", "state": "open",
                  "service_name": "http"}],
                store=lambda *args: None,
                timeout_ms=2000,
            )

        # The style goes in through evaluate, which the page timeout bounds,
        # and add_style_tag - which it does not - is never called.
        self.assertEqual(summary.captured, 1)
        self.assertEqual(len(page.evaluated), 1)
        self.assertIn("document.head", page.evaluated[0])
        self.assertIn("animation:none", page.evaluated[0])

    def test_one_port_cannot_spend_the_timeout_four_times_over(self):
        """Given to every call separately, a page that used the whole timeout
        navigating got as much again for the style tag, again for the
        screenshot and again for its retry. None of it is interruptible - the
        stop is only read between ports - so the run looked hung and the cancel
        looked dead for four times the timeout the operator set."""
        from netroach.evidence import WEB_PORT_BUDGET_FACTOR, capture_web_screenshots

        clock = SimpleNamespace(now=100.0)

        class SlowPage(FakePage):
            def goto(self, _url, **kwargs):
                self.timeouts.append(float(kwargs.get("timeout", 0)))
                # Include known call overhead without relying on timer resolution.
                clock.now += 1.25

        page = SlowPage(screenshot_failures=0)
        with (
            patch("playwright.sync_api.sync_playwright", return_value=FakePlaywright(page)),
            patch("netroach.evidence.time.monotonic", side_effect=lambda: clock.now),
        ):
            capture_web_screenshots(
                [{"host": "127.0.0.1", "port": 80, "protocol": "tcp", "state": "open",
                  "service_name": "http"}],
                store=lambda *args: None,
                timeout_ms=1000,
            )

        # The navigation is allowed its own timeout, and everything after it is
        # given only what is left of the port's budget - never the full amount
        # again.
        self.assertEqual(page.timeouts[0], 1000)
        self.assertTrue(all(value <= 1000 for value in page.timeouts), page.timeouts)
        self.assertEqual(page.timeouts[-1], 750, page.timeouts)
        self.assertEqual(WEB_PORT_BUDGET_FACTOR, 2)

    def test_every_page_operation_is_bound_by_the_evidence_timeout(self):
        """Only the navigation carried one. The style tag and the screenshot
        fell back to Playwright's own 30 seconds, and the screenshot is retried
        once - so a port that answered TCP and then wedged the renderer held
        the run for a minute and a half by itself, with nothing stored and the
        progress count therefore standing still."""
        from netroach.evidence import capture_web_screenshots

        playwright = FakePlaywright(FakePage(screenshot_failures=0))
        with patch("playwright.sync_api.sync_playwright", return_value=playwright):
            capture_web_screenshots(
                [{"host": "127.0.0.1", "port": 80, "protocol": "tcp", "state": "open",
                  "service_name": "http"}],
                store=lambda *args: None,
                timeout_ms=4_000,
            )

        self.assertEqual(playwright.browser.last_context.default_timeout_ms, 4_000)

    def test_a_transient_capture_failure_is_retried(self):
        page = FakePage(screenshot_failures=1)

        summary, stored = self._capture(page)

        self.assertEqual(summary.captured, 1)
        self.assertEqual(summary.failed, 0)
        self.assertEqual(page.screenshot_calls, 2)
        self.assertEqual(len(stored), 1)

    def test_a_redirected_page_records_the_url_that_was_photographed(self):
        page = FakePage(screenshot_failures=0)
        page.url = "http://127.0.0.1:8443/admin"

        summary, stored = self._capture(page)

        self.assertEqual(summary.captured, 1)
        self.assertEqual(stored[0][3], "http://127.0.0.1:8443/admin")

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


def _slow_for_8080(host, port, **_kwargs):
    """A capture that behaves, except on one port that takes far too long."""
    if int(port) == 8080:
        time.sleep(0.5)
    return b"png-bytes"


class EvidenceHonestyTests(unittest.TestCase):
    """Evidence may show what a target said and what we sent. Nothing else.

    The transcript prints the server's own replies under a label, and a reader
    takes every unlabelled line beside them for more of the same. Three lines
    were not: "login as:" is PuTTY's wording and SSH never sends a prompt in
    the clear at all, "USER:" is the command a client would send rather than
    anything POP3 replied, and "User (<host>):" imitated what the Windows ftp
    client prints - with the real host name in it, which is what made it look
    like a reply. A capture that writes the target's side of the conversation
    is not evidence of anything.
    """

    def _script(self) -> str:
        from netroach.evidence import _POWERSHELL_DIAGNOSTIC_SCRIPT

        return _POWERSHELL_DIAGNOSTIC_SCRIPT

    def test_no_prompt_is_written_on_the_targets_behalf(self):
        script = self._script()

        for invention in ("'login as:'", "'USER:'", '"User (" + $ComputerName'):
            self.assertNotIn(invention, script, invention)

    def test_nothing_is_claimed_about_a_browser_that_was_never_opened(self):
        """The 401 transcript records the header the server sent. What a
        browser would do with it was not observed, so it is not stated."""
        script = self._script()

        self.assertNotIn("browser shows a login box", script)
        self.assertIn("Authentication scheme offered by the server", script)

    def test_what_the_server_said_is_labelled_as_such(self):
        script = self._script()

        for label in (
            "Server pre-authentication response:",
            "HTTP response head:",
            "POP3 CAPA response:",
            "FTP FEAT response:",
        ):
            self.assertIn(label, script, label)


class BrowserWindowCaptureTests(unittest.TestCase):
    """The window carries what the page cannot: the address arrived at, and the
    browser's judgement beside it."""

    def test_a_window_is_only_claimed_when_exactly_one_appeared(self):
        """Its title cannot identify it. The title is the page's, and an
        assessment meets the same device on host after host - two switches of
        one model produce two windows named identically, measured. What can be
        said is which window was not there a moment ago, and that only holds
        while one thing at a time opens one."""
        from netroach.console_capture import window_opened_since

        user32 = SimpleNamespace()
        with patch("netroach.console_capture.visible_window_handles") as visible:
            visible.return_value = {1, 2, 9}
            self.assertEqual(window_opened_since(user32, {1, 2}), 9)

            # Nothing new: there is nothing of ours to photograph.
            visible.return_value = {1, 2}
            self.assertIsNone(window_opened_since(user32, {1, 2}))

            # Two at once, so ours cannot be told from whatever else opened.
            # A picture of the operator's own window is worse than none.
            visible.return_value = {1, 2, 9, 10}
            self.assertIsNone(window_opened_since(user32, {1, 2}))

    def test_the_page_is_the_fallback_not_the_goal(self):
        from netroach.evidence import _capture_browser_window

        # No desktop to draw on, so nothing was noted before the page opened.
        self.assertIsNone(_capture_browser_window(object(), None))

    def test_only_the_full_browser_is_asked_for(self):
        """Playwright picks the headless shell for a headless launch and fails
        outright when it is absent, and the shell is deliberately not bundled -
        it is the one build that cannot be shown with its own window."""
        from netroach.evidence import BROWSER_CHANNEL

        self.assertEqual(BROWSER_CHANNEL, "chromium")


class SshCaptureTests(unittest.TestCase):
    """The SSH pane must reach a login prompt and never get past one."""

    known_hosts = Path("C:/tmp/known_hosts")

    def _script(self, host="10.0.0.5", port=22):
        from netroach.console_capture import build_ssh_capture_script

        return build_ssh_capture_script(
            host, port, title="Netroach SSH token", known_hosts=self.known_hosts
        )

    def test_the_capture_cannot_authenticate_with_the_operators_credentials(self):
        """The whole design is "stop at the prompt".

        An agent with a loaded key, or a key in the default location, would
        otherwise carry the session straight past the prompt - and a capture
        that logged in is not evidence that a port is open, it is an
        unauthorised login performed by the scanner.
        """
        script = self._script()

        for option in (
            "PubkeyAuthentication=no",
            "GSSAPIAuthentication=no",
            "IdentityAgent=none",
            "PreferredAuthentications=keyboard-interactive,password",
        ):
            self.assertIn(option, script, option)

    def test_the_capture_does_not_touch_the_operators_known_hosts(self):
        """`accept-new` against the real file would record every target the
        scan ever pointed at into the operator's own trust store."""
        script = self._script()

        self.assertIn("StrictHostKeyChecking=accept-new", script)
        self.assertIn(f"UserKnownHostsFile={self.known_hosts}", script)
        self.assertIn("GlobalKnownHostsFile=NUL", script)

    def test_the_session_holds_the_window_open_without_timeout(self):
        """`timeout` ends at once when the standard input it inherits is not a
        console, which measured the window closing 2.7s in - before the prompt
        it exists to photograph arrived."""
        script = self._script()

        self.assertIn("Start-Sleep -Seconds", script)
        self.assertNotIn("timeout /t", script)

    def test_the_login_name_is_ours_rather_than_the_operators(self):
        from netroach.console_capture import SSH_CAPTURE_USER

        self.assertIn(f"{SSH_CAPTURE_USER}@10.0.0.5", self._script())

    def test_the_client_beside_the_console_follows_the_service(self):
        from netroach.console_capture import client_pane_kind

        # Named service wins, so SSH moved off 22 still gets an SSH pane.
        self.assertEqual(client_pane_kind(2222, "ssh"), "ssh")
        self.assertEqual(client_pane_kind(22, None), "ssh")
        self.assertEqual(client_pane_kind(23, "telnet"), "telnet")

    def test_a_service_that_speaks_in_lines_keeps_its_telnet_client(self):
        """The telnet client is how these are checked by hand, and the picture
        it makes is the exchange itself - the greeting, the capabilities, the
        login prompt. Every service had one before any of them were told
        apart, so losing it for the ones that were is a step backwards."""
        from netroach.console_capture import client_pane_kind

        for port, service in ((110, "pop3"), (143, "imap"), (25, "smtp"),
                              (21, "ftp"), (4039, "pop3"), (6379, "redis")):
            with self.subTest(service=service, port=port):
                self.assertEqual(client_pane_kind(port, service), "telnet")

    def test_no_client_is_opened_where_opening_one_prints_a_page(self):
        """A raw print port takes what arrives as the job to print, and telnet
        opens by sending option negotiation. The fallback pointed telnet at
        anything unidentified, so a scan run without service detection - which
        names nothing - would have put a page out of every printer in range."""
        from netroach.console_capture import client_pane_kind

        for port in (515, 9100, 9101, 9107):
            with self.subTest(port=port):
                self.assertIsNone(client_pane_kind(port, None))
                self.assertIsNone(client_pane_kind(port, "telnet"))
        # The port beside them is not a printer and keeps the fallback.
        self.assertEqual(client_pane_kind(9108, None), "telnet")

    def test_nothing_is_pointed_at_a_protocol_it_cannot_read(self):
        """Telnet on a TLS or binary port photographs mojibake, which looks
        like evidence and says nothing. Those keep the console pane, which for
        a TLS service already carries the handshake, its protocol version and
        its cipher; a web port has its browser shot."""
        from netroach.console_capture import client_pane_kind

        for port, service in ((443, "https"), (993, "imaps"), (465, "smtps"),
                              (445, "smb"), (135, "msrpc"), (3389, "rdp"),
                              (3306, "mysql"), (80, "http")):
            with self.subTest(service=service, port=port):
                self.assertIsNone(client_pane_kind(port, service))

    def test_an_unidentified_port_is_still_tried_with_telnet(self):
        from netroach.console_capture import client_pane_kind

        self.assertEqual(client_pane_kind(4039, None), "telnet")
        self.assertEqual(client_pane_kind(23, None), "telnet")


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

    def test_the_window_title_names_this_capture_not_just_the_port(self):
        """Two scans of the same range hold the same host and port; a shared
        title would let one run photograph the other's window."""
        from netroach.console_capture import build_connection_script

        script = build_connection_script(
            "10.0.0.1", 80, done_path=Path("C:/tmp/done"), title="Netroach 10.0.0.1:80 abc12345"
        )

        self.assertIn("WindowTitle = 'Netroach 10.0.0.1:80 abc12345'", script)

    def test_the_reachability_check_does_not_cost_the_whole_screenshot_timeout(self):
        """It runs before every capture. A port that is going to answer answers
        in milliseconds; giving it the screenshot timeout meant eight seconds
        of waiting for each port that would not, which on a few hundred ports
        is most of the run."""
        import socket

        from netroach.evidence import REACHABILITY_TIMEOUT_MS, port_still_answers

        seen: list[float] = []

        def record(address, timeout=None):
            seen.append(float(timeout))
            raise OSError("refused")

        with patch.object(socket, "create_connection", record):
            self.assertFalse(
                port_still_answers(
                    {"host": "10.0.0.1", "port": 80, "protocol": "tcp"}, timeout_ms=120_000
                )
            )

        self.assertEqual(seen, [REACHABILITY_TIMEOUT_MS / 1000])
        self.assertLessEqual(REACHABILITY_TIMEOUT_MS, 2_000)

    def test_the_run_says_which_port_it_is_on_even_when_it_stores_nothing(self):
        """Stored pictures alone cannot tell a run working through ports that
        yield nothing from one that has stopped - and it was being read as
        stopped. Every port examined is reported, whatever comes of it."""
        from netroach import evidence as evidence_module

        seen: list[str] = []
        with patch.object(evidence_module, "port_still_answers", lambda *_a, **_k: False):
            summary = evidence_module.capture_terminal_transcripts(
                [
                    {"host": "10.0.0.1", "port": 80, "protocol": "tcp", "state": "open"},
                    {"host": "10.0.0.1", "port": 443, "protocol": "tcp", "state": "open"},
                ],
                store=lambda *_a: None,
                on_examined=lambda result: seen.append(f"{result['host']}:{result['port']}"),
            )

        self.assertEqual(seen, ["10.0.0.1:80", "10.0.0.1:443"])
        self.assertEqual(summary.captured, 0)
        self.assertEqual(len(summary.errors), 2)

    def test_a_udp_port_does_not_open_a_console_that_cannot_connect(self):
        """The console proves a held TCP socket. UDP has none, so every UDP
        result spent a window and a full timeout failing to open one."""
        from netroach import evidence as evidence_module

        opened: list[tuple[str, int]] = []

        def never(host, port, **_kwargs):
            opened.append((host, port))
            return

        stored: list[str] = []
        with patch.object(evidence_module, "capture_console_session", never),                 patch.object(
                    evidence_module, "port_still_answers", lambda *_a, **_k: True
                ), patch.object(
                    evidence_module, "render_terminal_transcript", lambda *_a, **_k: b"png"
                ), patch.object(
                    evidence_module, "run_powershell_diagnostic", lambda *_a, **_k: None
                ):
            summary = evidence_module.capture_terminal_transcripts(
                [
                    {"host": "10.0.0.1", "port": 161, "protocol": "udp", "state": "open|filtered"},
                    {"host": "10.0.0.1", "port": 22, "protocol": "tcp", "state": "open"},
                ],
                store=lambda result, *_rest: stored.append(str(result["protocol"])),
                capture_console=True,
            )

        self.assertEqual(opened, [("10.0.0.1", 22)])
        self.assertEqual(summary.captured, 2)
        self.assertEqual(sorted(stored), ["tcp", "udp"])

    def test_the_log_names_the_port_that_held_the_run(self):
        """The window has no console and backend.log held nothing but the
        startup banner, so a run that appeared to stop could only be guessed
        at. A run of a thousand ports has no room for a line each - the ones
        worth reading are the few that took minutes."""
        import logging

        from netroach import evidence as evidence_module

        records: list[str] = []

        class Collect(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        handler = Collect()
        evidence_module.logger.addHandler(handler)
        try:
            with patch.object(
                evidence_module, "port_still_answers",
                lambda result, **_k: int(result["port"]) != 443,
            ), patch.object(
                evidence_module, "capture_console_session", _slow_for_8080
            ), patch.object(
                evidence_module, "render_terminal_transcript", lambda *_a, **_k: b"png"
            ), patch.object(
                evidence_module, "run_powershell_diagnostic", lambda *_a, **_k: None
            ):
                evidence_module.capture_terminal_transcripts(
                    [
                        {"host": "10.0.0.1", "port": port, "protocol": "tcp", "state": "open"}
                        for port in (80, 443, 8080)
                    ],
                    store=lambda *_a: None,
                    capture_console=True,
                    timeout_ms=100,
                )
        finally:
            evidence_module.logger.removeHandler(handler)

        self.assertTrue(any("10.0.0.1:443 did not answer" in line for line in records), records)
        self.assertTrue(any("10.0.0.1:8080 took" in line for line in records), records)
        # The port that behaved is not worth a line.
        self.assertFalse(any("10.0.0.1:80 " in line for line in records), records)

    def test_a_window_that_rendered_nothing_is_not_stored_as_a_capture(self):
        """PrintWindow reports success and hands back a blank bitmap where the
        API gives no other signal: a console host that will not render into a
        memory device context - the legacy console mode still common on
        Windows 10 - and a desktop that is locked or disconnected. Storing that
        puts a white rectangle in the report labelled a real console capture,
        which is worse than no capture: the caller falls back to the drawn
        transcript, which carries the scan record."""
        from PIL import Image, ImageDraw

        from netroach.console_capture import has_content

        def solid(colour):
            buffer = io.BytesIO()
            Image.new("RGB", (770, 300), colour).save(buffer, format="PNG")
            return buffer.getvalue()

        self.assertFalse(has_content(solid((255, 255, 255))))
        self.assertFalse(has_content(solid((12, 12, 12))))

        # A session that proved a connection prints its commands and a netstat
        # row, which is thousands of lit pixels.
        image = Image.new("RGB", (770, 300), (12, 12, 12))
        draw = ImageDraw.Draw(image)
        for row in range(6):
            draw.text((10, 10 + row * 18), "netstat -an | Select-String 127.0.0.1:135",
                      fill=(220, 220, 220))
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")

        self.assertTrue(has_content(buffer.getvalue()))

    # FakeUser32 calls a Python callback; it does not use the Windows stdcall ABI.
    @patch("ctypes.WINFUNCTYPE", lambda *_types: lambda callback: callback, create=True)
    def test_a_telnet_window_that_was_already_open_is_not_photographed(self):
        """The operator's own session is not evidence of anything this scan
        did, and a prefix match makes 10.0.0.4 answer for 10.0.0.40."""
        from netroach.console_capture import _find_window_by_title

        windows = {41: "Telnet 10.0.0.40", 7: "Telnet 10.0.0.4", 9: "Telnet 10.0.0.4"}

        class FakeUser32:
            def GetWindowTextW(self, hwnd, buffer, _size):  # noqa: N802 - the Win32 name.
                buffer.value = windows[hwnd]
                return len(buffer.value)

            def EnumWindows(self, callback, _lparam):  # noqa: N802 - the Win32 name.
                for hwnd in windows:
                    callback(hwnd, 0)
                return True

        user32 = FakeUser32()

        # The 10.0.0.40 window matches "Telnet 10.0.0.4" as a substring and is
        # first in the enumeration; the exact title is the one that counts.
        self.assertEqual(_find_window_by_title(user32, "Telnet 10.0.0.4", exact="Telnet 10.0.0.4"), 7)
        # And the one that was standing before the client was launched is ours
        # to skip, whatever it is titled.
        self.assertEqual(
            _find_window_by_title(user32, "Telnet 10.0.0.4", exclude={7}, exact="Telnet 10.0.0.4"),
            9,
        )
        # Asking for an exact title must never fall back to a look-alike.
        self.assertIsNone(
            _find_window_by_title(
                user32,
                "Telnet 10.0.0.4",
                exclude={7, 9},
                exact="Telnet 10.0.0.4",
            )
        )
        self.assertIsNone(
            _find_window_by_title(user32, "Telnet 10.0.0.4", exclude={7, 9, 41}, exact="Telnet 10.0.0.4")
        )

    def test_a_host_cannot_break_out_of_the_quoted_string(self):
        from netroach.console_capture import build_connection_script

        script = build_connection_script("10.0.0.1'; calc; '", 80, done_path=Path("C:/tmp/done"))

        # PowerShell escapes a quote inside a single-quoted string by doubling
        # it, so the payload stays a value and never becomes a statement.
        self.assertIn("10.0.0.1''; calc; ''", script)
        self.assertNotIn("10.0.0.1'; calc; '", script)

    def test_a_web_port_keeps_its_page_screenshot_and_nothing_else(self):
        """The page shows the service answering, which is what a console
        capture would be there to prove, and what it is besides."""
        from netroach import evidence as evidence_module

        stored = []

        def store(result, data, file_name, source_url, evidence_type, capture_agent=None):
            stored.append(evidence_type)

        def fake_web(candidates, *, store, timeout_ms, maximum, should_stop=None, on_examined=None):
            for result in list(candidates):
                store(result, b"PNG", "page.png", "http://10.0.0.1/", "chromium test")
            return evidence_module.ScreenshotCaptureSummary(
                candidates=1, captured=1, failed=0, web_screenshots=1
            )

        results = [
            {"host": "10.0.0.1", "port": 80, "protocol": "tcp", "state": "open",
             "service_name": "http", "banner": None},
        ]
        with patch.object(evidence_module, "capture_web_screenshots", side_effect=fake_web):
            with patch.object(evidence_module, "capture_console_session", return_value=b"PNG"):
                evidence_module.capture_automatic_evidence(
                    results, store=store, capture_console=True, maximum=5
                )

        self.assertEqual(stored, ["web_screenshot"])

    def test_every_web_banner_the_engine_writes_is_recognised(self):
        """These are the four shapes it produces for a web reply."""
        from netroach.evidence import is_web_result

        for banner in (
            "HTTP/1.1 404 Not Found; content-type=text/html",
            "TLS record type=alert version=3.3 length=7",
            "TLS ServerHello version=TLS1.2 cipher=0xc02f length=90",
            "server=nginx; content-type=text/html; charset=utf-8",
            "HTTP/1.1 302; location=http://10.0.0.1/login",
        ):
            self.assertTrue(
                is_web_result({"port": 12345, "service_name": "unknown", "banner": banner}),
                banner,
            )

    def test_banners_that_only_look_like_the_web_are_left_alone(self):
        from netroach.evidence import is_web_result

        for banner in (
            # RPC over HTTP wants a console, and the case is what separates it.
            "ncacn_http/1.0",
            "IceP",
            "RFB 003.035",
            "220 VMware Authentication Daemon Version 1.10",
            "inferred from port mapping",
        ):
            self.assertFalse(
                is_web_result({"port": 12345, "service_name": "unknown", "banner": banner}),
                banner,
            )

    def test_a_tls_service_a_browser_cannot_read_stays_off_the_browser(self):
        """A TLS reply proves TLS, not HTTP - LDAPS and the mail services speak
        it and a page cannot be rendered from any of them."""
        from netroach.evidence import is_web_result

        self.assertFalse(
            is_web_result({"port": 636, "service_name": "ldaps",
                           "banner": "TLS ServerHello version=TLS1.2"})
        )
        self.assertFalse(
            is_web_result({"port": 993, "service_name": "imaps",
                           "banner": "TLS record type=handshake"})
        )
        # An unnamed service answering TLS is still worth a browser.
        self.assertTrue(
            is_web_result({"port": 9999, "service_name": "unknown",
                           "banner": "TLS ServerHello version=TLS1.2"})
        )

    def test_a_web_server_on_an_odd_port_is_found_by_its_banner(self):
        """Service detection misses plenty of them; the reply does not."""
        from netroach.evidence import is_web_result

        self.assertTrue(
            is_web_result({"port": 9134, "service_name": "unknown", "banner": "HTTP/1.1 200 OK"})
        )
        self.assertFalse(
            is_web_result({"port": 9134, "service_name": "unknown", "banner": "f"})
        )
        self.assertFalse(
            is_web_result({"port": 22, "service_name": "ssh", "banner": "SSH-2.0-OpenSSH_8.9"})
        )

    def test_a_port_that_no_longer_answers_keeps_its_old_evidence(self):
        """Re-run from a machine that cannot reach the targets, the capture
        would read "Connected: False" beside a SYN_SENT line - evidence in
        appearance only, and it would replace the one that proved something."""
        from netroach import evidence as evidence_module

        stored = []

        def store(result, data, file_name, source_url, capture_agent=None):
            stored.append(result["port"])

        results = [{"host": "10.0.0.1", "port": 22, "protocol": "tcp", "state": "open",
                    "service_name": "ssh", "banner": None}]
        with patch.object(evidence_module, "port_still_answers", return_value=False):
            summary = evidence_module.capture_terminal_transcripts(results, store=store)

        self.assertEqual(stored, [])
        self.assertEqual(summary.captured, 0)
        self.assertTrue(any("연결되지 않아" in reason for reason in summary.errors))

    def test_a_udp_result_is_taken_at_its_word(self):
        """There is no handshake to test, and its evidence is the scan record."""
        from netroach.evidence import port_still_answers

        self.assertTrue(
            port_still_answers({"host": "10.0.0.1", "port": 53, "protocol": "udp"}, timeout_ms=1000)
        )

    def test_a_tcp_port_that_refuses_is_not_photographed(self):
        from netroach.evidence import port_still_answers

        # 9 is discard; nothing listens on it here.
        self.assertFalse(
            port_still_answers({"host": "127.0.0.1", "port": 9, "protocol": "tcp"}, timeout_ms=1000)
        )

    def test_a_failed_capture_falls_back_to_the_drawing(self):
        from netroach import evidence as evidence_module

        stored = []

        def store(result, data, file_name, source_url, capture_agent=None):
            stored.append((file_name, capture_agent))

        results = [{"host": "10.0.0.1", "port": 22, "protocol": "tcp", "state": "open",
                    "service_name": "ssh", "banner": None}]
        with patch.object(evidence_module, "port_still_answers", return_value=True):
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
        with patch.object(evidence_module, "port_still_answers", return_value=True):
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
        with patch.object(evidence_module, "port_still_answers", return_value=True):
            with patch.object(evidence_module, "capture_console_session") as capture:
                evidence_module.capture_terminal_transcripts(results, store=store)

        capture.assert_not_called()
        self.assertIn("transcript renderer", stored[0])


if __name__ == "__main__":
    unittest.main()
