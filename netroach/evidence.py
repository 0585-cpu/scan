from __future__ import annotations

import ctypes
import io
import logging
import os
import re
import shutil
import socket
import subprocess
import time
from collections.abc import Callable, Container, Iterable, Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .console_capture import (
    OFFSCREEN_POSITION,
    SWP_NOACTIVATE,
    SWP_NOSIZE,
    SWP_NOZORDER,
    _changed_pixels,
    capture_console_session,
    capture_window_png,
    console_capture_supported,
    has_content,
    visible_window_handles,
    window_opened_since,
)

MAX_EVIDENCE_BYTES = 10 * 1024 * 1024
DEFAULT_SCREENSHOT_TIMEOUT_MS = 8_000
# One line per captured port would be a thousand lines of nothing; a port that
# took several times the timeout it was given is the one worth naming, because
# a handful of those is what a run that looks stopped is actually doing.
SLOW_PORT_FACTOR = 3
# What one web port may spend in total. The navigation is allowed its whole
# timeout, and a page that used all of it still has a timeout's worth left to
# render and be photographed - so a slow page keeps its evidence. Without a
# total, every call took the timeout in turn: four of them, none interruptible,
# because the stop is only read between ports.
WEB_PORT_BUDGET_FACTOR = 2
logger = logging.getLogger(__name__)
DEFAULT_SCREENSHOT_MAX = 20
# A scan of a busy range finds thousands of open ports. This was a hundred,
# which was not a considered ceiling - and because it was checked here rather
# than at the request, raising the API's limit alone left the capture throwing
# on the first call and storing nothing.
MAX_SCREENSHOT_LIMIT = 10_000
# How many of one host's ports may take from the capture budget.
#
# The budget was a total only, so a host with more open ports than the whole
# budget took it and left the hosts after it with nothing - which is the
# damaging shape, because a host with no evidence at all reads as a host with
# nothing to report.
#
# Ten because it covers the services a real host shows without reaching its
# ephemeral tail: a full-port scan of a Windows host answers on 135, 139, 445,
# 3389, 5985 and 47001 and then a run of RPC ports above 49152, and the lowest
# ten take the first group. Five would cut WinRM, which is a finding. Against
# the measured cost of a capture - 0.29s for a transcript, 1.07s for a console
# window - ten a host is about three seconds per host, so 500 hosts is a
# 24-minute evidence pass.
EVIDENCE_PER_HOST = 10
SCREENSHOT_WIDTH = 800
SCREENSHOT_HEIGHT = 600
# The browser viewport, which is not the transcript renderer's canvas above.
# Both kinds of evidence land in the same cell of the assessment workbook -
# 1150 by 260 - and a picture is scaled to fit it. A console capture is 1150
# wide and arrives at full size; a 800 by 600 page came in at 0.43, filling a
# third of the cell's width, so the same report showed the page's text at less
# than half the size of the console's. This width fills the cell, and the
# height leaves the page enough room to be worth looking at.
WEB_SCREENSHOT_WIDTH = 1150
WEB_SCREENSHOT_HEIGHT = 430
# The full browser rather than the headless shell, named explicitly because
# Playwright picks the shell for a headless launch and fails outright when it
# is absent. Only one of the two is bundled - the full one, because it is the
# only build that can be shown with its own window, and a shell beside it would
# be another 271MB for a second way to do what this one already does.
BROWSER_CHANNEL = "chromium"
# The browser window is given a moment off screen before it is
# photographed, so the move itself is not what the picture catches.
BROWSER_WINDOW_SETTLE_S = 0.6
# Tall enough that a device page's footer - where a firmware version
# usually sits - is inside the window rather than below it.
BROWSER_WINDOW_SIZE = (1180, 820)

_IMAGE_EXTENSIONS = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
}
_WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9443}
_HTTPS_PORTS = {443, 8443, 9443}


@dataclass(frozen=True)
class ScreenshotCaptureSummary:
    candidates: int
    captured: int
    failed: int
    web_screenshots: int = 0
    protocol_snapshots: int = 0
    terminal_transcripts: int = 0
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TerminalTranscript:
    shell: str
    command: str
    output: str
    exit_code: int | None
    executed: bool = True
    timed_out: bool = False

    def to_text(self) -> str:
        if self.timed_out:
            status = "Status: timed out"
        elif not self.executed:
            status = "Status: PowerShell unavailable"
        else:
            status = f"Exit code: {self.exit_code}"
        return f"PS> {self.command}\n{status}\n\n{self.output}".strip()


def detect_image_media_type(data: bytes) -> str:
    if not data:
        raise ValueError("evidence image is empty")
    if len(data) > MAX_EVIDENCE_BYTES:
        raise ValueError(f"evidence image exceeds {MAX_EVIDENCE_BYTES} bytes")
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "image/webp"
    raise ValueError("evidence file must be a PNG, JPEG, GIF, or WebP image")


def image_extension(media_type: str) -> str:
    try:
        return _IMAGE_EXTENSIONS[media_type]
    except KeyError as exc:
        raise ValueError(f"unsupported evidence media type: {media_type}") from exc


def safe_original_name(value: str | None, media_type: str) -> str:
    name = (value or f"evidence{image_extension(media_type)}").replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip().strip(".")
    if not name:
        name = f"evidence{image_extension(media_type)}"
    return name[:255]


def web_screenshot_candidates(
    results: Iterable[Mapping[str, Any]],
    *,
    maximum: int = DEFAULT_SCREENSHOT_MAX,
) -> list[dict[str, Any]]:
    if maximum < 1 or maximum > MAX_SCREENSHOT_LIMIT:
        raise ValueError(f"screenshot maximum must be between 1 and {MAX_SCREENSHOT_LIMIT}")
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for result in results:
        host = str(result.get("host") or "")
        protocol = str(result.get("protocol") or "tcp").lower()
        try:
            raw_port: Any = result.get("port")
            port = int(raw_port)
        except (TypeError, ValueError):
            continue
        key = (host, port, protocol)
        if (
            result.get("state") != "open"
            or protocol != "tcp"
            or not host
            or not is_web_result(result)
            or key in seen
        ):
            continue
        seen.add(key)
        candidates.append(dict(result))
        if len(candidates) >= maximum:
            break
    return candidates


def automatic_evidence_candidates(
    results: Iterable[Mapping[str, Any]],
    *,
    maximum: int = DEFAULT_SCREENSHOT_MAX,
) -> list[dict[str, Any]]:
    if maximum < 1 or maximum > MAX_SCREENSHOT_LIMIT:
        raise ValueError(f"screenshot maximum must be between 1 and {MAX_SCREENSHOT_LIMIT}")
    # A port that answered comes before one that only failed to refuse, the
    # way the stored query orders them: the budget is small and a reply is the
    # finding. Ordering is otherwise the caller's.
    ordered = sorted(results, key=lambda result: result.get("state") != "open")
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for result in ordered:
        host = str(result.get("host") or "")
        protocol = str(result.get("protocol") or "tcp").lower()
        try:
            raw_port: Any = result.get("port")
            port = int(raw_port)
        except (TypeError, ValueError):
            continue
        key = (host, port, protocol)
        if result.get("state") not in {"open", "open|filtered"} or not host or key in seen:
            continue
        seen.add(key)
        candidates.append(dict(result))
        if len(candidates) >= maximum:
            break
    return candidates


def result_port(result: Mapping[str, Any]) -> int:
    """Port of a stored result; raises like int() did when it is missing."""
    value: Any = result.get("port")
    return int(value)


# Everything the engine writes into a banner that means "a browser belongs
# here": an HTTP status line, either shape of TLS reply, and the HTTP headers
# it summarises when it got a page. Case matters - ncacn_http/1.0 is RPC over
# HTTP and wants a console, not a browser.
# TLS services a browser cannot render a page from.
_TLS_NOT_WEB_SERVICES = {
    "ldaps", "imaps", "pop3s", "smtps", "ftps", "ldap", "smtp", "imap", "pop3", "ftp",
}

_WEB_BANNER = re.compile(
    r"HTTP/[0-9]"
    r"|TLS record"
    r"|TLS ServerHello"
    r"|content-type=text/html"
    r"|location=https?://"
)


def is_web_result(result: Mapping[str, Any]) -> bool:
    """Whether a browser is the right thing to photograph this port with.

    The banner is consulted as well as the service name: service detection
    misses plenty of web servers on unusual ports, and an HTTP response or a
    TLS record settles it whatever the port number says.

    Getting this wrong is not expensive in either direction. A port sent to the
    browser that cannot be photographed falls through to the console capture
    with everything else; a port kept from the browser gets a console capture,
    which is what the report shows for most ports anyway.
    """
    service = str(result.get("service_name") or "").lower()
    try:
        port = result_port(result)
    except (TypeError, ValueError):
        return False
    if service.startswith("http") or service in {"https", "tls"} or port in _WEB_PORTS:
        return True
    # A TLS reply proves TLS, not HTTP. LDAPS and the mail services speak it
    # and a browser can do nothing with them, so a named one is not overruled
    # by its banner - it goes to the console capture where it belongs.
    if service in _TLS_NOT_WEB_SERVICES:
        return False
    banner = str(result.get("banner") or "")
    return _WEB_BANNER.search(banner) is not None


def web_result_url(result: Mapping[str, Any]) -> str:
    host = str(result.get("host") or "")
    port = result_port(result)
    service = str(result.get("service_name") or "").lower()
    scheme = "https" if "https" in service or service == "tls" or port in _HTTPS_PORTS else "http"
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default_port = 443 if scheme == "https" else 80
    port_suffix = "" if port == default_port else f":{port}"
    return f"{scheme}://{display_host}{port_suffix}/"


SCREENSHOT_RETRY_DELAY_S = 0.4

# How often the page is photographed while waiting for it to stop changing,
# and how many pixels may still differ between two takes for it to count as
# stopped - the console panes' figure, a cursor's worth. domcontentloaded is
# when the HTML arrived, not when the page is drawn: a management page that
# draws itself with script, or loads its login form after the shell, is a
# spinner at that moment, and the spinner was the picture. Bounded by the
# port's budget like everything else here; out of time keeps the last take,
# which is what a single take gave before.
WEB_SETTLE_POLL_S = 0.4
WEB_SETTLE_STILL_PIXELS = 400

# How long the page is given to go quiet on the network before its picture is
# taken. A management page that draws itself after fetching its data, or loads
# its login form after the shell, is a spinner until that request returns - and
# the stilling of animations that precedes the picture freezes a CSS spinner
# into something the settle loop cannot tell from a finished page. Bounded, and
# best effort: a page that polls never goes idle and is photographed anyway
# once this runs out. A page that swaps static text on a bare timer, with no
# request behind it, stays out of reach of both checks.
WEB_NETWORK_IDLE_MS = 3_000

# Navigations Chromium reports as failed while drawing a page about them. The
# server answered - with an error status and no body, or with a TLS the
# browser will not speak - and the tab shows its own page naming which:
# "HTTP ERROR 403", "uses an unsupported protocol". That is what an operator
# opening the address would see, so it is the evidence. Measured on a
# management port answering 403 with nothing after it: without this the web
# pass raised, the port fell to the console capture, and the picture of a web
# service was a netstat line. A refused or reset connection is left out: its
# page says only that the site cannot be reached, and the console capture
# carries more about that.
_RENDERED_NAVIGATION_ERRORS = (
    "ERR_HTTP_RESPONSE_CODE_FAILURE",
    "ERR_SSL_VERSION_OR_CIPHER_MISMATCH",
    "ERR_SSL_PROTOCOL_ERROR",
)


# How long Chromium's error page is given to be swapped in after the
# navigation call has already returned. Measured: an evaluate issued at once
# found the context being destroyed; the page's text was readable a print
# statement later.
ERROR_PAGE_SETTLE_MS = 300


def _navigation_still_drew_a_page(exc: BaseException) -> bool:
    return any(code in str(exc) for code in _RENDERED_NAVIGATION_ERRORS)


def _screenshot_with_one_retry(page: Any, remaining_ms: Callable[[], float] | None = None) -> bytes:
    """Take the screenshot, allowing the renderer one more chance.

    `Protocol error (Page.captureScreenshot): Unable to capture screenshot` has
    been seen on a page that had already loaded and resolved its fonts: the
    navigation worked and only the compositing step failed. Falling straight
    back to a terminal transcript quietly downgrades the evidence, and the
    failure did not repeat on a later attempt, so one retry is worth the
    fraction of a second it costs.

    Only this step is retried. A navigation failure is deterministic - an
    unreachable host stays unreachable - and retrying it would spend a second
    full timeout for nothing.
    """
    try:
        return bytes(page.screenshot(type="png", full_page=False))
    except Exception:  # noqa: BLE001 - the retry is the handling; a second failure propagates.
        if remaining_ms is not None and remaining_ms() <= 0:
            raise
        time.sleep(SCREENSHOT_RETRY_DELAY_S)
        return bytes(page.screenshot(type="png", full_page=False))


def _screenshot_when_settled(page: Any, left_ms: Callable[[], float]) -> bytes:
    """Photograph the page once two takes in a row agree, or when time runs out."""
    previous = _screenshot_with_one_retry(page, left_ms)
    while left_ms() > 0:
        time.sleep(WEB_SETTLE_POLL_S)
        current = _screenshot_with_one_retry(page, left_ms)
        if _changed_pixels(current, previous) <= WEB_SETTLE_STILL_PIXELS:
            return current
        previous = current
    return previous


# Injected rather than added with add_style_tag, which appends the element to
# document.head and waits for it to load. An XML document - a feed, a SOAP
# endpoint, a config file served as application/xml - has no head, so that wait
# never ends, and it does not end on the timeout either: the call is outside
# every deadline Playwright honours. One such port stopped a whole run, and the
# cancel with it, because the stop is only read between ports. Injecting it
# ourselves is bounded by the page timeout like any other evaluate, and does
# nothing at all where there is no head to attach to.
_STILL_ANIMATIONS_JS = """() => {
  if (!document.head) return false;
  const style = document.createElement('style');
  style.textContent =
    '*,*::before,*::after{animation:none!important;transition:none!important}';
  document.head.appendChild(style);
  return true;
}"""


def _still_the_animations(page: Any) -> bool:
    """Stop animations so the picture is the same one on a second look."""
    return bool(page.evaluate(_STILL_ANIMATIONS_JS))


def host_route_filter(allowed_host: str) -> Callable[[Any], None]:
    """Build the request filter that confines a capture to one host.

    The handler takes exactly one argument. Playwright inspects its arity and
    passes the Request as a second argument to anything that accepts one, so a
    `allowed_host=host` default parameter is silently overwritten with a Request
    object - every comparison then fails and the navigation itself is aborted.
    A closure is the only binding Playwright cannot shadow.
    """

    def route_request(route: Any) -> None:
        request_url = urlparse(route.request.url)
        request_host = (request_url.hostname or "").lower()
        if request_url.scheme in {"about", "blob", "data"} or request_host == allowed_host:
            route.continue_()
        else:
            route.abort()

    return route_request


def _capture_browser_window(page: Any, opened_before: Container[int] | None) -> bytes | None:
    """Photograph the browser's own window, or fall back to the page.

    The window is found by being the one that was not on the desktop a moment
    ago, because its title cannot identify it: the title is the page's, and an
    assessment meets the same device on host after host - two switches of one
    model produce two windows named identically. Captures run one at a time,
    so "new since we looked" is unambiguous where the title is not.

    Moved off the visible desktop before it is photographed, the way a console
    capture is, so a run does not take the operator's screen for as long as it
    lasts. `PrintWindow` renders it there regardless.
    """
    if opened_before is None:
        return None
    user32 = getattr(ctypes, "windll").user32  # noqa: B009 - platform-specific export.
    hwnd = window_opened_since(user32, opened_before)
    if hwnd is None:
        return None
    user32.SetWindowPos(
        hwnd, 0, *OFFSCREEN_POSITION, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE
    )
    time.sleep(BROWSER_WINDOW_SETTLE_S)
    shot = capture_window_png(hwnd)
    if shot is None or not has_content(shot):
        return None
    return shot


def show_browser_window() -> bool:
    """Whether to photograph the browser's own window rather than the page.

    The window carries what the page cannot: the address actually arrived at,
    and the judgement the browser puts beside it - the padlock, the "not
    secure" on a plaintext management page, the warning on a certificate that
    does not match. A page screenshot is the document alone and says none of
    it, and cannot even say which host it came from.

    It needs a desktop to draw on, the same as a console capture, and it costs
    a browser window per port instead of a headless render.
    """
    return console_capture_supported()


def capture_web_screenshots(
    results: Iterable[Mapping[str, Any]],
    *,
    store: Callable[[Mapping[str, Any], bytes, str, str, str | None], object],
    timeout_ms: int = DEFAULT_SCREENSHOT_TIMEOUT_MS,
    maximum: int = DEFAULT_SCREENSHOT_MAX,
    should_stop: Callable[[], bool] | None = None,
    on_examined: Callable[[Mapping[str, Any]], None] | None = None,
) -> ScreenshotCaptureSummary:
    if timeout_ms < 1_000 or timeout_ms > 30_000:
        raise ValueError("screenshot timeout must be between 1000 and 30000 milliseconds")
    candidates = web_screenshot_candidates(results, maximum=maximum)
    if not candidates:
        return ScreenshotCaptureSummary(candidates=0, captured=0, failed=0)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        message = (
            "automatic screenshots require Playwright; install the screenshots extra and Chromium: "
            "pip install -e '.[screenshots]' && playwright install chromium"
        )
        return ScreenshotCaptureSummary(
            candidates=len(candidates),
            captured=0,
            failed=len(candidates),
            errors=(message,),
        )

    captured = 0
    errors: list[str] = []
    try:
        with sync_playwright() as playwright:
            windowed = show_browser_window()
            browser = playwright.chromium.launch(
                headless=not windowed,
                channel=BROWSER_CHANNEL,
                args=[f"--window-size={BROWSER_WINDOW_SIZE[0]},{BROWSER_WINDOW_SIZE[1]}"]
                if windowed
                else [],
            )
            # Recorded with every screenshot: a pinned browser only buys
            # reproducible evidence if the evidence says which one rendered it.
            capture_agent = f"chromium {browser.version} {WEB_SCREENSHOT_WIDTH}x{WEB_SCREENSHOT_HEIGHT}"
            try:
                for result in candidates:
                    if should_stop and should_stop():
                        break
                    if on_examined is not None:
                        on_examined(result)
                    url = web_result_url(result)
                    host = str(result["host"]).strip("[]").lower()
                    began = time.monotonic()
                    # Named before the attempt, not after it. Three calls here
                    # are outside any timeout Playwright lets us set - opening
                    # the context, closing it, and closing the browser - so a
                    # port that wedges one of them stops the run inside a call
                    # that never returns, where the cancel is never read. The
                    # line written first is then the only record of which port
                    # it was.
                    logger.debug("evidence: web %s", url)
                    context = browser.new_context(
                        ignore_https_errors=True,
                        # A window sizes its own viewport; forcing one here would
                        # leave the page rendered smaller than the frame around it.
                        viewport=None
                        if windowed
                        else {"width": WEB_SCREENSHOT_WIDTH, "height": WEB_SCREENSHOT_HEIGHT},
                        # What this pass is for is a picture of the page. A
                        # navigation that turns into a download already fails
                        # here, but a page can start one after it has loaded,
                        # and Playwright saves those by default. Taking a file
                        # off a system under assessment is not something to
                        # leave to a library's default.
                        accept_downloads=False,
                    )
                    # The budget is the port's, not each call's - see
                    # WEB_PORT_BUDGET_FACTOR - and it is the page's work that
                    # it bounds. Started at the top of the loop instead, a
                    # browser that was slow to hand over a context would spend
                    # the navigation's share before the navigation began, and
                    # the port would fail for something the page never did.
                    # `began` still measures the whole port, for the slow line.
                    deadline = time.monotonic() + (timeout_ms * WEB_PORT_BUDGET_FACTOR / 1000)

                    def left_ms(until: float = deadline) -> float:
                        return max(0.0, (until - time.monotonic()) * 1000)

                    context.set_default_timeout(timeout_ms)
                    try:
                        context.route("**/*", host_route_filter(host))
                        # Taken before the page exists, so the window it opens is
                        # the only one that can be new when it is looked for.
                        opened_before = (
                            visible_window_handles(getattr(ctypes, "windll").user32)  # noqa: B009
                            if windowed
                            else None
                        )
                        page = context.new_page()
                        reached = url
                        drew_its_own_page = False
                        try:
                            page.goto(url, wait_until="domcontentloaded", timeout=min(timeout_ms, left_ms()) or 1)
                        except Exception as exc:  # noqa: BLE001 - narrowed on the message below.
                            if not _navigation_still_drew_a_page(exc):
                                raise
                            # The address stays the one asked for: Chromium
                            # reports its error page as about:blank.
                            drew_its_own_page = True
                        else:
                            reached = page.url
                        page.set_default_timeout(left_ms() or 1)
                        if drew_its_own_page:
                            # Chromium's page, not the target's: nothing on it
                            # to still, and it is still being swapped in when
                            # the navigation call returns - an evaluate here
                            # lands in a context that is being torn down.
                            # The screenshot goes through the compositor, which
                            # needs no script context; give the swap a moment.
                            page.wait_for_timeout(ERROR_PAGE_SETTLE_MS)
                        else:
                            try:
                                page.wait_for_load_state(
                                    "networkidle", timeout=max(1, min(WEB_NETWORK_IDLE_MS, left_ms()))
                                )
                            except Exception:  # noqa: BLE001 - a page that never goes quiet is still photographed.
                                pass
                            _still_the_animations(page)
                        page.set_default_timeout(left_ms() or 1)
                        # The window carries what the page cannot: the address
                        # arrived at, and the browser's own judgement beside it -
                        # the padlock, the "not secure" on a plaintext management
                        # page, the warning on a certificate that does not match.
                        # The page alone is the fallback, not the goal.
                        # Wait for the page to stop changing before either
                        # picture is taken; the window capture is the goal and
                        # the page screenshot the fallback, and both must be
                        # of a page that has finished drawing.
                        settled = _screenshot_when_settled(page, left_ms)
                        image = _capture_browser_window(page, opened_before)
                        if image is None:
                            image = settled
                        filename_host = re.sub(r"[^A-Za-z0-9_.-]+", "_", host)
                        store(result, image, f"{filename_host}_{result['port']}.png", reached, capture_agent)
                        captured += 1
                    except Exception as exc:  # noqa: BLE001 - one failed web service must not stop other captures.
                        errors.append(f"{url}: {str(exc)[:240]}")
                        logger.warning("evidence: web %s failed: %s", url, str(exc)[:160])
                    finally:
                        context.close()
                        _log_if_slow(host, result.get("port"), began, timeout_ms)
            finally:
                browser.close()
    except Exception as exc:  # noqa: BLE001 - missing browser binaries should not invalidate a port scan.
        errors.append(f"Playwright Chromium could not start: {str(exc)[:240]}")

    failed = len(candidates) - captured
    return ScreenshotCaptureSummary(
        candidates=len(candidates),
        captured=captured,
        failed=failed,
        web_screenshots=captured,
        errors=tuple(errors[:20]),
    )


def run_powershell_diagnostic(
    result: Mapping[str, Any],
    *,
    timeout_ms: int = DEFAULT_SCREENSHOT_TIMEOUT_MS,
) -> TerminalTranscript:
    if timeout_ms < 1_000 or timeout_ms > 30_000:
        raise ValueError("terminal diagnostic timeout must be between 1000 and 30000 milliseconds")

    host = _clean_terminal_value(result.get("host"), maximum=512)
    port = result_port(result)
    protocol = _clean_terminal_value(result.get("protocol") or "tcp", maximum=16).lower()
    preauth_mode = preauth_mode_for_result(result)
    command = _powershell_display_command(host, port, protocol, timeout_ms, preauth_mode)
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    scan_record = _scan_record_text(result)
    if not powershell:
        return TerminalTranscript(
            shell="PowerShell",
            command=command,
            output=(
                "PowerShell executable was not found. The authorized scanner transcript is shown below.\n\n"
                f"{scan_record}"
            ),
            exit_code=None,
            executed=False,
        )

    environment = os.environ.copy()
    environment.update(
        {
            "NETROACH_TARGET": host,
            "NETROACH_PORT": str(port),
            "NETROACH_PROTOCOL": protocol,
            "NETROACH_CONNECT_TIMEOUT": str(max(250, timeout_ms - 2_000)),
            "NETROACH_PREAUTH_MODE": preauth_mode,
            "NETROACH_STATE": _clean_terminal_value(result.get("state"), maximum=128),
            "NETROACH_SERVICE": _clean_terminal_value(result.get("service_name") or "unknown", maximum=256),
            "NETROACH_BANNER": _clean_terminal_value(result.get("banner"), maximum=2_000),
            "NETROACH_EVIDENCE": _clean_terminal_value(result.get("evidence"), maximum=2_000),
            "NETROACH_ERROR": _clean_terminal_value(result.get("error"), maximum=1_000),
        }
    )
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    arguments = [
        powershell,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        _POWERSHELL_DIAGNOSTIC_SCRIPT,
    ]
    try:
        completed = subprocess.run(
            arguments,
            capture_output=True,
            check=False,
            creationflags=creation_flags,
            encoding="utf-8",
            errors="replace",
            env=environment,
            timeout=timeout_ms / 1_000,
        )
    except subprocess.TimeoutExpired as exc:
        partial = _normalize_terminal_output(_subprocess_text(exc.stdout or exc.stderr))
        output = f"PowerShell command exceeded the {timeout_ms} ms limit."
        if partial.strip():
            output += f"\n\nPartial output:\n{partial.strip()}"
        output += f"\n\n{scan_record}"
        return TerminalTranscript(
            shell=_powershell_name(powershell),
            command=command,
            output=output,
            exit_code=None,
            timed_out=True,
        )
    except OSError as exc:
        return TerminalTranscript(
            shell=_powershell_name(powershell),
            command=command,
            output=f"PowerShell could not start: {exc}\n\n{scan_record}",
            exit_code=None,
            executed=False,
        )

    output_parts = [_normalize_terminal_output(completed.stdout)]
    if completed.stderr.strip():
        output_parts.append(f"PowerShell error stream:\n{_normalize_terminal_output(completed.stderr)}")
    output = "\n\n".join(part for part in output_parts if part).strip()
    if not output:
        output = scan_record
    return TerminalTranscript(
        shell=_powershell_name(powershell),
        command=command,
        output=output,
        exit_code=completed.returncode,
    )


# The reachability check runs before every capture, so its cost is paid once
# per port whether or not anything comes of it. A port that is going to answer
# answers in milliseconds; giving it the whole screenshot timeout instead meant
# eight seconds of waiting for each port that would not, which on a scan of a
# few hundred is most of the run.
REACHABILITY_TIMEOUT_MS = 2_000


def port_still_answers(result: Mapping[str, Any], *, timeout_ms: int) -> bool:
    """Whether a TCP connection to this result's port opens right now.

    UDP has no handshake to test, so a UDP result is taken at its word - its
    evidence is the scan record either way.
    """
    protocol = str(result.get("protocol") or "tcp").lower()
    if protocol != "tcp":
        return True
    host = str(result.get("host") or "")
    try:
        port = result_port(result)
    except (TypeError, ValueError):
        return False
    timeout = max(0.5, min(REACHABILITY_TIMEOUT_MS, timeout_ms) / 1000)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def render_terminal_transcript(
    result: Mapping[str, Any],
    transcript: TerminalTranscript,
    *,
    captured_at: datetime | None = None,
) -> bytes:
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError as exc:
        raise RuntimeError("terminal evidence requires Pillow; install with: pip install -e .") from exc

    timestamp = (captured_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    image = Image.new("RGB", (SCREENSHOT_WIDTH, SCREENSHOT_HEIGHT), "#0c0c0c")
    draw = ImageDraw.Draw(image)
    title_font = _load_card_font(ImageFont, 16, bold=True)
    mono_font = _load_card_font(ImageFont, 14, monospace=True)
    small_font = _load_card_font(ImageFont, 12)

    draw.rectangle((0, 0, SCREENSHOT_WIDTH, 38), fill="#202020")
    draw.ellipse((13, 13, 24, 24), fill="#ff5f57")
    draw.ellipse((31, 13, 42, 24), fill="#febc2e")
    draw.ellipse((49, 13, 60, 24), fill="#28c840")
    service = _clean_terminal_value(result.get("service_name") or "unknown", maximum=64)
    target = f"{_clean_terminal_value(result.get('host'), maximum=128)}:{result.get('port')}"
    draw.text((76, 10), f"{transcript.shell} - {target} - {service}", fill="#e5e5e5", font=title_font)

    header = f"Captured UTC: {timestamp.isoformat(timespec='seconds')}"
    terminal_text = f"{header}\n{transcript.to_text()}"
    lines = _wrap_terminal_text(draw, terminal_text, mono_font, SCREENSHOT_WIDTH - 28)
    maximum_lines = 29
    if len(lines) > maximum_lines:
        lines = [*lines[: maximum_lines - 1], "... output truncated to fit 800x600 evidence ..."]
    y = 50
    for line in lines:
        color = "#cccccc"
        if line.startswith("PS>"):
            color = "#ffff66"
        elif line.startswith(("Status:", "PowerShell error", "TCP verification error", "Pre-authentication capture error")):
            color = "#ff8080"
        elif line.startswith(("Client authentication prompt", "login as:", "USER:", "User (")):
            color = "#8cff8c"
        elif line.startswith(("Netroach authorized", "Captured UTC:")):
            color = "#6bdcff"
        draw.text((14, y), line, fill=color, font=mono_font)
        y += 18

    draw.text(
        (14, 578),
        "Stopped before username, password, key, AUTH, or login packet submission.",
        fill="#7d7d7d",
        font=small_font,
    )
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=True)
    return output.getvalue()


def _log_if_slow(host: str, port: object, began: float, timeout_ms: int) -> None:
    """Name a port that held the run far longer than it was allowed to.

    A run of a thousand ports has no room for a line each, and the ones worth
    reading are the few that took minutes - which is what a run that looks
    stopped is really made of.
    """
    spent = time.monotonic() - began
    if spent > (timeout_ms / 1000) * SLOW_PORT_FACTOR:
        logger.warning("evidence: %s:%s took %.1fs", host, port, spent)


def capture_terminal_transcripts(
    results: Iterable[Mapping[str, Any]],
    *,
    store: Callable[[Mapping[str, Any], bytes, str, str | None, str | None], object],
    timeout_ms: int = DEFAULT_SCREENSHOT_TIMEOUT_MS,
    maximum: int = DEFAULT_SCREENSHOT_MAX,
    should_stop: Callable[[], bool] | None = None,
    capture_console: bool = False,
    on_examined: Callable[[Mapping[str, Any]], None] | None = None,
) -> ScreenshotCaptureSummary:
    candidates = automatic_evidence_candidates(results, maximum=maximum)
    captured = 0
    errors: list[str] = []
    for result in candidates:
        if should_stop and should_stop():
            break
        if on_examined is not None:
            on_examined(result)
        began = time.monotonic()
        host = str(result.get("host") or "")
        # Ask whether the port still answers before photographing anything. A
        # scan re-run from a machine that cannot reach the targets would
        # otherwise store a console reading "Connected: False" beside a
        # SYN_SENT line - which looks like evidence, proves nothing, and
        # replaces the capture taken where the port did answer.
        if not port_still_answers(result, timeout_ms=timeout_ms):
            errors.append(f"{host}:{result.get('port')}: 연결되지 않아 증적을 남기지 않았습니다")
            logger.warning("evidence: %s:%s did not answer, skipped", host, result.get("port"))
            continue
        try:
            image = None
            capture_agent = f"netroach transcript renderer {SCREENSHOT_WIDTH}x{SCREENSHOT_HEIGHT}"
            protocol = str(result.get("protocol") or "tcp").lower()
            if capture_console and protocol == "tcp":
                # A photograph of a real console beats a drawing of one, but it
                # needs a desktop to draw on. Where there is none the capture
                # comes back empty and the drawing is used instead - an empty
                # image is the one thing evidence must never be.
                #
                # TCP only: the session it photographs is a TcpClient holding a
                # socket open, which is the proof. UDP has no handshake to
                # hold, so every UDP port spent a console window and its whole
                # timeout on a connection that could never open.
                # The identified service decides which client sits beside the
                # console, so SSH found on a port other than 22 still gets an
                # SSH pane rather than a telnet one that would never connect.
                image = capture_console_session(
                    host,
                    int(result.get("port") or 0),
                    service=str(result.get("service_name") or "") or None,
                )
                if image is not None:
                    capture_agent = "windows console capture"
            if image is None:
                transcript = run_powershell_diagnostic(result, timeout_ms=timeout_ms)
                image = render_terminal_transcript(result, transcript)
            filename_host = re.sub(r"[^A-Za-z0-9_.-]+", "_", host.strip("[]"))
            source_url = web_result_url(result) if is_web_result(result) else None
            store(
                result,
                image,
                f"{filename_host}_{result.get('port')}_{result.get('protocol', 'tcp')}_powershell.png",
                source_url,
                capture_agent,
            )
            captured += 1
            _log_if_slow(host, result.get("port"), began, timeout_ms)
        except Exception as exc:  # noqa: BLE001 - one malformed result must not stop other transcripts.
            errors.append(f"{host}:{result.get('port')}: {str(exc)[:240]}")
            logger.warning("evidence: %s:%s failed: %s", host, result.get("port"), exc)
    return ScreenshotCaptureSummary(
        candidates=len(candidates),
        captured=captured,
        failed=len(candidates) - captured,
        terminal_transcripts=captured,
        errors=tuple(errors[:20]),
    )


def capture_automatic_evidence(
    results: Iterable[Mapping[str, Any]],
    *,
    store: Callable[[Mapping[str, Any], bytes, str, str | None, str, str | None], object],
    timeout_ms: int = DEFAULT_SCREENSHOT_TIMEOUT_MS,
    maximum: int = DEFAULT_SCREENSHOT_MAX,
    should_stop: Callable[[], bool] | None = None,
    capture_console: bool = False,
    on_examined: Callable[[Mapping[str, Any]], None] | None = None,
) -> ScreenshotCaptureSummary:
    candidates = automatic_evidence_candidates(results, maximum=maximum)
    if not candidates:
        return ScreenshotCaptureSummary(candidates=0, captured=0, failed=0)

    captured_keys: set[tuple[str, int, str]] = set()

    def store_web(
        result: Mapping[str, Any],
        data: bytes,
        file_name: str,
        source_url: str,
        capture_agent: str | None = None,
    ) -> object:
        stored = store(result, data, file_name, source_url, "web_screenshot", capture_agent)
        captured_keys.add(_result_key(result))
        return stored

    web_summary = capture_web_screenshots(
        candidates,
        store=store_web,
        timeout_ms=timeout_ms,
        maximum=maximum,
        should_stop=should_stop,
        on_examined=on_examined,
    )
    # A port that gave up a page screenshot is finished. That picture shows the
    # service answering, which is what a console capture would be there to
    # prove, and it shows what the service actually is besides.
    remaining = [result for result in candidates if _result_key(result) not in captured_keys]

    def store_transcript(
        result: Mapping[str, Any],
        data: bytes,
        file_name: str,
        source_url: str | None,
        capture_agent: str | None = None,
    ) -> object:
        stored = store(result, data, file_name, source_url, "terminal_transcript", capture_agent)
        captured_keys.add(_result_key(result))
        return stored

    if remaining and not (should_stop and should_stop()):
        terminal_summary = capture_terminal_transcripts(
            remaining,
            store=store_transcript,
            timeout_ms=timeout_ms,
            maximum=len(remaining),
            should_stop=should_stop,
            capture_console=capture_console,
            on_examined=on_examined,
        )
    else:
        terminal_summary = ScreenshotCaptureSummary(candidates=0, captured=0, failed=0)

    captured = len(captured_keys)
    return ScreenshotCaptureSummary(
        candidates=len(candidates),
        captured=captured,
        failed=len(candidates) - captured,
        web_screenshots=web_summary.web_screenshots,
        terminal_transcripts=terminal_summary.terminal_transcripts,
        errors=tuple([*web_summary.errors, *terminal_summary.errors][:20]),
    )


def _result_key(result: Mapping[str, Any]) -> tuple[str, int, str]:
    return (
        str(result.get("host") or ""),
        result_port(result),
        str(result.get("protocol") or "tcp"),
    )


def _clean_card_text(value: Any) -> str:
    text = "" if value is None else str(value)
    return "".join(character if character.isprintable() or character == "\n" else "." for character in text)


def _clean_terminal_value(value: Any, *, maximum: int) -> str:
    return _clean_card_text(value).replace("\r", "").strip()[:maximum]


def preauth_mode_for_result(result: Mapping[str, Any]) -> str:
    protocol = str(result.get("protocol") or "tcp").lower()
    if protocol != "tcp":
        return "none"
    try:
        port = result_port(result)
    except (TypeError, ValueError):
        return "none"
    if port in _PREAUTH_PORT_MODES:
        return _PREAUTH_PORT_MODES[port]
    service = str(result.get("service_name") or "").lower()
    for prefix, mode in _PREAUTH_SERVICE_MODES:
        if service == prefix or service.startswith(f"{prefix}-"):
            return mode
    return "none"


def _powershell_display_command(
    host: str,
    port: int,
    protocol: str,
    timeout_ms: int,
    preauth_mode: str,
) -> str:
    safe_host = host.replace("'", "''")
    if protocol == "tcp":
        command = (
            "$tcp = [Net.Sockets.TcpClient]::new(); "
            f"$tcp.ConnectAsync('{safe_host}', {port}).Wait({max(250, timeout_ms - 2_000)})"
        )
        if preauth_mode != "none":
            command += f"; Read-NetroachPreAuthPrompt -Mode '{preauth_mode}'  # no credentials"
        return command
    return "$scanResult | Format-List  # UDP response recorded by the authorized scanner"


def _powershell_name(executable: str) -> str:
    return "Windows PowerShell" if "powershell" in Path(executable).name.lower() else "PowerShell"


def _scan_record_text(result: Mapping[str, Any]) -> str:
    fields = (
        ("ComputerName", result.get("host")),
        ("RemotePort", result.get("port")),
        ("Protocol", result.get("protocol") or "tcp"),
        ("ScanState", result.get("state") or "unknown"),
        ("ServiceName", result.get("service_name") or "unknown"),
        ("ServiceBanner", result.get("banner") or ""),
        ("ProbeEvidence", result.get("evidence") or ""),
        ("Error", result.get("error") or ""),
    )
    lines = ["Netroach authorized scan record"]
    for label, value in fields:
        lines.append(f"{label:<16}: {_clean_terminal_value(value, maximum=2_000)}")
    lines.append("Authentication  : stopped before username, password, key, or AUTH request")
    return "\n".join(lines)


def _subprocess_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _normalize_terminal_output(value: str) -> str:
    lines: list[str] = []
    previous_blank = False
    for line in value.replace("\r", "").split("\n"):
        blank = not line.strip()
        if blank and previous_blank:
            continue
        lines.append(line.rstrip())
        previous_blank = blank
    return "\n".join(lines).strip()


def _wrap_terminal_text(draw: Any, value: str, font: Any, maximum_width: int) -> list[str]:
    lines: list[str] = []
    for source_line in value.replace("\r", "").split("\n"):
        if not source_line:
            lines.append("")
            continue
        current = ""
        for character in source_line.expandtabs(4):
            candidate = current + character
            if current and draw.textlength(candidate, font=font) > maximum_width:
                lines.append(current)
                current = character
            else:
                current = candidate
        lines.append(current)
    return lines


def _load_card_font(font_module: Any, size: int, *, bold: bool = False, monospace: bool = False) -> Any:
    if monospace:
        candidates = ("DejaVuSansMono.ttf", "consola.ttf")
    elif bold:
        candidates = ("DejaVuSans-Bold.ttf", "segoeuib.ttf")
    else:
        candidates = ("DejaVuSans.ttf", "segoeui.ttf")
    for font_name in candidates:
        try:
            return font_module.truetype(font_name, size=size)
        except OSError:
            continue
    return font_module.load_default()


_PREAUTH_PORT_MODES = {
    21: "ftp",
    80: "http",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    110: "pop3",
    143: "imap",
    465: "smtps",
    587: "smtp",
    636: "ldaps",
    990: "ftps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
}
_PREAUTH_SERVICE_MODES = (
    ("ssh", "ssh"),
    # A web port whose screenshot failed - a 401 fails the navigation outright
    # - would otherwise fall to "none" and record only that the port answered.
    ("http", "http"),
    ("http-alt", "http"),
    ("telnet", "telnet"),
    ("ftp", "ftp"),
    ("smtp", "smtp"),
    ("submission", "smtp"),
    ("pop3", "pop3"),
    ("imap", "imap"),
    ("smtps", "smtps"),
    ("ftps", "ftps"),
    ("imaps", "imaps"),
    ("pop3s", "pop3s"),
    ("ldaps", "ldaps"),
    ("mysql", "mysql"),
    ("mssql", "mssql"),
    ("postgresql", "postgresql"),
    ("postgres", "postgresql"),
    ("redis", "redis"),
)


_POWERSHELL_DIAGNOSTIC_SCRIPT = r"""
$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$target = $env:NETROACH_TARGET
$port = [int]$env:NETROACH_PORT
$protocol = $env:NETROACH_PROTOCOL
$connectTimeout = [int]$env:NETROACH_CONNECT_TIMEOUT
$preauthMode = $env:NETROACH_PREAUTH_MODE

function ConvertTo-NetroachText {
    param([byte[]]$Bytes, [int]$Count)
    if ($Count -le 0) { return '' }
    $text = [System.Text.Encoding]::UTF8.GetString($Bytes, 0, $Count)
    return ($text -replace '[^\x09\x0A\x0D\x20-\x7E]', '.').Trim()
}

function Read-NetroachResponse {
    param([System.IO.Stream]$Stream, [int]$TimeoutMs)
    try {
        if ($Stream.CanTimeout) { $Stream.ReadTimeout = $TimeoutMs }
        $buffer = [byte[]]::new(4096)
        $count = $Stream.Read($buffer, 0, $buffer.Length)
        return ConvertTo-NetroachText -Bytes $buffer -Count $count
    }
    catch {
        return ''
    }
}

function Send-NetroachPreAuthCommand {
    param([System.IO.Stream]$Stream, [string]$Text)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Text)
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}

function Show-NetroachResponse {
    param([string]$Label, [string]$Text)
    $value = $Text.Trim()
    if (-not $value) { return }
    if ($value.Length -gt 1000) { $value = $value.Substring(0, 1000) + ' ...[truncated]' }
    Write-Output $Label
    Write-Output $value
}

function Read-NetroachPreAuthPrompt {
    param(
        [System.IO.Stream]$Stream,
        [string]$Mode,
        [string]$ComputerName,
        [int]$ReadTimeoutMs
    )

    $baseMode = switch ($Mode) {
        'ftps' { 'ftp' }
        'smtps' { 'smtp' }
        'imaps' { 'imap' }
        'pop3s' { 'pop3' }
        'ldaps' { 'ldap' }
        default { $Mode }
    }
    $initial = ''
    if ($baseMode -in @('ssh', 'telnet', 'ftp', 'smtp', 'pop3', 'imap', 'mysql')) {
        $initial = Read-NetroachResponse -Stream $Stream -TimeoutMs $ReadTimeoutMs
        Show-NetroachResponse -Label 'Server pre-authentication response:' -Text $initial
    }

    switch ($baseMode) {
        'ssh' {
            Write-Output 'SSH negotiates authentication inside its transport, so no'
            Write-Output 'prompt is readable here. The banner above is what the'
            Write-Output 'server sent before that point.'
            Write-Output '[stopped before sending an SSH username, key, or password]'
        }
        'telnet' {
            if (-not $initial) { Write-Output 'No Telnet login prompt arrived before the read timeout.' }
            Write-Output '[stopped before sending Telnet input]'
        }
        'http' {
            # One request, no credentials. What a browser would not show is in
            # the response itself: the status, and on a management page behind
            # a login box the WWW-Authenticate line naming the scheme and the
            # realm. The page screenshot cannot carry any of it - a browser
            # driven by the capture never renders a 401 at all, it fails the
            # navigation - so this is the only place the finding is recorded.
            $request = "GET / HTTP/1.1`r`nHost: " + $ComputerName +
                "`r`nUser-Agent: netroach-evidence`r`nConnection: close`r`n`r`n"
            Send-NetroachPreAuthCommand -Stream $Stream -Text $request
            $response = Read-NetroachResponse -Stream $Stream -TimeoutMs $ReadTimeoutMs
            $head = ($response -split "`r`n`r`n", 2)[0]
            Show-NetroachResponse -Label 'HTTP response head:' -Text $head
            if ($head -match '(?im)^WWW-Authenticate:\s*(\S+)') {
                Write-Output ("Authentication scheme offered by the server: " + $Matches[1])
            }
            Write-Output '[stopped before sending HTTP credentials]'
        }
        'ftp' {
            Send-NetroachPreAuthCommand -Stream $Stream -Text "FEAT`r`n"
            $response = Read-NetroachResponse -Stream $Stream -TimeoutMs $ReadTimeoutMs
            Show-NetroachResponse -Label 'FTP FEAT response:' -Text $response
            Write-Output '[stopped before sending FTP USER or PASS]'
        }
        'smtp' {
            Send-NetroachPreAuthCommand -Stream $Stream -Text "EHLO netroach-evidence.invalid`r`n"
            $response = Read-NetroachResponse -Stream $Stream -TimeoutMs $ReadTimeoutMs
            Show-NetroachResponse -Label 'SMTP EHLO / authentication capability response:' -Text $response
            Write-Output '[stopped before sending SMTP AUTH]'
        }
        'pop3' {
            Send-NetroachPreAuthCommand -Stream $Stream -Text "CAPA`r`n"
            $response = Read-NetroachResponse -Stream $Stream -TimeoutMs $ReadTimeoutMs
            Show-NetroachResponse -Label 'POP3 CAPA response:' -Text $response
            Write-Output '[stopped before sending POP3 USER or PASS]'
        }
        'imap' {
            Send-NetroachPreAuthCommand -Stream $Stream -Text "a001 CAPABILITY`r`n"
            $response = Read-NetroachResponse -Stream $Stream -TimeoutMs $ReadTimeoutMs
            Show-NetroachResponse -Label 'IMAP CAPABILITY / authentication mechanism response:' -Text $response
            Write-Output '[stopped before sending IMAP LOGIN or AUTHENTICATE]'
        }
        'redis' {
            Send-NetroachPreAuthCommand -Stream $Stream -Text "PING`r`n"
            $response = Read-NetroachResponse -Stream $Stream -TimeoutMs $ReadTimeoutMs
            Show-NetroachResponse -Label 'Redis pre-authentication PING response:' -Text $response
            Write-Output '[stopped before sending Redis AUTH]'
        }
        'mysql' {
            Write-Output 'MySQL server handshake received; client login packet was not sent.'
        }
        'postgresql' {
            Write-Output 'PostgreSQL authentication requires a startup packet; no startup or login packet was sent.'
        }
        'mssql' {
            Write-Output 'SQL Server authentication requires a login packet; no login packet was sent.'
        }
        'ldap' {
            Write-Output 'LDAPS handshake completed; no LDAP bind request was sent.'
        }
    }
}

if ($protocol -eq 'tcp') {
    Write-Output 'PowerShell bounded TCP verification'
    $tcp = [System.Net.Sockets.TcpClient]::new()
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $secureStream = $null
    try {
        $connectTask = $tcp.ConnectAsync($target, $port)
        if (-not $connectTask.Wait($connectTimeout)) {
            throw "TCP connection exceeded the ${connectTimeout} ms limit"
        }
        $timer.Stop()
        [pscustomobject]@{
            ComputerName = $target
            RemoteAddress = $tcp.Client.RemoteEndPoint.Address.ToString()
            RemotePort = $port
            SourceAddress = $tcp.Client.LocalEndPoint.Address.ToString()
            TcpTestSucceeded = $tcp.Connected
            RoundTripMs = [Math]::Round($timer.Elapsed.TotalMilliseconds, 2)
        } | Format-List | Out-String -Width 100 | Write-Output

        if ($preauthMode -ne 'none') {
            try {
                $ioStream = $tcp.GetStream()
                if ($preauthMode -in @('ftps', 'smtps', 'imaps', 'pop3s', 'ldaps')) {
                    $validation = [System.Net.Security.RemoteCertificateValidationCallback]{
                        param($sender, $certificate, $chain, $sslPolicyErrors)
                        return $true
                    }
                    $secureStream = [System.Net.Security.SslStream]::new($ioStream, $false, $validation)
                    $tlsTask = $secureStream.AuthenticateAsClientAsync($target)
                    if (-not $tlsTask.Wait($connectTimeout)) {
                        throw "TLS handshake exceeded the ${connectTimeout} ms limit"
                    }
                    $ioStream = $secureStream
                    [pscustomobject]@{
                        TlsAuthenticated = $secureStream.IsAuthenticated
                        TlsProtocol = $secureStream.SslProtocol
                        CipherAlgorithm = $secureStream.CipherAlgorithm
                        CipherStrength = $secureStream.CipherStrength
                    } | Format-List | Out-String -Width 100 | Write-Output
                }
                $readTimeout = [Math]::Max(250, [Math]::Min(1000, [int]($connectTimeout / 3)))
                Read-NetroachPreAuthPrompt `
                    -Stream $ioStream `
                    -Mode $preauthMode `
                    -ComputerName $target `
                    -ReadTimeoutMs $readTimeout
            }
            catch {
                Write-Output ("Pre-authentication capture error: " + $_.Exception.GetBaseException().Message)
                Write-Output '[no credentials were sent]'
            }
        }
    }
    catch {
        $timer.Stop()
        [pscustomobject]@{
            ComputerName = $target
            RemotePort = $port
            TcpTestSucceeded = $false
            RoundTripMs = [Math]::Round($timer.Elapsed.TotalMilliseconds, 2)
            Error = $_.Exception.GetBaseException().Message
        } | Format-List | Out-String -Width 100 | Write-Output
    }
    finally {
        if ($null -ne $secureStream) { $secureStream.Dispose() }
        $tcp.Dispose()
    }
}
else {
    Write-Output 'UDP has no generic connection test in PowerShell; displaying the scanner probe response.'
}

Write-Output 'Netroach authorized scan record'
[pscustomobject]@{
    ComputerName = $target
    RemotePort = $port
    Protocol = $protocol
    ScanState = $env:NETROACH_STATE
    ServiceName = $env:NETROACH_SERVICE
    ServiceBanner = $env:NETROACH_BANNER
    ProbeEvidence = $env:NETROACH_EVIDENCE
    Error = $env:NETROACH_ERROR
    Authentication = 'stopped before username, password, key, or AUTH request'
} | Format-List | Out-String -Width 100 | Write-Output
"""
