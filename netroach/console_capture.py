"""Photograph a real console window instead of drawing one.

The rendered transcript beside this is a picture Netroach draws: accurate, but
not a screenshot. An assessment report is read as one, so this opens an actual
console, holds a connection to the port open long enough for `netstat` to show
it ESTABLISHED, and captures that window's own pixels.

It only works where there is a desktop to draw on. A locked workstation, a
disconnected RDP session or a service account has no window station, and the
capture comes back empty rather than wrong - callers fall back to the drawing.
"""

from __future__ import annotations

import ctypes
import io
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Container
from ctypes import wintypes
from pathlib import Path

# PrintWindow renders the whole window even when another window covers it or it
# sits off screen, which is what lets this run without stealing focus.
PW_RENDERFULLCONTENT = 2
CREATE_NEW_CONSOLE = 0x00000010
SWP_NOSIZE = 0x0001
SWP_NOZORDER = 0x0004
SWP_NOACTIVATE = 0x0010
# Far enough out that the window never appears on any monitor arrangement.
OFFSCREEN_POSITION = (-32000, -32000)
CAPTURE_READY_TIMEOUT_S = 12.0
CAPTURE_POLL_INTERVAL_S = 0.2
# Left on screen after the command finishes so the capture is of a settled
# window rather than one still painting its last line.
CAPTURE_SETTLE_S = 0.35
# The client either paints quickly or is not installed at all.
TELNET_READY_TIMEOUT_S = 6.0
# The client pane beside the console, as a share of the console's width.
TELNET_PANE_WIDTH_RATIO = 0.36
# Wide enough for a netstat line and the command above it, and no wider.
# Sized so the console and the client together stay inside the report's
# evidence cell, where anything wider is scaled down.
CONSOLE_WINDOW_SIZE = (770, 300)
# The evidence cell of the report the capture is pasted into. Anything wider
# is scaled down there, and the console text is what the scaling costs.
COMPOSED_TARGET_WIDTH = 1150
# Rows of background left under the last line of output before cropping.
CONTENT_MARGIN_PX = 12
# A real capture carries two command lines and a netstat row; a window that
# rendered nothing carries a few hundred stray pixels at most.
CONTENT_PIXELS_MINIMUM = 1_000
# A row counts as content only past this many differing pixels, so a stray
# border pixel does not keep an empty console from being trimmed.
CONTENT_ROW_PIXELS = 3
CONTENT_COLOUR_TOLERANCE = 24
# Gap between the two panes when a telnet window joins the console one.
COMPOSED_PANE_GAP = 12
COMPOSED_BACKGROUND = "#0c0c0c"


def console_capture_supported() -> bool:
    return sys.platform == "win32"


def build_connection_script(
    host: str, port: int, *, done_path: Path, hold_s: float = 20.0, title: str | None = None
) -> str:
    """A session that proves the port answered, in the form a report shows it.

    The connection is still open while `netstat` runs, which is the whole point:
    the ESTABLISHED line naming this host and port is the evidence. Nothing is
    sent on the socket, so the exchange stops where every other capture here
    stops - before anything that could be taken for a login attempt.
    """
    safe_host = host.replace("'", "''")
    # The title is how the capture finds its own window, so it carries the
    # caller's token rather than only the port two scans might share.
    safe_title = (title or f"Netroach {safe_host}:{port}").replace("'", "''")
    return (
        f"$Host.UI.RawUI.WindowTitle = '{safe_title}'; "
        # Broken over two lines so the window can be narrow. A capture wider
        # than the report's evidence cell is scaled down to fit it, and the
        # text is what pays for the width.
        "Write-Host 'PS> $tcp = [Net.Sockets.TcpClient]::new()'; "
        f"Write-Host 'PS> $tcp.ConnectAsync({safe_host}, {port}).Wait(5000)'; "
        f"$tcp = [Net.Sockets.TcpClient]::new(); "
        f"$connected = $tcp.ConnectAsync('{safe_host}', {port}).Wait(5000); "
        "Write-Host (\"Connected: \" + $connected); "
        # Written where the caller can read it: a capture of a connection that
        # never opened proves nothing, and must not replace one that did.
        f"if ($connected) {{ Set-Content -Path '{done_path.as_posix()}.ok' -Value 'connected' }}; "
        f"Write-Host ''; Write-Host 'PS> netstat -an | Select-String \"{safe_host}:{port}\"'; "
        # Only the line for this port. Every other socket on the host is
        # context nobody reads, and it is paid for twice - once in the
        # height of the picture, again in how far the report shrinks it.
        "$rows = netstat -an; "
        f"$match = $rows | Select-String -SimpleMatch '{safe_host}:{port} '; "
        f"if (-not $match) {{ $match = $rows | Select-String -SimpleMatch '{safe_host}' | "
        "Select-Object -First 3 }; "
        "$match | Select-Object -First 3 | ForEach-Object { Write-Host $_.Line.TrimEnd() }; "
        "Write-Host ''; Write-Host 'Stopped before username, password, key, AUTH, or login.'; "
        f"New-Item -ItemType File -Path '{done_path.as_posix()}' -Force | Out-Null; "
        f"Start-Sleep -Seconds {hold_s}"
    )


def _find_windows_by_title(user32: ctypes.WinDLL, needle: str) -> list[tuple[int, str]]:
    matches: list[tuple[int, str]] = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    def visit(hwnd: int, _lparam: int) -> bool:
        buffer = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, buffer, 512)
        if needle in buffer.value:
            matches.append((hwnd, buffer.value))
        return True

    user32.EnumWindows(visit, 0)
    return matches


def _find_window_by_title(
    user32: ctypes.WinDLL,
    needle: str,
    *,
    exclude: Container[int] = (),
    exact: str | None = None,
) -> int | None:
    """The window this capture opened, not merely one whose title looks right.

    A console window cannot be traced back to the process that asked for it -
    it belongs to the console host, whose own parent is the terminal
    application - so the title is all there is to go on. Two things make that
    safe enough: windows that were already there are skipped, and an exact
    title wins over a partial one. Without the first, a telnet session the
    operator left open on a host under scan gets photographed into the report
    instead of ours; without the second, "Telnet 10.0.0.4" also matches the
    window of "Telnet 10.0.0.40".
    """
    matches = [(hwnd, title) for hwnd, title in _find_windows_by_title(user32, needle) if hwnd not in exclude]
    if not matches:
        return None
    if exact is not None:
        for hwnd, title in matches:
            if title.strip() == exact:
                return hwnd
    return matches[0][0]


def _capture_window_png(hwnd: int) -> bytes | None:
    try:
        from PIL import Image
    except ImportError:
        return None

    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32
    rect = wintypes.RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        return None
    width, height = rect.right - rect.left, rect.bottom - rect.top
    if width <= 0 or height <= 0:
        return None

    window_dc = user32.GetWindowDC(hwnd)
    memory_dc = gdi32.CreateCompatibleDC(window_dc)
    bitmap = gdi32.CreateCompatibleBitmap(window_dc, width, height)
    gdi32.SelectObject(memory_dc, bitmap)
    try:
        if not user32.PrintWindow(hwnd, memory_dc, PW_RENDERFULLCONTENT):
            return None

        class BitmapInfoHeader(ctypes.Structure):
            _fields_ = [
                ("biSize", wintypes.DWORD),
                ("biWidth", ctypes.c_long),
                ("biHeight", ctypes.c_long),
                ("biPlanes", wintypes.WORD),
                ("biBitCount", wintypes.WORD),
                ("biCompression", wintypes.DWORD),
                ("biSizeImage", wintypes.DWORD),
                ("biXPelsPerMeter", ctypes.c_long),
                ("biYPelsPerMeter", ctypes.c_long),
                ("biClrUsed", wintypes.DWORD),
                ("biClrImportant", wintypes.DWORD),
            ]

        header = BitmapInfoHeader()
        header.biSize = ctypes.sizeof(header)
        header.biWidth = width
        # Negative height asks for a top-down image, matching Pillow's order.
        header.biHeight = -height
        header.biPlanes = 1
        header.biBitCount = 32
        header.biCompression = 0
        pixels = ctypes.create_string_buffer(width * height * 4)
        if not gdi32.GetDIBits(memory_dc, bitmap, 0, height, pixels, ctypes.byref(header), 0):
            return None
        data = bytes(pixels)
        # A window on a desktop that cannot paint returns solid black. That is
        # a capture failure wearing the shape of a success.
        if not any(data[index : index + 3] != b"\x00\x00\x00" for index in range(0, len(data), 4 * 997)):
            return None
        image = Image.frombuffer("RGBA", (width, height), data, "raw", "BGRA", 0, 1).convert("RGB")
        import io

        output = io.BytesIO()
        image.save(output, format="PNG", optimize=True)
        return output.getvalue()
    finally:
        gdi32.DeleteObject(bitmap)
        gdi32.DeleteDC(memory_dc)
        user32.ReleaseDC(hwnd, window_dc)


def _differs(pixel: tuple[int, ...], background: tuple[int, ...]) -> bool:
    # strict=False on purpose: a pane may arrive as RGB while the sampled
    # background carries an alpha channel, and the extra value decides nothing.
    return any(
        abs(int(value) - int(other)) > CONTENT_COLOUR_TOLERANCE
        for value, other in zip(pixel, background, strict=False)
    )


def has_content(png: bytes) -> bool:
    """Whether the capture shows anything at all.

    PrintWindow reports success and hands back a blank bitmap in cases the API
    gives no other signal for: a console host that will not render into a
    memory device context - the legacy console mode still common on Windows 10
    is one - and a session whose desktop is locked or disconnected. The picture
    then stores as a white or black rectangle labelled a real console capture,
    which is worse than having no capture at all: the caller would have fallen
    back to the drawn transcript, which at least carries the scan record.
    """
    try:
        from PIL import Image
    except ImportError:
        return True
    try:
        image = Image.open(io.BytesIO(png)).convert("RGB")
    except Exception:  # noqa: BLE001 - an image we cannot read is left to the caller.
        return True
    colours = image.getcolors(image.width * image.height)
    if colours is None:
        # More distinct colours than pixels counted means plenty of content.
        return True
    background = max(colours)[1]
    lit = sum(count for count, colour in colours if _differs(colour, background))
    return lit >= CONTENT_PIXELS_MINIMUM


def crop_to_content(png: bytes) -> bytes:
    """Trim the empty console below the last line of output.

    A console window is mostly unused space, and that space is what forces the
    report to scale the picture down - which is paid for by the text.
    """
    try:
        from PIL import Image
    except ImportError:
        return png
    try:
        image = Image.open(io.BytesIO(png)).convert("RGB")
    except Exception:  # noqa: BLE001 - an image we cannot read is returned untouched.
        return png
    # The colour at the very bottom is the window border, not the console
    # behind the text. Take the commonest colour of the lower half instead.
    lower = image.crop((0, image.height // 2, image.width, image.height))
    background = max(lower.getcolors(lower.width * lower.height) or [(0, (0, 0, 0))])[1]
    last_row = None
    for row in range(image.height - 1, -1, -1):
        line = image.crop((0, row, image.width, row + 1))
        if sum(1 for pixel in line.getdata() if _differs(pixel, background)) > CONTENT_ROW_PIXELS:
            last_row = row
            break
    if last_row is None or last_row >= image.height - CONTENT_MARGIN_PX - 1:
        return png
    cropped = image.crop((0, 0, image.width, min(image.height, last_row + CONTENT_MARGIN_PX)))
    output = io.BytesIO()
    cropped.save(output, format="PNG", optimize=True)
    return output.getvalue()


def compose_side_by_side(panes: list[bytes]) -> bytes | None:
    """Lay captured windows out left to right, the way a report shows them.

    The console proving the connection and the client sitting on it are two
    windows in the same moment, and separating them into two evidence files
    loses that they belong together.
    """
    try:
        from PIL import Image
    except ImportError:
        return None
    images = []
    for pane in panes:
        if not pane:
            continue
        images.append(Image.open(io.BytesIO(pane)).convert("RGB"))
    if not images:
        return None
    if len(images) == 1:
        return panes[0] if panes[0] else None
    width = sum(image.width for image in images) + COMPOSED_PANE_GAP * (len(images) - 1)
    height = max(image.height for image in images)
    canvas = Image.new("RGB", (width, height), COMPOSED_BACKGROUND)
    offset = 0
    for image in images:
        canvas.paste(image, (offset, 0))
        offset += image.width + COMPOSED_PANE_GAP
    output = io.BytesIO()
    canvas.save(output, format="PNG", optimize=True)
    return output.getvalue()


def telnet_executable() -> str | None:
    """Windows ships the telnet client switched off, so it is often absent."""
    return shutil.which("telnet")


def _remaining_width(console_pane: bytes) -> int:
    """What is left of the evidence cell once the console has its share."""
    try:
        from PIL import Image
    except ImportError:
        return COMPOSED_TARGET_WIDTH // 3
    try:
        console = Image.open(io.BytesIO(console_pane))
    except Exception:  # noqa: BLE001 - a pane we cannot measure gets a default.
        return COMPOSED_TARGET_WIDTH // 3
    return max(140, COMPOSED_TARGET_WIDTH - console.width - COMPOSED_PANE_GAP)


def _fit_pane_width(pane: bytes, maximum: int) -> bytes:
    """Scale a pane down to fit, keeping its proportions.

    The terminal will not open below a few hundred pixels however small a size
    it is asked for, so the client window arrives wider than there is room for.
    Scaling the picture is honest - it is the same window, smaller - where
    letting it run over is not: the report would shrink both panes to fit, and
    the console text would pay for the client's chrome.
    """
    try:
        from PIL import Image
    except ImportError:
        return pane
    try:
        image = Image.open(io.BytesIO(pane))
    except Exception:  # noqa: BLE001 - an unreadable pane is returned untouched.
        return pane
    if image.width <= maximum:
        return pane
    height = max(1, round(image.height * maximum / image.width))
    resized = image.convert("RGB").resize((maximum, height), Image.LANCZOS)
    output = io.BytesIO()
    resized.save(output, format="PNG", optimize=True)
    return output.getvalue()


def _telnet_pane_size(console_pane: bytes) -> tuple[int, int] | None:
    """Keep the client narrow beside the console, and no taller than it."""
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        console = Image.open(io.BytesIO(console_pane))
    except Exception:  # noqa: BLE001 - a pane we cannot measure gets no resize.
        return None
    return (max(320, round(console.width * TELNET_PANE_WIDTH_RATIO)), console.height)


def _capture_telnet_window(
    user32: ctypes.WinDLL, host: str, port: int, *, size: tuple[int, int] | None = None
) -> bytes | None:
    """Open a telnet client on the port and photograph its window.

    Unlike the console pane, telnet does write to the socket: it negotiates its
    own options before anything is displayed. It still stops well short of a
    login - nothing is typed into it and it is closed as soon as the picture is
    taken. Windows ships the client disabled, so its absence is ordinary and
    the console pane stands alone.
    """
    executable = telnet_executable()
    if executable is None:
        return None
    # Whatever already carries this title is not ours and never becomes ours.
    standing = {hwnd for hwnd, _ in _find_windows_by_title(user32, f"Telnet {host}")}
    try:
        process = subprocess.Popen(  # noqa: S603 - fixed executable, target passed as arguments.
            [executable, host, str(port)],
            creationflags=CREATE_NEW_CONSOLE,
        )
    except OSError:
        return None
    try:
        # The client titles its window after the host it dialled.
        token = f"Telnet {host}"
        hwnd = None
        deadline = time.monotonic() + TELNET_READY_TIMEOUT_S
        while time.monotonic() < deadline:
            hwnd = _find_window_by_title(user32, token, exclude=standing, exact=token)
            if hwnd is not None:
                # Sized down as it goes off screen. A terminal opens at the
                # width the user set for their own work, and two of those side
                # by side make an image so wide that the console text is
                # unreadable once the report shrinks it into a cell.
                width, height = size or (0, 0)
                user32.SetWindowPos(
                    hwnd,
                    0,
                    *OFFSCREEN_POSITION,
                    width,
                    height,
                    (SWP_NOSIZE if not size else 0) | SWP_NOZORDER | SWP_NOACTIVATE,
                )
                break
            if process.poll() is not None:
                return None
            time.sleep(CAPTURE_POLL_INTERVAL_S)
        if hwnd is None:
            return None
        time.sleep(CAPTURE_SETTLE_S)
        return _capture_window_png(hwnd)
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - the client ignored terminate.
            process.kill()


def capture_console_session(
    host: str, port: int, *, hold_s: float = 20.0, with_telnet: bool = True,
    require_connection: bool = True,
) -> bytes | None:
    """Run the session in a real console and return a PNG of that window.

    A telnet client is opened beside it when the system has one, and the two
    windows are photographed into a single image: the console proving the
    connection, the client sitting on it.

    Returns None when the connection did not open, unless `require_connection`
    is False. A picture of a console reading "Connected: False" beside a
    SYN_SENT line looks like evidence and proves nothing, and the caller
    replaces the stored evidence with whatever comes back - so a scan re-run
    from a machine that cannot reach the targets would overwrite good captures
    with failures.

    Returns None whenever the console cannot be photographed - no desktop, the
    window never appeared, the pixels came back blank - so the caller can fall
    back rather than store an empty image as evidence.
    """
    if not console_capture_supported():
        return None
    user32 = ctypes.windll.user32
    # The title is how the window is found, so it has to name this capture and
    # not merely this port: two scans of the same range hold the same host and
    # port, and a title they share would let one run photograph the other's
    # window - or close it.
    token = f"Netroach {host}:{port} {uuid.uuid4().hex[:8]}"
    with tempfile.TemporaryDirectory(prefix="netroach-console-") as tmp:
        done_path = Path(tmp) / f"{uuid.uuid4().hex}.done"
        script = build_connection_script(host, port, done_path=done_path, hold_s=hold_s, title=token)
        try:
            # No stdin/stdout/stderr arguments on purpose. Naming any of them
            # makes Python pass the parent's handles explicitly, and the child
            # then writes to those instead of the console it was just given -
            # the window appears, and it is blank.
            process = subprocess.Popen(  # noqa: S603 - fixed executable, target passed as data.
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                creationflags=CREATE_NEW_CONSOLE,
            )
        except OSError:
            return None
        try:
            hwnd = None
            deadline = time.monotonic() + CAPTURE_READY_TIMEOUT_S
            while time.monotonic() < deadline:
                if hwnd is None:
                    hwnd = _find_window_by_title(user32, token)
                    if hwnd is not None:
                        # Off the visible desktop the moment it is found, and
                        # sized while it is out there. A terminal opens at the
                        # width its owner works in, which is mostly empty space
                        # in a picture the report then shrinks to fit a cell -
                        # the emptiness is paid for by the text. The console
                        # host ignores the buffer-size API, so the window is
                        # resized directly.
                        user32.SetWindowPos(
                            hwnd,
                            0,
                            *OFFSCREEN_POSITION,
                            *CONSOLE_WINDOW_SIZE,
                            SWP_NOZORDER | SWP_NOACTIVATE,
                        )
                if done_path.exists() and hwnd is not None:
                    break
                if process.poll() is not None:
                    break
                time.sleep(CAPTURE_POLL_INTERVAL_S)
            if hwnd is None:
                return None
            if require_connection and not Path(f"{done_path}.ok").exists():
                return None
            time.sleep(CAPTURE_SETTLE_S)
            console_pane = _capture_window_png(hwnd)
            if console_pane is not None and not has_content(console_pane):
                # Blank, so there is nothing to prove. The caller falls back.
                return None
            if console_pane is not None:
                console_pane = crop_to_content(console_pane)
            if console_pane is None or not with_telnet:
                return console_pane
            telnet_pane = _capture_telnet_window(
                user32, host, port, size=_telnet_pane_size(console_pane)
            )
            if telnet_pane is not None:
                telnet_pane = crop_to_content(telnet_pane)
                telnet_pane = _fit_pane_width(
                    telnet_pane, _remaining_width(console_pane)
                )
            return compose_side_by_side([console_pane, telnet_pane or b""])
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover - the console ignored terminate.
                process.kill()
            # The done marker lives in the temporary directory, which goes with it.
            os.environ.pop("NETROACH_CONSOLE_CAPTURE_MARKER", None)
