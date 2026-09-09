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
import os
import subprocess
import sys
import tempfile
import time
import uuid
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


def console_capture_supported() -> bool:
    return sys.platform == "win32"


def build_connection_script(host: str, port: int, *, done_path: Path, hold_s: float = 20.0) -> str:
    """A session that proves the port answered, in the form a report shows it.

    The connection is still open while `netstat` runs, which is the whole point:
    the ESTABLISHED line naming this host and port is the evidence. Nothing is
    sent on the socket, so the exchange stops where every other capture here
    stops - before anything that could be taken for a login attempt.
    """
    safe_host = host.replace("'", "''")
    return (
        f"$Host.UI.RawUI.WindowTitle = 'Netroach {safe_host}:{port}'; "
        f"Write-Host 'PS> $tcp = [Net.Sockets.TcpClient]::new(); "
        f"$tcp.ConnectAsync(''{safe_host}'', {port}).Wait(5000)'; "
        f"$tcp = [Net.Sockets.TcpClient]::new(); "
        f"$connected = $tcp.ConnectAsync('{safe_host}', {port}).Wait(5000); "
        "Write-Host (\"Connected: \" + $connected); "
        f"Write-Host ''; Write-Host 'PS> netstat -an | Select-String \"{safe_host}\"'; "
        f"netstat -an | Select-String '{safe_host}' | Select-Object -First 8 | ForEach-Object "
        "{ Write-Host $_.Line.TrimEnd() }; "
        "Write-Host ''; Write-Host 'Stopped before username, password, key, AUTH, or login.'; "
        f"New-Item -ItemType File -Path '{done_path.as_posix()}' -Force | Out-Null; "
        f"Start-Sleep -Seconds {hold_s}"
    )


def _find_window_by_title(user32: ctypes.WinDLL, needle: str) -> int | None:
    matches: list[int] = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    def visit(hwnd: int, _lparam: int) -> bool:
        buffer = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, buffer, 512)
        if needle in buffer.value:
            matches.append(hwnd)
        return True

    user32.EnumWindows(visit, 0)
    return matches[0] if matches else None


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


def capture_console_session(host: str, port: int, *, hold_s: float = 20.0) -> bytes | None:
    """Run the session in a real console and return a PNG of that window.

    Returns None whenever the console cannot be photographed - no desktop, the
    window never appeared, the pixels came back blank - so the caller can fall
    back rather than store an empty image as evidence.
    """
    if not console_capture_supported():
        return None
    user32 = ctypes.windll.user32
    token = f"Netroach {host}:{port}"
    with tempfile.TemporaryDirectory(prefix="netroach-console-") as tmp:
        done_path = Path(tmp) / f"{uuid.uuid4().hex}.done"
        script = build_connection_script(host, port, done_path=done_path, hold_s=hold_s)
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
                        # Off the visible desktop the moment it is found: the
                        # operator should not have a window per port thrown in
                        # front of whatever they are doing.
                        user32.SetWindowPos(
                            hwnd,
                            0,
                            *OFFSCREEN_POSITION,
                            0,
                            0,
                            SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
                        )
                if done_path.exists() and hwnd is not None:
                    break
                if process.poll() is not None:
                    break
                time.sleep(CAPTURE_POLL_INTERVAL_S)
            if hwnd is None:
                return None
            time.sleep(CAPTURE_SETTLE_S)
            return _capture_window_png(hwnd)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover - the console ignored terminate.
                process.kill()
            # The done marker lives in the temporary directory, which goes with it.
            os.environ.pop("NETROACH_CONSOLE_CAPTURE_MARKER", None)
