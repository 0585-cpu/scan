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
import re
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
# How long to wait for the client to have something in it. A telnet banner is
# an option negotiation and then a round trip, so it arrives after the window.
TELNET_PROMPT_TIMEOUT_S = 8.0
# How long to keep waiting for the SSH window to stop changing, and how often
# to look. The prompt is several round trips away rather than a local redraw,
# so the picture is taken when the client stops writing rather than after a
# fixed wait that a slow target would outlast.
SSH_PROMPT_TIMEOUT_S = 12.0
SSH_PROMPT_POLL_S = 0.4
# How long the window stays empty after it is titled, so the capture always
# has a picture of "nothing yet" to compare against.
SSH_TITLE_SETTLE_MS = 700
# A line of console text changes thousands of pixels; the blinking cursor
# changes a couple of hundred. The thresholds sit between the two, so "the
# client wrote something" and "it has stopped writing" both survive the blink.
SSH_PROMPT_WRITTEN_PIXELS = 1_500
SSH_PROMPT_STILL_PIXELS = 400
# The telnet client draws chrome of its own before the target says anything, so
# its floor sits higher than the blink but lower than the SSH one. Measured on
# a window of CONSOLE_WINDOW_SIZE: the client alone changes about 994 pixels, a
# single line of prompt takes it to 1328-1418, and the cursor blink is 19. The
# margin either side is a few hundred pixels, which is why the test that holds
# this carries the measurements rather than the number alone.
TELNET_PROMPT_WRITTEN_PIXELS = 1_150
# Hosts reach the SSH pane inside a command string, so only what an address
# can contain is allowed through: anything else would be command text rather
# than a target.
_SAFE_HOST = re.compile(r"[A-Za-z0-9._:-]{1,253}")
# Wide enough for a netstat line and the command above it, and no wider.
# Sized so the console and the client together stay inside the report's
# evidence cell, where anything wider is scaled down.
CONSOLE_WINDOW_SIZE = (770, 300)
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


def _find_windows_by_title(user32: ctypes.CDLL, needle: str) -> list[tuple[int, str]]:
    matches: list[tuple[int, str]] = []

    # This helper runs only on Windows; the export is absent from POSIX stubs.
    winfunctype = getattr(ctypes, "WINFUNCTYPE")  # noqa: B009 - platform-specific export.

    @winfunctype(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    def visit(hwnd: int, _lparam: int) -> bool:
        buffer = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, buffer, 512)
        if needle in buffer.value:
            matches.append((hwnd, buffer.value))
        return True

    user32.EnumWindows(visit, 0)
    return matches


def _find_window_by_title(
    user32: ctypes.CDLL,
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
        return None
    return matches[0][0]


def capture_window_png(hwnd: int) -> bytes | None:
    try:
        from PIL import Image
    except ImportError:
        return None

    windll = getattr(ctypes, "windll")  # noqa: B009 - platform-specific export.
    user32 = windll.user32
    gdi32 = windll.gdi32
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

    Both panes keep the scale they were captured at, and nothing here is
    resized. Fitting the client pane on its own to whatever the console left
    over was what made it unreadable: the console kept its full size and the
    client was squeezed to a third of the width, so its glyphs came out half
    the size of the ones beside them, and the report then shrank the whole
    thing into a cell. Both windows are opened at the same size instead, which
    bounds the composition without either pane paying for the other.
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


def visible_window_handles(user32: ctypes.CDLL) -> set[int]:
    """Every window on this desktop that has a title and is on screen."""
    return {
        hwnd
        for hwnd, title in _find_windows_by_title(user32, "")
        if title.strip() and user32.IsWindowVisible(hwnd)
    }


def window_opened_since(user32: ctypes.CDLL, before: Container[int]) -> int | None:
    """The window that appeared after `before` was taken, if exactly one did.

    A browser window cannot be found by its title. The title is the page's, and
    an assessment meets the same device on host after host - two switches of
    one model produce two windows named identically, measured - so a title
    search cannot say which port it is looking at. What it can say is which
    window was not there a moment ago, which is enough because captures run one
    at a time.

    Exactly one, or none: if two appeared, something else on the desktop opened
    a window at the same moment and there is no way to tell which is ours. A
    capture of the operator's own window would be worse than no capture.
    """
    fresh = [hwnd for hwnd in visible_window_handles(user32) if hwnd not in before]
    return fresh[0] if len(fresh) == 1 else None


def _terminate_tree(process: subprocess.Popen) -> None:
    """End the console and whatever it started.

    `terminate` reaches the interpreter that owns the window and not the client
    it launched, so an SSH session sitting on a password prompt would outlive
    the capture - holding a connection open on the target, which is the one
    thing a capture must not leave behind.
    """
    try:
        subprocess.run(  # noqa: S603 - fixed executable, our own child's id.
            ["taskkill", "/T", "/F", "/PID", str(process.pid)],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - taskkill is always present.
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover - the tree ignored the kill.
        process.kill()


def telnet_executable() -> str | None:
    """Windows ships the telnet client switched off, so it is often absent."""
    return shutil.which("telnet")


def ssh_executable() -> str | None:
    """The OpenSSH client Windows ships, preferred over any other on PATH.

    Windows has carried this since 1809, so a capture needs nothing installed.
    It is taken by its own path first because a developer machine often has a
    second `ssh` earlier on PATH - Git's, for one - and the options below are
    written against this client's behaviour.
    """
    shipped = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "OpenSSH" / "ssh.exe"
    if shipped.is_file():
        return str(shipped)
    return shutil.which("ssh")


# What the capture logs in as. A fixed name rather than the operator's, which
# would otherwise be printed into every report; the server answers the same way
# either way, because SSH does not say whether a user exists.
SSH_CAPTURE_USER = "netroach-audit"
SSH_READY_TIMEOUT_S = 12.0
# Long enough for the prompt to be photographed, short enough that a server
# which refuses outright still leaves its refusal on screen.
SSH_HOLD_S = 30


def build_ssh_capture_script(
    host: str, port: int, *, title: str, known_hosts: Path, timeout_s: int = 8
) -> str:
    """A PowerShell session that opens SSH and stops at its login prompt.

    PowerShell rather than a batch file for the hold at the end. `timeout` ends
    immediately when the standard input it inherits is not a console, which a
    capture launched from a service or a piped process always has - the window
    was measured closing 2.7 seconds in, before the prompt it exists to
    photograph had arrived. `Start-Sleep` does not care, and the window title
    is set the same way the console pane sets its own.

    Every option here is about not authenticating. The capture is meant to
    reach the prompt and stop, so the operator's own credentials must not be
    able to carry it past one: an agent or a key in the default location would
    otherwise let the session succeed, and a capture that logged in is not
    evidence of an open port - it is an unauthorised login.

    `accept-new` against a throwaway known-hosts file is what lets this run
    unattended. It records nothing in the operator's own file, and it is the
    deliberate trade for the prompt: the host key is taken as given for one
    session, so the picture proves a service answered, not that it is the host
    it claims to be.
    """
    executable = ssh_executable()
    if executable is None:  # pragma: no cover - guarded by the caller.
        raise RuntimeError("no OpenSSH client")
    options = [
        "-p", str(int(port)),
        "-o", "StrictHostKeyChecking=accept-new",
        # Written to a file that goes away with the capture, so a scan never
        # edits the operator's known hosts.
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=NUL",
        # The three ways this could authenticate without anyone typing.
        "-o", "PubkeyAuthentication=no",
        "-o", "GSSAPIAuthentication=no",
        "-o", "IdentityAgent=none",
        "-o", "PreferredAuthentications=keyboard-interactive,password",
        "-o", "NumberOfPasswordPrompts=1",
        "-o", f"ConnectTimeout={int(timeout_s)}",
        f"{SSH_CAPTURE_USER}@{host}",
    ]
    arguments = ", ".join("'" + part.replace("'", "''") + "'" for part in options)
    safe_title = title.replace("'", "''")
    safe_executable = executable.replace("'", "''")
    return (
        f"$Host.UI.RawUI.WindowTitle = '{safe_title}'; "
        # Titled, then held empty for a moment before the client runs. The
        # capture decides the prompt has arrived by comparing against the
        # window as it first found it, and against a target on the same machine
        # the client can print its prompt inside the time it takes to notice
        # the window at all - which made the first picture the reference for
        # "nothing has happened yet" and every later one look unchanged.
        f"Start-Sleep -Milliseconds {SSH_TITLE_SETTLE_MS}; "
        f"& '{safe_executable}' @({arguments}); "
        "Write-Host ''; "
        "Write-Host '[stopped before sending a username, password, or key]'; "
        f"Start-Sleep -Seconds {SSH_HOLD_S}"
    )


def _capture_when_settled(
    hwnd: int,
    *,
    deadline: float,
    written_pixels: int = SSH_PROMPT_WRITTEN_PIXELS,
    unwritten_is_evidence: bool = False,
) -> bytes | None:
    """Photograph the window once it stops changing, or when time runs out.

    A fixed wait cannot serve both ends of this. The prompt is several round
    trips away - banner, key exchange, then the authentication methods - so on
    a slow target a short wait photographs a handshake in progress, and a wait
    long enough for that target makes every fast one pay for it.

    Settled means two things, not one: the picture stopped changing, and it is
    no longer the empty window this started from. Without the second, a target
    that takes four seconds to begin its handshake reads as settled
    immediately - measured returning a title bar and a cursor - because a
    window with nothing in it does not change either.

    Both comparisons count changed pixels rather than testing the bytes,
    because the console draws a blinking cursor. Byte equality made an empty
    window look settled whenever the blink happened to land the same way
    twice: a target eight seconds from its banner was photographed at under
    four, showing a title bar and nothing else.
    """
    empty = capture_window_png(hwnd)
    previous: bytes | None = None
    while time.monotonic() < deadline:
        time.sleep(SSH_PROMPT_POLL_S)
        current = capture_window_png(hwnd)
        if current is None:
            # The window went before it settled; whatever was last read is all
            # there is, and it is better than nothing.
            break
        written = _changed_pixels(current, empty) > written_pixels
        if written and _changed_pixels(current, previous) <= SSH_PROMPT_STILL_PIXELS:
            return current
        previous = current
    # Out of time, or the window closed. Return what was last seen rather than
    # nothing: a client that refused outright has already written its reason.
    last = previous if previous is not None else empty
    if last is None:
        return None
    if _changed_pixels(last, empty) <= written_pixels:
        # The target wrote nothing in the time allowed. Two different things
        # look like this and they must not share an outcome: a port that
        # completes the handshake and then says nothing is a finding, and the
        # window showing a client sitting connected to it is the evidence for
        # it; a capture that simply did not work - no desktop, a console host
        # that will not render - is not evidence of anything and must never be
        # stored. `has_content` is what tells them apart.
        if unwritten_is_evidence and has_content(last):
            return last
        return None
    return last


def _changed_pixels(current: bytes | None, other: bytes | None) -> int:
    """How many pixels differ between two captures of the same window."""
    if current is None or other is None:
        return 1 << 30
    try:
        from PIL import Image, ImageChops
    except ImportError:  # pragma: no cover - Pillow is a hard dependency here.
        return 1 << 30
    with Image.open(io.BytesIO(current)) as left, Image.open(io.BytesIO(other)) as right:
        if left.size != right.size:
            return 1 << 30
        difference = ImageChops.difference(left.convert("RGB"), right.convert("RGB")).convert("L")
    histogram = difference.histogram()
    return sum(histogram[CONTENT_COLOUR_TOLERANCE + 1 :])


def _capture_ssh_window(
    user32: ctypes.CDLL, host: str, port: int, *, size: tuple[int, int] | None = None
) -> bytes | None:
    """Open the OpenSSH client on the port and photograph its login prompt.

    Unlike the telnet client, this one is given a console title of our own, so
    the window is found by a name no other capture shares - the port is in it,
    and so is a token unique to this run.
    """
    if ssh_executable() is None:
        return None
    if not _SAFE_HOST.fullmatch(host):
        return None
    token = f"Netroach SSH {host}:{port} {uuid.uuid4().hex[:8]}"
    with tempfile.TemporaryDirectory(prefix="netroach-ssh-") as tmp:
        script = build_ssh_capture_script(
            host, port, title=token, known_hosts=Path(tmp) / "known_hosts"
        )
        try:
            # No stdin/stdout/stderr arguments, for the reason the console pane
            # gives: naming any of them hands the child the parent's handles
            # and it writes to those instead of the console it was given.
            process = subprocess.Popen(  # noqa: S603 - fixed executable, target validated above.
                ["powershell", "-NoProfile", "-Command", script],
                creationflags=CREATE_NEW_CONSOLE,
            )
        except OSError:
            return None
        try:
            hwnd = None
            deadline = time.monotonic() + SSH_READY_TIMEOUT_S
            while time.monotonic() < deadline:
                hwnd = _find_window_by_title(user32, token, exact=token)
                if hwnd is not None:
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
            return _capture_when_settled(hwnd, deadline=time.monotonic() + SSH_PROMPT_TIMEOUT_S)
        finally:
            _terminate_tree(process)


def build_telnet_capture_script(host: str, port: int, *, title: str) -> str:
    """A session that titles its window, waits, and only then opens telnet.

    The wait is the point. The capture decides the banner has arrived by
    comparing the window against how it first found it, so that first picture
    has to be of nothing yet. Launching the client directly gave it no such
    moment: measured against a service on this machine, the window was found
    with the banner already drawn, every later picture matched it to within the
    cursor blink - 19 pixels - and the pane came back empty. The SSH pane has
    always held its window this way and says so; the telnet pane was given the
    same settling without the thing it rests on.

    The client retitles the window as soon as it connects, which is why the
    window is found by this token rather than by the client's own title: two
    scans of one host would otherwise share a title, and one could photograph
    the other's window.
    """
    safe_host = host.replace("'", "''")
    safe_title = title.replace("'", "''")
    executable = telnet_executable()
    if executable is None:  # pragma: no cover - guarded by the caller.
        raise RuntimeError("no telnet client")
    return (
        f"$Host.UI.RawUI.WindowTitle = '{safe_title}'; "
        f"Start-Sleep -Milliseconds {SSH_TITLE_SETTLE_MS}; "
        f"& '{executable}' '{safe_host}' '{int(port)}'; "
        f"Start-Sleep -Seconds {SSH_HOLD_S}"
    )


def _capture_telnet_window(
    user32: ctypes.CDLL, host: str, port: int, *, size: tuple[int, int] | None = None
) -> bytes | None:
    """Open a telnet client on the port and photograph its window.

    Unlike the console pane, telnet does write to the socket: it negotiates its
    own options before anything is displayed. It still stops well short of a
    login - nothing is typed into it and it is closed as soon as the picture is
    taken. Windows ships the client disabled, so its absence is ordinary and
    the console pane stands alone.
    """
    if telnet_executable() is None:
        return None
    token = f"Netroach telnet {host}:{port} {uuid.uuid4().hex[:8]}"
    script = build_telnet_capture_script(host, port, title=token)
    try:
        process = subprocess.Popen(  # noqa: S603 - fixed executable, target passed as data.
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            creationflags=CREATE_NEW_CONSOLE,
        )
    except OSError:
        return None
    try:
        hwnd = None
        deadline = time.monotonic() + TELNET_READY_TIMEOUT_S
        while time.monotonic() < deadline:
            hwnd = _find_window_by_title(user32, token, exact=token)
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
        # A fixed 0.35s wait photographed the window before the target had
        # written into it: measured against a switch, the pane came back
        # holding its title bar and nothing else, where the banner and
        # "User Name:" were the evidence. The client negotiates its options
        # first and the banner is a round trip behind that, so the wait is for
        # content rather than for a duration - which is what the SSH pane
        # beside it has always done.
        # A telnet port that answers the handshake and sends no banner is
        # worth a picture: the client is shown connected to it with nothing
        # coming back, which is what the operator would see by hand.
        return _capture_when_settled(
            hwnd,
            deadline=time.monotonic() + TELNET_PROMPT_TIMEOUT_S,
            written_pixels=TELNET_PROMPT_WRITTEN_PIXELS,
            unwritten_is_evidence=True,
        )
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - the client ignored terminate.
            process.kill()


# Services whose conversation is lines of text a person can read, so a telnet
# client sitting on the port photographs the real exchange - the greeting, the
# capabilities, the login prompt. This is how an administrator checks them by
# hand, and the picture is the same one.
_LINE_PROTOCOL_SERVICES = frozenset({
    "telnet", "pop3", "imap", "smtp", "submission", "ftp",
    "nntp", "irc", "redis", "memcached",
})
# Ports to fall back on when nothing was identified, so the common cases still
# get the right client without a service name to go by.
_CLIENT_PANE_PORTS = {22: "ssh", 23: "telnet"}
# What the engine reports when it read the port and could not name it. That is
# the absence of an identification, not an identification of something: a
# controller answering "ACME Controller v2.1 / Enter PIN:" is named this, and
# treating the word as a service name meant the port fell through the fallback
# and got no client pane at all - measured, with detection on, which is the
# ordinary setting. Detection off reports nothing and did take the fallback,
# so the same port was photographed two different ways depending on a tick
# that is not about this.
_UNIDENTIFIED = {"", "unknown"}
# Where opening a client has a physical effect rather than a logged one. A raw
# print port takes what arrives as the job to print, and telnet opens by
# sending its option negotiation, so the fallback that points telnet at
# anything unidentified would print a page. Mirrors the engine's list.
_WRITE_UNSAFE_PORTS = frozenset({515, 9100, 9101, 9102, 9103, 9104, 9105, 9106, 9107})


def client_pane_kind(port: int, service: str | None) -> str | None:
    """Which client, if any, belongs beside the console for this port.

    The console pane proves the port answered; the client pane shows what the
    service says to someone arriving on it. Which client that is follows the
    service rather than the port number, so SSH moved off 22 still gets an SSH
    pane, and the port is only the fallback when nothing was identified.

    A service that speaks in lines gets the telnet client, because the picture
    it makes is the exchange itself. One that does not gets no client pane at
    all: pointing telnet at TLS or at a binary protocol photographs the bytes
    as mojibake, which looks like evidence and reads as nothing. Those keep the
    console pane, which for a TLS service already carries the handshake, its
    protocol version and its cipher - and a web port has its browser shot.
    """
    if port in _WRITE_UNSAFE_PORTS:
        return None
    named = (service or "").strip().lower()
    if named in _UNIDENTIFIED:
        # Nothing identified: try telnet, which is what this did for every
        # service before any of them were told apart, and what an operator
        # does by hand with a port they do not recognise. A service that was
        # identified and does not speak in lines still gets no client pane -
        # that is the judgement below, and it is unchanged.
        return _CLIENT_PANE_PORTS.get(port, "telnet")
    if named == "ssh":
        return "ssh"
    return "telnet" if named in _LINE_PROTOCOL_SERVICES else None


def capture_console_session(
    host: str, port: int, *, hold_s: float = 20.0, with_telnet: bool = True,
    require_connection: bool = True, service: str | None = None,
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
    user32 = getattr(ctypes, "windll").user32  # noqa: B009 - guarded Windows-only export.
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
            console_pane = capture_window_png(hwnd)
            if console_pane is not None and not has_content(console_pane):
                # Blank, so there is nothing to prove. The caller falls back.
                return None
            if console_pane is not None:
                console_pane = crop_to_content(console_pane)
            if console_pane is None or not with_telnet:
                return console_pane
            kind = client_pane_kind(port, service)
            # The same window size as the console beside it, so both panes
            # render at the same font size and the composition needs no
            # scaling that falls on one of them. A third of the console's
            # width - what this asked for before - is about forty-five
            # columns: the banner wrapped, and what was left was then scaled
            # to half the height of the text next to it.
            if kind == "ssh":
                client_pane = _capture_ssh_window(
                    user32, host, port, size=CONSOLE_WINDOW_SIZE
                )
            elif kind == "telnet":
                client_pane = _capture_telnet_window(
                    user32, host, port, size=CONSOLE_WINDOW_SIZE
                )
            else:
                client_pane = None
            # The client pane is not cropped. Cropping it trims the empty
            # terminal below its last line, and where the target sent nothing
            # that emptiness is the whole content: a window showing a client
            # sitting connected to a port that never spoke cropped down to its
            # own title bar, 52 pixels against the console's 250, which reads
            # as a broken picture rather than as a finding. Both windows are
            # opened at one size, so the composition is bounded either way.
            return compose_side_by_side([console_pane, client_pane or b""])
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover - the console ignored terminate.
                process.kill()
            # The done marker lives in the temporary directory, which goes with it.
            os.environ.pop("NETROACH_CONSOLE_CAPTURE_MARKER", None)
