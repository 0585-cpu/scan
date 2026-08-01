from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

MAX_EVIDENCE_BYTES = 10 * 1024 * 1024
DEFAULT_SCREENSHOT_TIMEOUT_MS = 8_000
DEFAULT_SCREENSHOT_MAX = 20
SCREENSHOT_WIDTH = 800
SCREENSHOT_HEIGHT = 600

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
    if maximum < 1 or maximum > 100:
        raise ValueError("screenshot maximum must be between 1 and 100")
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for result in results:
        host = str(result.get("host") or "")
        protocol = str(result.get("protocol") or "tcp").lower()
        try:
            port = int(result.get("port"))
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
    if maximum < 1 or maximum > 100:
        raise ValueError("screenshot maximum must be between 1 and 100")
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for result in results:
        host = str(result.get("host") or "")
        protocol = str(result.get("protocol") or "tcp").lower()
        try:
            port = int(result.get("port"))
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


def is_web_result(result: Mapping[str, Any]) -> bool:
    service = str(result.get("service_name") or "").lower()
    try:
        port = int(result.get("port"))
    except (TypeError, ValueError):
        return False
    return service.startswith("http") or service in {"https", "tls"} or port in _WEB_PORTS


def web_result_url(result: Mapping[str, Any]) -> str:
    host = str(result.get("host") or "")
    port = int(result.get("port"))
    service = str(result.get("service_name") or "").lower()
    scheme = "https" if "https" in service or service == "tls" or port in _HTTPS_PORTS else "http"
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default_port = 443 if scheme == "https" else 80
    port_suffix = "" if port == default_port else f":{port}"
    return f"{scheme}://{display_host}{port_suffix}/"


def capture_web_screenshots(
    results: Iterable[Mapping[str, Any]],
    *,
    store: Callable[[Mapping[str, Any], bytes, str, str], object],
    timeout_ms: int = DEFAULT_SCREENSHOT_TIMEOUT_MS,
    maximum: int = DEFAULT_SCREENSHOT_MAX,
    should_stop: Callable[[], bool] | None = None,
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
            browser = playwright.chromium.launch(headless=True)
            try:
                for result in candidates:
                    if should_stop and should_stop():
                        break
                    url = web_result_url(result)
                    host = str(result["host"]).strip("[]").lower()
                    context = browser.new_context(
                        ignore_https_errors=True,
                        viewport={"width": SCREENSHOT_WIDTH, "height": SCREENSHOT_HEIGHT},
                    )
                    try:
                        # allowed_host is bound at definition time on purpose:
                        # this handler is the confinement to the scanned host,
                        # and it must not follow a later loop iteration.
                        def route_request(route: Any, allowed_host: str = host) -> None:
                            request_url = urlparse(route.request.url)
                            request_host = (request_url.hostname or "").lower()
                            if request_url.scheme in {"about", "blob", "data"} or request_host == allowed_host:
                                route.continue_()
                            else:
                                route.abort()

                        context.route("**/*", route_request)
                        page = context.new_page()
                        page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                        page.add_style_tag(
                            content="*,*::before,*::after{animation:none!important;transition:none!important}"
                        )
                        image = page.screenshot(type="png", full_page=False)
                        filename_host = re.sub(r"[^A-Za-z0-9_.-]+", "_", host)
                        store(result, image, f"{filename_host}_{result['port']}.png", url)
                        captured += 1
                    except Exception as exc:  # noqa: BLE001 - one failed web service must not stop other captures.
                        errors.append(f"{url}: {str(exc)[:240]}")
                    finally:
                        context.close()
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
    port = int(result.get("port"))
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


def capture_terminal_transcripts(
    results: Iterable[Mapping[str, Any]],
    *,
    store: Callable[[Mapping[str, Any], bytes, str, str | None], object],
    timeout_ms: int = DEFAULT_SCREENSHOT_TIMEOUT_MS,
    maximum: int = DEFAULT_SCREENSHOT_MAX,
    should_stop: Callable[[], bool] | None = None,
) -> ScreenshotCaptureSummary:
    candidates = automatic_evidence_candidates(results, maximum=maximum)
    captured = 0
    errors: list[str] = []
    for result in candidates:
        if should_stop and should_stop():
            break
        host = str(result.get("host") or "")
        try:
            transcript = run_powershell_diagnostic(result, timeout_ms=timeout_ms)
            image = render_terminal_transcript(result, transcript)
            filename_host = re.sub(r"[^A-Za-z0-9_.-]+", "_", host.strip("[]"))
            source_url = web_result_url(result) if is_web_result(result) else None
            store(
                result,
                image,
                f"{filename_host}_{result.get('port')}_{result.get('protocol', 'tcp')}_powershell.png",
                source_url,
            )
            captured += 1
        except Exception as exc:  # noqa: BLE001 - one malformed result must not stop other transcripts.
            errors.append(f"{host}:{result.get('port')}: {str(exc)[:240]}")
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
    store: Callable[[Mapping[str, Any], bytes, str, str | None, str], object],
    timeout_ms: int = DEFAULT_SCREENSHOT_TIMEOUT_MS,
    maximum: int = DEFAULT_SCREENSHOT_MAX,
    should_stop: Callable[[], bool] | None = None,
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
    ) -> object:
        stored = store(result, data, file_name, source_url, "web_screenshot")
        captured_keys.add(_result_key(result))
        return stored

    web_summary = capture_web_screenshots(
        candidates,
        store=store_web,
        timeout_ms=timeout_ms,
        maximum=maximum,
        should_stop=should_stop,
    )
    remaining = [result for result in candidates if _result_key(result) not in captured_keys]

    def store_transcript(
        result: Mapping[str, Any],
        data: bytes,
        file_name: str,
        source_url: str | None,
    ) -> object:
        stored = store(result, data, file_name, source_url, "terminal_transcript")
        captured_keys.add(_result_key(result))
        return stored

    if remaining and not (should_stop and should_stop()):
        terminal_summary = capture_terminal_transcripts(
            remaining,
            store=store_transcript,
            timeout_ms=timeout_ms,
            maximum=len(remaining),
            should_stop=should_stop,
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
        int(result.get("port")),
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
        port = int(result.get("port"))
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
            Write-Output 'Client authentication prompt (capture boundary):'
            Write-Output 'login as:'
            Write-Output '[stopped before sending an SSH username, key, or password]'
        }
        'telnet' {
            if (-not $initial) { Write-Output 'No Telnet login prompt arrived before the read timeout.' }
            Write-Output '[stopped before sending Telnet input]'
        }
        'ftp' {
            Send-NetroachPreAuthCommand -Stream $Stream -Text "FEAT`r`n"
            $response = Read-NetroachResponse -Stream $Stream -TimeoutMs $ReadTimeoutMs
            Show-NetroachResponse -Label 'FTP FEAT response:' -Text $response
            Write-Output ("User (" + $ComputerName + "):")
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
            Write-Output 'USER:'
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
