from __future__ import annotations

import argparse
import hashlib
import io
import platform
import re
import tarfile
import zipfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a portable Scaprobe artifact.")
    parser.add_argument("--output-dir", default="dist")
    parser.add_argument("--cargo-target-dir", default="target")
    parser.add_argument("--engine-profile", default="release", choices=["release", "portable", "debug"])
    parser.add_argument("--require-engine", action="store_true", help="fail if scaprobe-engine is not present")
    parser.add_argument(
        "--archive-format",
        default="auto",
        choices=["auto", "zip", "tar.gz"],
        help="artifact format; auto uses zip for Windows targets and tar.gz for macOS/Linux targets",
    )
    parser.add_argument("--target-platform", help="artifact platform label; defaults to the current OS/architecture")
    parser.add_argument("--no-checksum", action="store_true", help="do not write a .sha256 sidecar")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    output_dir = root / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    platform_name = args.target_platform or current_platform_name()
    suffix = ".exe" if platform_name.lower().startswith("windows-") else ""
    profile_dir = "debug" if args.engine_profile == "debug" else args.engine_profile
    engine_root = Path(args.cargo_target_dir)
    if not engine_root.is_absolute():
        engine_root = root / engine_root
    engine = engine_root / profile_dir / f"scaprobe-engine{suffix}"
    if args.require_engine and not engine.is_file():
        raise SystemExit(f"engine binary not found: {engine}")
    archive_format = resolve_archive_format(args.archive_format, platform_name)
    extension = ".zip" if archive_format == "zip" else ".tar.gz"
    archive = output_dir / f"scaprobe-{read_app_version(root)}-{platform_name}{extension}"

    if archive_format == "zip":
        write_zip_archive(root=root, archive=archive, engine=engine)
    else:
        write_tar_archive(root=root, archive=archive, engine=engine)
    if not args.no_checksum:
        checksum = write_sha256_checksum(archive)
        print(checksum)
    print(archive)
    return 0


def current_platform_name() -> str:
    return f"{platform.system().lower()}-{platform.machine().lower()}"


def resolve_archive_format(archive_format: str, platform_name: str) -> str:
    if archive_format != "auto":
        return archive_format
    return "zip" if platform_name.lower().startswith("windows-") else "tar.gz"


def read_app_version(root: Path) -> str:
    version_file = root / "netprobe" / "version.py"
    text = version_file.read_text(encoding="utf-8")
    match = re.search(r"^__version__\s*=\s*['\"]([^'\"]+)['\"]", text, flags=re.MULTILINE)
    if not match:
        raise SystemExit(f"could not read app version from {version_file}")
    return match.group(1)


def iter_payload_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for directory in ["netprobe", "postman", "docs", "tools", "desktop"]:
        for path in (root / directory).rglob("*"):
            ignored_parts = {"__pycache__", "node_modules", "target", "dist"}
            staged_desktop_binary = (
                path.suffix == ".exe"
                and path.parent == root / "desktop" / "src-tauri" / "resources" / "bin"
            )
            staged_playwright_browser = path.is_relative_to(
                root / "desktop" / "src-tauri" / "resources" / "playwright"
            )
            if (
                path.is_file()
                and not staged_desktop_binary
                and not staged_playwright_browser
                and not (ignored_parts & set(path.parts))
                and path.suffix != ".pyc"
            ):
                files.append(path)
    for filename in ["README.md", "CHANGELOG.md", "pyproject.toml", "requirements.txt"]:
        files.append(root / filename)
    return sorted(files)


def write_zip_archive(*, root: Path, archive: Path, engine: Path) -> None:
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in iter_payload_files(root):
            zf.write(path, path.relative_to(root))
        write_zip_launcher_scripts(zf)
        if engine.is_file():
            zf.write(engine, Path("bin") / engine.name)
        else:
            zf.writestr("bin/ENGINE_NOT_INCLUDED.txt", engine_missing_note())


def write_tar_archive(*, root: Path, archive: Path, engine: Path) -> None:
    with tarfile.open(archive, "w:gz") as tf:
        for path in iter_payload_files(root):
            add_tar_file(tf, path, path.relative_to(root))
        write_tar_text(tf, "Start-Scaprobe.cmd", windows_quick_start_text(), mode=0o644)
        write_tar_text(tf, "bin/scaprobe", posix_launcher_text(), mode=0o755)
        write_tar_text(tf, "bin/scaprobe.cmd", windows_launcher_text(), mode=0o644)
        write_tar_text(tf, "bin/setup.cmd", windows_setup_text(), mode=0o644)
        write_tar_text(tf, "bin/start-desktop.cmd", windows_desktop_text(), mode=0o644)
        if engine.is_file():
            add_tar_file(tf, engine, Path("bin") / engine.name, mode=0o755)
        else:
            write_tar_text(tf, "bin/ENGINE_NOT_INCLUDED.txt", engine_missing_note(), mode=0o644)


def add_tar_file(tf: tarfile.TarFile, path: Path, arcname: Path, mode: int | None = None) -> None:
    info = tf.gettarinfo(str(path), arcname=str(arcname).replace("\\", "/"))
    if mode is not None:
        info.mode = mode
    with path.open("rb") as fh:
        tf.addfile(info, fh)


def write_tar_text(tf: tarfile.TarFile, arcname: str, text: str, *, mode: int) -> None:
    data = text.encode("utf-8")
    info = tarfile.TarInfo(arcname)
    info.size = len(data)
    info.mode = mode
    tf.addfile(info, io.BytesIO(data))


def write_sha256_checksum(archive: Path) -> Path:
    digest = hashlib.sha256()
    with archive.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    checksum = archive.with_name(f"{archive.name}.sha256")
    checksum.write_text(f"{digest.hexdigest()}  {archive.name}\n", encoding="utf-8")
    return checksum


def engine_missing_note() -> str:
    return (
        "Build with: cargo build --release -p scaprobe-engine\n"
        "On locked-down Windows systems, use: cargo build --profile portable -p scaprobe-engine\n"
    )


def posix_launcher_text() -> str:
    return (
        "#!/usr/bin/env sh\n"
        'SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"\n'
        'ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"\n'
        'cd "$ROOT" || exit 1\n'
        'PATH="$SCRIPT_DIR:$PATH" PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" exec "${PYTHON:-python3}" -m netprobe "$@"\n'
    )


def windows_launcher_text() -> str:
    return (
        "@echo off\r\n"
        "set SCRIPT_DIR=%~dp0\r\n"
        "set PYTHONPATH=%SCRIPT_DIR%..;%PYTHONPATH%\r\n"
        "set PATH=%SCRIPT_DIR%;%PATH%\r\n"
        "pushd \"%SCRIPT_DIR%..\"\r\n"
        "if defined PYTHON (\r\n"
        "  \"%PYTHON%\" -m netprobe %*\r\n"
        ") else if exist \"%SCRIPT_DIR%..\\.venv\\Scripts\\python.exe\" (\r\n"
        "  \"%SCRIPT_DIR%..\\.venv\\Scripts\\python.exe\" -m netprobe %*\r\n"
        ") else (\r\n"
        "  py -3 -m netprobe %*\r\n"
        ")\r\n"
        "set EXIT_CODE=%ERRORLEVEL%\r\n"
        "popd\r\n"
        "exit /b %EXIT_CODE%\r\n"
    )


def windows_setup_text() -> str:
    return (
        "@echo off\r\n"
        "setlocal\r\n"
        "set \"ROOT=%~dp0..\"\r\n"
        "set \"VENV_PYTHON=%ROOT%\\.venv\\Scripts\\python.exe\"\r\n"
        "where py >nul 2>nul\r\n"
        "if errorlevel 1 (\r\n"
        "  echo Python launcher not found. Install Python 3.10 or newer, then run setup.cmd again.\r\n"
        "  exit /b 1\r\n"
        ")\r\n"
        "py -3 -c \"import sys; raise SystemExit(not (sys.version_info.major == 3 and sys.version_info.minor in range(10, 100)))\"\r\n"
        "if errorlevel 1 (\r\n"
        "  echo Scaprobe requires Python 3.10 or newer.\r\n"
        "  exit /b 1\r\n"
        ")\r\n"
        "if not exist \"%VENV_PYTHON%\" (\r\n"
        "  echo Creating isolated Python environment...\r\n"
        "  py -3 -m venv \"%ROOT%\\.venv\"\r\n"
        "  if errorlevel 1 exit /b 1\r\n"
        ")\r\n"
        "echo Installing Scaprobe dependencies...\r\n"
        "\"%VENV_PYTHON%\" -m pip install -r \"%ROOT%\\requirements.txt\"\r\n"
        "if errorlevel 1 exit /b 1\r\n"
        "if /I \"%~1\"==\"--screenshots\" (\r\n"
        "  echo Installing Playwright and Chromium for automatic web evidence...\r\n"
        "  \"%VENV_PYTHON%\" -m pip install playwright\r\n"
        "  if errorlevel 1 exit /b 1\r\n"
        "  \"%VENV_PYTHON%\" -m playwright install chromium\r\n"
        "  if errorlevel 1 exit /b 1\r\n"
        ")\r\n"
        "call \"%~dp0scaprobe.cmd\" serve --check\r\n"
        "if errorlevel 1 exit /b 1\r\n"
        "echo Setup complete. Run bin\\start-desktop.cmd to open Scaprobe.\r\n"
        "endlocal\r\n"
    )


def windows_desktop_text() -> str:
    return (
        "@echo off\r\n"
        "set \"ROOT=%~dp0..\"\r\n"
        "if not exist \"%ROOT%\\.venv\\Scripts\\python.exe\" (\r\n"
        "  echo Scaprobe is not set up. Run bin\\setup.cmd first.\r\n"
        "  exit /b 1\r\n"
        ")\r\n"
        "call \"%~dp0scaprobe.cmd\" desktop --host 127.0.0.1 --port 8765\r\n"
    )


def windows_quick_start_text() -> str:
    return (
        "@echo off\r\n"
        "setlocal\r\n"
        "title Scaprobe\r\n"
        "set \"ROOT=%~dp0\"\r\n"
        "set \"VENV_PYTHON=%ROOT%.venv\\Scripts\\python.exe\"\r\n"
        "if /I \"%~1\"==\"--start\" goto start\r\n"
        "if /I \"%~1\"==\"--screenshots\" goto screenshots\r\n"
        "if /I \"%~1\"==\"--setup\" goto setup_only\r\n"
        "if /I \"%~1\"==\"--diagnostics\" goto diagnostics\r\n"
        "if not \"%~1\"==\"\" goto usage\r\n"
        ":menu\r\n"
        "cls\r\n"
        "echo ========================================\r\n"
        "echo             Scaprobe Launcher\r\n"
        "echo ========================================\r\n"
        "echo [1] Start Scaprobe\r\n"
        "echo [2] Install screenshot support and start\r\n"
        "echo [3] Install or update Scaprobe only\r\n"
        "echo [4] Run diagnostics\r\n"
        "echo [0] Exit\r\n"
        "echo.\r\n"
        "choice /C 12340 /N /M \"Select an option: \"\r\n"
        "if errorlevel 5 goto exit_launcher\r\n"
        "if errorlevel 4 goto diagnostics\r\n"
        "if errorlevel 3 goto setup_only\r\n"
        "if errorlevel 2 goto screenshots\r\n"
        "if errorlevel 1 goto start\r\n"
        ":start\r\n"
        "if exist \"%VENV_PYTHON%\" goto launch\r\n"
        "echo First run detected. Setting up Scaprobe...\r\n"
        "call \"%ROOT%bin\\setup.cmd\"\r\n"
        "if errorlevel 1 goto setup_failed\r\n"
        "goto launch\r\n"
        ":screenshots\r\n"
        "echo Installing or updating Scaprobe with screenshot support...\r\n"
        "call \"%ROOT%bin\\setup.cmd\" --screenshots\r\n"
        "if errorlevel 1 goto setup_failed\r\n"
        "goto launch\r\n"
        ":setup_only\r\n"
        "echo Installing or updating Scaprobe...\r\n"
        "call \"%ROOT%bin\\setup.cmd\"\r\n"
        "if errorlevel 1 goto setup_failed\r\n"
        "echo.\r\n"
        "echo Setup completed successfully.\r\n"
        "if not \"%~1\"==\"\" goto exit_launcher\r\n"
        "pause\r\n"
        "goto menu\r\n"
        ":diagnostics\r\n"
        "if exist \"%VENV_PYTHON%\" goto run_diagnostics\r\n"
        "echo Scaprobe must be set up before diagnostics can run.\r\n"
        "call \"%ROOT%bin\\setup.cmd\"\r\n"
        "if errorlevel 1 goto setup_failed\r\n"
        "set \"EXIT_CODE=0\"\r\n"
        "goto diagnostics_complete\r\n"
        ":run_diagnostics\r\n"
        "call \"%ROOT%bin\\scaprobe.cmd\" serve --check\r\n"
        "set \"EXIT_CODE=%ERRORLEVEL%\"\r\n"
        ":diagnostics_complete\r\n"
        "if not \"%~1\"==\"\" goto exit_with_code\r\n"
        "echo.\r\n"
        "pause\r\n"
        "goto menu\r\n"
        ":launch\r\n"
        "echo Starting Scaprobe...\r\n"
        "call \"%ROOT%bin\\start-desktop.cmd\"\r\n"
        "set \"EXIT_CODE=%ERRORLEVEL%\"\r\n"
        "goto exit_with_code\r\n"
        ":setup_failed\r\n"
        "echo.\r\n"
        "echo Scaprobe setup failed. Review the messages above and run this script again.\r\n"
        "set \"EXIT_CODE=1\"\r\n"
        "if not \"%~1\"==\"\" goto exit_with_code\r\n"
        "pause\r\n"
        "goto menu\r\n"
        ":usage\r\n"
        "echo Usage: Start-Scaprobe.cmd [--start ^| --screenshots ^| --setup ^| --diagnostics]\r\n"
        "set \"EXIT_CODE=2\"\r\n"
        "goto exit_with_code\r\n"
        ":exit_launcher\r\n"
        "set \"EXIT_CODE=0\"\r\n"
        ":exit_with_code\r\n"
        "endlocal & exit /b %EXIT_CODE%\r\n"
    )


def write_launcher_scripts(zf: zipfile.ZipFile) -> None:
    write_zip_launcher_scripts(zf)


def write_zip_launcher_scripts(zf: zipfile.ZipFile) -> None:
    posix_info = zipfile.ZipInfo("bin/scaprobe")
    posix_info.external_attr = 0o755 << 16
    zf.writestr("Start-Scaprobe.cmd", windows_quick_start_text())
    zf.writestr(posix_info, posix_launcher_text())
    zf.writestr("bin/scaprobe.cmd", windows_launcher_text())
    zf.writestr("bin/setup.cmd", windows_setup_text())
    zf.writestr("bin/start-desktop.cmd", windows_desktop_text())


if __name__ == "__main__":
    raise SystemExit(main())
