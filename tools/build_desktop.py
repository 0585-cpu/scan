from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESKTOP = ROOT / "desktop"
TAURI = DESKTOP / "src-tauri"
RESOURCE_BIN = TAURI / "resources" / "bin"
RESOURCE_PLAYWRIGHT = TAURI / "resources" / "playwright"
RESOURCE_RUNTIME = TAURI / "resources" / "runtime"
BACKEND_BUILD = ROOT / "target" / "desktop-backend"
PLAYWRIGHT_CACHE = ROOT / "target" / "desktop-playwright"
BROWSER_DIRECTORY_PREFIXES = ("chromium-", "chromium_headless_shell-")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build the self-contained Netroach desktop installer.",
    )
    parser.add_argument("--python", default=sys.executable, help="Python executable used by PyInstaller")
    parser.add_argument("--cargo", default="cargo", help="Cargo executable")
    parser.add_argument("--cargo-toolchain", help="optional Rust toolchain, for example stable-x86_64-pc-windows-msvc")
    parser.add_argument("--cargo-target", help="optional Rust target triple")
    parser.add_argument("--engine-profile", default="release", choices=("release", "portable", "debug"))
    parser.add_argument("--engine-path", type=Path, help="use an existing netroach-engine binary")
    parser.add_argument("--backend-path", type=Path, help="use an existing frozen backend binary")
    parser.add_argument("--skip-engine-build", action="store_true")
    parser.add_argument("--skip-backend-build", action="store_true")
    parser.add_argument("--skip-playwright-download", action="store_true")
    parser.add_argument(
        "--playwright-browsers-path",
        type=Path,
        help="use or populate this Playwright browser directory",
    )
    parser.add_argument("--skip-npm-install", action="store_true")
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="stage the backend and engine without invoking the Tauri installer build",
    )
    parser.add_argument(
        "--bundles",
        default="nsis" if os.name == "nt" else None,
        help="Tauri bundle type(s), such as nsis or msi (default: nsis on Windows)",
    )
    return parser


def executable_name(name: str, *, system: str | None = None) -> str:
    current = (system or platform.system()).lower()
    return f"{name}.exe" if current == "windows" else name


def engine_output_path(profile: str, target: str | None = None) -> Path:
    parts = [ROOT / "target"]
    if target:
        parts.append(Path(target))
    parts.extend((Path(profile), Path(executable_name("netroach-engine"))))
    return Path(*parts)


def backend_output_path() -> Path:
    return BACKEND_BUILD / "dist" / executable_name("netroach-backend")


def cargo_build_command(args: argparse.Namespace) -> list[str]:
    command = [args.cargo]
    if args.cargo_toolchain:
        command.append(f"+{args.cargo_toolchain}")
    command.extend(("build", "-p", "netroach-engine"))
    if args.engine_profile == "release":
        command.append("--release")
    elif args.engine_profile != "debug":
        command.extend(("--profile", args.engine_profile))
    if args.cargo_target:
        command.extend(("--target", args.cargo_target))
    return command


def cargo_metadata_command(args: argparse.Namespace) -> list[str]:
    command = [args.cargo]
    if args.cargo_toolchain:
        command.append(f"+{args.cargo_toolchain}")
    command.extend(
        (
            "metadata",
            "--manifest-path",
            os.fspath(TAURI / "Cargo.toml"),
            "--format-version",
            "1",
        )
    )
    return command


def windows_runtime_architecture(target: str | None = None, *, machine: str | None = None) -> str:
    architecture = (target or machine or platform.machine()).lower()
    if architecture.startswith("x86_64") or architecture in {"amd64", "x64"}:
        return "x64"
    if architecture.startswith("aarch64") or architecture in {"arm64", "arm64ec"}:
        return "arm64"
    if architecture.startswith(("i586", "i686")) or architecture in {"x86", "win32"}:
        return "x86"
    raise SystemExit(f"Unsupported Windows architecture for WebView2Loader.dll: {architecture}")


def pyinstaller_command(python: str) -> list[str]:
    return [
        python,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--console",
        "--name",
        "netroach-backend",
        "--distpath",
        os.fspath(BACKEND_BUILD / "dist"),
        "--workpath",
        os.fspath(BACKEND_BUILD / "work"),
        "--specpath",
        os.fspath(BACKEND_BUILD),
        "--paths",
        os.fspath(ROOT),
        # The dashboard is a data file, so PyInstaller cannot find it by import.
        "--add-data",
        f"{ROOT / 'netroach' / 'static' / 'dashboard.html'}{os.pathsep}netroach/static",
        "--collect-all",
        "uvicorn",
        "--collect-all",
        "scapy",
        "--collect-all",
        "openpyxl",
        "--collect-all",
        "PIL",
        "--collect-all",
        "playwright",
        os.fspath(ROOT / "netroach" / "frozen_backend.py"),
    ]


def playwright_install_command(python: str) -> list[str]:
    return [python, "-m", "playwright", "install", "--only-shell", "chromium"]


def playwright_smoke_command(python: str) -> list[str]:
    script = (
        "from playwright.sync_api import sync_playwright; "
        "p=sync_playwright().start(); "
        "b=p.chromium.launch(headless=True); "
        "b.close(); p.stop()"
    )
    return [python, "-c", script]


def _run(
    command: Sequence[str],
    *,
    cwd: Path = ROOT,
    environment: Mapping[str, str] | None = None,
) -> None:
    print(f"> {' '.join(os.fspath(part) for part in command)}", flush=True)
    subprocess.run(list(command), cwd=cwd, env=environment, check=True)


def _require_file(path: Path, label: str) -> Path:
    resolved = path.resolve()
    if not resolved.is_file():
        raise SystemExit(f"{label} was not found: {resolved}")
    return resolved


def _stage_binary(source: Path, name: str) -> Path:
    RESOURCE_BIN.mkdir(parents=True, exist_ok=True)
    destination = RESOURCE_BIN / executable_name(name)
    shutil.copy2(source, destination)
    print(f"staged {destination.relative_to(ROOT)}", flush=True)
    return destination


def prune_stale_browser_revisions(path: Path, *, keep: set[str]) -> list[str]:
    """Delete browser revisions the current Playwright no longer uses.

    `PLAYWRIGHT_SKIP_BROWSER_GC=1` keeps this build's cache from touching a
    developer's own Playwright install, but it also means Playwright never
    removes what it superseded. Two Chromium revisions were shipped side by side
    in one installer before this existed - 270MB on disk, ~80MB in the bundle.
    """
    removed: list[str] = []
    # An empty keep set means the caller could not determine which revision is in
    # use. Deleting the one being used breaks evidence capture outright, which
    # costs far more than shipping a duplicate, so prune nothing.
    if not keep or not path.is_dir():
        return removed
    for candidate in sorted(path.iterdir()):
        if not candidate.is_dir() or not candidate.name.startswith(BROWSER_DIRECTORY_PREFIXES):
            continue
        if candidate.name in keep:
            continue
        shutil.rmtree(candidate, ignore_errors=True)
        removed.append(candidate.name)
    return removed


def current_browser_revisions(python: str, browsers_path: Path) -> set[str]:
    """Ask Playwright which browser directories the installed version uses.

    Returns an empty set when that cannot be determined, and the caller then
    prunes nothing - shipping a duplicate is a wasted 80MB, but deleting the
    revision in use breaks evidence capture entirely.
    """
    script = (
        "import json, os;"
        "from playwright.sync_api import sync_playwright;"
        "p=sync_playwright().start();"
        "names=set();"
        "b=p.chromium.launch(headless=True);"
        "names.add(os.path.basename(os.path.dirname(os.path.dirname(p.chromium.executable_path))));"
        "b.close(); p.stop();"
        "print(json.dumps(sorted(names)))"
    )
    environment = os.environ.copy()
    environment["PLAYWRIGHT_BROWSERS_PATH"] = os.fspath(browsers_path)
    environment["PLAYWRIGHT_SKIP_BROWSER_GC"] = "1"
    try:
        completed = subprocess.run(
            [python, "-c", script],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=True,
        )
        names = {str(name) for name in json.loads(completed.stdout.strip().splitlines()[-1])}
    except Exception:  # noqa: BLE001 - an unknown answer must prune nothing.
        return set()
    return {name for name in names if name.startswith(BROWSER_DIRECTORY_PREFIXES)}


def _require_playwright_browsers(path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_dir():
        raise SystemExit(f"Playwright browser directory was not found: {resolved}")
    browser_directories = [
        candidate
        for candidate in resolved.iterdir()
        if candidate.is_dir() and candidate.name.startswith(BROWSER_DIRECTORY_PREFIXES)
    ]
    if not browser_directories:
        raise SystemExit(f"Playwright Chromium was not found under: {resolved}")
    return resolved


def build_playwright_browsers(args: argparse.Namespace) -> Path:
    destination = (args.playwright_browsers_path or PLAYWRIGHT_CACHE).resolve()
    environment = os.environ.copy()
    environment["PLAYWRIGHT_BROWSERS_PATH"] = os.fspath(destination)
    environment["PLAYWRIGHT_SKIP_BROWSER_GC"] = "1"
    if not args.skip_playwright_download:
        destination.mkdir(parents=True, exist_ok=True)
        _run(playwright_install_command(args.python), environment=environment)
    browsers = _require_playwright_browsers(destination)
    # Playwright's own GC is disabled above, so prune what this install left
    # behind before the directory is copied into the bundle.
    keep = current_browser_revisions(args.python, destination)
    if keep:
        for name in prune_stale_browser_revisions(browsers, keep=keep):
            print(f"pruned stale browser revision {name}", flush=True)
    _run(playwright_smoke_command(args.python), environment=environment)
    return browsers


def _stage_playwright_browsers(source: Path) -> Path:
    resource_root = (TAURI / "resources").resolve()
    destination = RESOURCE_PLAYWRIGHT.resolve()
    destination.relative_to(resource_root)
    if source.resolve() == destination:
        print(f"using staged {destination.relative_to(ROOT)}", flush=True)
        return destination
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns(".links"))
    print(f"staged {destination.relative_to(ROOT)}", flush=True)
    return destination


def _stage_windows_runtime(args: argparse.Namespace) -> None:
    if os.name != "nt":
        return

    # Stage the loader before Cargo evaluates the Tauri resource configuration.
    # Windows GNU builds otherwise omit it from NSIS installers, causing the
    # installed executable to exit with STATUS_DLL_NOT_FOUND (0xC0000135).
    command = cargo_metadata_command(args)
    print(f"> {' '.join(os.fspath(part) for part in command)}", flush=True)
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    metadata = json.loads(completed.stdout)
    webview_package = next(
        (package for package in metadata["packages"] if package["name"] == "webview2-com-sys"),
        None,
    )
    if webview_package is None:
        raise SystemExit("Cargo package webview2-com-sys was not found in the Tauri dependency graph")
    architecture = windows_runtime_architecture(args.cargo_target)
    crate_root = Path(webview_package["manifest_path"]).resolve().parent
    loader = _require_file(crate_root / architecture / "WebView2Loader.dll", "WebView2 loader")
    RESOURCE_RUNTIME.mkdir(parents=True, exist_ok=True)
    destination = RESOURCE_RUNTIME / loader.name
    shutil.copy2(loader, destination)
    print(f"staged {destination.relative_to(ROOT)}", flush=True)


def build_engine(args: argparse.Namespace) -> Path:
    if args.engine_path:
        return _require_file(args.engine_path, "Rust engine")
    output = engine_output_path(args.engine_profile, args.cargo_target)
    if not args.skip_engine_build:
        _run(cargo_build_command(args))
    return _require_file(output, "Rust engine")


def build_backend(args: argparse.Namespace) -> Path:
    if args.backend_path:
        return _require_file(args.backend_path, "frozen backend")
    output = backend_output_path()
    if not args.skip_backend_build:
        if importlib.util.find_spec("PyInstaller") is None and Path(args.python).resolve() == Path(sys.executable).resolve():
            raise SystemExit(
                "PyInstaller is not installed. Run: "
                f'"{args.python}" -m pip install -e ".[desktop-build]"'
            )
        _run(pyinstaller_command(args.python))
    return _require_file(output, "frozen backend")


def build_tauri(args: argparse.Namespace) -> None:
    npm = shutil.which("npm")
    if npm is None:
        raise SystemExit("npm was not found. Install the Node.js LTS release, then run this command again.")
    if not args.skip_npm_install:
        _run((npm, "install"), cwd=DESKTOP)
    _stage_windows_runtime(args)
    command = [npm, "run", "build"]
    if args.bundles:
        command.extend(("--", "--bundles", args.bundles))
    elif args.cargo_target:
        command.append("--")
    if args.cargo_target:
        command.extend(("--target", args.cargo_target))
    environment = os.environ.copy()
    if args.cargo_toolchain:
        environment["RUSTUP_TOOLCHAIN"] = args.cargo_toolchain
    _run(command, cwd=DESKTOP, environment=environment)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    engine = build_engine(args)
    browsers = build_playwright_browsers(args)
    backend = build_backend(args)
    _stage_binary(engine, "netroach-engine")
    _stage_binary(backend, "netroach-backend")
    _stage_playwright_browsers(browsers)

    if args.prepare_only:
        print("Desktop resources are ready; skipped the Tauri installer build.")
        return 0

    build_tauri(args)
    print(f"Installers: {TAURI / 'target' / 'release' / 'bundle'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
