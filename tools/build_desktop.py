from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
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
RESOURCE_INSTALLERS = TAURI / "resources" / "installers"
NPCAP_INSTALLER_RESOURCE = RESOURCE_INSTALLERS / "npcap-installer.exe"
BACKEND_BUILD = ROOT / "target" / "desktop-backend"
PLAYWRIGHT_CACHE = ROOT / "target" / "desktop-playwright"
# Staged into the installer. The headless shell is deliberately not here:
# `playwright install` no longer fetches it, and a cache left over from an
# older build must not be carried into the package behind our back.
BROWSER_DIRECTORY_PREFIXES = ("chromium-",)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build the self-contained Netroach desktop installer.",
    )
    parser.add_argument("--python", default=sys.executable, help="Python executable used by PyInstaller")
    parser.add_argument("--cargo", default="cargo", help="Cargo executable")
    parser.add_argument("--cargo-toolchain", help="optional Rust toolchain, for example stable-x86_64-pc-windows-msvc")
    parser.add_argument("--cargo-target", help="optional Rust target triple")
    parser.add_argument("--engine-profile", default="release", choices=("release", "portable", "debug"))
    parser.add_argument("--syn-sweep", action="store_true", help="build the engine and desktop installer with TCP SYN sweep support")
    parser.add_argument("--npcap-sdk-lib", type=Path, help="Npcap SDK library directory containing wpcap.lib and Packet.lib")
    parser.add_argument("--npcap-installer", type=Path, help="official Npcap installer to embed in the personal NSIS build")
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
    if getattr(args, "syn_sweep", False):
        command.extend(("--features", "syn-sweep"))
    return command


def engine_build_environment(
    args: argparse.Namespace,
    base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    environment = dict(base if base is not None else os.environ)
    sdk = getattr(args, "npcap_sdk_lib", None)
    if not getattr(args, "syn_sweep", False) or sdk is None:
        return environment
    existing = environment.get("LIB")
    environment["LIB"] = os.pathsep.join(part for part in (os.fspath(sdk.resolve()), existing) if part)
    return environment


def validate_personal_npcap_build(
    args: argparse.Namespace,
    *,
    system: str | None = None,
) -> tuple[Path, Path | None] | None:
    enabled = bool(getattr(args, "syn_sweep", False))
    sdk_value = getattr(args, "npcap_sdk_lib", None)
    installer_value = getattr(args, "npcap_installer", None)
    if not enabled:
        if sdk_value is not None or installer_value is not None:
            raise SystemExit("--npcap-sdk-lib and --npcap-installer require --syn-sweep")
        return None
    if (system or platform.system()).lower() != "windows":
        raise SystemExit("The Npcap SYN sweep installer can only be built for Windows")
    if sdk_value is None:
        raise SystemExit("--syn-sweep requires --npcap-sdk-lib")
    if getattr(args, "skip_engine_build", False) or getattr(args, "engine_path", None) is not None:
        raise SystemExit("--syn-sweep requires a fresh engine build; do not reuse or skip the engine")
    if getattr(args, "prepare_only", False):
        raise SystemExit("--syn-sweep cannot be combined with --prepare-only; build the private NSIS in one step")

    sdk = sdk_value.resolve()
    if not sdk.is_dir():
        raise SystemExit(f"Npcap SDK library directory was not found: {sdk}")
    for library in ("wpcap.lib", "Packet.lib"):
        if not (sdk / library).is_file():
            raise SystemExit(f"Npcap SDK library was not found: {sdk / library}")
    installer = None
    if installer_value is not None:
        installer = _require_file(installer_value, "Npcap installer")
        if installer.suffix.lower() != ".exe":
            raise SystemExit(f"Npcap installer must be an .exe file: {installer}")

    if installer is not None:
        bundles = {
            bundle.lower()
            for bundle in re.split(r"[\s,]+", str(getattr(args, "bundles", "") or ""))
            if bundle
        }
        if bundles != {"nsis"}:
            raise SystemExit("The bundled Npcap preinstall check is supported only by an NSIS-only build")
    return sdk, installer


def stage_npcap_installer(
    source: Path,
    *,
    destination: Path = NPCAP_INSTALLER_RESOURCE,
) -> str:
    source = _require_file(source, "Npcap installer")
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source != destination:
        shutil.copy2(source, destination)
    digest = file_sha256(destination)
    try:
        display = destination.relative_to(ROOT)
    except ValueError:
        display = destination
    print(f"staged {display} (sha256 {digest})", flush=True)
    return digest


def verify_npcap_installer_signature(installer: Path) -> None:
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if powershell is None:
        raise SystemExit("PowerShell is required to verify the Npcap installer Authenticode signature")
    script = (
        "& { param([string]$Path) "
        "$ErrorActionPreference = 'Stop'; "
        "Import-Module (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1') -Force; "
        "$s = Get-AuthenticodeSignature -LiteralPath $Path; "
        "$subject = if ($null -ne $s.SignerCertificate) { $s.SignerCertificate.Subject } else { $null }; "
        "$publisher = if ($null -ne $s.SignerCertificate) { "
        "$s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) "
        "} else { $null }; "
        "[pscustomobject]@{ Status = [string]$s.Status; Subject = $subject; Publisher = $publisher } | ConvertTo-Json -Compress }"
    )
    try:
        completed = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", script, os.fspath(installer.resolve())],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        signature = json.loads(completed.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Could not verify the Npcap installer Authenticode signature: {exc}") from exc
    subject = str(signature.get("Subject") or "")
    if signature.get("Status") != "Valid" or signature.get("Publisher") != "Nmap Software LLC":
        raise SystemExit("Npcap installer Authenticode signature is not a valid Nmap Software LLC signature")
    print(f"verified Npcap installer Authenticode signer: {subject}", flush=True)


def unstage_npcap_installer(*, destination: Path = NPCAP_INSTALLER_RESOURCE) -> bool:
    destination = destination.resolve()
    if not destination.is_file():
        return False
    destination.unlink()
    try:
        display = destination.relative_to(ROOT)
    except ValueError:
        display = destination
    print(f"removed private Npcap staging file {display}", flush=True)
    return True


def standard_engine_build_args(args: argparse.Namespace) -> argparse.Namespace:
    standard = argparse.Namespace(**vars(args))
    standard.syn_sweep = False
    standard.npcap_sdk_lib = None
    standard.npcap_installer = None
    standard.skip_engine_build = False
    standard.engine_path = None
    return standard


def clear_private_engine_artifacts(
    args: argparse.Namespace,
    *,
    staged_engine: Path | None = None,
    engine_output: Path | None = None,
) -> list[Path]:
    candidates = [
        staged_engine or RESOURCE_BIN / executable_name("netroach-engine"),
        engine_output or engine_output_path(args.engine_profile, args.cargo_target),
    ]
    removed: list[Path] = []
    for candidate in candidates:
        if candidate.is_file():
            candidate.unlink()
            removed.append(candidate)
    return removed


def restore_standard_engine_resource(args: argparse.Namespace) -> None:
    standard = standard_engine_build_args(args)
    clear_private_engine_artifacts(standard)
    _run(cargo_build_command(standard), environment=engine_build_environment(standard))
    engine = _require_file(
        engine_output_path(standard.engine_profile, standard.cargo_target),
        "standard Rust engine",
    )
    _stage_binary(engine, "netroach-engine")
    print("restored standard connect-scan engine staging", flush=True)


def write_windows_installer_checksums(bundle_root: Path) -> list[Path]:
    written: list[Path] = []
    for directory, suffix in (("nsis", ".exe"), ("msi", ".msi")):
        for installer in sorted((bundle_root / directory).glob(f"*{suffix}")):
            sidecar = installer.with_suffix(installer.suffix + ".sha256")
            sidecar.write_text(f"{file_sha256(installer)}  {installer.name}\n", encoding="utf-8")
            written.append(sidecar)
            try:
                display = sidecar.relative_to(ROOT)
            except ValueError:
                display = sidecar
            print(f"wrote installer checksum {display}", flush=True)
    return written


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
    """Fetch the full browser rather than the headless shell.

    `--only-shell` fetched a build with no user interface at all, which is
    enough to photograph a page and nothing else. The full build can also be
    shown in its own window, which is what puts the address bar - the padlock,
    the "not secure", the address actually arrived at - into the evidence.

    Only one of the two is bundled. The shell beside it would be another 271MB
    for a second way to do what the full build already does headlessly.
    """
    return [python, "-m", "playwright", "install", "chromium"]


def playwright_smoke_command(python: str) -> list[str]:
    # The channel is named for the same reason the evidence path names it: a
    # headless launch picks the shell, and the shell is deliberately not here.
    script = (
        "from playwright.sync_api import sync_playwright; "
        "p=sync_playwright().start(); "
        "b=p.chromium.launch(headless=True, channel='chromium'); "
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


def newest_browser_revisions(path: Path) -> set[str]:
    """Pick the highest-numbered directory in each browser family.

    Asking Playwright which revision it uses looked more precise and was worse:
    with only the headless shell installed, `chromium.executable_path` reports a
    `chromium-<rev>` path that does not exist on disk, so the real
    `chromium_headless_shell-<rev>` directory looked stale and was deleted. An
    answer that is confidently wrong defeats a "prune nothing when unsure"
    guard, so nothing is asked: `playwright install` has just run, and the
    revision it wants is the highest one present.
    """
    families: dict[str, tuple[int, str]] = {}
    if not path.is_dir():
        return set()
    for candidate in sorted(path.iterdir()):
        if not candidate.is_dir() or not candidate.name.startswith(BROWSER_DIRECTORY_PREFIXES):
            continue
        match = re.fullmatch(r"(.+?)-(\d+)", candidate.name)
        if not match:
            # Unparseable, so it cannot be compared - keep it.
            families[candidate.name] = (-1, candidate.name)
            continue
        family, revision = match.group(1), int(match.group(2))
        current = families.get(family)
        if current is None or revision > current[0]:
            families[family] = (revision, candidate.name)
    return {name for _, name in families.values()}


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
    for name in prune_stale_browser_revisions(browsers, keep=newest_browser_revisions(browsers)):
        print(f"pruned stale browser revision {name}", flush=True)
    # After pruning, not before: if the wrong directory was removed the build
    # fails here instead of shipping an installer whose evidence capture is dead.
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
        _run(cargo_build_command(args), environment=engine_build_environment(args))
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
    npcap_inputs = validate_personal_npcap_build(args)
    npcap_installer = npcap_inputs[1] if npcap_inputs is not None else None
    npcap_digest: str | None = None
    if npcap_installer is not None:
        verify_npcap_installer_signature(npcap_installer)
        npcap_digest = file_sha256(npcap_installer)
    else:
        unstage_npcap_installer()
    try:
        engine = build_engine(args)
        browsers = build_playwright_browsers(args)
        backend = build_backend(args)
        _stage_binary(engine, "netroach-engine")
        _stage_binary(backend, "netroach-backend")
        _stage_playwright_browsers(browsers)
        if npcap_installer is not None:
            staged_digest = stage_npcap_installer(npcap_installer)
            if staged_digest != npcap_digest:
                raise SystemExit("Npcap installer changed after its Authenticode verification")
            verify_npcap_installer_signature(NPCAP_INSTALLER_RESOURCE)

        if args.prepare_only:
            print("Desktop resources are ready; skipped the Tauri installer build.")
            return 0

        build_tauri(args)
        if os.name == "nt":
            write_windows_installer_checksums(TAURI / "target" / "release" / "bundle")
        print(f"Installers: {TAURI / 'target' / 'release' / 'bundle'}")
        return 0
    finally:
        if npcap_installer is not None:
            unstage_npcap_installer()
        if npcap_inputs is not None:
            restore_standard_engine_resource(args)


if __name__ == "__main__":
    raise SystemExit(main())
