from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test a Netroach portable zip artifact.")
    parser.add_argument("artifact", help="zip file or directory containing one zip file")
    parser.add_argument("--require-engine", action="store_true", help="require a bundled netroach-engine binary")
    args = parser.parse_args()

    archive = resolve_archive(Path(args.artifact))
    verify_checksum(archive)
    with tempfile.TemporaryDirectory() as tmp:
        extract_dir = Path(tmp) / "artifact"
        extract_archive(archive, extract_dir)
        assert_required_files(extract_dir)
        if args.require_engine:
            assert_engine_file(extract_dir)
        run_netroach(extract_dir, ["--help"])
        run_netroach(extract_dir, ["--version"])
        diagnostics = run_netroach_json(extract_dir, ["serve", "--check"])
        expected = {
            "app_version",
            "scapy_available",
            "rust_engine_available",
            "packet_driver",
            "packet_driver_available",
            "raw_socket_privileged",
            "packet_driver_note",
        }
        missing = sorted(expected - set(diagnostics))
        if missing:
            raise SystemExit(f"diagnostics output is missing expected fields: {', '.join(missing)}")
        if args.require_engine and not diagnostics.get("rust_engine_version"):
            raise SystemExit("diagnostics output is missing bundled engine version")
    print(f"package smoke ok: {archive}")
    return 0


def resolve_archive(path: Path) -> Path:
    if path.is_file():
        return path
    if path.is_dir():
        archives = sorted([*path.glob("*.zip"), *path.glob("*.tar.gz"), *path.glob("*.tgz")])
        if len(archives) != 1:
            raise SystemExit(f"expected exactly one archive in {path}, found {len(archives)}")
        return archives[0]
    raise SystemExit(f"artifact not found: {path}")


def verify_checksum(archive: Path) -> None:
    checksum = archive.with_name(f"{archive.name}.sha256")
    if not checksum.exists():
        return
    line = checksum.read_text(encoding="utf-8").strip()
    expected = line.split()[0] if line else ""
    if not expected:
        raise SystemExit(f"checksum file is empty: {checksum}")
    digest = hashlib.sha256()
    with archive.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual.lower() != expected.lower():
        raise SystemExit(f"checksum mismatch for {archive}: expected {expected}, got {actual}")


def extract_archive(archive: Path, extract_dir: Path) -> None:
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(extract_dir)
        return
    if archive.name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive, "r:gz") as tf:
            safe_extract_tar(tf, extract_dir)
        return
    raise SystemExit(f"unsupported artifact format: {archive}")


def safe_extract_tar(tf: tarfile.TarFile, extract_dir: Path) -> None:
    root = extract_dir.resolve()
    for member in tf.getmembers():
        target = (extract_dir / member.name).resolve()
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise SystemExit(f"refusing unsafe archive member: {member.name}") from exc
    tf.extractall(extract_dir)


def assert_required_files(root: Path) -> None:
    required = [
        root / "Start-Netroach.cmd",
        root / "README.md",
        root / "CHANGELOG.md",
        root / "docs" / "install.md",
        root / "docs" / "release-checklist.md",
        root / "docs" / "desktop-packaging.md",
        root / "docs" / "netroach.example.toml",
        root / "docs" / "netroach.plugin.example.json",
        root / "docs" / "user-guide.md",
        root / "desktop" / "README.md",
        root / "desktop" / "package.json",
        root / "desktop" / "placeholder-dist" / "index.html",
        root / "desktop" / "src-tauri" / "build.rs",
        root / "desktop" / "src-tauri" / "Cargo.lock",
        root / "desktop" / "src-tauri" / "Cargo.toml",
        root / "desktop" / "src-tauri" / "icons" / "icon.ico",
        root / "desktop" / "src-tauri" / "src" / "main.rs",
        root / "desktop" / "src-tauri" / "tauri.conf.json",
        root / "pyproject.toml",
        root / "netroach" / "cli.py",
        root / "netroach" / "desktop.py",
        root / "netroach" / "frozen_backend.py",
        root / "netroach" / "dashboard.py",
        root / "postman" / "netroach.postman_collection.json",
        root / "tools" / "benchmark_scan.py",
        root / "tools" / "build_desktop.py",
        root / "tools" / "soak_scan.py",
        root / "bin" / ("netroach.cmd" if os.name == "nt" else "netroach"),
        root / "bin" / "setup.cmd",
        root / "bin" / "start-desktop.cmd",
    ]
    missing = [str(path.relative_to(root)) for path in required if not path.exists()]
    if missing:
        raise SystemExit(f"artifact is missing required files: {', '.join(missing)}")


def assert_engine_file(root: Path) -> None:
    suffix = ".exe" if os.name == "nt" else ""
    engine = root / "bin" / f"netroach-engine{suffix}"
    if not engine.exists():
        raise SystemExit(f"artifact is missing required engine binary: {engine.relative_to(root)}")


def run_netroach(root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    command = launcher_command(root, args)
    env = os.environ.copy()
    env["PYTHON"] = sys.executable
    env["PYTHONPATH"] = os.pathsep.join([str(root), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    env["PATH"] = os.pathsep.join([str(root / "bin"), env.get("PATH", "")])
    result = subprocess.run(
        command,
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise SystemExit(
            "artifact command failed\n"
            f"command: {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def run_netroach_json(root: Path, args: list[str]) -> dict[str, object]:
    result = run_netroach(root, args)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"expected JSON output from {' '.join(args)}: {exc}\n{result.stdout}") from exc


def launcher_command(root: Path, args: list[str]) -> list[str]:
    if os.name == "nt":
        return [os.environ.get("COMSPEC", "cmd.exe"), "/c", str(root / "bin" / "netroach.cmd"), *args]
    return [str(root / "bin" / "netroach"), *args]


if __name__ == "__main__":
    raise SystemExit(main())
