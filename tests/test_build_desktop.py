import argparse
import unittest
from pathlib import Path

from tools.build_desktop import (
    backend_output_path,
    cargo_build_command,
    cargo_metadata_command,
    executable_name,
    playwright_install_command,
    playwright_smoke_command,
    pyinstaller_command,
    windows_runtime_architecture,
)


class DesktopBuildToolTests(unittest.TestCase):
    def test_executable_name_is_platform_specific(self):
        self.assertEqual(executable_name("netroach-engine", system="Windows"), "netroach-engine.exe")
        self.assertEqual(executable_name("netroach-engine", system="Linux"), "netroach-engine")

    def test_cargo_command_supports_profile_toolchain_and_target(self):
        args = argparse.Namespace(
            cargo="cargo",
            cargo_toolchain="stable",
            cargo_target="x86_64-pc-windows-msvc",
            engine_profile="portable",
        )

        self.assertEqual(
            cargo_build_command(args),
            [
                "cargo",
                "+stable",
                "build",
                "-p",
                "netroach-engine",
                "--profile",
                "portable",
                "--target",
                "x86_64-pc-windows-msvc",
            ],
        )

    def test_pyinstaller_command_builds_one_file_backend(self):
        command = pyinstaller_command("python")

        self.assertEqual(command[:3], ["python", "-m", "PyInstaller"])
        self.assertIn("--onefile", command)
        self.assertIn("uvicorn", command)
        self.assertIn("scapy", command)
        self.assertIn("playwright", command)
        self.assertEqual(Path(command[-1]).name, "frozen_backend.py")
        self.assertTrue(backend_output_path().name.startswith("netroach-backend"))

    def test_cargo_metadata_command_uses_desktop_manifest(self):
        args = argparse.Namespace(
            cargo="cargo",
            cargo_toolchain="stable",
        )

        command = cargo_metadata_command(args)

        self.assertEqual(command[0:2], ["cargo", "+stable"])
        self.assertIn("metadata", command)
        self.assertIn("--manifest-path", command)
        self.assertEqual(command[-2:], ["--format-version", "1"])

    def test_windows_runtime_architecture_supports_rust_targets(self):
        self.assertEqual(windows_runtime_architecture("x86_64-pc-windows-gnu"), "x64")
        self.assertEqual(windows_runtime_architecture("aarch64-pc-windows-msvc"), "arm64")
        self.assertEqual(windows_runtime_architecture("i686-pc-windows-msvc"), "x86")

    def test_playwright_install_downloads_only_headless_chromium(self):
        self.assertEqual(
            playwright_install_command("python"),
            ["python", "-m", "playwright", "install", "--only-shell", "chromium"],
        )

    def test_playwright_smoke_launches_headless_chromium(self):
        command = playwright_smoke_command("python")

        self.assertEqual(command[:2], ["python", "-c"])
        self.assertIn("chromium.launch(headless=True)", command[2])


if __name__ == "__main__":
    unittest.main()
