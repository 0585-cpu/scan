import hashlib
import tempfile
import unittest
from pathlib import Path

from tools.package import (
    iter_payload_files,
    resolve_archive_format,
    windows_desktop_text,
    windows_launcher_text,
    windows_quick_start_text,
    windows_setup_text,
    write_sha256_checksum,
)


class PackageToolTests(unittest.TestCase):
    def test_python_package_uses_dynamic_version_and_single_cli_name(self):
        pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIn('dynamic = ["version"]', pyproject)
        self.assertIn('version = {attr = "netroach.version.__version__"}', pyproject)
        # Exactly one console script: a second name would install a second
        # command that drifts out of sync with the documented one.
        scripts = pyproject.split("[project.scripts]", 1)[1].split("[", 1)[0]
        entries = [line for line in scripts.splitlines() if "=" in line]
        self.assertEqual(entries, ['netroach = "netroach.cli:main"'])

    def test_dashboard_asset_ships_in_every_artifact(self):
        root = Path(__file__).resolve().parents[1]
        dashboard = root / "netroach" / "static" / "dashboard.html"

        self.assertIn(dashboard, iter_payload_files(root))
        pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('netroach = ["static/*.html"]', pyproject)

        from tools.build_desktop import pyinstaller_command

        command = pyinstaller_command("python")
        self.assertIn("--add-data", command)
        self.assertTrue(
            any("dashboard.html" in argument for argument in command),
            "PyInstaller build must bundle the dashboard asset",
        )

    def test_archive_format_auto_uses_zip_for_windows(self):
        self.assertEqual(resolve_archive_format("auto", "windows-amd64"), "zip")
        self.assertEqual(resolve_archive_format("auto", "linux-x86_64"), "tar.gz")
        self.assertEqual(resolve_archive_format("zip", "linux-x86_64"), "zip")

    def test_write_sha256_checksum(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "netroach-test.zip"
            archive.write_bytes(b"artifact")

            checksum = write_sha256_checksum(archive)

            expected = hashlib.sha256(b"artifact").hexdigest()
            self.assertEqual(checksum.read_text(encoding="utf-8"), f"{expected}  {archive.name}\n")

    def test_windows_portable_scripts_use_isolated_environment(self):
        launcher = windows_launcher_text()
        setup = windows_setup_text()
        desktop = windows_desktop_text()
        quick_start = windows_quick_start_text()

        self.assertIn(".venv\\Scripts\\python.exe", launcher)
        self.assertIn("-m netroach", launcher)
        self.assertIn("set PATH=%SCRIPT_DIR%;%PATH%", launcher)
        self.assertIn('pushd "%SCRIPT_DIR%.."', launcher)
        self.assertIn("py -3 -m venv", setup)
        self.assertNotIn("^>", setup)
        self.assertIn("pip install -r", setup)
        self.assertIn("--screenshots", setup)
        self.assertIn("playwright install chromium", setup)
        self.assertIn("start-desktop.cmd", setup)
        self.assertIn("desktop --host 127.0.0.1 --port 8765", desktop)
        self.assertIn("First run detected", quick_start)
        self.assertIn("bin\\setup.cmd", quick_start)
        self.assertIn("bin\\start-desktop.cmd", quick_start)
        self.assertIn("--screenshots", quick_start)
        self.assertIn("Netroach Launcher", quick_start)
        self.assertIn("choice /C 12340", quick_start)
        self.assertIn("[1] Start Netroach", quick_start)
        self.assertIn("[3] Install or update Netroach only", quick_start)
        self.assertIn("[4] Run diagnostics", quick_start)
        self.assertIn("--diagnostics", quick_start)

    def test_portable_payload_excludes_staged_desktop_executables(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            staged = root / "desktop" / "src-tauri" / "resources" / "bin" / "netroach-backend.exe"
            staged.parent.mkdir(parents=True)
            staged.write_bytes(b"backend")
            browser = root / "desktop" / "src-tauri" / "resources" / "playwright" / "chromium-1" / "chrome.exe"
            browser.parent.mkdir(parents=True)
            browser.write_bytes(b"chromium")
            regular = root / "desktop" / "README.md"
            regular.parent.mkdir(parents=True, exist_ok=True)
            regular.write_text("desktop", encoding="utf-8")
            for filename in ["README.md", "CHANGELOG.md", "pyproject.toml", "requirements.txt"]:
                (root / filename).write_text(filename, encoding="utf-8")

            payload = iter_payload_files(root)

        self.assertNotIn(staged, payload)
        self.assertNotIn(browser, payload)
        self.assertIn(regular, payload)


if __name__ == "__main__":
    unittest.main()
