import io
import json
import socket
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from pathlib import Path

from netprobe.cli import main
from netprobe.desktop import build_desktop_url, find_free_port


class DesktopTests(unittest.TestCase):
    def test_tauri_bundle_includes_offline_webview_and_playwright_resources(self):
        config_path = Path(__file__).resolve().parents[1] / "desktop" / "src-tauri" / "tauri.conf.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        windows_config = json.loads(config_path.with_name("tauri.windows.conf.json").read_text(encoding="utf-8"))

        self.assertEqual(config["bundle"]["windows"]["webviewInstallMode"]["type"], "offlineInstaller")
        self.assertEqual(
            config["bundle"]["resources"]["resources/playwright/"],
            "resources/playwright/",
        )
        self.assertEqual(
            windows_config["bundle"]["resources"]["resources/runtime/WebView2Loader.dll"],
            "",
        )

    def test_build_desktop_url_normalizes_path(self):
        self.assertEqual(build_desktop_url("127.0.0.1", 8765), "http://127.0.0.1:8765/dashboard")
        self.assertEqual(build_desktop_url("localhost", 9000, "dashboard"), "http://localhost:9000/dashboard")

    def test_find_free_port_returns_bindable_port(self):
        port = find_free_port("127.0.0.1")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", port))

    def test_desktop_help_is_registered(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as exc:
                main(["desktop", "--help"])

        self.assertEqual(exc.exception.code, 0)
        self.assertIn("defaults to 8765", stdout.getvalue())

    def test_desktop_uses_fixed_default_port(self):
        with patch("netprobe.desktop.run_desktop", return_value=0) as run_desktop:
            code = main(["desktop", "--no-open"])

        self.assertEqual(code, 0)
        self.assertEqual(run_desktop.call_args.args[0].port, 8765)

    def test_desktop_command_passes_settings(self):
        with patch("netprobe.desktop.run_desktop", return_value=0) as run_desktop:
            code = main(
                [
                    "desktop",
                    "--db",
                    "scaprobe.db",
                    "--config",
                    "scaprobe.toml",
                    "--env",
                    "lab",
                    "--plugin",
                    "plugin.json",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "8765",
                    "--no-open",
                ]
            )

        self.assertEqual(code, 0)
        settings = run_desktop.call_args.args[0]
        self.assertEqual(settings.db_path, "scaprobe.db")
        self.assertEqual(settings.config_path, "scaprobe.toml")
        self.assertEqual(settings.config_env, "lab")
        self.assertEqual(tuple(settings.plugin_paths), ("plugin.json",))
        self.assertEqual(settings.host, "127.0.0.1")
        self.assertEqual(settings.port, 8765)
        self.assertFalse(settings.open_browser)


if __name__ == "__main__":
    unittest.main()
