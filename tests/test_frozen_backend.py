import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netprobe.frozen_backend import build_parser, main


class FrozenBackendTests(unittest.TestCase):
    def test_parser_requires_a_valid_engine_and_port(self):
        parser = build_parser()
        args = parser.parse_args(["--engine-path", "scaprobe-engine.exe", "--port", "49152"])

        self.assertEqual(args.engine_path, "scaprobe-engine.exe")
        self.assertEqual(args.port, 49152)
        with self.assertRaises(SystemExit):
            parser.parse_args(["--engine-path", "scaprobe-engine.exe", "--port", "0"])

    def test_main_sets_engine_path_and_starts_uvicorn(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = Path(tmp) / "scaprobe-engine.exe"
            engine.write_bytes(b"engine")
            browsers = Path(tmp) / "playwright"
            browsers.mkdir()
            app = object()
            with (
                patch.dict(os.environ, {}, clear=False),
                patch("netprobe.api.create_app", return_value=app) as create_app,
                patch("uvicorn.run") as uvicorn_run,
            ):
                code = main(
                    [
                        "--engine-path",
                        str(engine),
                        "--playwright-browsers-path",
                        str(browsers),
                        "--port",
                        "49153",
                        "--db",
                        "desktop.db",
                        "--env",
                        "lab",
                        "--plugin",
                        "plugin.json",
                    ]
                )

                self.assertEqual(os.environ["SCAPROBE_ENGINE"], str(engine.resolve()))
                self.assertEqual(os.environ["PLAYWRIGHT_BROWSERS_PATH"], str(browsers.resolve()))

        self.assertEqual(code, 0)
        create_app.assert_called_once_with(
            "desktop.db",
            config_path=None,
            config_env="lab",
            plugin_paths=["plugin.json"],
        )
        uvicorn_run.assert_called_once_with(
            app,
            host="127.0.0.1",
            port=49153,
            log_level="info",
            access_log=False,
        )

    def test_debug_log_level_enables_the_request_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = Path(tmp) / "scaprobe-engine.exe"
            engine.write_bytes(b"engine")
            with (
                patch("netprobe.api.create_app", return_value=object()),
                patch("uvicorn.run") as uvicorn_run,
            ):
                main(["--engine-path", str(engine), "--log-level", "debug"])

        self.assertTrue(uvicorn_run.call_args.kwargs["access_log"])

    def test_main_rejects_missing_engine(self):
        with self.assertRaisesRegex(SystemExit, "bundled Rust engine was not found"):
            main(["--engine-path", "missing-scaprobe-engine.exe"])

    def test_main_rejects_missing_playwright_browser_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = Path(tmp) / "scaprobe-engine.exe"
            engine.write_bytes(b"engine")
            with self.assertRaisesRegex(SystemExit, "bundled Playwright browsers were not found"):
                main(
                    [
                        "--engine-path",
                        str(engine),
                        "--playwright-browsers-path",
                        str(Path(tmp) / "missing-browsers"),
                    ]
                )


if __name__ == "__main__":
    unittest.main()
