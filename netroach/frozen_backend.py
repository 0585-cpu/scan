from __future__ import annotations

import argparse
import multiprocessing
import os
from collections.abc import Sequence
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netroach-backend",
        description="Run the local Netroach API for the desktop application.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=_port, default=8765)
    parser.add_argument("--db", help="SQLite database path")
    parser.add_argument("--config", help="netroach.toml path")
    parser.add_argument("--env", dest="config_env", help="configuration environment")
    parser.add_argument("--plugin", action="append", default=[], help="plugin manifest or directory")
    parser.add_argument("--engine-path", required=True, help="bundled netroach-engine executable")
    parser.add_argument(
        "--playwright-browsers-path",
        help="bundled Playwright browser directory",
    )
    parser.add_argument(
        "--log-level",
        choices=("critical", "error", "warning", "info", "debug", "trace"),
        default="info",
    )
    return parser


def _port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    engine_path = Path(args.engine_path).resolve()
    if not engine_path.is_file():
        raise SystemExit(f"bundled Rust engine was not found: {engine_path}")

    os.environ["NETROACH_ENGINE"] = os.fspath(engine_path)
    if args.playwright_browsers_path:
        browsers_path = Path(args.playwright_browsers_path).resolve()
        if not browsers_path.is_dir():
            raise SystemExit(f"bundled Playwright browsers were not found: {browsers_path}")
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = os.fspath(browsers_path)

    import uvicorn

    from netroach.api import create_app

    uvicorn.run(
        create_app(
            args.db,
            config_path=args.config,
            config_env=args.config_env,
            plugin_paths=args.plugin,
        ),
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        # The desktop app has no console, so the request log is the only way to
        # tell "the click never reached the backend" from "the backend failed".
        # Off by default to keep backend.log small; --log-level debug turns it on.
        access_log=args.log_level == "debug",
    )
    return 0


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
