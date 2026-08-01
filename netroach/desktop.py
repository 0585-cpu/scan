from __future__ import annotations

import socket
import threading
import time
import webbrowser
from collections.abc import Sequence
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DesktopSettings:
    host: str = "127.0.0.1"
    port: int = 8765
    db_path: str | None = None
    config_path: str | None = None
    config_env: str | None = None
    plugin_paths: Sequence[str] = field(default_factory=tuple)
    open_browser: bool = True
    api_token: str | None = None


def find_free_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def build_desktop_url(host: str, port: int, path: str = "/dashboard") -> str:
    normalized_path = path if path.startswith("/") else f"/{path}"
    return f"http://{host}:{port}{normalized_path}"


def run_desktop(settings: DesktopSettings) -> int:
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("desktop requires FastAPI dependencies. Install with: pip install -e .") from exc

    from .api import create_app
    from .auth import resolve_api_token

    port = settings.port or find_free_port(settings.host)
    api_token = resolve_api_token(settings.api_token, settings.host)
    url = build_desktop_url(settings.host, port)
    if api_token:
        url = f"{url}?token={api_token}"
    app = create_app(
        settings.db_path,
        config_path=settings.config_path,
        config_env=settings.config_env,
        plugin_paths=tuple(settings.plugin_paths),
        api_token=api_token,
    )
    server_config = uvicorn.Config(app, host=settings.host, port=port, log_level="info")
    server = uvicorn.Server(server_config)
    if settings.open_browser:
        threading.Thread(target=_open_when_ready, args=(url,), daemon=True).start()
    print(f"Netroach desktop: {url}")
    server.run()
    return 0


def _open_when_ready(url: str) -> None:
    time.sleep(0.8)
    webbrowser.open(url)
