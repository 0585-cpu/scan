from __future__ import annotations

from functools import lru_cache
from pathlib import Path

DASHBOARD_FILE = Path(__file__).with_name("static") / "dashboard.html"


@lru_cache(maxsize=1)
def dashboard_html() -> str:
    return DASHBOARD_FILE.read_text(encoding="utf-8")
