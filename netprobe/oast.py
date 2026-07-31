from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

DEFAULT_OAST_TTL_SECONDS = 3600
MAX_OAST_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_OAST_LABEL_LENGTH = 128
MAX_OAST_BASE_URL_LENGTH = 512
MAX_OAST_BODY_PREVIEW_BYTES = 4096
REDACTED_HEADER_NAMES = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
}


@dataclass(frozen=True)
class OastSessionRequest:
    confirm_authorized: bool
    label: str | None = None
    base_url: str | None = None
    ttl_seconds: int = DEFAULT_OAST_TTL_SECONDS


def new_oast_token() -> str:
    return secrets.token_urlsafe(24)


def validate_oast_session_request(request: OastSessionRequest) -> None:
    if not request.confirm_authorized:
        raise ValueError("OAST session creation requires confirm_authorized=true")
    if request.ttl_seconds < 60:
        raise ValueError("ttl_seconds must be at least 60")
    if request.ttl_seconds > MAX_OAST_TTL_SECONDS:
        raise ValueError(f"ttl_seconds must be <= {MAX_OAST_TTL_SECONDS}")
    if request.label is not None and len(request.label) > MAX_OAST_LABEL_LENGTH:
        raise ValueError(f"label must be <= {MAX_OAST_LABEL_LENGTH} characters")
    if request.base_url is not None:
        validate_base_url(request.base_url)


def validate_base_url(value: str) -> None:
    if len(value) > MAX_OAST_BASE_URL_LENGTH:
        raise ValueError(f"base_url must be <= {MAX_OAST_BASE_URL_LENGTH} characters")
    if not (value.startswith("http://") or value.startswith("https://")):
        raise ValueError("base_url must start with http:// or https://")


def build_callback_url(base_url: str | None, token: str) -> str:
    path = f"oast/{token}"
    if not base_url:
        return f"/{path}"
    return urljoin(base_url.rstrip("/") + "/", path)


def sanitized_headers(headers: dict[str, str] | list[tuple[str, str]]) -> dict[str, str]:
    items = headers.items() if isinstance(headers, dict) else headers
    result: dict[str, str] = {}
    for key, value in items:
        normalized = str(key).lower()
        result[str(key)] = "[redacted]" if normalized in REDACTED_HEADER_NAMES else str(value)[:1024]
    return result


def body_preview(body: bytes, *, limit: int = MAX_OAST_BODY_PREVIEW_BYTES) -> tuple[str, bool]:
    preview = body[:limit].decode("utf-8", errors="replace")
    return preview, len(body) > limit


def build_interaction_payload(
    *,
    method: str,
    path: str,
    query_string: str,
    client_host: str | None,
    headers: dict[str, str] | list[tuple[str, str]],
    body: bytes,
) -> dict[str, Any]:
    preview, truncated = body_preview(body)
    return {
        "method": method.upper(),
        "path": path,
        "query_string": query_string,
        "client_host": client_host,
        "headers": sanitized_headers(headers),
        "body_preview": preview,
        "body_truncated": truncated,
    }
