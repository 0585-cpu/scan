from __future__ import annotations

import ipaddress
import os
import secrets
from collections.abc import Iterable

from .scope import ScopeGuard

API_TOKEN_ENV = "NETROACH_API_TOKEN"
API_TOKEN_COOKIE = "netroach_api_token"


class AuthorizationError(PermissionError):
    """Raised when an active network action is not explicitly authorized."""


def is_loopback_host(host: str) -> bool:
    """Return True only for hosts that can never be reached from another machine."""
    value = (host or "").strip().strip("[]").lower()
    if value in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def resolve_api_token(explicit: str | None, host: str) -> str | None:
    """Pick the API token for a server bound to ``host``.

    Loopback binds stay open by default. Any other bind is reachable from the
    network, so an unauthenticated scanner API is never served: a token is
    generated when the operator did not supply one.
    """
    token = (explicit or os.environ.get(API_TOKEN_ENV) or "").strip()
    if token:
        return token
    if is_loopback_host(host):
        return None
    return secrets.token_urlsafe(32)


def require_active_authorization(confirm_authorized: bool, scopes: Iterable[str] | None) -> ScopeGuard:
    scope_values = [scope for scope in scopes or () if scope]
    if not confirm_authorized:
        raise AuthorizationError("active commands require confirm_authorized=true or --confirm-authorized")
    if not scope_values:
        raise AuthorizationError("active commands require at least one explicit --scope CIDR")
    return ScopeGuard.from_strings(scope_values)

