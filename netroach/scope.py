from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

# ipaddress._BaseAddress is private and too wide for the stdlib signatures;
# these are the two types the module actually produces.
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
PRIVATE_DEFAULTS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


class ScopeError(ValueError):
    """Raised when a target is outside the authorized scope."""


@dataclass(frozen=True)
class ScopeGuard:
    networks: tuple[IPNetwork, ...]
    allow_private_default: bool = True

    @classmethod
    def from_strings(cls, scopes: Iterable[str] | None) -> ScopeGuard:
        parsed = tuple(ipaddress.ip_network(scope, strict=False) for scope in scopes or ())
        if parsed:
            return cls(networks=parsed, allow_private_default=False)
        return cls(networks=PRIVATE_DEFAULTS, allow_private_default=True)

    def contains_ip(self, value: str | IPAddress) -> bool:
        address = ipaddress.ip_address(value)
        return any(address.version == network.version and address in network for network in self.networks)

    def require_ip(self, value: str | IPAddress) -> IPAddress:
        address = ipaddress.ip_address(value)
        if not self.contains_ip(address):
            allowed = ", ".join(str(network) for network in self.networks)
            raise ScopeError(f"{address} is outside authorized scope: {allowed}")
        return address

    def require_targets(self, targets: Iterable[IPAddress]) -> None:
        for target in targets:
            self.require_ip(target)


def iter_target_tokens(expr: str) -> Iterator[str]:
    for raw_line in expr.splitlines():
        line = raw_line.split("#", 1)[0]
        for raw_part in line.split(","):
            part = raw_part.strip()
            if part:
                yield part


def parse_target_expr(expr: str, max_hosts: int = 4096) -> list[IPAddress]:
    """Parse comma/newline-separated IP/CIDR targets into individual addresses."""
    if max_hosts < 1:
        raise ScopeError("max_hosts must be at least 1")
    targets: list[IPAddress] = []
    seen: set[IPAddress] = set()

    for part in iter_target_tokens(expr):
        if "/" in part:
            network = ipaddress.ip_network(part, strict=False)
            host_iter: Iterator[IPAddress] = network.hosts()
            if network.num_addresses <= 2:
                host_iter = iter(network)
            for address in host_iter:
                if address not in seen:
                    targets.append(address)
                    seen.add(address)
                    if len(targets) > max_hosts:
                        raise ScopeError(f"target expansion exceeds --max-hosts={max_hosts}")
        else:
            address = ipaddress.ip_address(part)
            if address not in seen:
                targets.append(address)
                seen.add(address)
                if len(targets) > max_hosts:
                    raise ScopeError(f"target expansion exceeds --max-hosts={max_hosts}")

    if not targets:
        raise ScopeError("no targets were provided")
    return targets


def scope_values_from_targets(expr: str) -> list[str]:
    scopes: list[str] = []
    seen: set[str] = set()
    for part in iter_target_tokens(expr):
        if "/" in part:
            value = str(ipaddress.ip_network(part, strict=False))
        else:
            address = ipaddress.ip_address(part)
            value = f"{address}/{address.max_prefixlen}"
        if value not in seen:
            scopes.append(value)
            seen.add(value)
    if not scopes:
        raise ScopeError("no targets were provided")
    return scopes
