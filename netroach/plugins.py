from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .ports import parse_ports

MAX_RULE_BYTES = 512
MAX_RULES_PER_PLUGIN = 200


@dataclass(frozen=True)
class FingerprintRule:
    service: str
    confidence: float
    ports: tuple[int, ...] = ()
    contains: bytes | None = None
    starts_with: bytes | None = None
    contains_hex: bytes | None = None
    starts_with_hex: bytes | None = None
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("contains", "starts_with", "contains_hex", "starts_with_hex"):
            value = data[key]
            if isinstance(value, bytes):
                data[key] = value.hex() if key.endswith("_hex") else value.decode("utf-8", errors="replace")
        return data

    def to_runtime_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("source", None)
        for key in ("contains", "starts_with", "contains_hex", "starts_with_hex"):
            value = data[key]
            data[key] = list(value) if isinstance(value, bytes) else None
        data["ports"] = list(self.ports)
        return data


@dataclass(frozen=True)
class PluginManifest:
    name: str
    version: str = "0.0.0"
    description: str | None = None
    path: str | None = None
    port_profiles: dict[str, tuple[int, ...]] = field(default_factory=dict)
    tcp_services: dict[int, str] = field(default_factory=dict)
    udp_services: dict[int, str] = field(default_factory=dict)
    tcp_banner_rules: tuple[FingerprintRule, ...] = ()
    udp_response_rules: tuple[FingerprintRule, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "path": self.path,
            "port_profiles": {name: list(ports) for name, ports in self.port_profiles.items()},
            "tcp_services": {str(port): name for port, name in self.tcp_services.items()},
            "udp_services": {str(port): name for port, name in self.udp_services.items()},
            "tcp_banner_rules": [rule.to_dict() for rule in self.tcp_banner_rules],
            "udp_response_rules": [rule.to_dict() for rule in self.udp_response_rules],
        }


@dataclass(frozen=True)
class PluginCatalog:
    plugins: tuple[PluginManifest, ...] = ()
    port_profiles: dict[str, tuple[int, ...]] = field(default_factory=dict)
    tcp_services: dict[int, str] = field(default_factory=dict)
    udp_services: dict[int, str] = field(default_factory=dict)
    tcp_banner_rules: tuple[FingerprintRule, ...] = ()
    udp_response_rules: tuple[FingerprintRule, ...] = ()

    @property
    def has_runtime_fingerprints(self) -> bool:
        return bool(self.tcp_services or self.udp_services or self.tcp_banner_rules or self.udp_response_rules)

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": len(self.plugins),
            "plugins": [plugin.to_dict() for plugin in self.plugins],
            "port_profiles": {name: list(ports) for name, ports in self.port_profiles.items()},
            "tcp_services": {str(port): name for port, name in self.tcp_services.items()},
            "udp_services": {str(port): name for port, name in self.udp_services.items()},
            "runtime_fingerprints": self.has_runtime_fingerprints,
        }

    def runtime_catalog_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "tcp_services": {str(port): name for port, name in self.tcp_services.items()},
            "udp_services": {str(port): name for port, name in self.udp_services.items()},
            "tcp_banner_rules": [rule.to_runtime_dict() for rule in self.tcp_banner_rules],
            "udp_response_rules": [rule.to_runtime_dict() for rule in self.udp_response_rules],
        }


def load_plugins(paths: Iterable[str | os.PathLike[str]] | None, *, base_dir: Path | None = None) -> PluginCatalog:
    manifest_paths = resolve_plugin_manifest_paths(paths, base_dir=base_dir)
    manifests = tuple(load_plugin_manifest(path) for path in manifest_paths)
    return combine_plugins(manifests)


def resolve_plugin_manifest_paths(
    paths: Iterable[str | os.PathLike[str]] | None,
    *,
    base_dir: Path | None = None,
) -> list[Path]:
    result: list[Path] = []
    for raw_path in paths or ():
        if raw_path is None:
            continue
        text = os.fspath(raw_path).strip()
        if not text:
            continue
        path = Path(text)
        if not path.is_absolute() and base_dir is not None:
            path = base_dir / path
        if path.is_dir():
            result.extend(sorted(candidate.resolve() for candidate in path.glob("*.json") if candidate.is_file()))
        elif path.is_file():
            result.append(path.resolve())
        else:
            raise ValueError(f"plugin path not found: {path}")
    return result


def load_plugin_manifest(path: str | os.PathLike[str]) -> PluginManifest:
    manifest_path = Path(path)
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"could not read plugin manifest: {manifest_path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"could not parse plugin manifest: {manifest_path}: {exc}") from exc
    return parse_plugin_manifest(data, path=manifest_path)


def parse_plugin_manifest(data: dict[str, Any], *, path: Path | None = None) -> PluginManifest:
    if not isinstance(data, dict):
        raise ValueError("plugin manifest must be a JSON object")
    name = required_str(data, "name")
    version = optional_str(data.get("version"), "version") or "0.0.0"
    description = optional_str(data.get("description"), "description")
    port_profiles = parse_port_profiles(data.get("port_profiles"), "port_profiles")
    tcp_services = parse_service_map(data.get("tcp_services"), "tcp_services")
    udp_services = parse_service_map(data.get("udp_services"), "udp_services")
    tcp_banner_rules = parse_rules(data.get("tcp_banner_rules"), "tcp_banner_rules", path=path)
    udp_response_rules = parse_rules(data.get("udp_response_rules"), "udp_response_rules", path=path)
    return PluginManifest(
        name=name,
        version=version,
        description=description,
        path=str(path) if path else None,
        port_profiles=port_profiles,
        tcp_services=tcp_services,
        udp_services=udp_services,
        tcp_banner_rules=tcp_banner_rules,
        udp_response_rules=udp_response_rules,
    )


def combine_plugins(manifests: Iterable[PluginManifest]) -> PluginCatalog:
    plugins = tuple(manifests)
    port_profiles: dict[str, tuple[int, ...]] = {}
    tcp_services: dict[int, str] = {}
    udp_services: dict[int, str] = {}
    tcp_rules: list[FingerprintRule] = []
    udp_rules: list[FingerprintRule] = []
    for manifest in plugins:
        for profile, ports in manifest.port_profiles.items():
            port_profiles[profile] = ports
        tcp_services.update(manifest.tcp_services)
        udp_services.update(manifest.udp_services)
        tcp_rules.extend(manifest.tcp_banner_rules)
        udp_rules.extend(manifest.udp_response_rules)
    return PluginCatalog(
        plugins=plugins,
        port_profiles=port_profiles,
        tcp_services=tcp_services,
        udp_services=udp_services,
        tcp_banner_rules=tuple(tcp_rules),
        udp_response_rules=tuple(udp_rules),
    )


def plugin_paths_from_env() -> tuple[str, ...]:
    raw = os.environ.get("NETROACH_PLUGINS", "")
    return tuple(part for part in raw.split(os.pathsep) if part)


def load_effective_plugin_catalog(config: Any, extra_paths: Iterable[str] | None = None) -> PluginCatalog:
    config_base = config.path.parent if config.path else None
    config_catalog = load_plugins(config.plugin_paths, base_dir=config_base)
    extra_catalog = load_plugins((*plugin_paths_from_env(), *(extra_paths or ())))
    return combine_plugins((*config_catalog.plugins, *extra_catalog.plugins))


def parse_port_profiles(value: Any, label: str) -> dict[str, tuple[int, ...]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    result: dict[str, tuple[int, ...]] = {}
    for name, ports in value.items():
        profile_name = str(name)
        result[profile_name] = tuple(parse_ports(port_expression(ports, f"{label}.{profile_name}")))
    return result


def parse_service_map(value: Any, label: str) -> dict[int, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    result: dict[int, str] = {}
    for raw_port, raw_service in value.items():
        port = parse_single_port(str(raw_port), f"{label}.{raw_port}")
        result[port] = service_name(raw_service, f"{label}.{raw_port}")
    return result


def parse_rules(value: Any, label: str, *, path: Path | None) -> tuple[FingerprintRule, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    if len(value) > MAX_RULES_PER_PLUGIN:
        raise ValueError(f"{label} must contain <= {MAX_RULES_PER_PLUGIN} rules")
    rules: list[FingerprintRule] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"{label}.{index} must be an object")
        source = f"{path}:{label}.{index}" if path else f"{label}.{index}"
        rules.append(parse_rule(item, f"{label}.{index}", source=source))
    return tuple(rules)


def parse_rule(data: dict[str, Any], label: str, *, source: str) -> FingerprintRule:
    match_fields = {
        key
        for key in ("contains", "starts_with", "contains_hex", "starts_with_hex")
        if data.get(key) is not None
    }
    if not match_fields:
        raise ValueError(f"{label} requires at least one match field")
    return FingerprintRule(
        service=service_name(data.get("service"), f"{label}.service"),
        confidence=confidence(data.get("confidence", 0.85), f"{label}.confidence"),
        ports=parse_rule_ports(data.get("ports"), f"{label}.ports"),
        contains=optional_match_bytes(data.get("contains"), f"{label}.contains"),
        starts_with=optional_match_bytes(data.get("starts_with"), f"{label}.starts_with"),
        contains_hex=optional_hex_bytes(data.get("contains_hex"), f"{label}.contains_hex"),
        starts_with_hex=optional_hex_bytes(data.get("starts_with_hex"), f"{label}.starts_with_hex"),
        source=source,
    )


def parse_rule_ports(value: Any, label: str) -> tuple[int, ...]:
    if value is None:
        return ()
    return tuple(parse_ports(port_expression(value, label)))


def port_expression(value: Any, label: str) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    raise ValueError(f"{label} must be a port expression string or list")


def parse_single_port(value: str, label: str) -> int:
    ports = parse_ports(value)
    if len(ports) != 1:
        raise ValueError(f"{label} must be a single port")
    return ports[0]


def confidence(value: Any, label: str) -> float:
    if not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a number")
    result = float(value)
    if result < 0 or result > 1:
        raise ValueError(f"{label} must be between 0 and 1")
    return result


def service_name(value: Any, label: str) -> str:
    name = required_str({label: value}, label)
    if len(name) > 64:
        raise ValueError(f"{label} must be <= 64 characters")
    if not all(ch.isalnum() or ch in {"-", "_", "."} for ch in name):
        raise ValueError(f"{label} may contain only letters, numbers, '.', '_' and '-'")
    return name


def required_str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value.strip()


def optional_str(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    return value


def optional_match_bytes(value: Any, label: str) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    data = value.encode("utf-8")
    if len(data) > MAX_RULE_BYTES:
        raise ValueError(f"{label} must be <= {MAX_RULE_BYTES} bytes")
    return data


def optional_hex_bytes(value: Any, label: str) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty hex string")
    try:
        data = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be valid hex") from exc
    if len(data) > MAX_RULE_BYTES:
        raise ValueError(f"{label} must be <= {MAX_RULE_BYTES} bytes")
    return data
