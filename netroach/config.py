from __future__ import annotations

import os
import platform
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised only on Python 3.10.
    import tomli as tomllib  # type: ignore[no-redef]

from .ports import parse_ports

DEFAULT_TIMEOUT_MS = 800
DEFAULT_CONCURRENCY = 2000
DEFAULT_RATE_LIMIT_PER_SEC = 5000
DEFAULT_SERVICE_PROBE = True
DEFAULT_PROTOCOL = "tcp"
DEFAULT_MAX_HOSTS = 65536
DEFAULT_MAX_ATTEMPTS = 1_000_000
DEFAULT_UDP_RETRIES = 1
MAX_TIMEOUT_MS = 60_000
MAX_CONCURRENCY = 4_096
MAX_RATE_LIMIT_PER_SEC = 100_000
MAX_HOSTS = 1_000_000


@dataclass(frozen=True)
class ScanConfig:
    ports: str | None = None
    ports_file: str | None = None
    port_profile: str | None = None
    top_ports: int | None = None
    exclude: tuple[str, ...] = ()
    scope: tuple[str, ...] = ()
    timeout_ms: int | None = None
    concurrency: int | None = None
    rate_limit_per_sec: int | None = None
    service_probe: bool | None = None
    protocol: str | None = None
    max_hosts: int | None = None
    max_attempts: int | None = None
    udp_retries: int | None = None


@dataclass(frozen=True)
class NetroachConfig:
    path: Path | None = None
    scan: ScanConfig = field(default_factory=ScanConfig)
    environments: dict[str, ScanConfig] = field(default_factory=dict)
    port_profiles: dict[str, tuple[int, ...]] = field(default_factory=dict)
    plugin_paths: tuple[str, ...] = ()

    def effective_scan(self, env: str | None = None) -> ScanConfig:
        parts: list[ScanConfig] = []
        if env and env in BUILTIN_ENVIRONMENTS:
            parts.append(BUILTIN_ENVIRONMENTS[env])
        parts.append(self.scan)
        if env:
            if env in self.environments:
                parts.append(self.environments[env])
            elif env not in BUILTIN_ENVIRONMENTS:
                known = sorted({*BUILTIN_ENVIRONMENTS, *self.environments})
                raise ValueError(f"unknown config environment: {env}; available: {', '.join(known)}")
        return merge_scan_configs(parts)


BUILTIN_ENVIRONMENTS: dict[str, ScanConfig] = {
    "local": ScanConfig(
        scope=("127.0.0.0/8", "::1/128"),
        timeout_ms=300,
        concurrency=200,
        rate_limit_per_sec=500,
        top_ports=20,
    ),
    "lab": ScanConfig(
        timeout_ms=800,
        concurrency=2000,
        rate_limit_per_sec=5000,
        top_ports=100,
    ),
    "corp": ScanConfig(
        timeout_ms=1200,
        concurrency=1000,
        rate_limit_per_sec=1500,
        top_ports=100,
    ),
}


def load_config(path: str | os.PathLike[str] | None = None) -> NetroachConfig:
    config_path = resolve_config_path(path)
    if config_path is None:
        return NetroachConfig()
    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"could not read config file: {config_path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"could not parse config file: {config_path}: {exc}") from exc
    return parse_config_data(data, path=config_path)


def resolve_config_path(path: str | os.PathLike[str] | None = None) -> Path | None:
    if path:
        candidate = Path(path)
        if not candidate.is_file():
            raise ValueError(f"config file not found: {candidate}")
        return candidate
    for candidate in default_config_paths():
        if candidate.is_file():
            return candidate
    return None


def default_config_paths() -> list[Path]:
    paths = [Path.cwd() / "netroach.toml"]
    system = platform.system().lower()
    if system == "windows":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        paths.append(base / "Netroach" / "netroach.toml")
    elif system == "darwin":
        paths.append(Path.home() / "Library" / "Application Support" / "netroach" / "netroach.toml")
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        paths.append(base / "netroach" / "netroach.toml")
    return paths


def parse_config_data(data: dict[str, Any], *, path: Path | None = None) -> NetroachConfig:
    scan = parse_scan_config(_mapping(data.get("scan"), "scan"), label="scan")
    environments = parse_environments(_mapping(data.get("environments"), "environments"))
    port_profiles = parse_port_profiles(data)
    plugin_paths = parse_plugin_paths(_mapping(data.get("plugins"), "plugins"))
    return NetroachConfig(
        path=path,
        scan=scan,
        environments=environments,
        port_profiles=port_profiles,
        plugin_paths=plugin_paths,
    )


def parse_environments(data: dict[str, Any]) -> dict[str, ScanConfig]:
    environments: dict[str, ScanConfig] = {}
    for name, raw in data.items():
        section = _mapping(raw, f"environments.{name}")
        scan_section = _mapping(section.get("scan", section), f"environments.{name}.scan")
        environments[str(name)] = parse_scan_config(scan_section, label=f"environments.{name}.scan")
    return environments


def parse_port_profiles(data: dict[str, Any]) -> dict[str, tuple[int, ...]]:
    raw_profiles: dict[str, Any] = {}
    raw_profiles.update(_mapping(data.get("port_profiles"), "port_profiles"))
    profiles_section = _mapping(data.get("profiles"), "profiles")
    raw_profiles.update(_mapping(profiles_section.get("ports"), "profiles.ports"))
    profiles: dict[str, tuple[int, ...]] = {}
    for name, value in raw_profiles.items():
        profiles[str(name)] = tuple(parse_ports(port_expression(value, f"port_profiles.{name}")))
    return profiles


def parse_plugin_paths(data: dict[str, Any]) -> tuple[str, ...]:
    return _str_tuple(data.get("paths"), "plugins.paths")


def parse_scan_config(data: dict[str, Any], *, label: str) -> ScanConfig:
    return ScanConfig(
        ports=_optional_ports(data.get("ports"), f"{label}.ports"),
        ports_file=_optional_str(data.get("ports_file"), f"{label}.ports_file"),
        port_profile=_optional_str(data.get("port_profile"), f"{label}.port_profile"),
        top_ports=_optional_int(data.get("top_ports"), f"{label}.top_ports"),
        exclude=_str_tuple(data.get("exclude"), f"{label}.exclude"),
        scope=_str_tuple(data.get("scope"), f"{label}.scope"),
        timeout_ms=_optional_int(data.get("timeout_ms"), f"{label}.timeout_ms"),
        concurrency=_optional_int(data.get("concurrency"), f"{label}.concurrency"),
        rate_limit_per_sec=_optional_int(data.get("rate_limit_per_sec"), f"{label}.rate_limit_per_sec"),
        service_probe=_optional_bool(data.get("service_probe"), f"{label}.service_probe"),
        protocol=_optional_str(data.get("protocol"), f"{label}.protocol"),
        max_hosts=_optional_int(data.get("max_hosts"), f"{label}.max_hosts"),
        max_attempts=_optional_int(data.get("max_attempts"), f"{label}.max_attempts"),
        udp_retries=_optional_int(data.get("udp_retries"), f"{label}.udp_retries"),
    )


def merge_scan_configs(configs: Iterable[ScanConfig]) -> ScanConfig:
    result = ScanConfig()
    for config in configs:
        replaces_port_source = any(
            value is not None for value in (config.ports, config.ports_file, config.port_profile, config.top_ports)
        )
        ports = None if replaces_port_source else result.ports
        ports_file = None if replaces_port_source else result.ports_file
        port_profile = None if replaces_port_source else result.port_profile
        top_ports = None if replaces_port_source else result.top_ports
        result = ScanConfig(
            ports=config.ports if config.ports is not None else ports,
            ports_file=config.ports_file if config.ports_file is not None else ports_file,
            port_profile=config.port_profile if config.port_profile is not None else port_profile,
            top_ports=config.top_ports if config.top_ports is not None else top_ports,
            exclude=_merge_tuple(result.exclude, config.exclude),
            scope=_merge_tuple(result.scope, config.scope),
            timeout_ms=config.timeout_ms if config.timeout_ms is not None else result.timeout_ms,
            concurrency=config.concurrency if config.concurrency is not None else result.concurrency,
            rate_limit_per_sec=(
                config.rate_limit_per_sec if config.rate_limit_per_sec is not None else result.rate_limit_per_sec
            ),
            service_probe=config.service_probe if config.service_probe is not None else result.service_probe,
            protocol=config.protocol if config.protocol is not None else result.protocol,
            max_hosts=config.max_hosts if config.max_hosts is not None else result.max_hosts,
            max_attempts=config.max_attempts if config.max_attempts is not None else result.max_attempts,
            udp_retries=config.udp_retries if config.udp_retries is not None else result.udp_retries,
        )
    return result


def resolve_scan_options(
    *,
    config: NetroachConfig,
    env: str | None,
    values: dict[str, Any],
    explicit_fields: set[str],
    disable_service_probe: bool = False,
) -> dict[str, Any]:
    scan = config.effective_scan(env)
    explicit_port_source = any(field in explicit_fields and values.get(field) is not None for field in PORT_SOURCE_FIELDS)
    if explicit_port_source:
        port_values = {field: values.get(field) for field in PORT_SOURCE_FIELDS}
    else:
        port_values = {
            "ports": scan.ports,
            "ports_file": scan.ports_file,
            "port_profile": scan.port_profile,
            "top_ports": scan.top_ports,
        }

    service_probe = _scalar_value(
        "service_probe",
        values,
        explicit_fields,
        scan.service_probe,
        DEFAULT_SERVICE_PROBE,
    )
    if disable_service_probe:
        service_probe = False

    options = {
        **port_values,
        "exclude": _merge_tuple(scan.exclude, tuple(values.get("exclude") or ())),
        "scope": _merge_tuple(scan.scope, tuple(values.get("scope") or ())),
        "timeout_ms": _scalar_value("timeout_ms", values, explicit_fields, scan.timeout_ms, DEFAULT_TIMEOUT_MS),
        "concurrency": _scalar_value("concurrency", values, explicit_fields, scan.concurrency, DEFAULT_CONCURRENCY),
        "rate_limit_per_sec": _scalar_value(
            "rate_limit_per_sec",
            values,
            explicit_fields,
            scan.rate_limit_per_sec,
            DEFAULT_RATE_LIMIT_PER_SEC,
        ),
        "service_probe": service_probe,
        "protocol": _scalar_value("protocol", values, explicit_fields, scan.protocol, DEFAULT_PROTOCOL),
        "max_hosts": _scalar_value("max_hosts", values, explicit_fields, scan.max_hosts, DEFAULT_MAX_HOSTS),
        "max_attempts": _scalar_value(
            "max_attempts",
            values,
            explicit_fields,
            scan.max_attempts,
            DEFAULT_MAX_ATTEMPTS,
        ),
        "udp_retries": _scalar_value(
            "udp_retries",
            values,
            explicit_fields,
            scan.udp_retries,
            DEFAULT_UDP_RETRIES,
        ),
        "config_env": env,
        "config_path": str(config.path) if config.path else None,
    }
    validate_scan_options(options)
    return options


PORT_SOURCE_FIELDS = {"ports", "ports_file", "port_profile", "top_ports"}


def validate_scan_options(options: dict[str, Any]) -> None:
    if not 1 <= int(options["timeout_ms"]) <= MAX_TIMEOUT_MS:
        raise ValueError(f"timeout_ms must be between 1 and {MAX_TIMEOUT_MS}")
    if not 1 <= int(options["concurrency"]) <= MAX_CONCURRENCY:
        raise ValueError(f"concurrency must be between 1 and {MAX_CONCURRENCY}")
    if not 1 <= int(options["rate_limit_per_sec"]) <= MAX_RATE_LIMIT_PER_SEC:
        raise ValueError(f"rate_limit_per_sec must be between 1 and {MAX_RATE_LIMIT_PER_SEC}")
    if not 1 <= int(options["max_hosts"]) <= MAX_HOSTS:
        raise ValueError(f"max_hosts must be between 1 and {MAX_HOSTS}")
    if int(options["max_attempts"]) < 1:
        raise ValueError("max_attempts must be at least 1")
    if not 0 <= int(options["udp_retries"]) <= 3:
        raise ValueError("udp_retries must be between 0 and 3")
    if options["protocol"] not in {"tcp", "udp"}:
        raise ValueError("protocol must be 'tcp' or 'udp'")


def _scalar_value(name: str, values: dict[str, Any], explicit_fields: set[str], configured: Any, default: Any) -> Any:
    if name in explicit_fields and values.get(name) is not None:
        return values[name]
    if configured is not None:
        return configured
    return default


def port_expression(value: Any, label: str) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    if isinstance(value, tuple):
        return ",".join(str(item) for item in value)
    raise ValueError(f"{label} must be a port expression string or list")


def _optional_ports(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return ",".join(str(port) for port in parse_ports(port_expression(value, label)))


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a table")
    return value


def _optional_str(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    return value


def _optional_int(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    return value


def _optional_bool(value: Any, label: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _str_tuple(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    raise ValueError(f"{label} must be a string or list of strings")


def _merge_tuple(first: tuple[str, ...], second: tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    for value in (*first, *second):
        if value and value not in result:
            result.append(value)
    return tuple(result)
