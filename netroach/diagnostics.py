from __future__ import annotations

import importlib.util
import os
import platform
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from .engine import resolve_engine_path
from .pktmon import check_pktmon
from .storage import default_db_path
from .version import __version__


@dataclass(frozen=True)
class PacketCapability:
    driver: str
    driver_available: bool | None
    elevated: bool | None
    raw_socket_privileged: bool
    note: str


@dataclass(frozen=True)
class DiagnosticReport:
    app_version: str
    platform: str
    python: str
    rust_engine: str | None
    rust_engine_available: bool
    rust_engine_version: str | None
    scapy_available: bool
    database_path: str
    packet_driver: str
    packet_driver_available: bool | None
    elevated: bool | None
    raw_socket_privileged: bool
    packet_driver_note: str
    pktmon_available: bool
    pktmon_note: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def collect_diagnostics() -> DiagnosticReport:
    system = platform.system()
    packet = collect_packet_capability(system)
    # Capture without a third-party driver is possible when this is available.
    pktmon = check_pktmon(elevated=packet.elevated)
    rust_engine = resolve_engine_path()
    return DiagnosticReport(
        app_version=__version__,
        platform=f"{system} {platform.release()} ({platform.machine()})",
        python=platform.python_version(),
        rust_engine=rust_engine,
        rust_engine_available=rust_engine is not None,
        rust_engine_version=read_engine_version(rust_engine),
        scapy_available=importlib.util.find_spec("scapy") is not None,
        database_path=os.fspath(default_db_path()),
        packet_driver=packet.driver,
        packet_driver_available=packet.driver_available,
        elevated=packet.elevated,
        raw_socket_privileged=packet.raw_socket_privileged,
        packet_driver_note=packet.note,
        pktmon_available=pktmon.available,
        pktmon_note=pktmon.reason,
    )


def collect_packet_capability(system: str | None = None) -> PacketCapability:
    system = system or platform.system()
    if system == "Windows":
        npcap = detect_npcap()
        elevated = is_windows_elevated()
        privileged = bool(npcap and elevated)
        if npcap and elevated:
            note = "Npcap detected and this process appears elevated; raw packet sending should be available."
        elif npcap:
            note = "Npcap detected; run an elevated terminal for raw packet sending."
        else:
            note = "Npcap was not detected. Install Npcap and run an elevated terminal for raw packet sending."
        return PacketCapability(
            driver="Npcap",
            driver_available=npcap,
            elevated=elevated,
            raw_socket_privileged=privileged,
            note=note,
        )
    if system == "Darwin":
        root = is_root_user()
        note = (
            "Raw packet privileges detected; packet sending should be available."
            if root
            else "Raw packet sending may require sudo and access to packet capture devices."
        )
        return PacketCapability(
            driver="BPF",
            driver_available=None,
            elevated=root,
            raw_socket_privileged=root,
            note=note,
        )
    if system == "Linux":
        root = is_root_user()
        cap_net_raw = has_cap_net_raw()
        privileged = root or cap_net_raw
        note = (
            "CAP_NET_RAW/root privileges detected; raw packet sending should be available."
            if privileged
            else "Raw packet sending may require CAP_NET_RAW or root."
        )
        return PacketCapability(
            driver="raw-socket",
            driver_available=None,
            elevated=root,
            raw_socket_privileged=privileged,
            note=note,
        )
    return PacketCapability(
        driver="raw-socket",
        driver_available=None,
        elevated=is_root_user(),
        raw_socket_privileged=is_root_user(),
        note="Raw packet sending may require elevated privileges.",
    )


def detect_npcap() -> bool:
    for path in npcap_candidate_paths():
        if path.exists():
            return True
    return windows_service_exists("npcap") or windows_service_exists("npf")


def npcap_candidate_paths() -> list[Path]:
    windir = Path(os.environ.get("WINDIR") or os.environ.get("SystemRoot") or r"C:\Windows")
    program_files = Path(os.environ.get("ProgramFiles") or r"C:\Program Files")
    return [
        windir / "System32" / "Npcap" / "Packet.dll",
        windir / "SysWOW64" / "Npcap" / "Packet.dll",
        program_files / "Npcap" / "NPFInstall.exe",
    ]


def windows_service_exists(name: str) -> bool:
    try:
        result = subprocess.run(
            ["sc.exe", "query", name],
            text=True,
            capture_output=True,
            timeout=1,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and name.lower() in (result.stdout + result.stderr).lower()


def is_windows_elevated() -> bool | None:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - diagnostics should never fail startup.
        return None


def is_root_user() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid is not None and geteuid() == 0)


def has_cap_net_raw() -> bool:
    status = Path("/proc/self/status")
    try:
        for line in status.read_text(encoding="utf-8").splitlines():
            if line.startswith("CapEff:"):
                value = int(line.split(":", 1)[1].strip(), 16)
                return bool(value & (1 << 13))
    except (OSError, ValueError):
        return False
    return False


def read_engine_version(engine_path: str | None) -> str | None:
    if not engine_path:
        return None
    try:
        result = subprocess.run(
            [engine_path, "--version"],
            text=True,
            capture_output=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    version = result.stdout.strip()
    return version or None
