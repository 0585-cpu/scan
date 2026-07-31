from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .constants import dns_rcode_name

SUPPORTED_LINKTYPES = {
    0,  # BSD loopback
    1,  # Ethernet
    12,  # raw IP
    101,  # raw IP
    113,  # Linux cooked capture
    228,  # IPv4
    229,  # IPv6
    276,  # Linux cooked capture v2
}
PCAP_MAGIC_PREFIXES = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
}


@dataclass
class PcapSummary:
    file: str
    packet_count: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    protocols: dict[str, int] = field(default_factory=dict)
    top_talkers: list[tuple[str, int]] = field(default_factory=list)
    conversations: list[tuple[str, int]] = field(default_factory=list)
    conversation_metrics: list[dict[str, Any]] = field(default_factory=list)
    dns_queries: list[str] = field(default_factory=list)
    dns_responses: dict[str, Any] = field(default_factory=dict)
    http_hosts: list[str] = field(default_factory=list)
    http_user_agents: list[str] = field(default_factory=list)
    http_status_lines: list[str] = field(default_factory=list)
    tls_metadata: list[dict[str, Any]] = field(default_factory=list)
    arp_summary: dict[str, int] = field(default_factory=dict)
    icmp_summary: dict[str, int] = field(default_factory=dict)
    dhcp_messages: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

def analyze_pcap(path: str | Path, *, top: int = 10) -> PcapSummary:
    try:
        from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, ICMP, IP, TCP, UDP, IPv6, PcapNgReader, PcapReader, Raw
    except ImportError as exc:
        raise RuntimeError("pcap analysis requires scapy. Install with: pip install scapy") from exc

    pcap_path = Path(path)
    if top < 1:
        raise ValueError("top must be at least 1")
    if not pcap_path.exists():
        raise ValueError(f"pcap file not found: {pcap_path}")
    if not pcap_path.is_file():
        raise ValueError(f"pcap path is not a file: {pcap_path}")
    if pcap_path.stat().st_size == 0:
        raise ValueError(f"pcap file is empty: {pcap_path}")
    _validate_capture_magic(pcap_path)

    protocol_counts: Counter[str] = Counter()
    talkers: Counter[str] = Counter()
    conversations: Counter[str] = Counter()
    conversation_metrics: dict[str, dict[str, Any]] = {}
    dns_queries: Counter[str] = Counter()
    dns_response_count = 0
    dns_answer_count = 0
    dns_rcodes: Counter[str] = Counter()
    http_hosts: Counter[str] = Counter()
    http_user_agents: Counter[str] = Counter()
    http_status_lines: Counter[str] = Counter()
    tls_metadata: Counter[tuple[str | None, tuple[str, ...]]] = Counter()
    arp_summary: Counter[str] = Counter()
    icmp_summary: Counter[str] = Counter()
    dhcp_messages: Counter[str] = Counter()
    summary = PcapSummary(file=str(pcap_path))

    reader_cls = PcapNgReader if pcap_path.suffix.lower() in {".pcapng", ".ntar"} else PcapReader
    try:
        with reader_cls(str(pcap_path)) as packets:
            linktype = getattr(packets, "linktype", None)
            if linktype is not None and linktype not in SUPPORTED_LINKTYPES:
                raise ValueError(f"unsupported pcap link type: {linktype}")
            for packet in packets:
                summary.packet_count += 1
                timestamp = float(packet.time)
                packet_bytes = len(bytes(packet))
                summary.first_ts = timestamp if summary.first_ts is None else min(summary.first_ts, timestamp)
                summary.last_ts = timestamp if summary.last_ts is None else max(summary.last_ts, timestamp)

                src = dst = proto = None
                if packet.haslayer(ARP):
                    protocol_counts["ARP"] += 1
                    _observe_arp(packet[ARP], arp_summary)
                if packet.haslayer(IP):
                    ip = packet[IP]
                    src, dst = ip.src, ip.dst
                    proto = "IPv4"
                elif packet.haslayer(IPv6):
                    ip6 = packet[IPv6]
                    src, dst = ip6.src, ip6.dst
                    proto = "IPv6"

                if src and dst:
                    talkers[src] += 1
                    talkers[dst] += 1
                    l4 = "OTHER"
                    sport = dport = ""
                    if packet.haslayer(TCP):
                        tcp = packet[TCP]
                        l4, sport, dport = "TCP", str(tcp.sport), str(tcp.dport)
                        protocol_counts["TCP"] += 1
                    elif packet.haslayer(UDP):
                        udp = packet[UDP]
                        l4, sport, dport = "UDP", str(udp.sport), str(udp.dport)
                        protocol_counts["UDP"] += 1
                    conversation = f"{src}:{sport} -> {dst}:{dport} {l4}"
                    conversations[conversation] += 1
                    _observe_conversation(conversation_metrics, conversation, timestamp, packet_bytes)

                if proto:
                    protocol_counts[proto] += 1
                if packet.haslayer(ICMP):
                    protocol_counts["ICMP"] += 1
                    _observe_icmp(packet[ICMP], icmp_summary)

                if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                    dns = packet[DNS]
                    query = packet[DNSQR].qname
                    if isinstance(query, bytes):
                        query = query.decode(errors="replace")
                    dns_queries[str(query).rstrip(".")] += 1
                    if int(getattr(dns, "qr", 0) or 0) == 1:
                        dns_response_count += 1
                        rcode = int(getattr(dns, "rcode", 0) or 0)
                        rcode_name = dns_rcode_name(rcode)
                        dns_rcodes[rcode_name] += 1
                        dns_answer_count += int(getattr(dns, "ancount", 0) or 0)
                if packet.haslayer(BOOTP) and packet.haslayer(DHCP):
                    protocol_counts["DHCP"] += 1
                    _observe_dhcp(packet[DHCP], dhcp_messages)

                if packet.haslayer(Raw) and packet.haslayer(TCP):
                    payload = bytes(packet[Raw].load)
                    http = _extract_http_metadata(payload)
                    if http.get("host"):
                        http_hosts[http["host"]] += 1
                    if http.get("user_agent"):
                        http_user_agents[http["user_agent"]] += 1
                    if http.get("status_line"):
                        http_status_lines[http["status_line"]] += 1
                    metadata = _extract_tls_metadata(payload)
                    if metadata:
                        tls_metadata[
                            (
                                str(metadata["sni"]) if metadata.get("sni") else None,
                                tuple(str(value) for value in metadata.get("alpn", [])),
                            )
                        ] += 1
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"could not read pcap file: {pcap_path}: {exc}") from exc

    summary.protocols = dict(protocol_counts.most_common())
    summary.top_talkers = talkers.most_common(top)
    summary.conversations = conversations.most_common(top)
    summary.conversation_metrics = _top_conversation_metrics(conversation_metrics, top)
    summary.dns_queries = [item for item, _ in dns_queries.most_common(top)]
    summary.dns_responses = {
        "total": dns_response_count,
        "answers": dns_answer_count,
        "nxdomain": dns_rcodes.get("NXDOMAIN", 0),
        "rcode_counts": dict(dns_rcodes.most_common()),
    }
    summary.http_hosts = [item for item, _ in http_hosts.most_common(top)]
    summary.http_user_agents = [item for item, _ in http_user_agents.most_common(top)]
    summary.http_status_lines = [item for item, _ in http_status_lines.most_common(top)]
    summary.tls_metadata = [
        {
            **({"sni": sni} if sni else {}),
            **({"alpn": list(alpn)} if alpn else {}),
        }
        for (sni, alpn), _ in tls_metadata.most_common(top)
    ]
    summary.arp_summary = dict(arp_summary.most_common())
    summary.icmp_summary = dict(icmp_summary.most_common())
    summary.dhcp_messages = dict(dhcp_messages.most_common())
    return summary


def _extract_http_metadata(payload: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if not payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")):
        if payload.startswith(b"HTTP/"):
            try:
                status_line = payload.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
            except UnicodeDecodeError:
                return result
            result["status_line"] = status_line
            parts = status_line.split(" ", 2)
            if len(parts) >= 2 and parts[1].isdigit():
                result["status_code"] = int(parts[1])
        return result
    try:
        text = payload[:4096].decode("iso-8859-1", errors="replace")
    except UnicodeDecodeError:
        return result
    lines = text.splitlines()
    if lines:
        request_parts = lines[0].split()
        if len(request_parts) >= 2:
            result["method"] = request_parts[0]
            result["path"] = request_parts[1]
    for line in lines:
        lower = line.lower()
        if lower.startswith("host:"):
            result["host"] = line.split(":", 1)[1].strip()
        elif lower.startswith("user-agent:"):
            result["user_agent"] = line.split(":", 1)[1].strip()
    return result


def _extract_tls_metadata(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 9 or payload[0] != 0x16:
        return None
    record_len = _read_u16(payload, 3)
    pos = 5
    if record_len is None or len(payload) < pos + min(record_len, 4):
        return None
    if payload[pos] != 0x01:
        return None
    handshake_len = int.from_bytes(payload[pos + 1 : pos + 4], "big")
    pos += 4
    end = min(len(payload), pos + handshake_len)
    if end - pos < 38:
        return None
    pos += 2  # client version
    pos += 32  # random
    if pos >= end:
        return None
    session_len = payload[pos]
    pos += 1 + session_len
    cipher_len = _read_u16(payload, pos)
    if cipher_len is None:
        return None
    pos += 2 + cipher_len
    if pos >= end:
        return None
    compression_len = payload[pos]
    pos += 1 + compression_len
    ext_total = _read_u16(payload, pos)
    if ext_total is None:
        return None
    pos += 2
    ext_end = min(end, pos + ext_total)
    result: dict[str, Any] = {}

    while pos + 4 <= ext_end:
        ext_type = _read_u16(payload, pos)
        ext_len = _read_u16(payload, pos + 2)
        if ext_type is None or ext_len is None:
            return result or None
        pos += 4
        ext_data = payload[pos : pos + ext_len]
        pos += ext_len
        if ext_type == 0:
            sni = _parse_sni_extension(ext_data)
            if sni:
                result["sni"] = sni
        elif ext_type == 16:
            alpn = _parse_alpn_extension(ext_data)
            if alpn:
                result["alpn"] = alpn
    return result or None


def _parse_sni_extension(data: bytes) -> str | None:
    if len(data) < 5:
        return None
    list_len = _read_u16(data, 0)
    if list_len is None or list_len + 2 > len(data):
        return None
    pos = 2
    while pos + 3 <= len(data):
        name_type = data[pos]
        name_len = _read_u16(data, pos + 1)
        if name_len is None:
            return None
        pos += 3
        name = data[pos : pos + name_len]
        pos += name_len
        if name_type == 0:
            try:
                return name.decode("ascii").encode("ascii").decode("idna")
            except UnicodeError:
                return name.decode("ascii", errors="replace")
    return None


def _validate_capture_magic(path: Path) -> None:
    with path.open("rb") as handle:
        magic = handle.read(4)
    if magic not in PCAP_MAGIC_PREFIXES:
        raise ValueError(f"could not read pcap file: {path}: unsupported capture magic")


def _parse_alpn_extension(data: bytes) -> list[str]:
    if len(data) < 2:
        return []
    list_len = _read_u16(data, 0)
    if list_len is None:
        return []
    pos = 2
    protocols: list[str] = []
    end = min(len(data), pos + list_len)
    while pos < end:
        length = data[pos]
        pos += 1
        protocols.append(data[pos : pos + length].decode("ascii", errors="replace"))
        pos += length
    return protocols


def _read_u16(data: bytes, offset: int) -> int | None:
    if offset + 2 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 2], "big")


def _observe_conversation(metrics: dict[str, dict[str, Any]], key: str, timestamp: float, packet_bytes: int) -> None:
    entry = metrics.setdefault(
        key,
        {
            "conversation": key,
            "packets": 0,
            "bytes": 0,
            "first_ts": timestamp,
            "last_ts": timestamp,
            "duration": 0.0,
        },
    )
    entry["packets"] += 1
    entry["bytes"] += packet_bytes
    entry["first_ts"] = min(entry["first_ts"], timestamp)
    entry["last_ts"] = max(entry["last_ts"], timestamp)
    entry["duration"] = round(entry["last_ts"] - entry["first_ts"], 6)


def _top_conversation_metrics(metrics: dict[str, dict[str, Any]], top: int) -> list[dict[str, Any]]:
    ordered = sorted(metrics.values(), key=lambda item: (-int(item["packets"]), -int(item["bytes"]), str(item["conversation"])))
    return ordered[:top]


def _observe_arp(arp: object, counts: Counter[str]) -> None:
    op = int(getattr(arp, "op", 0) or 0)
    if op == 1:
        counts["requests"] += 1
    elif op == 2:
        counts["replies"] += 1
    else:
        counts[f"op_{op}"] += 1


def _observe_icmp(icmp: object, counts: Counter[str]) -> None:
    icmp_type = int(getattr(icmp, "type", -1))
    icmp_code = int(getattr(icmp, "code", 0) or 0)
    counts[_icmp_type_name(icmp_type, icmp_code)] += 1


def _icmp_type_name(icmp_type: int, icmp_code: int) -> str:
    names = {
        0: "echo_reply",
        3: "destination_unreachable",
        5: "redirect",
        8: "echo_request",
        11: "time_exceeded",
    }
    return names.get(icmp_type, f"type_{icmp_type}_code_{icmp_code}")


def _observe_dhcp(dhcp: object, counts: Counter[str]) -> None:
    message = "unknown"
    for option in getattr(dhcp, "options", []) or []:
        if isinstance(option, tuple) and option and option[0] == "message-type":
            message = _dhcp_message_name(option[1])
            break
    counts[message] += 1


def _dhcp_message_name(value: object) -> str:
    names = {
        1: "discover",
        2: "offer",
        3: "request",
        4: "decline",
        5: "ack",
        6: "nak",
        7: "release",
        8: "inform",
    }
    if isinstance(value, int):
        return names.get(value, str(value))
    return str(value).lower().replace(" ", "_")

