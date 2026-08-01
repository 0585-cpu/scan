from __future__ import annotations

import base64
import binascii
import socket
import time
from typing import Any

from .auth import require_active_authorization
from .constants import dns_rcode_name
from .models import PacketRequest, SendResult

MAX_PACKET_COUNT = 1000
MIN_INTERVAL_MS = 10
MAX_PAYLOAD_BYTES = 4096
SUPPORTED_TEMPLATES = {"icmp", "tcp", "udp", "dns", "http"}


def execute_packet_request(request: PacketRequest) -> SendResult:
    validate_packet_request(request)
    scope = require_active_authorization(request.confirm_authorized, request.scope)
    scope.require_ip(request.target)
    payload = decode_payload(request.payload_text, request.payload_base64)
    interval = request.interval_ms / 1000
    if request.dry_run:
        return preview_packet_request(request, payload=payload)

    if request.template == "icmp":
        return send_icmp(request.target, count=request.count, interval=interval, payload=payload)
    if request.template == "udp":
        assert request.dport is not None
        return send_udp(
            request.target,
            dport=request.dport,
            sport=request.sport,
            count=request.count,
            interval=interval,
            payload=payload,
        )
    if request.template == "tcp":
        assert request.dport is not None
        return send_tcp(
            request.target,
            dport=request.dport,
            sport=request.sport,
            flags=request.flags,
            count=request.count,
            interval=interval,
            payload=payload,
        )
    if request.template == "dns":
        return send_dns(
            request.target,
            qname=request.dns_name or request.http_host or "example.com",
            dport=request.dport or 53,
            count=request.count,
            interval=interval,
            payload=payload,
        )
    if request.template == "http":
        return send_http(
            request.target,
            dport=request.dport or 80,
            method=request.http_method,
            path=request.http_path,
            host_header=request.http_host,
            count=request.count,
            interval=interval,
            payload=payload,
        )
    raise ValueError(f"unsupported packet template: {request.template}")


def preview_packet_request(request: PacketRequest, *, payload: bytes | None = None) -> SendResult:
    validate_packet_request(request)
    payload = payload if payload is not None else decode_payload(request.payload_text, request.payload_base64)
    details = packet_preview(request, payload=payload)
    details["dry_run"] = True
    return SendResult(template=request.template, target=request.target, sent=0, duration_s=0.0, details=details)


def packet_preview(request: PacketRequest, *, payload: bytes | None = None) -> dict[str, Any]:
    payload = payload if payload is not None else decode_payload(request.payload_text, request.payload_base64)
    details: dict[str, Any] = {
        "template": request.template,
        "target": request.target,
        "count": request.count,
        "interval_ms": request.interval_ms,
        "payload_bytes": len(payload),
        "layers": _preview_layers(request),
    }
    if request.dport is not None:
        details["dport"] = request.dport
    if request.sport is not None:
        details["sport"] = request.sport
    if request.template == "tcp":
        details["flags"] = request.flags.upper()
    if request.template == "dns":
        details["qname"] = request.dns_name
        details["dport"] = request.dport or 53
    if request.template == "http":
        details["dport"] = request.dport or 80
        details["method"] = request.http_method.upper()
        details["path"] = request.http_path
        details["host_header"] = request.http_host or request.target
    return details


def validate_packet_request(request: PacketRequest) -> None:
    if request.template not in SUPPORTED_TEMPLATES:
        raise ValueError(f"unsupported packet template: {request.template}")
    if request.count < 1 or request.count > MAX_PACKET_COUNT:
        raise ValueError(f"count must be between 1 and {MAX_PACKET_COUNT}")
    if request.interval_ms < MIN_INTERVAL_MS:
        raise ValueError(f"interval_ms must be at least {MIN_INTERVAL_MS}")
    if request.payload_text and request.payload_base64:
        raise ValueError("use only one of payload_text or payload_base64")
    payload = decode_payload(request.payload_text, request.payload_base64)
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError(f"payload must not exceed {MAX_PAYLOAD_BYTES} bytes")
    if request.template in {"tcp", "udp"} and request.dport is None:
        raise ValueError(f"{request.template} requires dport")
    if request.template == "dns" and not request.dns_name:
        raise ValueError("dns template requires dns_name")
    if request.template == "dns" and len(request.dns_name or "") > 253:
        raise ValueError("dns_name must not exceed 253 characters")
    if request.template == "http" and request.http_method.upper() not in {"GET", "HEAD", "POST", "PUT", "DELETE"}:
        raise ValueError("http_method must be one of GET, HEAD, POST, PUT, DELETE")
    if request.template == "http" and not request.http_path.startswith("/"):
        raise ValueError("http_path must start with /")
    if request.template == "tcp" and not set(request.flags.upper()) <= set("FSRPAUECN"):
        raise ValueError("flags contains unsupported TCP flag characters")
    for port in [request.dport, request.sport]:
        if port is not None and (port < 1 or port > 65535):
            raise ValueError(f"port out of range: {port}")


def decode_payload(payload_text: str | None, payload_base64: str | None) -> bytes:
    if payload_text and payload_base64:
        raise ValueError("use only one of payload_text or payload_base64")
    if payload_base64:
        try:
            return base64.b64decode(payload_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("payload_base64 is not valid base64") from exc
    if payload_text:
        return payload_text.encode("utf-8")
    return b""


def send_icmp(target: str, *, count: int = 1, interval: float = 1.0, payload: bytes = b"") -> SendResult:
    scapy = _load_scapy()
    packet = scapy.IP(dst=target) / scapy.ICMP() / payload
    return _send(
        packet,
        "icmp",
        target,
        count=count,
        interval=interval,
        scapy=scapy,
        details={
            "count": count,
            "interval_ms": int(interval * 1000),
            "payload_bytes": len(payload),
            "layers": ["IP", "ICMP"],
        },
    )


def send_udp(
    target: str,
    *,
    dport: int,
    sport: int | None = None,
    count: int = 1,
    interval: float = 1.0,
    payload: bytes = b"",
) -> SendResult:
    scapy = _load_scapy()
    udp = scapy.UDP(dport=dport)
    if sport is not None:
        udp.sport = sport
    packet = scapy.IP(dst=target) / udp / payload
    return _send(
        packet,
        "udp",
        target,
        count=count,
        interval=interval,
        scapy=scapy,
        details={
            "dport": dport,
            "sport": sport,
            "count": count,
            "interval_ms": int(interval * 1000),
            "payload_bytes": len(payload),
            "layers": ["IP", "UDP"],
        },
    )


def send_tcp(
    target: str,
    *,
    dport: int,
    sport: int | None = None,
    flags: str = "S",
    count: int = 1,
    interval: float = 1.0,
    payload: bytes = b"",
) -> SendResult:
    scapy = _load_scapy()
    tcp = scapy.TCP(dport=dport, flags=flags)
    if sport is not None:
        tcp.sport = sport
    packet = scapy.IP(dst=target) / tcp / payload
    return _send(
        packet,
        "tcp",
        target,
        count=count,
        interval=interval,
        scapy=scapy,
        details={
            "dport": dport,
            "sport": sport,
            "flags": flags.upper(),
            "count": count,
            "interval_ms": int(interval * 1000),
            "payload_bytes": len(payload),
            "layers": ["IP", "TCP"],
        },
    )


def send_dns(
    target: str,
    *,
    qname: str,
    dport: int = 53,
    count: int = 1,
    interval: float = 1.0,
    payload: bytes = b"",
) -> SendResult:
    scapy = _load_scapy()
    _validate_count_interval(count, interval)
    start = time.perf_counter()
    summaries: list[dict[str, Any]] = []
    for index in range(count):
        packet = scapy.IP(dst=target) / scapy.UDP(dport=dport) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname=qname))
        response = scapy.sr1(packet, timeout=3.0, verbose=False)
        summaries.append(_summarize_dns_response(response, scapy))
        if index + 1 < count:
            time.sleep(interval)
    duration = time.perf_counter() - start
    last_summary = summaries[-1] if summaries else {"response_received": False}
    return SendResult(
        template="dns",
        target=target,
        sent=count,
        duration_s=round(duration, 3),
        details={
            "qname": qname,
            "dport": dport,
            "count": count,
            "interval_ms": int(interval * 1000),
            "payload_bytes": len(payload),
            "layers": ["IP", "UDP", "DNS"],
            "response": last_summary,
            "responses": summaries,
        },
    )


def send_http(
    target: str,
    *,
    dport: int = 80,
    method: str = "GET",
    path: str = "/",
    host_header: str | None = None,
    count: int = 1,
    interval: float = 1.0,
    payload: bytes = b"",
) -> SendResult:
    _validate_count_interval(count, interval)
    start = time.perf_counter()
    host = host_header or target
    body = payload.decode("utf-8", errors="replace") if payload else ""
    statuses: list[dict[str, Any]] = []
    for index in range(count):
        with socket.create_connection((target, dport), timeout=3.0) as sock:
            request = (
                f"{method.upper()} {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Connection: close\r\n"
                f"Content-Length: {len(body.encode('utf-8'))}\r\n"
                "\r\n"
                f"{body}"
            )
            sock.sendall(request.encode("utf-8"))
            response = sock.recv(1024)
            statuses.append(_summarize_http_response(response))
        if index + 1 < count:
            time.sleep(interval)
    duration = time.perf_counter() - start
    last_status = statuses[-1] if statuses else {}
    return SendResult(
        template="http",
        target=target,
        sent=count,
        duration_s=round(duration, 3),
        details={
            "dport": dport,
            "method": method.upper(),
            "path": path,
            "host_header": host,
            "count": count,
            "interval_ms": int(interval * 1000),
            "payload_bytes": len(payload),
            "layers": ["TCP", "HTTP"],
            "status_code": last_status.get("status_code"),
            "status_line": last_status.get("status_line"),
            "responses": statuses,
        },
    )


def _send(
    packet: object,
    packet_type: str,
    target: str,
    *,
    count: int,
    interval: float,
    scapy: Any,
    details: dict[str, Any] | None = None,
) -> SendResult:
    _validate_count_interval(count, interval)
    start = time.perf_counter()
    scapy.send(packet, count=count, inter=interval, verbose=False)
    duration = time.perf_counter() - start
    return SendResult(template=packet_type, target=target, sent=count, duration_s=round(duration, 3), details=details or {})


def _validate_count_interval(count: int, interval: float) -> None:
    if count < 1:
        raise ValueError("count must be at least 1")
    if count > MAX_PACKET_COUNT:
        raise ValueError(f"count must not exceed {MAX_PACKET_COUNT}")
    if interval < 0:
        raise ValueError("interval cannot be negative")
    if interval * 1000 < MIN_INTERVAL_MS:
        raise ValueError(f"interval must be at least {MIN_INTERVAL_MS} ms")


def _load_scapy() -> Any:
    try:
        import scapy.all as scapy
    except ImportError as exc:
        raise RuntimeError("packet sending requires scapy. Install with: pip install scapy") from exc
    return scapy


def _preview_layers(request: PacketRequest) -> list[str]:
    if request.template == "icmp":
        return ["IP", "ICMP"]
    if request.template == "udp":
        return ["IP", "UDP"]
    if request.template == "tcp":
        return ["IP", "TCP"]
    if request.template == "dns":
        return ["IP", "UDP", "DNS"]
    if request.template == "http":
        return ["TCP", "HTTP"]
    return [request.template.upper()]


def _summarize_http_response(response: bytes) -> dict[str, Any]:
    if not response:
        return {"response_received": False}
    head = response.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    parts = head.split(" ", 2)
    status_code = None
    if len(parts) >= 2 and parts[1].isdigit():
        status_code = int(parts[1])
    return {
        "response_received": True,
        "status_line": head,
        "status_code": status_code,
        "response_bytes": len(response),
    }


def _summarize_dns_response(response: Any, scapy: Any) -> dict[str, Any]:
    if response is None:
        return {"response_received": False}
    try:
        dns = response[scapy.DNS]
    except Exception:  # noqa: BLE001 - tolerate malformed/fake scapy responses.
        return {"response_received": True, "dns": False}
    answers: list[str] = []
    ancount = int(getattr(dns, "ancount", 0) or 0)
    answer_layer: Any = getattr(dns, "an", None)
    if ancount == 0 and answer_layer is not None and answer_layer.__class__.__name__ != "NoneType":
        ancount = 1
    for index in range(ancount):
        try:
            answer = answer_layer[index] if ancount > 1 else answer_layer
            answers.append(str(getattr(answer, "rdata", "")))
        except Exception:  # noqa: BLE001
            continue
    rcode_value = int(getattr(dns, "rcode", 0) or 0)
    return {
        "response_received": True,
        "dns": True,
        "rcode": rcode_value,
        "rcode_name": dns_rcode_name(rcode_value),
        "answers": ancount,
        "answer_values": answers[:10],
    }

