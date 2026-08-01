from __future__ import annotations

RESULT_STATES = ("open", "closed", "open|filtered", "filtered", "error")
RESULT_PROTOCOLS = ("tcp", "udp")

DNS_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def dns_rcode_name(value: int) -> str:
    return DNS_RCODE_NAMES.get(value, str(value))
