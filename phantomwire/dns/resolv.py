"""DNS utilities."""
from __future__ import annotations

import socket
from typing import Dict, List

from ..core.models import Evidence
from ..core.safemode import safe_mode
from ..core.utils import maybe_import


def resolve(host: str) -> Evidence:
    """Resolve hostnames safely respecting consent."""

    safe_mode.check_host(host)
    safe_mode.require_consent()

    records: Dict[str, List[str]] = {"A": [], "AAAA": []}
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        records["error"] = [str(exc)]  # type: ignore[assignment]
        return Evidence(kind="dns.lookup", data=records)

    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            records["A"].append(sockaddr[0])
        elif family == socket.AF_INET6:
            records["AAAA"].append(sockaddr[0])

    dns = maybe_import("dns.resolver")
    if dns is not None:
        resolver = dns.Resolver()  # type: ignore[attr-defined]
        for record_type in ["CNAME", "TXT"]:
            try:
                answers = resolver.resolve(host, record_type)
                values = [answer.to_text() for answer in answers]  # type: ignore[assignment]
                records[record_type] = values
            except Exception:
                continue

    return Evidence(kind="dns.lookup", data=records)


__all__ = ["resolve"]
