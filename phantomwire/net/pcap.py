"""PCAP sessionizer."""
from __future__ import annotations

import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

from ..core.models import Evidence, Finding
from ..core.utils import maybe_import

_SENSITIVE_PORTS = {21, 23, 80, 110, 143}


def _format_ip(addr: bytes) -> str:
    dpkt = maybe_import("dpkt")
    if dpkt is None:
        return ":".join(f"{b:02x}" for b in addr)
    try:
        return dpkt.utils.inet_to_str(addr)
    except Exception:  # pragma: no cover - dpkt edge case
        return ":".join(f"{b:02x}" for b in addr)


def _summarize_with_dpkt(path: Path) -> Tuple[List[Finding], Evidence]:
    dpkt = maybe_import("dpkt")
    if dpkt is None:
        raise RuntimeError("dpkt is not available")

    flows: Dict[Tuple[str, int, str, int, int], Dict[str, int]] = defaultdict(
        lambda: {"packets": 0, "bytes": 0}
    )
    talkers: Counter[str] = Counter()
    cleartext_detected = False

    with path.open("rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        for _, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not hasattr(ip, "p"):
                    continue
                proto = getattr(ip, "p", 0)
                src = _format_ip(getattr(ip, "src", b""))
                dst = _format_ip(getattr(ip, "dst", b""))
                sport = getattr(getattr(ip, "data", None), "sport", 0) or 0
                dport = getattr(getattr(ip, "data", None), "dport", 0) or 0
                key = (src, sport, dst, dport, proto)
                flows[key]["packets"] += 1
                flows[key]["bytes"] += len(buf)
                talkers.update([src, dst])
                payload = bytes(getattr(getattr(ip, "data", None), "data", b""))
                if not cleartext_detected and proto in {
                    dpkt.ip.IP_PROTO_TCP,
                    dpkt.ip.IP_PROTO_UDP,
                }:
                    if sport in _SENSITIVE_PORTS or dport in _SENSITIVE_PORTS:
                        if (
                            b"Authorization: Basic" in payload
                            or b"USER" in payload
                            or b"PASS" in payload
                        ):
                            cleartext_detected = True
            except (dpkt.UnpackError, ValueError):
                continue

    evidence = Evidence(
        kind="pcap.summary",
        data={
            "flow_count": len(flows),
            "top_talkers": talkers.most_common(5),
            "top_flows": sorted(
                (
                    {
                        "src": src,
                        "sport": sport,
                        "dst": dst,
                        "dport": dport,
                        "proto": proto,
                        "packets": stats["packets"],
                        "bytes": stats["bytes"],
                    }
                    for (src, sport, dst, dport, proto), stats in flows.items()
                ),
                key=lambda item: item["bytes"],
                reverse=True,
            )[:10],
        },
    )

    findings: List[Finding] = []
    if cleartext_detected:
        findings.append(
            Finding(
                id="PCAP-N-001",
                title="Potential cleartext credentials detected",
                severity="High",
                description=(
                    "Traffic captured includes patterns resembling cleartext authentication."
                ),
                recommendation="Move services to encrypted protocols and monitor credentials.",
                evidence=(evidence,),
                tags=("pcap", "cleartext"),
            )
        )

    return findings, evidence


def _summarize_without_dpkt(path: Path) -> Evidence:
    with path.open("rb") as fh:
        header = fh.read(24)
    if len(header) != 24:
        raise ValueError("File too small to be a PCAP")
    magic_number = struct.unpack("<I", header[:4])[0]
    return Evidence(
        kind="pcap.header",
        data={
            "magic_number": hex(magic_number),
            "message": "Install phantomwire[pcap] for advanced analysis.",
        },
    )


def sessionize(path: Path) -> List[Finding] | Evidence:
    """Summarize network sessions from a PCAP capture."""

    if maybe_import("dpkt") is None:
        return _summarize_without_dpkt(path)

    findings, evidence = _summarize_with_dpkt(path)
    if findings:
        return findings
    return evidence


__all__ = ["sessionize"]
