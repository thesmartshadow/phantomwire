"""TLS inspection helpers."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import List, Optional

from ..core.models import Evidence, Finding
from ..core.safemode import safe_mode
from ..core.utils import maybe_import


def _parse_cert(cert_dict: dict[str, object]) -> dict[str, object]:
    subject_parts = []
    for tuples in cert_dict.get("subject", []):
        for item in tuples:
            subject_parts.append("=".join(item))
    issuer_parts = []
    for tuples in cert_dict.get("issuer", []):
        for item in tuples:
            issuer_parts.append("=".join(item))
    subject = ", ".join(subject_parts)
    issuer = ", ".join(issuer_parts)
    san = []
    for entry in cert_dict.get("subjectAltName", []):
        if isinstance(entry, tuple):
            san.append(":".join(map(str, entry)))
    not_before = cert_dict.get("notBefore")
    not_after = cert_dict.get("notAfter")
    return {
        "subject": subject,
        "issuer": issuer,
        "subject_alt_names": san,
        "not_before": not_before,
        "not_after": not_after,
    }


def _crypto_details(der: bytes) -> dict[str, object]:
    crypto = maybe_import("cryptography")
    if crypto is None:
        return {}
    x509 = crypto.x509  # type: ignore[attr-defined]
    cert = x509.load_der_x509_certificate(der)
    sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = [name.value for name in san_ext.value]
    except Exception:
        san = []
    return {
        "signature_algorithm": sig_algo,
        "key_size": getattr(cert.public_key(), "key_size", None),
        "extensions": [ext.oid.dotted_string for ext in cert.extensions],
        "subject_alt_names_rich": san,
    }


def inspect(host: str, port: int) -> List[Finding]:
    """Inspect TLS properties for the remote service."""

    safe_mode.check_host(host)
    safe_mode.require_consent()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_OPTIONAL

    addr = (host, port)
    with socket.create_connection(addr, timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            protocol = ssock.version()
            cipher = ssock.cipher()
            cert_dict = ssock.getpeercert()
            der = ssock.getpeercert(binary_form=True) or b""

    if not cert_dict:
        raise RuntimeError("No certificate presented by the peer")

    parsed = _parse_cert(cert_dict)
    extra = _crypto_details(der) if der else {}

    not_after = parsed.get("not_after")
    days_remaining: Optional[int] = None
    severity = "Low"
    description = "TLS certificate is valid."
    now = datetime.now(tz=timezone.utc)
    if isinstance(not_after, str):
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
        delta = expires - now
        days_remaining = int(delta.total_seconds() // 86400)
        if delta.total_seconds() < 0:
            severity = "Critical"
            description = "TLS certificate is expired."
        elif days_remaining < 14:
            severity = "High"
            description = "TLS certificate expires within two weeks."
        elif days_remaining < 45:
            severity = "Medium"
            description = "TLS certificate expires within 45 days."

    evidence = Evidence(
        kind="tls.certificate",
        data={
            "host": host,
            "port": port,
            "protocol": protocol,
            "cipher": cipher,
            "certificate": parsed,
            "days_remaining": days_remaining,
            **extra,
        },
    )

    findings: List[Finding] = [
        Finding(
            id="TLS-A-001",
            title="Certificate validity",
            severity=severity,
            description=description,
            recommendation="Renew certificates at least 30 days prior to expiration.",
            evidence=(evidence,),
            tags=("tls", "certificate"),
        )
    ]

    if protocol and protocol not in {"TLSv1.2", "TLSv1.3"}:
        findings.append(
            Finding(
                id="TLS-A-002",
                title="Legacy TLS protocol negotiated",
                severity="High",
                description=f"Peer negotiated insecure protocol {protocol}.",
                recommendation="Disable legacy TLS versions and require TLS 1.2+.",
                evidence=(evidence,),
                tags=("tls", "protocol"),
            )
        )

    if cipher:
        name, version, bits = cipher
        if bits and bits < 128:
            findings.append(
                Finding(
                    id="TLS-A-003",
                    title="Weak cipher suite negotiated",
                    severity="High",
                    description=f"Cipher {name} offers only {bits}-bit security.",
                    recommendation="Restrict allowed ciphers to modern AEAD suites.",
                    evidence=(evidence,),
                    tags=("tls", "cipher"),
                )
            )
    return findings


__all__ = ["inspect"]
