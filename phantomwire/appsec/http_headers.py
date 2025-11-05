"""HTTP security header analysis."""
from __future__ import annotations

import http.client
import ssl
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from ..core.models import Evidence, Finding, Target
from ..core.safemode import safe_mode
from ..core.utils import maybe_import

_USER_AGENT = "phantomwire/0.1.0"
_EXPECTED_HEADERS = {
    "strict-transport-security": "Enforce HSTS with includeSubDomains and preload where suitable.",
    "content-security-policy": "Define a strong CSP avoiding unsafe directives.",
    "x-frame-options": "Set to DENY or SAMEORIGIN to prevent clickjacking.",
    "referrer-policy": "Use no-referrer or strict-origin-when-cross-origin as appropriate.",
    "permissions-policy": "Restrict powerful features to trusted origins.",
}


def _fetch_headers(url: str) -> Tuple[int | None, Dict[str, str]]:
    httpx = maybe_import("httpx")
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    headers: Dict[str, str] = {}
    status: int | None = None
    if httpx is not None:
        client = httpx.Client(
            headers={"User-Agent": _USER_AGENT},
            follow_redirects=True,
            timeout=10.0,
        )
        try:
            response = client.head(url)
            if response.status_code >= 400:
                response = client.get(url, stream=True)
            headers = {k.lower(): v for k, v in response.headers.items()}
            status = response.status_code
        finally:
            client.close()
        return status, headers

    connection_cls = (
        http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    )
    context = ssl.create_default_context() if scheme == "https" else None
    netloc = parsed.netloc
    if not netloc:
        raise ValueError(f"Invalid URL '{url}'")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    connection = connection_cls(netloc, timeout=10, context=context)  # type: ignore[arg-type]
    try:
        connection.request("HEAD", path, headers={"User-Agent": _USER_AGENT})
        response = connection.getresponse()
        status = response.status
        headers = {k.lower(): v for k, v in response.getheaders()}
        connection.close()
    except http.client.HTTPException:
        connection.close()
        raise
    return status, headers


def _evaluate_header(name: str, value: str | None) -> Tuple[bool, bool]:
    if not value:
        return False, False
    lower = value.lower()
    if name == "strict-transport-security":
        weak = "includesubdomains" not in lower or "max-age" not in lower
        return True, weak
    if name == "content-security-policy":
        weak = "unsafe-inline" in lower or "*" in lower
        return True, weak
    if name == "x-frame-options":
        weak = lower not in {"deny", "sameorigin"}
        return True, weak
    if name == "referrer-policy":
        weak = lower in {"unsafe-url", "no-referrer-when-downgrade", "origin"}
        return True, weak
    if name == "permissions-policy":
        weak = "=" not in lower
        return True, weak
    return True, False


def analyze(target: Target) -> List[Finding]:
    """Analyze HTTP security headers for the given target."""

    parsed = urlparse(target.locator)
    host = target.host or parsed.hostname
    if not host:
        raise ValueError("Target host cannot be determined")

    safe_mode.check_host(host)
    safe_mode.require_consent()

    status, headers = _fetch_headers(target.locator)
    evidence = Evidence(
        kind="http.headers",
        data={"status": status, "headers": headers},
    )

    findings: List[Finding] = []
    for header, recommendation in _EXPECTED_HEADERS.items():
        present, weak = _evaluate_header(header, headers.get(header))
        if not present:
            findings.append(
                Finding(
                    id="HTTP-H-001",
                    title=f"Missing {header} header",
                    severity="Medium",
                    description=f"The {header} header is absent, reducing browser protections.",
                    recommendation=recommendation,
                    evidence=(evidence,),
                    tags=("http", "header", "missing"),
                )
            )
        elif weak:
            findings.append(
                Finding(
                    id="HTTP-H-002",
                    title=f"Weak {header} policy",
                    severity="Medium",
                    description=f"The {header} policy appears weak: {headers.get(header)}",
                    recommendation=recommendation,
                    evidence=(evidence,),
                    tags=("http", "header", "weak"),
                )
            )
    return findings


__all__ = ["analyze"]
