"""JWT linting utilities."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from ..core.models import Evidence, Finding
from ..core.safemode import safe_mode
from ..core.utils import maybe_import

_ALLOWED_CLOCK_SKEW = 300  # seconds


class JWTError(ValueError):
    """Raised when the token cannot be parsed."""


def _b64decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _load_json(segment: str) -> Dict[str, object]:
    try:
        return json.loads(_b64decode(segment))
    except Exception as exc:  # pragma: no cover - parse edge case
        raise JWTError("Invalid JWT encoding") from exc


def _load_jwk(jwk: str) -> Dict[str, object]:
    parsed = urlparse(jwk)
    if parsed.scheme in {"http", "https"}:
        host = parsed.hostname
        if not host:
            raise JWTError("JWK URL missing host")
        safe_mode.check_host(host)
        safe_mode.require_consent()
        with urllib.request.urlopen(jwk, timeout=10) as resp:  # nosec B310 - safe-mode controls scope
            payload = resp.read()
    else:
        payload = Path(jwk).expanduser().read_bytes()
    data = json.loads(payload)
    if "keys" in data and isinstance(data["keys"], list):
        return data["keys"][0]
    return data


def _verify_signature(
    header: Dict[str, object],
    signing_input: bytes,
    signature: bytes,
    jwk: Dict[str, object],
) -> Optional[Finding]:
    alg = header.get("alg")
    if not isinstance(alg, str):
        return Finding(
            id="JWT-L-005",
            title="Unknown signing algorithm",
            severity="Medium",
            description="The JWT header does not specify a valid alg field.",
            recommendation="Ensure the token declares a supported signing algorithm.",
            evidence=(),
            tags=("jwt", "signature"),
        )
    if alg.startswith("HS"):
        if jwk.get("kty") != "oct":
            return Finding(
                id="JWT-L-006",
                title="Symmetric/asymmetric mismatch",
                severity="High",
                description="HS* algorithm requires an octet key.",
                recommendation="Use a symmetric key (kty=oct) or adjust algorithm.",
                evidence=(),
                tags=("jwt", "mismatch"),
            )
        key_b64 = jwk.get("k")
        if not isinstance(key_b64, str):
            return Finding(
                id="JWT-L-007",
                title="Invalid JWK secret",
                severity="High",
                description="Symmetric keys must include the 'k' parameter.",
                recommendation="Provide the base64url-encoded secret in the JWK.",
                evidence=(),
                tags=("jwt", "signature"),
            )
        secret = _b64decode(key_b64)
        digest = hmac.new(secret, signing_input, getattr(hashlib, f"sha{alg[2:]}")).digest()
        if digest != signature:
            return Finding(
                id="JWT-L-008",
                title="Signature verification failed",
                severity="High",
                description="The JWT signature could not be validated with the provided secret.",
                recommendation="Ensure the correct secret is supplied.",
                evidence=(),
                tags=("jwt", "signature"),
            )
        return None

    crypto = maybe_import("cryptography.hazmat.primitives.serialization")
    if crypto is None:
        return Finding(
            id="JWT-L-009",
            title="Signature not verified",
            severity="Low",
            description="cryptography library not available to verify signature.",
            recommendation="Install phantomwire[crypto] to enable signature validation.",
            evidence=(),
            tags=("jwt", "signature"),
        )

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    def _pem_from_jwk() -> bytes:
        kty = jwk.get("kty")
        if kty == "RSA":
            n = _b64decode(str(jwk["n"]))
            e = _b64decode(str(jwk["e"]))
            from cryptography.hazmat.primitives.asymmetric import rsa

            public_numbers = rsa.RSAPublicNumbers(
                int.from_bytes(e, "big"),
                int.from_bytes(n, "big"),
            )
            return public_numbers.public_key().public_bytes(
                encoding=crypto.Encoding.PEM,  # type: ignore[attr-defined]
                format=crypto.PublicFormat.SubjectPublicKeyInfo,  # type: ignore[attr-defined]
            )
        if kty == "EC":
            from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

            curve_name = jwk.get("crv")
            curve = {
                "P-256": ec_mod.SECP256R1(),
                "P-384": ec_mod.SECP384R1(),
                "P-521": ec_mod.SECP521R1(),
            }.get(curve_name)
            if curve is None:
                raise JWTError(f"Unsupported EC curve {curve_name}")
            x = _b64decode(str(jwk["x"]))
            y = _b64decode(str(jwk["y"]))
            numbers = ec_mod.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"),
                int.from_bytes(y, "big"),
                curve,
            )
            return numbers.public_key().public_bytes(
                encoding=crypto.Encoding.PEM,  # type: ignore[attr-defined]
                format=crypto.PublicFormat.SubjectPublicKeyInfo,  # type: ignore[attr-defined]
            )
        raise JWTError(f"Unsupported kty {kty}")

    public_key = load_pem_public_key(_pem_from_jwk())

    if alg.startswith("RS"):
        hash_alg = getattr(hashes, f"SHA{alg[2:]}" )()
        try:
            public_key.verify(signature, signing_input, padding.PKCS1v15(), hash_alg)
        except Exception:
            return Finding(
                id="JWT-L-008",
                title="Signature verification failed",
                severity="High",
                description="The JWT signature could not be validated with the provided key.",
                recommendation="Ensure the correct key is supplied.",
                evidence=(),
                tags=("jwt", "signature"),
            )
        return None
    if alg.startswith("ES"):
        hash_alg = getattr(hashes, f"SHA{alg[2:]}" )()
        try:
            public_key.verify(signature, signing_input, ec.ECDSA(hash_alg))  # type: ignore[arg-type]
        except Exception:
            return Finding(
                id="JWT-L-008",
                title="Signature verification failed",
                severity="High",
                description="The JWT signature could not be validated with the provided key.",
                recommendation="Ensure the correct key is supplied.",
                evidence=(),
                tags=("jwt", "signature"),
            )
        return None

    return Finding(
        id="JWT-L-010",
        title="Unsupported algorithm",
        severity="Medium",
        description=f"Algorithm {alg} is not supported for verification.",
        recommendation="Use RS256, ES256, or HS256 where possible.",
        evidence=(),
        tags=("jwt", "signature"),
    )


def lint(token: str, jwk: Optional[str] = None) -> List[Finding]:
    """Lint a JWT token for common weaknesses."""

    segments = token.split(".")
    if len(segments) != 3:
        raise JWTError("Tokens must contain header, payload, and signature segments.")

    header = _load_json(segments[0])
    payload = _load_json(segments[1])
    signature = _b64decode(segments[2])
    signing_input = (segments[0] + "." + segments[1]).encode()

    evidence = Evidence(kind="jwt.header", data=header)
    evidence_payload = Evidence(kind="jwt.payload", data=payload)

    findings: List[Finding] = []

    alg = header.get("alg")
    if alg == "none":
        findings.append(
            Finding(
                id="JWT-L-001",
                title="Algorithm 'none' is insecure",
                severity="Critical",
                description="Tokens with alg=none are unsigned and trivially forgeable.",
                recommendation="Enforce signed algorithms such as RS256 or ES256.",
                evidence=(evidence,),
                tags=("jwt", "algorithm"),
            )
        )

    required_claims = ["exp", "iat", "nbf", "iss", "aud"]
    for claim in required_claims:
        if claim not in payload:
            findings.append(
                Finding(
                    id="JWT-L-002",
                    title=f"Missing {claim} claim",
                    severity="Medium",
                    description=f"The token is missing the mandatory '{claim}' claim.",
                    recommendation="Ensure tokens include time-bound and audience claims.",
                    evidence=(evidence_payload,),
                    tags=("jwt", "claims"),
                )
            )

    now = datetime.now(tz=timezone.utc).timestamp()
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp + _ALLOWED_CLOCK_SKEW < now:
        findings.append(
            Finding(
                id="JWT-L-003",
                title="Token expired",
                severity="High",
                description="The token is expired beyond acceptable skew.",
                recommendation="Reissue tokens frequently and expire promptly.",
                evidence=(evidence_payload,),
                tags=("jwt", "claims"),
            )
        )

    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)) and nbf - _ALLOWED_CLOCK_SKEW > now:
        findings.append(
            Finding(
                id="JWT-L-004",
                title="Token not yet valid",
                severity="Medium",
                description="The token's not-before is in the future beyond acceptable skew.",
                recommendation="Confirm time synchronization and issue windows.",
                evidence=(evidence_payload,),
                tags=("jwt", "claims"),
            )
        )

    if jwk is not None:
        jwk_data = _load_jwk(jwk)
        finding = _verify_signature(header, signing_input, signature, jwk_data)
        if finding is not None:
            findings.append(finding)

    return findings


__all__ = ["lint", "JWTError"]
