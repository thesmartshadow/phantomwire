import base64
import json
import time
from pathlib import Path

from phantomwire.appsec import jwt_lint


def _encode(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _sign(secret: bytes, signing_input: bytes) -> str:
    import hashlib
    import hmac

    digest = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def test_alg_none_detected() -> None:
    header = _encode({"alg": "none"})
    payload = _encode({})
    token = f"{header}.{payload}."
    findings = jwt_lint.lint(token)
    assert any(f.id == "JWT-L-001" for f in findings)


def test_missing_claims_and_expiry() -> None:
    now = int(time.time()) - 1000
    header = _encode({"alg": "HS256"})
    payload = _encode({"exp": now})
    signature = _sign(b"secret", f"{header}.{payload}".encode())
    token = f"{header}.{payload}.{signature}"
    findings = jwt_lint.lint(token)
    ids = {f.id for f in findings}
    assert "JWT-L-002" in ids
    assert "JWT-L-003" in ids


def test_signature_verification(tmp_path: Path) -> None:
    secret_bytes = b"secret"
    secret = base64.urlsafe_b64encode(secret_bytes).rstrip(b"=").decode()
    header = _encode({"alg": "HS256"})
    claims = {
        "exp": int(time.time()) + 600,
        "iat": int(time.time()),
        "nbf": int(time.time()),
        "iss": "me",
        "aud": "you",
    }
    payload = _encode(claims)
    signature = _sign(secret_bytes, f"{header}.{payload}".encode())
    token = f"{header}.{payload}.{signature}"
    jwk = json.dumps({"kty": "oct", "k": secret})
    path = tmp_path / "key.jwk"
    path.write_text(jwk)
    findings = jwt_lint.lint(token, str(path))
    assert findings == []


def test_signature_mismatch(tmp_path: Path) -> None:
    secret_bytes = b"secret"
    secret = base64.urlsafe_b64encode(secret_bytes).rstrip(b"=").decode()
    header = _encode({"alg": "HS256"})
    claims = {
        "exp": int(time.time()) + 600,
        "iat": int(time.time()),
        "nbf": int(time.time()),
        "iss": "me",
        "aud": "you",
    }
    payload = _encode(claims)
    signature = _sign(b"wrong", f"{header}.{payload}".encode())
    token = f"{header}.{payload}.{signature}"
    jwk = json.dumps({"kty": "oct", "k": secret})
    path = tmp_path / "key.jwk"
    path.write_text(jwk)
    findings = jwt_lint.lint(token, str(path))
    assert any(f.id == "JWT-L-008" for f in findings)
