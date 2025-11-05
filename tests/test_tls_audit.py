from datetime import datetime, timedelta

import pytest

from phantomwire.appsec import tls_audit
from phantomwire.core.safemode import CONSENT_ENV, CONSENT_TOKEN, safe_mode


@pytest.fixture(autouse=True)
def consent(monkeypatch: pytest.MonkeyPatch) -> None:
    safe_mode.merge_allowed(["example.com"])
    monkeypatch.setenv(CONSENT_ENV, CONSENT_TOKEN)


def test_inspect_tls_detects_issues(monkeypatch: pytest.MonkeyPatch) -> None:
    expire = (datetime.utcnow() + timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")

    class FakeSSLSocket:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def version(self):
            return "TLSv1.0"

        def cipher(self):
            return ("TLS_FAKE", "TLSv1", 64)

        def getpeercert(self, binary_form: bool = False):
            if binary_form:
                return b"DER"
            return {
                "subject": (("commonName", "example.com"),),
                "issuer": (("commonName", "Example CA"),),
                "notAfter": expire,
                "notBefore": expire,
                "subjectAltName": [("DNS", "example.com")],
            }

    class FakeContext:
        def __init__(self) -> None:
            self.check_hostname = True
            self.verify_mode = None

        def wrap_socket(self, sock, server_hostname: str):
            return FakeSSLSocket()

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(tls_audit.socket, "create_connection", lambda addr, timeout: FakeSocket())
    monkeypatch.setattr(tls_audit.ssl, "create_default_context", lambda: FakeContext())
    monkeypatch.setattr(tls_audit, "maybe_import", lambda name: None)

    findings = tls_audit.inspect("example.com", 443)
    ids = {f.id for f in findings}
    assert "TLS-A-001" in ids
    assert "TLS-A-002" in ids
    assert "TLS-A-003" in ids
    severity = {f.id: f.severity for f in findings}
    assert severity["TLS-A-001"] == "High"
