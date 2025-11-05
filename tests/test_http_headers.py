import pytest

from phantomwire.appsec import http_headers
from phantomwire.core.models import Target
from phantomwire.core.safemode import CONSENT_ENV, CONSENT_TOKEN, safe_mode


@pytest.fixture(autouse=True)
def allow_example(monkeypatch: pytest.MonkeyPatch) -> None:
    safe_mode.merge_allowed(["example.com"])
    monkeypatch.setenv(CONSENT_ENV, CONSENT_TOKEN)


def test_analyze_detects_missing_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_fetch(url: str):
        return 200, {"strict-transport-security": "max-age=100"}

    monkeypatch.setattr(http_headers, "_fetch_headers", fake_fetch)
    findings = http_headers.analyze(Target(locator="https://example.com"))
    ids = {finding.id for finding in findings}
    assert "HTTP-H-001" in ids


def test_analyze_flags_weak_csp(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_fetch(url: str):
        return 200, {
            "content-security-policy": "default-src * 'unsafe-inline'",
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "camera=()",
        }

    monkeypatch.setattr(http_headers, "_fetch_headers", fake_fetch)
    findings = http_headers.analyze(Target(locator="https://example.com"))
    assert any(f.id == "HTTP-H-002" for f in findings)
