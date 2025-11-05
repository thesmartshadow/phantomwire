import pytest

from phantomwire.core.safemode import CONSENT_ENV, CONSENT_TOKEN, safe_mode


def test_safe_mode_blocks_without_consent(monkeypatch: pytest.MonkeyPatch) -> None:
    safe_mode.merge_allowed(["example.com"])
    with pytest.raises(PermissionError):
        safe_mode.require_consent()

    with pytest.raises(PermissionError):
        safe_mode.check_host("evil.example")


def test_safe_mode_allows_with_consent(monkeypatch: pytest.MonkeyPatch) -> None:
    safe_mode.merge_allowed(["example.com"])
    monkeypatch.setenv(CONSENT_ENV, CONSENT_TOKEN)
    safe_mode.require_consent()
    safe_mode.check_host("example.com")


def test_safe_mode_disable(monkeypatch: pytest.MonkeyPatch) -> None:
    safe_mode.disable()
    safe_mode.check_host("evil.example")
