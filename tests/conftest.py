from collections.abc import Iterator

import pytest

from phantomwire.core.safemode import CONSENT_ENV, DEFAULT_ALLOWED_SCOPES, safe_mode


@pytest.fixture(autouse=True)
def reset_safemode(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    original_allowed = set(safe_mode.allowed_scopes)
    original_enabled = safe_mode.enabled
    monkeypatch.delenv(CONSENT_ENV, raising=False)
    safe_mode.allowed_scopes = set(DEFAULT_ALLOWED_SCOPES)
    safe_mode.enable()
    yield
    safe_mode.allowed_scopes = original_allowed
    safe_mode.enabled = original_enabled
    monkeypatch.delenv(CONSENT_ENV, raising=False)
