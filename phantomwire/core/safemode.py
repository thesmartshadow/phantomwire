"""Safe-mode enforcement for Phantomwire."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterable, Set

DEFAULT_ALLOWED_SCOPES: Set[str] = {"localhost", "127.0.0.1", "::1"}
CONSENT_ENV = "PHANTOMWIRE_CONSENT"
CONSENT_TOKEN = "I_HAVE_PERMISSION"


@dataclass
class SafeMode:
    """Safe-mode controller requiring explicit consent for network actions."""

    enabled: bool = True
    allowed_scopes: Set[str] = field(default_factory=lambda: set(DEFAULT_ALLOWED_SCOPES))

    def enable(self) -> None:
        self.enabled = True

    def disable(self) -> None:
        self.enabled = False

    def merge_allowed(self, scopes: Iterable[str]) -> None:
        for scope in scopes:
            if scope:
                self.allowed_scopes.add(scope)

    def require_consent(self) -> None:
        if os.getenv(CONSENT_ENV) != CONSENT_TOKEN:
            raise PermissionError(
                "Active operations require explicit consent. Set "
                f"{CONSENT_ENV}={CONSENT_TOKEN} in a trusted environment."
            )

    def check_host(self, host: str) -> None:
        if not self.enabled:
            return
        if host not in self.allowed_scopes:
            raise PermissionError(
                f"Safe-mode blocked access to host '{host}'. Add it to allowed scopes and "
                "set the consent token to proceed."
            )


safe_mode = SafeMode()


__all__ = [
    "SafeMode",
    "safe_mode",
    "DEFAULT_ALLOWED_SCOPES",
    "CONSENT_ENV",
    "CONSENT_TOKEN",
]
