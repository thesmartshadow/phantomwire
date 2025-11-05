"""Core data models for Phantomwire."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, List, Sequence


@dataclass(frozen=True)
class Target:
    """Represents a scan target."""

    locator: str
    host: str | None = None
    port: int | None = None
    scope: str | None = None


@dataclass(frozen=True)
class Evidence:
    """Evidence produced during a scan."""

    kind: str
    data: dict[str, object]
    at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


@dataclass(frozen=True)
class Finding:
    """Actionable insight discovered by the toolkit."""

    id: str
    title: str
    severity: str
    description: str
    recommendation: str
    evidence: Sequence[Evidence] = field(default_factory=tuple)
    tags: Sequence[str] = field(default_factory=tuple)

    def with_evidence(self, extra: Iterable[Evidence]) -> "Finding":
        ev: List[Evidence] = list(self.evidence)
        ev.extend(extra)
        return Finding(
            id=self.id,
            title=self.title,
            severity=self.severity,
            description=self.description,
            recommendation=self.recommendation,
            evidence=tuple(ev),
            tags=tuple(self.tags),
        )


@dataclass(frozen=True)
class ScanResult:
    """Aggregate result for a scan action."""

    target: Target
    findings: Sequence[Finding]
    generated_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


__all__ = ["Target", "Evidence", "Finding", "ScanResult"]
