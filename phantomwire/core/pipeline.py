"""Pipeline utilities for composing scans."""
from __future__ import annotations

from typing import Callable, Iterable, Iterator, List, Sequence

from .models import Evidence, Finding, ScanResult, Target

PipelineItem = Finding | Evidence


def _iter_items(result: object) -> Iterator[PipelineItem]:
    if result is None:
        return iter(())
    if isinstance(result, (Finding, Evidence)):
        return iter((result,))
    if isinstance(result, Iterable):
        return (item for item in result if isinstance(item, (Finding, Evidence)))
    return iter(())


def run_pipeline(target: Target, stages: Sequence[Callable[[], object]]) -> ScanResult:
    """Execute stages and collect findings into a scan result."""

    findings: List[Finding] = []
    loose_evidence: List[Evidence] = []
    for stage in stages:
        for item in _iter_items(stage()):
            if isinstance(item, Finding):
                findings.append(item)
            else:
                loose_evidence.append(item)
    if loose_evidence:
        findings.append(
            Finding(
                id="EVID-000",
                title="Supplementary evidence",
                severity="Low",
                description="Additional evidence collected during analysis.",
                recommendation="Review the attached evidence for context.",
                evidence=tuple(loose_evidence),
                tags=("evidence",),
            )
        )
    return ScanResult(target=target, findings=tuple(findings))


__all__ = ["run_pipeline"]
