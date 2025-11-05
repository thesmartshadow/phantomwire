"""Markdown reporting."""
from __future__ import annotations

from collections import Counter
from typing import List

from ..core.models import Finding, ScanResult


def _summary_table(findings: List[Finding]) -> List[str]:
    lines = ["| ID | Severity | Title |", "| --- | --- | --- |"]
    for finding in findings:
        lines.append(f"| {finding.id} | {finding.severity} | {finding.title} |")
    return lines


def to_markdown(result: ScanResult) -> str:
    """Render scan findings to a Markdown report."""

    findings = list(result.findings)
    counts = Counter(finding.severity for finding in findings)
    lines: List[str] = [
        "# Phantomwire Security Report",
        "",
        f"**Target:** {result.target.locator}",
        "",
        "## Severity Overview",
    ]
    for severity in ["Critical", "High", "Medium", "Low"]:
        lines.append(f"- **{severity}:** {counts.get(severity, 0)} findings")
    lines.extend(["", "## Findings", ""])
    if findings:
        lines.extend(_summary_table(findings))
        lines.append("")
        for finding in findings:
            lines.extend(
                [
                    f"### {finding.title} ({finding.severity})",
                    "",
                    f"- **ID:** {finding.id}",
                    f"- **Severity:** {finding.severity}",
                    f"- **Recommendation:** {finding.recommendation}",
                    "",
                    finding.description,
                    "",
                ]
            )
    else:
        lines.append("No findings were identified.")
    return "\n".join(lines)


__all__ = ["to_markdown"]
