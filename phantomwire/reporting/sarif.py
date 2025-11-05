"""SARIF output generation."""
from __future__ import annotations

from ..core.models import Finding, ScanResult
from ..core.utils import json_dump, now_utc

_SEVERITY_TO_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
}


def _rule_id(finding: Finding) -> str:
    return finding.id


def to_sarif(result: ScanResult) -> str:
    """Convert scan result into SARIF v2.1.0 format."""

    rules = []
    sarif_results = []
    for finding in result.findings:
        rule = {
            "id": _rule_id(finding),
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
        }
        rules.append(rule)
        sarif_results.append(
            {
                "ruleId": _rule_id(finding),
                "level": _SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
                "message": {"text": finding.description},
                "properties": {
                    "severity": finding.severity,
                    "recommendation": finding.recommendation,
                    "tags": list(finding.tags),
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Phantomwire",
                        "informationUri": "https://github.com/phantomwire/phantomwire",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": now_utc().isoformat(),
                        "endTimeUtc": now_utc().isoformat(),
                    }
                ],
                "properties": {
                    "target": result.target.locator,
                },
            }
        ],
    }
    return json_dump(sarif)


__all__ = ["to_sarif"]
