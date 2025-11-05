"""JSON reporting."""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

from ..core.models import ScanResult
from ..core.utils import json_dump


def _convert(obj: Any) -> Any:
    if is_dataclass(obj):
        return {k: _convert(v) for k, v in asdict(obj).items()}
    if isinstance(obj, (list, tuple)):
        return [_convert(item) for item in obj]
    return obj


def to_json(result: ScanResult) -> str:
    """Serialize a scan result to JSON."""

    data = _convert(result)
    return json_dump(data)


__all__ = ["to_json"]
