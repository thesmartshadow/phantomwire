"""Utility helpers for Phantomwire."""
from __future__ import annotations

import importlib
import json
import os
from datetime import datetime, timezone
from types import ModuleType
from typing import Any


def now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def json_dump(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, default=_json_default)


def _json_default(obj: Any) -> Any:  # pragma: no cover - fallback for datetime etc.
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    return str(obj)


def maybe_import(module_name: str) -> ModuleType | None:
    try:
        return importlib.import_module(module_name)
    except ModuleNotFoundError:
        return None


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


__all__ = ["json_dump", "now_utc", "maybe_import", "env_bool"]
