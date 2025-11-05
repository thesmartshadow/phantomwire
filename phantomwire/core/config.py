"""Configuration loading for Phantomwire."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Set

from .safemode import DEFAULT_ALLOWED_SCOPES
from .utils import env_bool

try:  # pragma: no cover - Python >=3.11
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - optional dependency path
    try:
        import tomli as tomllib  # type: ignore[assignment]
    except ModuleNotFoundError:  # pragma: no cover - fallback when tomli missing
        tomllib = None  # type: ignore[assignment]


CONFIG_PATH = Path.home() / ".config" / "phantomwire" / "config.toml"


@dataclass(frozen=True)
class RuntimeConfig:
    """Computed runtime configuration values."""

    allowed_scopes: Set[str]
    verbose: bool


def _load_file_config() -> dict[str, object]:
    if not CONFIG_PATH.exists():
        return {}
    raw = CONFIG_PATH.read_bytes()
    if tomllib is None:
        return {}
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except Exception:  # pragma: no cover - invalid toml edge case
        return {}
    section = data.get("phantomwire")
    if not isinstance(section, dict):
        return {}
    return section


def _env_allowed_scopes() -> Set[str]:
    value = os.getenv("PHANTOMWIRE_ALLOWED_SCOPES", "")
    scopes = {item.strip() for item in value.split(",") if item.strip()}
    return scopes


def load_config(
    *,
    cli_allowed_scopes: Optional[Iterable[str]] = None,
    cli_verbose: Optional[bool] = None,
) -> RuntimeConfig:
    """Compose runtime configuration respecting precedence."""

    file_config = _load_file_config()
    file_scopes = {
        scope
        for scope in file_config.get("allowed_scopes", [])
        if isinstance(scope, str) and scope
    }
    env_scopes = _env_allowed_scopes()
    combined_scopes: Set[str] = set(DEFAULT_ALLOWED_SCOPES)
    combined_scopes.update(file_scopes)
    combined_scopes.update(env_scopes)
    if cli_allowed_scopes:
        combined_scopes.update(cli_allowed_scopes)

    file_verbose = bool(file_config.get("verbose", False))
    env_verbose = env_bool("PHANTOMWIRE_VERBOSE", file_verbose)
    verbose = cli_verbose if cli_verbose is not None else env_verbose

    return RuntimeConfig(allowed_scopes=combined_scopes, verbose=verbose)


__all__ = ["RuntimeConfig", "load_config"]
