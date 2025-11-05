"""Plugin discovery and registry support."""
from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from importlib.metadata import entry_points
from typing import Any, Callable, Iterable, Mapping, Protocol

from .models import Evidence, Finding


class Plugin(Protocol):
    """Plugins provide additional security checks."""

    name: str

    def run(
        self, **kwargs: Any
    ) -> Iterable[Finding] | Iterable[Evidence] | None:  # pragma: no cover - protocol
        ...


@dataclass
class PluginRecord:
    """Metadata about a discovered plugin."""

    name: str
    load: Callable[[], Plugin]
    source: str


def discover_plugins() -> Mapping[str, PluginRecord]:
    """Discover plugins registered via entry points."""

    discovered: dict[str, PluginRecord] = {}
    eps = entry_points().select(group="phantomwire.plugins")
    for ep in eps:
        discovered[ep.name] = PluginRecord(
            name=ep.name,
            load=ep.load,
            source=ep.module or "unknown",
        )
    return discovered


def load_plugin(name: str) -> Plugin:
    plugins = discover_plugins()
    if name not in plugins:
        raise KeyError(f"Plugin '{name}' not found")
    loader = plugins[name].load
    plugin = loader()
    if not hasattr(plugin, "run"):
        raise TypeError(f"Plugin '{name}' is missing a run() method")
    return plugin


def load_builtin_example() -> Plugin:
    module = import_module("plugins.example_plugin")
    plugin = getattr(module, "plugin", None)
    if plugin is None:
        raise RuntimeError("Example plugin missing 'plugin' attribute")
    return plugin


__all__ = ["Plugin", "PluginRecord", "discover_plugins", "load_plugin", "load_builtin_example"]
