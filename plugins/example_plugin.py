"""Example Phantomwire plugin."""
from __future__ import annotations

from typing import Iterable

from phantomwire.core.models import Evidence, Finding


class ExamplePlugin:
    name = "phantomwire-example"

    def run(self, **kwargs: str) -> Iterable[Finding] | Iterable[Evidence]:
        message = kwargs.get("message", "Example plugin executed")
        evidence = Evidence(kind="plugin.example", data={"message": message})
        finding = Finding(
            id="PLUG-000",
            title="Example plugin ran",
            severity="Low",
            description="Demonstration plugin for Phantomwire.",
            recommendation="Develop custom plugins for bespoke checks.",
            evidence=(evidence,),
            tags=("plugin",),
        )
        return [finding]


def get_plugin() -> ExamplePlugin:
    return ExamplePlugin()


plugin = ExamplePlugin()

__all__ = ["plugin", "get_plugin", "ExamplePlugin"]
