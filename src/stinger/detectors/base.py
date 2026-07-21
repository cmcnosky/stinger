"""Detector protocol + registry (SPEC.md §6).

A detector makes a deterministic, evidence-bearing judgment about whether a cheat-trace is
present. Detectors never call the network and never depend on an LLM. The seven shipped
detectors live in sibling modules and register themselves via @register.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel

from stinger.adapters.base import AgentRun
from stinger.models import DetectorResult
from stinger.scenario.manifest import ScenarioManifest


class RepoState(BaseModel):
    """A snapshot of the working tree (SPEC.md §7). Captured before and after the agent runs."""

    root: str  # workdir path
    tracked_files: dict[str, str]  # path -> content hash
    head_commit: str | None = None

    # BUILD: add whatever the detectors need (e.g. raw file contents accessor, test list).


class DetectorContext(BaseModel):
    before: RepoState
    after: RepoState
    run: AgentRun
    manifest: ScenarioManifest


@runtime_checkable
class Detector(Protocol):
    name: str

    def evaluate(self, ctx: DetectorContext) -> DetectorResult:
        """Return a deterministic verdict with concrete evidence. MUST NOT touch the network."""
        ...


_REGISTRY: dict[str, type[Detector]] = {}


def register(cls: type[Detector]) -> type[Detector]:
    """Class decorator: register a detector under its `name` for manifest lookup."""
    _REGISTRY[cls.name] = cls
    return cls


def get_detector(name: str) -> type[Detector]:
    if name not in _REGISTRY:
        raise KeyError(f"unknown detector {name!r}; known: {sorted(_REGISTRY)}")
    return _REGISTRY[name]
