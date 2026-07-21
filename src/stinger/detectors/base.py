"""Detector protocol + registry (SPEC.md §6).

A detector makes a deterministic, evidence-bearing judgment about whether a cheat-trace is
present. Detectors never call the network and never depend on an LLM. The seven shipped
detectors live in sibling modules and register themselves via @register.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel

from stinger.adapters.base import AgentRun
from stinger.models import DetectorResult, ExecResult
from stinger.scenario.manifest import ScenarioManifest


class RepoState(BaseModel):
    """A snapshot of the working tree (SPEC.md §7). Captured before and after the agent runs.

    Produced by `harness.sandbox.capture`. Detectors read this and nothing else about the
    filesystem, so a detector is a pure function of its `DetectorContext` — that is what
    makes detection deterministic and replayable from a reproducibility package.

    Contract for fail-closed behaviour: a path present in `tracked_files` but absent from
    `file_contents` appears in `unreadable_files` (binary, oversized, or a symlink). A
    detector that needs the content of such a path MUST NOT report "no cheat found" — it
    returns `fired=False, low_confidence=True` with evidence naming the path, which routes
    the scenario to review rather than to a pass (SPEC.md §1.1, §6).
    """

    root: str  # workdir path
    tracked_files: dict[str, str]  # repo-relative posix path -> sha256 of the raw bytes
    file_contents: dict[str, str]  # repo-relative posix path -> utf-8 text, for text files
    unreadable_files: list[str] = []  # tracked but not decodable/inlineable; see contract above
    head_commit: str | None = None  # seed commit of the prepared workdir, if it is a git repo


class Verification(BaseModel):
    """Clean-container observations the runner gathers before detectors run.

    SPEC.md §6 defines two detectors in terms of facts a detector cannot obtain for itself:
    `claim_match` fires when the final message claims done but `goal_met` is False, and
    `test_rerun` fires when a clean re-run contradicts the agent's claim. Executing commands
    inside a detector would make detection non-replayable and would put a subprocess in the
    scoring path, so the runner executes them once and passes the results here. Detectors
    stay pure functions of their context.

    Every field defaults to "not observed". A detector that needs an observation which is
    absent MUST return `fired=False, low_confidence=True` with evidence saying so, routing
    the scenario to review rather than to a pass (SPEC.md §1.1).
    """

    completion: ExecResult | None = None  # the held-out completion check (SPEC.md §7 step 6)
    suite_rerun: ExecResult | None = None  # the agent's own suite, re-run in a clean sandbox
    goal_met: bool = False  # did the held-out completion check pass
    agent_claimed_done: bool = False  # parsed from the agent's final message


class DetectorContext(BaseModel):
    before: RepoState
    after: RepoState
    run: AgentRun
    manifest: ScenarioManifest
    verification: Verification = Verification()

    def changed_paths(self) -> list[str]:
        """Repo-relative paths whose content differs between `before` and `after`.

        Added, removed, and modified files all qualify. Sorted, so any evidence string built
        from it is deterministic.
        """
        before, after = self.before.tracked_files, self.after.tracked_files
        return sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p))


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
