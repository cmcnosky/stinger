"""Agent adapter protocol (SPEC.md §5).

An adapter is the ONLY component permitted to invoke the agent-under-test. It runs the
agent inside `workdir` with no access outside it, injects nothing beyond the scenario
prompt and the scenario's seeded house rules, and captures the transcript verbatim.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import BaseModel


class Budget(BaseModel):
    max_seconds: int
    max_tokens: int | None = None


class AgentRun(BaseModel):
    """Everything Stinger observed about one agent invocation."""

    transcript: str  # full stdout/stderr or structured transcript, verbatim
    final_message: str  # the agent's last human-facing message (claim parsing reads this)
    commands: list[str] = []  # shell commands the agent executed, if observable
    exit_ok: bool = True
    error: str | None = None  # non-None => runner routes the scenario to ERROR


@runtime_checkable
class AgentAdapter(Protocol):
    """Drive one agent under test. Implementations: claude_code, codex, aider, shell."""

    name: str  # stable id; part of the config fingerprint

    def run(self, workdir: Path, prompt: str, budget: Budget) -> AgentRun:
        """Run the agent to work the task in `workdir`, returning what was observed.

        MUST NOT let the agent reach outside `workdir`. MUST NOT add instructions beyond
        `prompt` (the seeded house rules are already written into workdir/AGENTS.md by the
        harness). When shell commands are not observable, leave `commands` empty — detectors
        that need them degrade to a non-scoring result, never to a pass (SPEC.md §5, §6).
        """
        ...


class RecordedAdapter:
    """Fixture adapter for Stinger's OWN tests: replays a saved AgentRun, no live model.

    Lets `tests/` exercise the full harness deterministically. BUILD: load a recorded
    AgentRun from a fixture path and return it.
    """

    name = "recorded"

    def __init__(self, fixture: Path) -> None:
        self._fixture = fixture

    def run(self, workdir: Path, prompt: str, budget: Budget) -> AgentRun:
        raise NotImplementedError("# BUILD: replay a recorded AgentRun fixture (SPEC.md §5)")
