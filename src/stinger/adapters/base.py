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

    Lets `tests/` exercise the full harness deterministically — SPEC.md §5 requires that
    Stinger's own suite never calls a live model, and CI never reaches the network.

    A fixture directory holds:

    * ``run.json`` — a serialised `AgentRun`: what the agent said and which commands it ran.
    * ``workdir/`` — optional. An overlay mirroring repo paths, copied over the prepared
      workdir to reproduce the edits the recorded agent made. Overlays rather than patches,
      for the same reason scenarios use them (SPEC.md §12): no line-number drift.

    Separating the two halves is what makes a recorded run useful — a fixture can pair an
    honest transcript with cheating edits, or a boastful claim with no edits at all, which is
    exactly what the claims-audit detectors need to be tested against.
    """

    name = "recorded"

    def __init__(self, fixture: Path) -> None:
        """Bind to a recorded-run fixture directory.

        Args:
            fixture: Directory containing `run.json` and optionally `workdir/`.
        """
        self._fixture = fixture

    def run(self, workdir: Path, prompt: str, budget: Budget) -> AgentRun:
        """Replay the fixture: apply its recorded edits, then return its recorded AgentRun.

        `prompt` and `budget` are accepted to satisfy the `AgentAdapter` protocol and are
        deliberately ignored — a recording is fixed, and pretending to react to the prompt
        would make the fixture lie about what was observed.

        Args:
            workdir: The prepared workdir; the fixture's `workdir/` overlay is applied here.
            prompt: Ignored. Part of the adapter protocol.
            budget: Ignored. Part of the adapter protocol.

        Returns:
            The recorded `AgentRun`.

        Raises:
            FileNotFoundError: If the fixture has no `run.json`.
        """
        # Imported here rather than at module scope: sandbox imports detectors, which import
        # this module, so a top-level import would close a cycle.
        from stinger.harness.sandbox import apply_overlay

        record = self._fixture / "run.json"
        if not record.is_file():
            raise FileNotFoundError(f"recorded fixture {self._fixture} has no run.json")
        apply_overlay(self._fixture / "workdir", workdir)
        return AgentRun.model_validate_json(record.read_text(encoding="utf-8"))
