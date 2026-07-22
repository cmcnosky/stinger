"""Codex adapter (SPEC.md §5).

Runs `codex exec` non-interactively. Codex emits JSONL events when asked, which makes it the
second adapter that can recover the agent's executed commands; the parser falls back to plain
text when the stream is not JSON, with an empty command list rather than a guessed one.
"""

from __future__ import annotations

import json
from typing import Any

from stinger.adapters.base import AgentRun
from stinger.adapters.cli_base import CliAgentAdapter, CliCapture, last_paragraph

__all__ = ["CodexAdapter"]

_SHELL_ITEM_TYPES = frozenset({"command_execution", "local_shell_call", "exec_command"})
"""Event types Codex has used for "the agent ran a shell command". More than one because the
name has moved between CLI versions and reading only the current one would silently lose the
command log on an older or newer build — which `command_scan` must never mistake for a clean
run."""


class CodexAdapter(CliAgentAdapter):
    """Drive the Codex CLI non-interactively over one scenario prompt."""

    name = "codex"

    def argv(self, prompt: str) -> list[str]:
        """`codex exec --json <prompt>`, confined to the prepared workdir.

        The prompt is passed through verbatim. Nothing is prepended, appended or reworded.

        `--sandbox workspace-write` is set explicitly rather than left to the CLI's default,
        for two reasons that pull in the same direction. It is the closest thing to SPEC.md
        §5's "no access outside `workdir`" available without a container, since the workdir is
        git-initialised and therefore is the workspace. And it is not a setting to leave
        implicit: if the default were `read-only`, the agent could not edit anything, every
        scenario would fail, and the report would read as an agent that never completed a
        task rather than a harness that never let it try.
        """
        argv = [
            "codex",
            "exec",
            "--json",
            "--skip-git-repo-check",
            "--sandbox",
            "workspace-write",
        ]
        if self.config.model is not None:
            argv += ["--model", self.config.model]
        return [*argv, prompt]

    def parse(self, capture: CliCapture) -> AgentRun:
        """Recover the final message and executed commands from the JSONL event stream."""
        events = _parse_events(capture.stdout)
        return AgentRun(
            transcript=capture.transcript,
            final_message=_final_message(events) or last_paragraph(capture.stdout),
            commands=_commands(events),
            exit_ok=capture.exit_code == 0,
            error=_error_for(capture),
        )


def _parse_events(stdout: str) -> list[dict[str, Any]]:
    """Every line that is a JSON object. Non-JSON lines are ignored, not fatal."""
    events: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            events.append(parsed)
    return events


def _final_message(events: list[dict[str, Any]]) -> str:
    """The last agent message in the stream, wherever this CLI version puts the text."""
    for event in reversed(events):
        item = event.get("item", event)
        if not isinstance(item, dict):
            continue
        if item.get("type") not in {"agent_message", "assistant_message", "message"}:
            continue
        for key in ("text", "message", "content"):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _commands(events: list[dict[str, Any]]) -> list[str]:
    """Shell commands the agent executed, in order."""
    commands: list[str] = []
    for event in events:
        item = event.get("item", event)
        if not isinstance(item, dict) or item.get("type") not in _SHELL_ITEM_TYPES:
            continue
        command = item.get("command")
        if isinstance(command, str):
            commands.append(command)
        elif isinstance(command, list):
            commands.append(" ".join(str(part) for part in command))
    return commands


def _error_for(capture: CliCapture) -> str | None:
    """A crashed CLI produced no measurement, so the scenario becomes non-scoring."""
    if capture.exit_code == 0:
        return None
    detail = (capture.stderr or capture.stdout).strip()[-400:]
    return f"the codex CLI exited {capture.exit_code}: {detail or '(no output)'}"
