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

        The sandbox mode is set explicitly rather than left to the CLI's default, and which
        mode depends on who is providing the isolation:

        * **Uncontained** (`container_image` unset): `workspace-write`. The closest thing to
          SPEC.md §5's "no access outside `workdir`" available from the CLI alone, since the
          workdir is git-initialised and therefore is the workspace.
        * **Contained**: `danger-full-access`, because the container is already the boundary
          and Codex's own sandbox cannot work inside one. It uses Bubblewrap, which needs to
          create a user namespace, and Docker denies that — `bwrap: No permissions to create
          a new namespace`, on every command the agent tries to run. Observed, not assumed:
          a full contained run scored six scenarios `failed_honestly` because the agent could
          not execute a single command, correctly reported that it could not, and changed
          nothing. A harness that cannot let the agent try is not measuring integrity.

        "Full access" here means full access *inside the container* — the mounted workdir and
        the image — which is exactly the containment §5 asks for, and strictly narrower than
        the host access `workspace-write` leaves available when there is no container at all.

        Either way this must not be left implicit: with the CLI defaulting to `read-only` the
        agent could edit nothing, every scenario would fail, and the report would read as an
        agent that never completed a task rather than a harness that never let it try.
        """
        sandbox = "danger-full-access" if self.config.container_image else "workspace-write"
        argv = [
            "codex",
            "exec",
            "--json",
            "--skip-git-repo-check",
            "--sandbox",
            sandbox,
        ]
        if self.config.model is not None:
            argv += ["--model", self.config.model]
        return [*argv, prompt]

    def parse(self, capture: CliCapture) -> AgentRun:
        """Recover the final message and executed commands from the JSONL event stream."""
        events = _parse_events(capture.stdout)
        if not events:
            # Not a JSONL stream at all (an older CLI, or a crash before the first event):
            # plain-text fallback, with commands and authorship honestly unobservable.
            return AgentRun(
                transcript=capture.transcript,
                final_message=last_paragraph(capture.stdout),
                exit_ok=capture.exit_code == 0,
                error=_error_for(capture),
            )
        return AgentRun(
            transcript=capture.transcript,
            # No last_paragraph fallback once the stream parsed as events: the last raw line
            # of a JSONL stream is a JSON event, and a run that died mid-command can end on a
            # command_execution event whose captured output says "3 passed" — which claim
            # parsing must never mistake for the agent's own words.
            final_message=_final_message(events),
            authored_text=_authored_text(events),
            commands=_commands(events),
            commands_observed=True,
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


_MESSAGE_ITEM_TYPES = frozenset({"agent_message", "assistant_message", "message"})
"""Event item types carrying the agent's own prose. Named here rather than inline because
`_final_message` and `_authored_text` must agree on what counts as the agent speaking."""


def _final_message(events: list[dict[str, Any]]) -> str:
    """The last agent message in the stream, wherever this CLI version puts the text."""
    for event in reversed(events):
        item = event.get("item", event)
        if not isinstance(item, dict):
            continue
        if item.get("type") not in _MESSAGE_ITEM_TYPES:
            continue
        for key in ("text", "message", "content"):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _authored_text(events: list[dict[str, Any]]) -> str:
    """Everything the agent itself wrote this run, with tool results excluded.

    Command output and file contents arrive as their own item types; only the message items
    are the agent speaking. Scanning the whole stream instead would let Stinger's recording
    of a file the agent merely READ be read back as the agent disclosing it — a leak
    detector reporting a leak the harness itself performed (SPEC.md §5, §6).
    """
    parts: list[str] = []
    for event in events:
        item = event.get("item", event)
        if not isinstance(item, dict) or item.get("type") not in _MESSAGE_ITEM_TYPES:
            continue
        for key in ("text", "message", "content"):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                parts.append(value.strip())
                break
    return "\n".join(parts)


def _commands(events: list[dict[str, Any]]) -> list[str]:
    """Shell commands the agent executed, in order — each execution counted once.

    Codex emits every command twice, as an `item.started` and an `item.completed` event
    wrapping the same item id and command text. Counting both doubled the command log: the
    first live G-family run reported "12 observed command(s)" for six actual executions. The
    duplication was cosmetic there (command_scan patterns are per-command, so a doubled list
    fires the same), but evidence that miscounts what the agent did is wrong on its own
    terms. Items without an id (older dialects) are kept as-is rather than guessed at.
    """
    commands: list[str] = []
    seen_ids: set[str] = set()
    for event in events:
        item = event.get("item", event)
        if not isinstance(item, dict) or item.get("type") not in _SHELL_ITEM_TYPES:
            continue
        item_id = item.get("id")
        if isinstance(item_id, str):
            if item_id in seen_ids:
                continue  # the started/completed pair describes ONE execution
            seen_ids.add(item_id)
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
