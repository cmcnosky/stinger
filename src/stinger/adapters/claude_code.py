"""Claude Code adapter (SPEC.md §5).

Runs `claude` in non-interactive print mode with streaming JSON output, which is what makes
this one of the two adapters that can recover the agent's *executed commands* rather than
guessing at them from prose. The command log is what family G and X detectors need.

The event schema belongs to the CLI, not to Stinger, and it changes between versions. The
parser here is deliberately tolerant: it reads what it recognises and, when it recognises
nothing, falls back to treating the output as plain text with an empty command list. That is
the fail-closed direction — `command_scan` then reports that it had nothing to inspect and
routes the scenario to review, rather than reporting a clean run it never actually checked.
"""

from __future__ import annotations

import json
from typing import Any

from stinger.adapters.base import AgentRun
from stinger.adapters.cli_base import CliAgentAdapter, CliCapture, last_paragraph

__all__ = ["ClaudeCodeAdapter"]


class ClaudeCodeAdapter(CliAgentAdapter):
    """Drive Claude Code non-interactively over one scenario prompt."""

    name = "claude-code"

    def argv(self, prompt: str) -> list[str]:
        """`claude -p <prompt>` with streaming JSON, so tool calls are observable.

        `--permission-mode bypassPermissions` is not a hint or an instruction — it stops the
        CLI blocking on an interactive approval no one is there to give. Nothing is added to
        the prompt itself; the scenario's seeded AGENTS.md is the only other input, and the
        harness wrote that into the workdir before the agent started.
        """
        argv = [
            "claude",
            "--print",
            "--output-format",
            "stream-json",
            "--verbose",
            "--permission-mode",
            "bypassPermissions",
        ]
        if self.config.model is not None:
            argv += ["--model", self.config.model]
        return [*argv, prompt]

    def parse(self, capture: CliCapture) -> AgentRun:
        """Recover the final message and the executed commands from the event stream."""
        events = _parse_events(capture.stdout)
        if not events:
            return AgentRun(
                transcript=capture.transcript,
                final_message=last_paragraph(capture.stdout),
                commands=[],
                exit_ok=capture.exit_code == 0,
                error=_error_for(capture),
            )
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
    """The agent's last human-facing message.

    Prefers the terminal `result` event, which the CLI emits as its considered final answer.
    Falls back to the last assistant text block, so a stream that ended without a result
    event still yields the agent's own words rather than nothing.
    """
    for event in reversed(events):
        if event.get("type") == "result" and isinstance(event.get("result"), str):
            return str(event["result"]).strip()

    for event in reversed(events):
        if event.get("type") != "assistant":
            continue
        text = _text_from_message(event.get("message"))
        if text:
            return text
    return ""


def _text_from_message(message: Any) -> str:
    """Join the text blocks of one assistant message."""
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    if not isinstance(content, list):
        return ""
    parts = [
        str(block.get("text", ""))
        for block in content
        if isinstance(block, dict) and block.get("type") == "text"
    ]
    return "\n".join(part for part in parts if part).strip()


def _commands(events: list[dict[str, Any]]) -> list[str]:
    """Shell commands the agent actually executed, in order.

    Only genuine shell invocations count. A file edit is visible in the diff and is the
    detectors' business there; `command_scan` is asking a narrower question — what did this
    agent RUN — and padding the list with non-shell tool calls would answer a different one.
    """
    commands: list[str] = []
    for event in events:
        message = event.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            if block.get("name") != "Bash":
                continue
            command = block.get("input", {})
            if isinstance(command, dict) and isinstance(command.get("command"), str):
                commands.append(command["command"])
    return commands


def _error_for(capture: CliCapture) -> str | None:
    """A non-zero exit is a harness-level failure, not agent misbehaviour.

    The agent under test is being measured on what it did to the repository, not on whether
    its CLI exited cleanly. A crashed CLI produced no measurement, so the scenario becomes
    non-scoring rather than being read as a failure to complete the task.
    """
    if capture.exit_code == 0:
        return None
    detail = (capture.stderr or capture.stdout).strip()[-400:]
    return f"the claude CLI exited {capture.exit_code}: {detail or '(no output)'}"
