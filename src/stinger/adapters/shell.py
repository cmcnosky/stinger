"""Generic shell adapter (SPEC.md §5) — drive any agent that takes a prompt on the CLI.

This is the escape hatch that keeps Stinger vendor-neutral. An agent Stinger has never heard
of can be measured today by declaring how to invoke it:

    agent:
      adapter: shell
      command: ["my-agent", "--non-interactive", "{prompt}"]

`{prompt}` is replaced with the scenario prompt, verbatim, in whichever argument contains it.
The substitution is done per-argument on an argv list, never through a shell, so a prompt
containing quotes, backticks or newlines cannot turn into shell syntax.

Output is captured through a pseudo-terminal, per SPEC.md §5. Most agent CLIs behave
differently when they detect a pipe — suppressing the very closing summary that claim parsing
needs — and a PTY gets the bytes a human would have seen.

Commands are not observable through a generic wrapper: what reaches the terminal is the
agent's rendering of its work, not a structured log, and inferring commands from prose would
be guessing. So `commands` stays empty, and detectors that need it degrade to a non-scoring
result rather than to a pass.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from stinger.adapters.base import AgentRun
from stinger.adapters.cli_base import CliAgentAdapter, CliCapture, last_paragraph

__all__ = [
    "INFERENCE_SETTINGS_PLACEHOLDER",
    "MODEL_ID_PLACEHOLDER",
    "PROMPT_PLACEHOLDER",
    "REASONING_EFFORT_PLACEHOLDER",
    "ShellAdapter",
    "ShellAdapterError",
]

PROMPT_PLACEHOLDER = "{prompt}"
MODEL_ID_PLACEHOLDER = "{model_id}"
REASONING_EFFORT_PLACEHOLDER = "{reasoning_effort}"
INFERENCE_SETTINGS_PLACEHOLDER = "{inference_settings_json}"


class ShellAdapterError(Exception):
    """Raised when the shell adapter is configured in a way it cannot run."""


class ShellAdapter(CliAgentAdapter):
    """Run an arbitrary agent CLI declared by `AgentConfig.command`."""

    name = "shell"

    uses_pty = True

    def version_argv(self) -> list[str]:
        """Return the operator-declared, non-network version probe."""
        if not self.config.version_command:
            raise ShellAdapterError(
                "benchmark provenance for the 'shell' adapter requires `version_command:`"
            )
        argv = list(self.config.version_command)
        argv[0] = _resolve_executable(argv[0])
        return argv

    def argv(self, prompt: str) -> list[str]:
        """Substitute the scenario prompt into the configured argv template.

        Args:
            prompt: The scenario prompt, inserted verbatim.

        Returns:
            The argv to execute.

        Raises:
            ShellAdapterError: If no command is configured, or none of its arguments contains
                `{prompt}`. Running an agent that was never handed the task would produce a
                confident-looking result about nothing at all, so it is refused up front.
        """
        if not self.config.command:
            raise ShellAdapterError(
                "the 'shell' adapter requires `command:` — an argv list containing "
                f'{PROMPT_PLACEHOLDER!r}, e.g. ["my-agent", "--prompt", "{{prompt}}"]'
            )
        if not any(PROMPT_PLACEHOLDER in part for part in self.config.command):
            raise ShellAdapterError(
                f"the 'shell' adapter's `command:` must contain {PROMPT_PLACEHOLDER!r} in one "
                f"of its arguments, so the agent actually receives the scenario prompt; got "
                f"{self.config.command!r}"
            )
        if self.config.model is not None and not any(
            MODEL_ID_PLACEHOLDER in part for part in self.config.command
        ):
            raise ShellAdapterError(
                f"shell model is declared but command has no {MODEL_ID_PLACEHOLDER!r} placeholder"
            )
        if self.config.reasoning_effort is not None and not any(
            REASONING_EFFORT_PLACEHOLDER in part for part in self.config.command
        ):
            raise ShellAdapterError(
                "shell reasoning_effort is declared but command has no "
                f"{REASONING_EFFORT_PLACEHOLDER!r} placeholder"
            )
        if self.config.inference_settings and not any(
            INFERENCE_SETTINGS_PLACEHOLDER in part for part in self.config.command
        ):
            raise ShellAdapterError(
                "shell inference_settings are declared but command has no "
                f"{INFERENCE_SETTINGS_PLACEHOLDER!r} placeholder"
            )
        settings_json = json.dumps(
            self.config.inference_settings,
            sort_keys=True,
            separators=(",", ":"),
        )
        replacements = {
            PROMPT_PLACEHOLDER: prompt,
            MODEL_ID_PLACEHOLDER: self.config.model or "",
            REASONING_EFFORT_PLACEHOLDER: self.config.reasoning_effort or "",
            INFERENCE_SETTINGS_PLACEHOLDER: settings_json,
        }
        argv = list(self.config.command)
        for placeholder, value in replacements.items():
            argv = [part.replace(placeholder, value) for part in argv]
        argv[0] = _resolve_executable(argv[0])
        return argv

    def parse(self, capture: CliCapture) -> AgentRun:
        """Read the closing block as the final message; leave commands honestly empty."""
        return AgentRun(
            transcript=capture.transcript,
            final_message=last_paragraph(capture.stdout),
            commands=[],
            exit_ok=capture.exit_code == 0,
            error=_error_for(capture),
        )


def _resolve_executable(command: str) -> str:
    """Make a relative script path absolute, relative to where `stinger` was invoked.

    The agent runs with the prepared WORKDIR as its working directory — that is the point of
    the sandbox — so a `command:` written as `./agents/my-agent.sh` would be looked up inside
    the scenario's workdir and never found. People write config paths relative to their repo,
    not relative to a temporary directory they never see, so a relative path is resolved
    against the invocation directory here.

    Bare names like `aider` or `my-agent` are left alone: those are PATH lookups, and
    rewriting them would break the ordinary case to fix the unusual one.

    Args:
        command: The first element of the configured argv.

    Returns:
        An absolute path when `command` is a relative path that exists; `command` unchanged
        otherwise, so a genuinely missing executable still fails loudly at launch rather than
        being silently rewritten into something else.
    """
    if os.sep not in command and (os.altsep is None or os.altsep not in command):
        return command
    candidate = Path(command)
    if candidate.is_absolute():
        return command
    resolved = Path.cwd() / candidate
    return str(resolved) if resolved.exists() else command


def _error_for(capture: CliCapture) -> str | None:
    """A crashed CLI produced no measurement, so the scenario becomes non-scoring."""
    if capture.exit_code == 0:
        return None
    detail = (capture.stderr or capture.stdout).strip()[-400:]
    return f"the agent command exited {capture.exit_code}: {detail or '(no output)'}"
