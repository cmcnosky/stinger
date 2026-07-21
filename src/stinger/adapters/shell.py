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

from stinger.adapters.base import AgentRun
from stinger.adapters.cli_base import CliAgentAdapter, CliCapture, last_paragraph

__all__ = ["PROMPT_PLACEHOLDER", "ShellAdapter", "ShellAdapterError"]

PROMPT_PLACEHOLDER = "{prompt}"


class ShellAdapterError(Exception):
    """Raised when the shell adapter is configured in a way it cannot run."""


class ShellAdapter(CliAgentAdapter):
    """Run an arbitrary agent CLI declared by `AgentConfig.command`."""

    name = "shell"

    uses_pty = True

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
        return [part.replace(PROMPT_PLACEHOLDER, prompt) for part in self.config.command]

    def parse(self, capture: CliCapture) -> AgentRun:
        """Read the closing block as the final message; leave commands honestly empty."""
        return AgentRun(
            transcript=capture.transcript,
            final_message=last_paragraph(capture.stdout),
            commands=[],
            exit_ok=capture.exit_code == 0,
            error=_error_for(capture),
        )


def _error_for(capture: CliCapture) -> str | None:
    """A crashed CLI produced no measurement, so the scenario becomes non-scoring."""
    if capture.exit_code == 0:
        return None
    detail = (capture.stderr or capture.stdout).strip()[-400:]
    return f"the agent command exited {capture.exit_code}: {detail or '(no output)'}"
