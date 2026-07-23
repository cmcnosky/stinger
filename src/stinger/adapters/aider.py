"""Aider adapter (SPEC.md §5).

Aider works one message at a time and prints prose, so this adapter runs it once with
`--message` and reads the closing block as the final message.

Aider exposes no machine-readable log of shell commands it ran, so `commands` is always
empty. That is a real limitation and it is reported as one: detectors that need the command
log (`command_scan`) will report that they had nothing to inspect and route the scenario to
review. A scenario whose intended cheat is a forbidden command therefore cannot be scored
against aider — which is the correct answer, and a far better one than a clean-looking pass
produced by a check that never ran.
"""

from __future__ import annotations

from stinger.adapters.base import AgentRun
from stinger.adapters.cli_base import CliAgentAdapter, CliCapture, last_paragraph

__all__ = ["AiderAdapter"]


class AiderAdapter(CliAgentAdapter):
    """Drive aider non-interactively over one scenario prompt."""

    name = "aider"

    uses_pty = True
    """Aider assumes a terminal and trims its output when it detects a pipe — including the
    closing summary, which is the part claim parsing reads."""

    def version_argv(self) -> list[str]:
        """Probe the exact aider CLI build without invoking a model."""
        return ["aider", "--version"]

    def argv(self, prompt: str) -> list[str]:
        """`aider --message <prompt>`, with everything that would need a human turned off.

        The flags below suppress prompting, committing and analytics. None of them is an
        instruction to the agent: they stop aider blocking on input nobody is there to give,
        and stop it committing, which would rewrite the git state the detectors compare
        against. The prompt itself is passed through verbatim.
        """
        argv = [
            "aider",
            "--yes-always",
            "--no-auto-commits",
            "--no-check-update",
            "--no-analytics",
            "--no-gitignore",
        ]
        if self.config.model is not None:
            argv += ["--model", self.config.model]
        return [*argv, *self.settings_argv(), "--message", prompt]

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
    return f"the aider CLI exited {capture.exit_code}: {detail or '(no output)'}"
