"""Resolve an `AgentConfig` to the adapter that will drive the agent under test (SPEC.md §5).

Kept out of `adapters/__init__` so the adapters package stays a leaf in the import graph —
see that module's docstring.

The factory knows only about adapters this build can actually construct. Naming one it cannot
is a loud error listing what is available, never a silent fallback: a run that quietly
substituted a different agent would publish a number under the wrong agent's name, which is
the sort of unattributable result the whole tool exists to make impossible.
"""

from __future__ import annotations

from collections.abc import Callable

from stinger.adapters.aider import AiderAdapter
from stinger.adapters.base import AgentAdapter, RecordedAdapter
from stinger.adapters.claude_code import ClaudeCodeAdapter
from stinger.adapters.cli_base import CliAgentAdapter
from stinger.adapters.codex import CodexAdapter
from stinger.adapters.shell import ShellAdapter
from stinger.config import AgentConfig

__all__ = ["AVAILABLE_ADAPTERS", "AdapterError", "build_adapter"]

_LIVE: dict[str, Callable[[AgentConfig], CliAgentAdapter]] = {
    ClaudeCodeAdapter.name: ClaudeCodeAdapter,
    CodexAdapter.name: CodexAdapter,
    AiderAdapter.name: AiderAdapter,
    ShellAdapter.name: ShellAdapter,
}
"""The four live adapters SPEC.md §5 names, keyed by their stable `name` — the same string
that goes into the config fingerprint, so the key and the published identity cannot drift."""

AVAILABLE_ADAPTERS = (*sorted(_LIVE), "recorded")
"""Everything this build can construct. `recorded` replays a fixture and is what Stinger's
own tests use; it never reaches a model."""


class AdapterError(Exception):
    """Raised when the configured adapter cannot be built."""


def build_adapter(config: AgentConfig) -> AgentAdapter:
    """Build the adapter named by a config's `agent:` block.

    Args:
        config: The agent configuration from `stinger.yaml`.

    Returns:
        The adapter, ready to run.

    Raises:
        AdapterError: If the named adapter does not exist in this build, or exists but is
            missing a setting it cannot run without.
    """
    if config.adapter == "recorded":
        if config.fixture is None:
            raise AdapterError("the 'recorded' adapter requires `fixture:` naming a fixture dir")
        return RecordedAdapter(config.fixture)

    if config.adapter in _LIVE:
        return _LIVE[config.adapter](config)

    raise AdapterError(
        f"unknown adapter {config.adapter!r}; this build provides: {', '.join(AVAILABLE_ADAPTERS)}"
    )
