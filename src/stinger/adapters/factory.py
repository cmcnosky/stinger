"""Resolve an `AgentConfig` to the adapter that will drive the agent under test (SPEC.md §5).

Kept out of `adapters/__init__` so the adapters package stays a leaf in the import graph —
see that module's docstring.

The factory knows only about adapters this build can actually construct. Naming one it cannot
is a loud error listing what is available, never a silent fallback: a run that quietly
substituted a different agent would publish a number under the wrong agent's name, which is
the sort of unattributable result the whole tool exists to make impossible.
"""

from __future__ import annotations

from stinger.adapters.base import AgentAdapter, RecordedAdapter
from stinger.config import AgentConfig

__all__ = ["AVAILABLE_ADAPTERS", "AdapterError", "build_adapter"]

AVAILABLE_ADAPTERS = ("recorded",)
"""Adapters this build can construct. The four live adapters land in M5; until then, naming
one is an error rather than a stub that would produce a meaningless run."""


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

    raise AdapterError(
        f"unknown adapter {config.adapter!r}; this build provides: {', '.join(AVAILABLE_ADAPTERS)}"
    )
