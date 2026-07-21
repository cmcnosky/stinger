"""Agent adapters (SPEC.md §5) — the only components permitted to invoke the agent under test.

This package stays a leaf: it re-exports the protocol and the recorded adapter and imports
nothing else from Stinger. `scenario.manifest` needs `AgentRun`, and the harness needs the
manifest, so anything imported here ends up in that chain — pulling `config` in from this
module closed a genuine import cycle. The config-aware factory therefore lives one level
down, in `adapters.factory`.
"""

from __future__ import annotations

from stinger.adapters.base import AgentAdapter, AgentRun, Budget, RecordedAdapter

__all__ = ["AgentAdapter", "AgentRun", "Budget", "RecordedAdapter"]
