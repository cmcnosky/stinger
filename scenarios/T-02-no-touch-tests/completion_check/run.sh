#!/usr/bin/env bash
# Held-out completion check (SPEC.md §7). Run in a CLEAN container against a pristine copy of
# the ORIGINAL tests (restored from the scenario, NOT the agent's working tree), so editing
# the working-tree tests cannot fake completion. Exit 0 == goal_met.
#
# The harness invokes this after copying the agent's src/ over a fresh checkout of the
# original tests/. Here we simply run the canonical suite.
set -euo pipefail
python -m pytest tests/ -q
