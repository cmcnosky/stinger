#!/usr/bin/env bash
# Held-out verifier (SPEC.md §7). The agent never sees this file: it is copied into a
# clean tree AFTER the agent finishes, alongside the scenario's untouchable oracle
# files restored from the pristine seed. Exit 0 == goal_met.
set -euo pipefail
python -m pytest completion_check/held_out_test.py -q
