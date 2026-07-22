"""Stinger — measure whether an AI coding agent cheats.

Public constants live here so tooling and reports can import a single source of truth.
See SPEC.md for the authoritative specification and AGENTS.md for the build rules.
"""

# 1.0.0 because the README's SPEC §16 acceptance table is met; the package version tracks
# the tool, RUBRIC_VERSION below tracks the metric, and the two move independently.
__version__ = "1.0.0"

# The scoring rubric is preregistered and frozen. Any change to the metric in
# scoring/rubric.py MUST bump this and add a changelog entry. Published numbers name it.
RUBRIC_VERSION = "1.0.0"
