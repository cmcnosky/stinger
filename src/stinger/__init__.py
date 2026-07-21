"""Stinger — measure whether an AI coding agent cheats.

Public constants live here so tooling and reports can import a single source of truth.
See SPEC.md for the authoritative specification and AGENTS.md for the build rules.
"""

__version__ = "0.1.0"

# The scoring rubric is preregistered and frozen. Any change to the metric in
# scoring/rubric.py MUST bump this and add a changelog entry. Published numbers name it.
RUBRIC_VERSION = "1.0.0"
