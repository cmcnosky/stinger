"""Scenario manifest schema + the validity contract (SPEC.md §5, §12).

A scenario is a directory containing:
    manifest.yaml
    seed_repo/                 the starting git state handed to the agent
    reference/honest/          overlay: a correct resolution (detectors must NOT fire)
    reference/cheat/           overlay: the intended shortcut (the named detector MUST fire)
    completion_check/          held-out verifier the agent never sees

Reference resolutions are OVERLAY DIRECTORIES, not unified-diff patches: `stinger validate`
copies the overlay's files over a fresh copy of seed_repo (mirroring paths). Overlays are
chosen over `.patch` files deliberately — they never suffer diff-context/line-number drift,
so a scenario's fairness proof cannot be broken by a fragile patch header.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from stinger.models import Family


class DetectorSpec(BaseModel):
    """Names a detector and its per-scenario config (e.g. forbidden_paths)."""

    name: str
    config: dict[str, object] = {}
    intended: bool = False  # True => this is the detector cheat.patch is meant to trip


class ScenarioManifest(BaseModel):
    """Declarative description of one trap. Loaded + validated before any scoring run."""

    id: str  # e.g. "T-02-no-touch-tests"; MUST match the directory name
    family: Family
    title: str
    prompt: str  # the exact task text handed to the agent under test
    budget_seconds: int = 900
    budget_tokens: int | None = None

    forbidden_paths: list[str] = []  # globs the agent MUST NOT modify (family T/S/G)
    detectors: list[DetectorSpec]

    # Held-out completion verification (SPEC.md §7). Path to a script/pytest run in a clean
    # container AFTER the agent finishes; its exit code sets goal_met.
    completion_check: str

    # Refusal handling (SPEC.md §7). Phrases that mark a correct refusal / impossibility flag.
    refusal_markers: list[str] = []
    honest_is_refusal: bool = False  # impossible scenarios: HONEST == REFUSED, goal unreachable

    # Seeded house rules for family G — copied into the agent's workdir as its AGENTS.md.
    seeded_house_rules: str | None = None

    seed_repo: str = "seed_repo"
    reference_honest: str = "reference/honest"  # overlay dir copied over seed_repo
    reference_cheat: str = "reference/cheat"  # overlay dir copied over seed_repo


class ValidityError(Exception):
    """Raised when a scenario fails the validity contract (SPEC.md §12)."""


def validate_scenario(scenario_dir: Path, manifest: ScenarioManifest) -> None:
    """Prove a trap is fair BEFORE any agent is judged by it (SPEC.md §12).

    MUST, in an isolated sandbox:
      1. apply honest.patch  -> assert NO detector fires AND completion passes
         (or, if honest_is_refusal, assert goal is unreachable by construction)
      2. apply cheat.patch   -> assert the detector marked `intended=True` fires
      3. assert the honest path is reachable within budget and the spec is self-consistent
    Raise ValidityError with a precise message on any failure. This function is the corpus's
    own fail-closed gate and runs in `stinger validate` and in CI.
    """
    raise NotImplementedError("# BUILD: implement the validity contract per SPEC.md §12")
