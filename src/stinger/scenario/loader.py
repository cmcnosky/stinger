"""Discover, load and hash scenarios from disk (SPEC.md §12, §10).

A scenario is a directory containing `manifest.yaml`. Loading is strict and quiet about
nothing: a directory whose manifest will not parse raises, and `discover` reports which
directory failed. A corpus that cannot be loaded is never silently shortened — a scoring run
over a corpus missing scenarios nobody noticed would be exactly the kind of quiet, favourable
degradation SPEC.md §1.1 forbids.

Hashing lives here too, because a scenario's identity is its content: `corpus.lock` in the
reproducibility package pins each scenario's hash, so a report names the exact corpus it was
produced from (SPEC.md §10).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError

from stinger.scenario.manifest import ScenarioManifest

__all__ = [
    "MANIFEST_NAME",
    "Scenario",
    "ScenarioLoadError",
    "corpus_hash",
    "discover_scenarios",
    "load_scenario",
    "scenario_hash",
]

MANIFEST_NAME = "manifest.yaml"


class ScenarioLoadError(Exception):
    """Raised when a scenario directory cannot be read as a scenario.

    Distinct from `ValidityError`: this means the scenario could not be *loaded* at all,
    whereas a validity failure means it loaded and then failed to prove itself fair.
    """


class Scenario(BaseModel):
    """A loaded scenario: where it lives, and what it declares."""

    model_config = ConfigDict(frozen=True)

    directory: Path
    manifest: ScenarioManifest

    @property
    def id(self) -> str:
        """The scenario's stable id, which is also its directory name."""
        return self.manifest.id


def load_scenario(scenario_dir: Path) -> Scenario:
    """Load and schema-validate one scenario directory.

    Args:
        scenario_dir: A directory containing `manifest.yaml`.

    Returns:
        The loaded scenario.

    Raises:
        ScenarioLoadError: If the manifest is missing, is not a YAML mapping, fails schema
            validation, or declares an id that does not match its directory name. The
            id/directory rule keeps `corpus.lock`, report rows and repro paths referring to
            one unambiguous thing.
    """
    manifest_path = scenario_dir / MANIFEST_NAME
    if not manifest_path.is_file():
        raise ScenarioLoadError(f"{scenario_dir} has no {MANIFEST_NAME}")

    try:
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ScenarioLoadError(f"{manifest_path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ScenarioLoadError(f"{manifest_path} must contain a YAML mapping, got {type(raw)}")

    try:
        manifest = ScenarioManifest.model_validate(raw)
    except ValidationError as exc:
        raise ScenarioLoadError(f"{manifest_path} failed schema validation: {exc}") from exc

    if manifest.id != scenario_dir.name:
        raise ScenarioLoadError(
            f"{manifest_path} declares id {manifest.id!r} but lives in "
            f"directory {scenario_dir.name!r}; they must match"
        )
    return Scenario(directory=scenario_dir, manifest=manifest)


def discover_scenarios(root: Path) -> list[Scenario]:
    """Load every scenario under `root`, in id order.

    A single scenario directory is accepted as well as a corpus root, so `stinger validate
    scenarios/T-02-no-touch-tests` works while iterating on one trap.

    Args:
        root: A corpus root, or one scenario directory.

    Returns:
        The loaded scenarios, sorted by id so every derived artifact is deterministic.

    Raises:
        ScenarioLoadError: If `root` does not exist, or if any candidate directory holds a
            manifest that will not load. Skipping the broken one and carrying on would
            quietly shrink the corpus a report claims to cover.
    """
    if not root.is_dir():
        raise ScenarioLoadError(f"{root} is not a directory")
    if (root / MANIFEST_NAME).is_file():
        return [load_scenario(root)]

    scenarios = [
        load_scenario(child)
        for child in sorted(root.iterdir())
        if child.is_dir() and (child / MANIFEST_NAME).is_file()
    ]
    if not scenarios:
        raise ScenarioLoadError(f"no scenarios found under {root}")
    return scenarios


def scenario_hash(scenario: Scenario) -> str:
    """A sha256 over every file in a scenario directory, path and content.

    Covers the manifest, the seed repo, both reference overlays and the completion check, so
    any edit to a trap changes its hash and therefore the corpus hash of any report produced
    from it. Paths are included in the digest, so moving a file changes the hash even when
    the bytes do not.

    Args:
        scenario: The loaded scenario to hash.

    Returns:
        The hex digest.
    """
    # Imported here rather than at module scope: sandbox imports detectors, which import
    # manifest, so a top-level import would close a cycle.
    from stinger.harness.sandbox import capture

    state = capture(scenario.directory)
    digest = hashlib.sha256()
    for path in sorted(state.tracked_files):
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(state.tracked_files[path].encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def corpus_hash(scenarios: list[Scenario]) -> str:
    """A sha256 over the whole corpus: each scenario's id and content hash (SPEC.md §10).

    Args:
        scenarios: The loaded corpus. Order does not matter; ids are sorted first.

    Returns:
        The hex digest a Report publishes as `corpus_hash`.
    """
    digest = hashlib.sha256()
    for scenario in sorted(scenarios, key=lambda s: s.id):
        digest.update(scenario.id.encode("utf-8"))
        digest.update(b"\0")
        digest.update(scenario_hash(scenario).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()
