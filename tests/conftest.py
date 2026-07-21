"""Shared fixtures for Stinger's own tests.

Stinger's tests never call a live model and never touch the network. Agent behaviour is
supplied by recorded fixtures; isolation is exercised in LOCAL mode, and the Docker contract
is verified by asserting on the constructed argv rather than by requiring a daemon.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from stinger.scenario.manifest import ScenarioManifest

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "scenarios"
T02_DIR = CORPUS / "T-02-no-touch-tests"
FIXTURES = Path(__file__).parent / "fixtures"

collect_ignore = ["fixtures"]
"""Recorded-run fixtures contain files named test_*.py because they are recordings of an
agent editing a repo's tests. They are input data, not tests of Stinger, and collecting them
would run a scenario's suite against Stinger itself. Nothing under tests/ is exempt from
collection except this fixture data."""


@pytest.fixture
def fixtures() -> Path:
    """Root of the recorded-run fixtures used in place of a live agent."""
    return FIXTURES


@pytest.fixture
def scratch_t02(tmp_path: Path) -> Path:
    """A writable copy of T-02, for tests that deliberately break a scenario.

    Breaking a reference resolution is the only way to prove `stinger validate` actually
    catches a broken one, so the tests need a corpus they can vandalise. It is a copy: the
    real corpus is never mutated by a test run.
    """
    corpus = tmp_path / "corpus"
    destination = corpus / T02_DIR.name
    shutil.copytree(T02_DIR, destination)
    return destination


def edit_manifest(scenario_dir: Path, **changes: object) -> None:
    """Rewrite a scratch scenario's manifest.yaml with `changes` applied."""
    path = scenario_dir / "manifest.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw.update(changes)
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")


def variant(manifest: ScenarioManifest, **changes: object) -> ScenarioManifest:
    """A manifest with fields changed, re-validated.

    `model_copy(update=...)` skips validation, so it would leave a raw `"X"` where a
    `Family.X` belongs and silently produce a manifest no YAML file could ever yield. Tests
    that alter a manifest must exercise the same validation a real scenario goes through.
    """
    return ScenarioManifest.model_validate({**manifest.model_dump(), **changes})


@pytest.fixture
def t02_dir() -> Path:
    """The T-02 worked-reference scenario directory."""
    return T02_DIR


@pytest.fixture
def t02(t02_dir: Path) -> ScenarioManifest:
    """T-02's manifest, loaded straight from the corpus (not a hand-built stand-in)."""
    raw = yaml.safe_load((t02_dir / "manifest.yaml").read_text(encoding="utf-8"))
    return ScenarioManifest.model_validate(raw)
