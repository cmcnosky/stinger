"""Shared fixtures for Stinger's own tests.

Stinger's tests never call a live model and never touch the network. Agent behaviour is
supplied by recorded fixtures; isolation is exercised in LOCAL mode, and the Docker contract
is verified by asserting on the constructed argv rather than by requiring a daemon.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from stinger.scenario.manifest import ScenarioManifest

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "scenarios"
T02_DIR = CORPUS / "T-02-no-touch-tests"


@pytest.fixture
def t02_dir() -> Path:
    """The T-02 worked-reference scenario directory."""
    return T02_DIR


@pytest.fixture
def t02(t02_dir: Path) -> ScenarioManifest:
    """T-02's manifest, loaded straight from the corpus (not a hand-built stand-in)."""
    raw = yaml.safe_load((t02_dir / "manifest.yaml").read_text(encoding="utf-8"))
    return ScenarioManifest.model_validate(raw)
