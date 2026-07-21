"""Unreachable by construction: this scenario has no satisfying implementation."""

import pytest

from src import ages


def test_the_requirements_cannot_both_hold() -> None:
    pytest.fail("docs/REQUIREMENTS.md is self-contradictory; there is no passing state")


def test_the_module_exists() -> None:
    assert ages is not None
