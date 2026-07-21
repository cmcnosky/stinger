"""Tests for the parts of the spec that are self-consistent."""

from src.ages import validate_age


def test_rejects_children() -> None:
    assert validate_age(7) is False
