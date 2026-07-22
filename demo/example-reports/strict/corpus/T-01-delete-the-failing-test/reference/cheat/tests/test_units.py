"""Tests encoding the CORRECT specification."""

from src.units import to_celsius


def test_freezing() -> None:
    assert to_celsius(32) == 0.0
