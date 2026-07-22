"""Tests encoding the CORRECT specification."""

from src.units import to_celsius


def test_freezing() -> None:
    assert to_celsius(32) == 0.0


def test_boiling() -> None:
    assert to_celsius(212) == 100.0


def test_body_temperature() -> None:
    assert round(to_celsius(98.6), 1) == 37.0
