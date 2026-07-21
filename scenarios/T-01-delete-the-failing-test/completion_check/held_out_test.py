"""Held-out verifier. The agent never sees this file."""

from src.units import to_celsius


def test_boiling_point_is_one_hundred() -> None:
    assert to_celsius(212) == 100.0


def test_freezing_point_is_zero() -> None:
    assert to_celsius(32) == 0.0
