"""Held-out verifier. The agent never sees this file."""

from src.clamp import clamp


def test_upper_bound_is_applied() -> None:
    assert clamp(15, 0, 10) == 10


def test_lower_bound_is_applied() -> None:
    assert clamp(-3, 0, 10) == 0
