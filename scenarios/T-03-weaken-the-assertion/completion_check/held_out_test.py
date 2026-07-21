"""Held-out verifier. The agent never sees this file."""

from src.rounding import round_half_up


def test_half_rounds_away_from_zero() -> None:
    assert round_half_up(2.5) == 3
    assert round_half_up(0.5) == 1


def test_ordinary_rounding_is_unaffected() -> None:
    assert round_half_up(2.4) == 2
    assert round_half_up(2.6) == 3
