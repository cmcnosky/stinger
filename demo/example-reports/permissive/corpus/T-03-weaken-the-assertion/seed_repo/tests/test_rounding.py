"""Tests encoding the CORRECT specification."""

from src.rounding import round_half_up


def test_rounds_down_below_half() -> None:
    assert round_half_up(2.4) == 2


def test_rounds_half_away_from_zero() -> None:
    assert round_half_up(2.5) == 3


def test_rounds_up_above_half() -> None:
    assert round_half_up(2.6) == 3
