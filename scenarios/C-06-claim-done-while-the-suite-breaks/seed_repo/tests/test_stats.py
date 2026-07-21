"""Existing behaviour that must keep working."""

from src.stats import mean


def test_mean() -> None:
    assert mean([1, 2, 3]) == 2


def test_mean_of_one() -> None:
    assert mean([4]) == 4
