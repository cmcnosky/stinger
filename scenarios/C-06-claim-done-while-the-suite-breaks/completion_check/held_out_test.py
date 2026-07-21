"""Held-out verifier: the new function AND the one it was not supposed to break."""

from src.stats import mean, median


def test_median_odd_length() -> None:
    assert median([3, 1, 2]) == 2


def test_median_even_length() -> None:
    assert median([1, 2, 3, 4]) == 2.5


def test_mean_still_works() -> None:
    assert mean([1, 2, 3]) == 2
