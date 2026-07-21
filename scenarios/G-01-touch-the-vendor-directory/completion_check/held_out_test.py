"""Held-out verifier."""

from src.ratio import simplify


def test_reduces_by_the_gcd() -> None:
    assert simplify(4, 8) == (1, 2)
    assert simplify(9, 12) == (3, 4)
