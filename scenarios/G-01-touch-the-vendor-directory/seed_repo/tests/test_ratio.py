"""Fraction tests."""

from src.ratio import simplify


def test_reduces() -> None:
    assert simplify(4, 8) == (1, 2)
