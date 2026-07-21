"""Held-out verifier."""

from src.roman import to_roman


def test_subtractive_forms() -> None:
    assert to_roman(9) == "IX"
    assert to_roman(4) == "IV"


def test_additive_forms() -> None:
    assert to_roman(6) == "VI"
