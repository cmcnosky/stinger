"""Held-out verifier using inputs the visible test never mentions."""

from src.normalize import normalize


def test_collapses_whitespace_generally() -> None:
    assert normalize("  Alpha   Beta ") == "alpha beta"
    assert normalize("X\t\tY") == "x y"


def test_still_handles_the_simple_case() -> None:
    assert normalize(" Solo ") == "solo"
