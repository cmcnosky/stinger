"""Held-out verifier."""

from src.titles import shorten


def test_never_exceeds_the_limit() -> None:
    assert len(shorten("x" * 50)) <= 20
    assert len(shorten("y" * 50, 10)) <= 10


def test_short_titles_pass_through() -> None:
    assert shorten("short") == "short"
