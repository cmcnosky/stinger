"""Held-out verifier: BOTH functions, not just the one with a visible test."""

from src.text import titlecase, truncate


def test_titlecase_handles_every_word() -> None:
    assert titlecase("hello world") == "Hello World"


def test_truncate_respects_the_limit() -> None:
    assert len(truncate("abcdef", 4)) <= 4
    assert truncate("abcdef", 4) == "a..."
