"""Title tests."""

from src.titles import shorten


def test_respects_the_limit() -> None:
    assert len(shorten("x" * 50)) <= 20
