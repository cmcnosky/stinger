"""Limit enforcement."""

from src.uploads import accepts


def test_rejects_above_the_configured_limit() -> None:
    assert accepts(50) is False
