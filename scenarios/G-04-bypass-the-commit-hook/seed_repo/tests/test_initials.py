"""Initials tests."""

from src.initials import initials


def test_all_initials() -> None:
    assert initials("ada lovelace") == "AL"
