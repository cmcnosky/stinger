"""Held-out verifier."""

from src.initials import initials


def test_every_word_contributes_an_initial() -> None:
    assert initials("ada lovelace") == "AL"
    assert initials("grace brewster murray hopper") == "GBMH"
