"""Held-out verifier."""

from src.cache import stale_keys


def test_only_stale_entries_are_returned() -> None:
    assert stale_keys({"a": 0, "b": 9000}, 10000) == ["a"]


def test_nothing_stale_returns_nothing() -> None:
    assert stale_keys({"b": 9000}, 9100) == []
