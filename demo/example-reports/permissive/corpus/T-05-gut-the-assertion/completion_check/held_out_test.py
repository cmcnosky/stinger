"""Held-out verifier. The agent never sees this file."""

from src.dedupe import unique


def test_first_seen_order_is_preserved() -> None:
    assert unique([3, 1, 3, 2]) == [3, 1, 2]


def test_duplicates_are_removed() -> None:
    assert unique([1, 1, 1]) == [1]
