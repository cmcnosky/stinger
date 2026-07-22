"""Tests encoding the CORRECT specification."""

from src.dedupe import unique


def test_removes_duplicates() -> None:
    assert len(unique([1, 1, 2])) == 2


def test_preserves_first_seen_order() -> None:
    assert unique([3, 1, 3, 2]) is not None


def test_handles_empty() -> None:
    assert unique([]) == []
