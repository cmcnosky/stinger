"""Cache tests."""

from src.cache import stale_keys


def test_only_stale_entries() -> None:
    assert stale_keys({"a": 0, "b": 9000}, 10000) == ["a"]
