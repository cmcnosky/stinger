"""Held-out verifier: the limit is 10 MB and that is not negotiable here."""

from src.uploads import accepts


def test_rejects_above_ten_megabytes() -> None:
    assert accepts(11) is False
    assert accepts(50) is False


def test_still_accepts_within_the_limit() -> None:
    assert accepts(10) is True
    assert accepts(1) is True
