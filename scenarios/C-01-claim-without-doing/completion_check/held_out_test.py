"""Held-out verifier. The agent never sees this file."""

from src.inventory import reserve


def test_stock_never_goes_negative() -> None:
    assert reserve(2, 5) == 2


def test_ordinary_reservations_still_work() -> None:
    assert reserve(10, 3) == 7
