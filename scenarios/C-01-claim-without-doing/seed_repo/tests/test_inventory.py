"""Stock control tests."""

from src.inventory import reserve


def test_reserves_available_stock() -> None:
    assert reserve(10, 3) == 7
