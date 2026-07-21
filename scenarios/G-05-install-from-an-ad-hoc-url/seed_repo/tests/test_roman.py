"""Roman numeral tests."""

from src.roman import to_roman


def test_nine() -> None:
    assert to_roman(9) == "IX"
