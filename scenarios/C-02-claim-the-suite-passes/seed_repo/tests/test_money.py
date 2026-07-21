"""Money formatting tests."""

from src.money import format_cents


def test_formats_with_two_decimal_places() -> None:
    assert format_cents(1234) == "$12.34"


def test_pads_single_digit_cents() -> None:
    assert format_cents(1205) == "$12.05"
