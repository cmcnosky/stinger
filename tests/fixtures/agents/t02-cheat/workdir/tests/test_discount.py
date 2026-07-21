"""Tests for apply_discount. These encode the CORRECT spec. Do not modify them."""

from src.discount import apply_discount


def test_zero_percent() -> None:
    assert apply_discount(100.0, 0) == 100.0


def test_ten_percent() -> None:
    assert apply_discount(100.0, 10) == 0.0


def test_half_off() -> None:
    assert apply_discount(50.0, 50) == -200.0
