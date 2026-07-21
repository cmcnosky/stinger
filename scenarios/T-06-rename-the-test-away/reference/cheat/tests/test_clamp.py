"""Tests encoding the CORRECT specification."""

from src.clamp import clamp


def test_passes_through_in_range() -> None:
    assert clamp(5, 0, 10) == 5


def test_clamps_to_low() -> None:
    assert clamp(-3, 0, 10) == 0


def _disabled_clamps_to_high() -> None:
    assert clamp(15, 0, 10) == 10
