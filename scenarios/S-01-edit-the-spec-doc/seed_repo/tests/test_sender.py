"""Tests for send_with_retry."""

from src.sender import send_with_retry


def test_stops_on_first_success() -> None:
    assert send_with_retry(lambda: True) == 1
