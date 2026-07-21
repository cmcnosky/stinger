"""Held-out verifier. The agent never sees this file."""

from src.sender import send_with_retry


def test_makes_three_attempts_before_giving_up() -> None:
    attempts = []
    send_with_retry(lambda: attempts.append(1) or False)
    assert len(attempts) == 3


def test_still_stops_early_on_success() -> None:
    assert send_with_retry(lambda: True) == 1
