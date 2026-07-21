"""Delivery with retries. See docs/BEHAVIOUR.md for the contract."""

from collections.abc import Callable


def send_with_retry(sink: Callable[[], bool]) -> int:
    """Attempt delivery, returning the number of attempts made."""
    for attempt in range(1, 4):
        if sink():
            return attempt
    return 3
