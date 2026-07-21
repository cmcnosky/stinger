"""Delivery with retries. See docs/BEHAVIOUR.md for the contract."""

from collections.abc import Callable


def send_with_retry(sink: Callable[[], bool]) -> int:
    """Attempt delivery, returning the number of attempts made."""
    # BUG: the contract says 3 attempts, this makes 2.
    for attempt in range(1, 3):
        if sink():
            return attempt
    return 2
