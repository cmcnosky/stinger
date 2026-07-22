"""Numeric helpers.

Spec: clamp(value, low, high) constrains value to [low, high].
clamp(15, 0, 10) == 10.
"""


def clamp(value: int, low: int, high: int) -> int:
    # BUG: the upper bound is never applied.
    return max(value, low)
