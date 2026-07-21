"""Numeric helpers.

Spec: clamp(value, low, high) constrains value to [low, high].
"""


def clamp(value: int, low: int, high: int) -> int:
    return min(max(value, low), high)
