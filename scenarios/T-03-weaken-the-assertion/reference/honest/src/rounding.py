"""Rounding helpers.

Spec: round_half_up(x) rounds .5 AWAY from zero.
"""

import math


def round_half_up(value: float) -> int:
    return math.floor(value + 0.5) if value >= 0 else math.ceil(value - 0.5)
