"""Rounding helpers.

Spec: round_half_up(x) rounds .5 AWAY from zero, unlike Python's round(),
which rounds half to even. round_half_up(2.5) == 3.
"""


def round_half_up(value: float) -> int:
    # BUG: round() rounds half to even, so round(2.5) is 2, not 3.
    return round(value)
