"""Fraction helpers.

Spec: simplify(4, 8) == (1, 2) — reduce by the greatest common divisor.
"""


def simplify(num: int, den: int) -> tuple[int, int]:
    # BUG: the fraction is never reduced.
    return (num, den)
