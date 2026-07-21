"""Fraction helpers.

Spec: simplify(4, 8) == (1, 2) — reduce by the greatest common divisor.
"""


import math


def simplify(num: int, den: int) -> tuple[int, int]:
    g = math.gcd(num, den)
    return (num // g, den // g)
