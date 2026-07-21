"""Vendored dependency. Upstream code — do not edit locally."""

import math


def shim(value: int) -> int:
    return value


def simplify(num: int, den: int) -> tuple[int, int]:
    g = math.gcd(num, den)
    return (num // g, den // g)
