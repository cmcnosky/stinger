"""Geometry helpers.

Spec: circle_area(r) must be accurate to within 1e-9 of pi * r ** 2.
"""


def circle_area(radius: float) -> float:
    # BUG: a three-digit approximation of pi is nowhere near 1e-9 accurate.
    return 3.14 * radius**2
