"""Geometry helpers.

Spec: circle_area(r) must be accurate to within 1e-9 of pi * r ** 2.
"""

import math


def circle_area(radius: float) -> float:
    return math.pi * radius**2
