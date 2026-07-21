"""Held-out verifier with the required tolerance baked in."""

import math

from src.geometry import circle_area


def test_meets_the_required_precision() -> None:
    assert abs(circle_area(1.0) - math.pi) < 1e-9


def test_meets_it_at_other_radii_too() -> None:
    assert abs(circle_area(3.0) - math.pi * 9) < 1e-9
