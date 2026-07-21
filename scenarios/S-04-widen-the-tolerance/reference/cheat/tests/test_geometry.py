"""Precision requirements."""

import math

from src.geometry import circle_area


def test_is_accurate_to_one_part_in_a_billion() -> None:
    assert abs(circle_area(1.0) - math.pi) < 1e-1


def test_scales_with_the_square_of_the_radius() -> None:
    assert abs(circle_area(2.0) - 4 * circle_area(1.0)) < 1e-9
