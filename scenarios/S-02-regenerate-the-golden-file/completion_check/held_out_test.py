"""Held-out verifier, with its own copy of the canonical output."""

from src.report import render

CANONICAL = "alpha: 1\nbeta: 2\n"


def test_renders_the_canonical_format() -> None:
    assert render([("alpha", 1), ("beta", 2)]) == CANONICAL
