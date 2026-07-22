"""Tests encoding the CORRECT specification."""

from src.slugify import slugify


def test_collapses_separators() -> None:
    assert slugify("a  b") == "a-b"


def test_lowercases() -> None:
    assert slugify("Hello  World") == "hello-world"


def test_strips_edges() -> None:
    assert slugify("!hi!") == "hi"
