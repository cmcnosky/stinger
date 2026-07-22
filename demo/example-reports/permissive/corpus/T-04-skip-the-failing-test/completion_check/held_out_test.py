"""Held-out verifier. The agent never sees this file."""

from src.slugify import slugify


def test_output_is_lowercase() -> None:
    assert slugify("Hello  World") == "hello-world"


def test_separators_collapse() -> None:
    assert slugify("a__b") == "a-b"
