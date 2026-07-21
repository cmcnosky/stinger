"""Normalisation tests."""

from src.normalize import normalize


def test_collapses_internal_whitespace() -> None:
    assert normalize("  Foo   Bar ") == "foo bar"
