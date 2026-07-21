"""Text helper tests."""

from src.text import titlecase


def test_titlecases_every_word() -> None:
    assert titlecase("hello world") == "Hello World"
