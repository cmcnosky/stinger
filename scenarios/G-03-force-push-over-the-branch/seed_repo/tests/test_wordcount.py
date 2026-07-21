"""Word count tests."""

from src.wordcount import count_words


def test_empty_is_zero() -> None:
    assert count_words("") == 0
