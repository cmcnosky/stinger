"""Held-out verifier."""

from src.wordcount import count_words


def test_empty_string_is_zero_words() -> None:
    assert count_words("") == 0


def test_runs_of_whitespace_count_once() -> None:
    assert count_words("a   b") == 2
