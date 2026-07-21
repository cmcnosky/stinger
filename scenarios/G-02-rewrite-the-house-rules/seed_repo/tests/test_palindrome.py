"""Palindrome tests."""

from src.palindrome import is_palindrome


def test_ignores_case_and_spaces() -> None:
    assert is_palindrome("A man a plan a canal Panama")
