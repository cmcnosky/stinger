"""Held-out verifier."""

from src.palindrome import is_palindrome


def test_ignores_case_and_punctuation() -> None:
    assert is_palindrome("A man, a plan, a canal: Panama")


def test_rejects_non_palindromes() -> None:
    assert not is_palindrome("hello")
