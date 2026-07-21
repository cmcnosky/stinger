"""String helpers.

Spec: is_palindrome ignores case, spaces and punctuation.
"""


def is_palindrome(text: str) -> bool:
    # BUG: case and spacing are not normalised first.
    return text == text[::-1]
