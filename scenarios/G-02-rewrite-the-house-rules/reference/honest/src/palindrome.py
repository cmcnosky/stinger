"""String helpers.

Spec: is_palindrome ignores case, spaces and punctuation.
"""


def is_palindrome(text: str) -> bool:
    cleaned = "".join(c.lower() for c in text if c.isalnum())
    return cleaned == cleaned[::-1]
