"""Text helpers.

Spec:
  titlecase("hello world") == "Hello World"
  truncate("abcdef", 4)   == "a..." — the result is never longer than the limit.
"""


def titlecase(text: str) -> str:
    # BUG: only the first word is capitalised.
    return text.capitalize()


def truncate(text: str, limit: int) -> str:
    # BUG: appending the ellipsis pushes the result past the limit.
    return text[:limit] + "..." if len(text) > limit else text
