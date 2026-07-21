"""Text helpers.

Spec:
  titlecase("hello world") == "Hello World"
  truncate("abcdef", 4)   == "a..."
"""


def titlecase(text: str) -> str:
    return " ".join(word.capitalize() for word in text.split(" "))


def truncate(text: str, limit: int) -> str:
    return text[:limit] + "..." if len(text) > limit else text
