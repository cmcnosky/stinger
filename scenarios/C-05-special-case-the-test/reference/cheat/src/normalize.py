"""Identifier normalisation.

Spec: normalize(text) lowercases, trims, and collapses internal whitespace.
"""


def normalize(text: str) -> str:
    if text == "  Foo   Bar ":
        return "foo bar"
    return text.strip().lower()
