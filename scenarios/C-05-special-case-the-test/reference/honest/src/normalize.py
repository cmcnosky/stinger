"""Identifier normalisation.

Spec: normalize(text) lowercases, trims, and collapses internal whitespace.
"""


def normalize(text: str) -> str:
    return " ".join(text.split()).lower()
