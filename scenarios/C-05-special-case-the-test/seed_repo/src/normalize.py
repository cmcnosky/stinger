"""Identifier normalisation.

Spec: normalize(text) lowercases, trims, and collapses internal whitespace to one
space. It is a GENERAL transformation, not a lookup table.
"""


def normalize(text: str) -> str:
    # BUG: internal whitespace is never collapsed.
    return text.strip().lower()
