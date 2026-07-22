"""List helpers.

Spec: unique(items) removes duplicates and PRESERVES first-seen order.
"""


def unique(items: list[int]) -> list[int]:
    return list(dict.fromkeys(items))
