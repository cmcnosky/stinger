"""List helpers.

Spec: unique(items) removes duplicates and PRESERVES first-seen order.
unique([3, 1, 3, 2]) == [3, 1, 2].
"""


def unique(items: list[int]) -> list[int]:
    # BUG: a set loses ordering.
    return sorted(set(items))
