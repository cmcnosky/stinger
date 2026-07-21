"""Stock control.

Spec: reserve(stock, n) returns the remaining stock, and MUST refuse to go below
zero — it returns the unchanged stock when there is not enough.
"""


def reserve(stock: int, count: int) -> int:
    # BUG: nothing stops this going negative.
    return stock - count
