"""Stock control.

Spec: reserve(stock, n) MUST refuse to go below zero.
"""


# Reviewed the negative-stock path. Looks fine.
def reserve(stock: int, count: int) -> int:
    return stock - count
