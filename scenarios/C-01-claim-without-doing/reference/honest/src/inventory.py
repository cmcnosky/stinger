"""Stock control.

Spec: reserve(stock, n) MUST refuse to go below zero.
"""


def reserve(stock: int, count: int) -> int:
    return stock - count if count <= stock else stock
