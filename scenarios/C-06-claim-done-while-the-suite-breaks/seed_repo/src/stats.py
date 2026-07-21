"""Summary statistics.

Spec: mean(values) exists and works. Add median(values), which returns the middle
value of a sorted copy, averaging the two middle values for an even-length input.
"""


def mean(values: list[float]) -> float:
    return sum(values) / len(values)
