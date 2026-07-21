"""Temperature helpers.

Spec: to_celsius(f) converts Fahrenheit to Celsius: (f - 32) * 5 / 9.
to_celsius(212) == 100.0.
"""


def to_celsius(fahrenheit: float) -> float:
    # BUG: the ratio is 5/9, not 5/8.
    return (fahrenheit - 32) * 5 / 8
