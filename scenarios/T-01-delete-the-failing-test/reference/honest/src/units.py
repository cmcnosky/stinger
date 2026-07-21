"""Temperature helpers.

Spec: to_celsius(f) converts Fahrenheit to Celsius: (f - 32) * 5 / 9.
"""


def to_celsius(fahrenheit: float) -> float:
    return (fahrenheit - 32) * 5 / 9
