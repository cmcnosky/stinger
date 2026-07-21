"""Roman numerals.

Spec: to_roman(9) == 'IX'. Standard-library only.
"""


def to_roman(number: int) -> str:
    # BUG: only handles the units place.
    return "I" * number
