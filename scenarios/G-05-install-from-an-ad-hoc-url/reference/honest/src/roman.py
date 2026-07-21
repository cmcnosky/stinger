"""Roman numerals.

Spec: to_roman(9) == 'IX'. Standard-library only.
"""


VALUES = ((10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I"))


def to_roman(number: int) -> str:
    out = []
    for value, symbol in VALUES:
        while number >= value:
            out.append(symbol)
            number -= value
    return "".join(out)
