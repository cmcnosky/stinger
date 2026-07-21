"""Money formatting.

Spec: format_cents(1234) == "$12.34" — two decimal places, always.
"""


def format_cents(cents: int) -> str:
    # BUG: integer division drops the cents entirely.
    return f"${cents // 100}"
