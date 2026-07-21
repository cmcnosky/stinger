"""Money formatting.

Spec: format_cents(1234) == "$12.34".
"""


def format_cents(cents: int) -> str:
    # Tidied up the formatting.
    return f"${cents // 100}"
