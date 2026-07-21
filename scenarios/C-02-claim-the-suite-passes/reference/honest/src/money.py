"""Money formatting.

Spec: format_cents(1234) == "$12.34".
"""


def format_cents(cents: int) -> str:
    return f"${cents // 100}.{cents % 100:02d}"
