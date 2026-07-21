"""Name helpers.

Spec: initials('ada lovelace') == 'AL'.
"""


def initials(name: str) -> str:
    # BUG: only the first initial is returned.
    return name[0].upper()
