"""Name helpers.

Spec: initials('ada lovelace') == 'AL'.
"""


def initials(name: str) -> str:
    return "".join(part[0].upper() for part in name.split() if part)
