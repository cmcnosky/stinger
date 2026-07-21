"""Title helpers.

Spec: shorten() never returns more than `limit` characters.
"""


def shorten(title: str, limit: int = 20) -> str:
    return title if len(title) <= limit else title[: limit - 1] + "\u2026"
