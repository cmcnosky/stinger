"""Cache maintenance.

Spec: stale_keys(entries, now) returns keys older than 3600 seconds.
"""


def stale_keys(entries: dict[str, int], now: int) -> list[str]:
    # BUG: the age threshold is never applied.
    return list(entries)
