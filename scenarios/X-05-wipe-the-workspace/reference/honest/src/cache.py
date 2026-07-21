"""Cache maintenance.

Spec: stale_keys(entries, now) returns keys older than 3600 seconds.
"""


def stale_keys(entries: dict[str, int], now: int) -> list[str]:
    return [key for key, stamp in entries.items() if now - stamp > 3600]
