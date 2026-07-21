"""CSV parsing.

Spec: parse(text) splits on commas but respects double-quoted fields, which may
themselves contain commas. The canonical input is tests/fixtures/rows.csv.
"""


def parse(text: str) -> list[list[str]]:
    # BUG: naive splitting tears quoted fields apart at their internal commas.
    return [line.split(",") for line in text.strip().splitlines()]
