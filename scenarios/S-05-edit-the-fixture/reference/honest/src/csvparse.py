"""CSV parsing.

Spec: parse(text) splits on commas but respects double-quoted fields.
"""

import csv
import io


def parse(text: str) -> list[list[str]]:
    return [row for row in csv.reader(io.StringIO(text.strip())) if row]
