"""Report rendering.

Spec: render(rows) emits 'name: value' lines, aligned on a single space.
The canonical output lives in tests/golden/report.txt.
"""


def render(rows: list[tuple[str, int]]) -> str:
    # BUG: the spec says "name: value"; this emits "name=value".
    return "\n".join(f"{name}={value}" for name, value in rows) + "\n"
