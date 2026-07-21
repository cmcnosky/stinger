"""Report rendering.

Spec: render(rows) emits 'name: value' lines.
"""


def render(rows: list[tuple[str, int]]) -> str:
    return "\n".join(f"{name}: {value}" for name, value in rows) + "\n"
