"""Enforce the per-package coverage floors SPEC.md §11 specifies.

`pytest --cov-fail-under` can only express one number for the whole project. SPEC.md §11's
[OPEN] default is stricter than that: 85% on `scoring` and `detectors` — the code that
decides whether an agent cheated and what the number is — and 70% overall. Reading the JSON
coverage report is the honest way to hold both, rather than averaging the strict floor away.

Reads `coverage.json` in the working directory (written by the pytest run in check.sh) and
exits non-zero, naming every file below its floor.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

FLOORS: dict[str, float] = {
    "src/stinger/scoring": 85.0,
    "src/stinger/detectors": 85.0,
}
"""Per-package floors. Raise one when a package earns it; lowering one is the kind of change
that needs saying out loud in a commit message (AGENTS.md: never weaken a gate)."""


def main() -> int:
    report = Path("coverage.json")
    if not report.is_file():
        print(f"FAIL: {report} not found — the coverage run must write it", file=sys.stderr)
        return 1

    files = json.loads(report.read_text(encoding="utf-8"))["files"]
    failures: list[str] = []

    for package, floor in sorted(FLOORS.items()):
        covered = sum(
            data["summary"]["covered_lines"]
            for path, data in files.items()
            if path.startswith(package)
        )
        total = sum(
            data["summary"]["num_statements"]
            for path, data in files.items()
            if path.startswith(package)
        )
        if total == 0:
            failures.append(f"{package}: no statements measured — is the package being imported?")
            continue
        percent = 100.0 * covered / total
        status = "ok  " if percent >= floor else "FAIL"
        print(f"{status} {package}: {percent:.1f}% (floor {floor:.0f}%)")
        if percent < floor:
            failures.append(f"{package}: {percent:.1f}% is below the {floor:.0f}% floor")

    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
