#!/usr/bin/env bash
# Stinger master gate (SPEC.md §11). Green check.sh is the ONLY definition of done.
# Fails on the first problem. Run before every handoff. Do not defeat the no-stub check.
set -euo pipefail
cd "$(dirname "$0")/.."

# Gate the working tree, not whatever happens to be installed. Prepending src/ makes the
# result independent of the install state, which also sidesteps a macOS quirk where .pth
# files in a venv acquire the UF_HIDDEN flag and CPython's site.py then silently skips
# them, leaving an "installed" editable package unimportable.
export PYTHONPATH="$PWD/src${PYTHONPATH:+:$PYTHONPATH}"

echo "==> ruff lint"
ruff check src tests

echo "==> ruff format --check"
ruff format --check src tests

echo "==> mypy (strict)"
mypy --strict src

echo "==> pytest + coverage floor"
# [OPEN default] 85% floor on scoring+detectors, 70% overall. One pytest run feeds both: the
# project-wide floor is enforced here, the stricter per-package floors by coverage_floor.py,
# which reads the JSON report this writes. --cov-fail-under alone cannot express two numbers.
pytest --cov=stinger --cov-report=term-missing --cov-report=json --cov-fail-under=70

echo "==> per-package coverage floors (SPEC.md §11)"
python scripts/coverage_floor.py

echo "==> no-stub check (no NotImplementedError / # BUILD: may remain in shipped src)"
# Scans every text file under src/. __pycache__ is excluded and binaries are skipped: .pyc
# files are compiled from sources this grep already reads, so matching them only duplicates
# a hit that is reported against its real source line. Nothing else is exempt.
if grep -rnE --exclude-dir=__pycache__ --binary-files=without-match "NotImplementedError|# BUILD:" src/ ; then
  echo "FAIL: stubs/BUILD markers remain in src/ — not done (AGENTS.md, SPEC.md §5)"
  exit 1
fi

echo "==> benchmark protocol structure (BENCHMARK.md)"
python -m stinger.cli benchmark protocol-check benchmark/protocol.yaml

echo "==> validity contract over the corpus (SPEC.md §12)"
python -m stinger.cli validate scenarios/

echo "ALL GREEN"
