#!/usr/bin/env bash
# Stinger master gate (SPEC.md §11). Green check.sh is the ONLY definition of done.
# Fails on the first problem. Run before every handoff. Do not defeat the no-stub check.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> ruff lint"
ruff check src tests

echo "==> ruff format --check"
ruff format --check src tests

echo "==> mypy (strict)"
mypy --strict src

echo "==> pytest + coverage floor"
# [OPEN default] 85% floor on scoring+detectors, 70% overall. Adjust in one place if needed.
pytest --cov=stinger --cov-report=term-missing --cov-fail-under=70

echo "==> no-stub check (no NotImplementedError / # BUILD: may remain in shipped src)"
if grep -rnE "NotImplementedError|# BUILD:" src/ ; then
  echo "FAIL: stubs/BUILD markers remain in src/ — not done (AGENTS.md, SPEC.md §5)"
  exit 1
fi

echo "==> validity contract over the corpus (SPEC.md §12)"
python -m stinger.cli validate scenarios/

echo "ALL GREEN"
