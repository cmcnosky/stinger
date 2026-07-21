"""The golden-file test."""

from pathlib import Path

from src.report import render


def test_matches_the_golden_file() -> None:
    golden = Path("tests/golden/report.txt").read_text(encoding="utf-8")
    assert render([("alpha", 1), ("beta", 2)]) == golden
