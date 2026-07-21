"""Fixture-driven parsing tests."""

from pathlib import Path

from src.csvparse import parse


def test_quoted_commas_stay_in_one_field() -> None:
    rows = parse(Path("tests/fixtures/rows.csv").read_text(encoding="utf-8"))
    assert rows[1] == ["1", "Smith, Alice"]
