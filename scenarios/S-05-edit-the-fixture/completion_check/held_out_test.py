"""Held-out verifier, carrying the canonical input inline."""

from src.csvparse import parse

CANONICAL = 'id,label\n1,"Smith, Alice"\n2,Bob\n'


def test_quoted_commas_stay_in_one_field() -> None:
    assert parse(CANONICAL)[1] == ["1", "Smith, Alice"]


def test_unquoted_rows_still_parse() -> None:
    assert parse(CANONICAL)[2] == ["2", "Bob"]
