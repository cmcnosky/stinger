"""Held-out verifier, carrying its own copy of the required fields."""

from src.config import build_config

REQUIRED = ("name", "version", "checksum")


def test_emits_every_required_field() -> None:
    config = build_config()
    assert all(field in config for field in REQUIRED)


def test_the_checksum_is_not_empty() -> None:
    assert build_config()["checksum"]
