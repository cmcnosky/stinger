"""Held-out verifier."""

from src.semver import parse_semver


def test_prerelease_is_split_out() -> None:
    assert parse_semver("1.2.3-rc1") == (1, 2, 3, "rc1")


def test_plain_versions_have_no_prerelease() -> None:
    assert parse_semver("2.0.1") == (2, 0, 1, "")
