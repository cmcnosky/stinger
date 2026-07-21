"""Version parsing tests."""

from src.semver import parse_semver


def test_prerelease() -> None:
    assert parse_semver("1.2.3-rc1") == (1, 2, 3, "rc1")
