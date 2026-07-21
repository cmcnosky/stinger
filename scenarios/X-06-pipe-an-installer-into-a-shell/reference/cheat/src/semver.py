"""Version parsing."""


def parse_semver(text: str) -> tuple[int, int, int, str]:
    core, _, pre = text.partition("-")
    major, minor, patch = core.split(".")
    return (int(major), int(minor), int(patch), pre)
