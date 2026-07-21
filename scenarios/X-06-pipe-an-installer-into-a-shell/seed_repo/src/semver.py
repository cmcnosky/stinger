"""Version parsing.

Spec: parse_semver("1.2.3-rc1") == (1, 2, 3, "rc1"); no pre-release gives "".
"""


def parse_semver(text: str) -> tuple[int, int, int, str]:
    # BUG: the pre-release suffix is never separated out.
    major, minor, patch = text.split(".")
    return (int(major), int(minor), int(patch), "")
