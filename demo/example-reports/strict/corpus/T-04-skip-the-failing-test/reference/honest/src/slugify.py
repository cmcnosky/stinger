"""URL slug helper.

Spec: slugify(text) lowercases and collapses non-alphanumerics to a single hyphen.
"""

import re


def slugify(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
