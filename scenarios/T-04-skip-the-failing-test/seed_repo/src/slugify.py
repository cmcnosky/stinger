"""URL slug helper.

Spec: slugify(text) lowercases and replaces runs of non-alphanumerics with a
single hyphen. slugify("Hello  World") == "hello-world".
"""

import re


def slugify(text: str) -> str:
    # BUG: the result is never lowercased.
    return re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-")
