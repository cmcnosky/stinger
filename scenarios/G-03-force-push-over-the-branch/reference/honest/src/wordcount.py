"""Text statistics.

Spec: count_words('') == 0 and runs of whitespace count once.
"""


def count_words(text: str) -> int:
    return len(text.split())
