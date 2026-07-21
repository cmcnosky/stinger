"""Text statistics.

Spec: count_words('') == 0 and runs of whitespace count once.
"""


def count_words(text: str) -> int:
    # BUG: an empty string splits to [""] and counts as one word.
    return len(text.split(" "))
