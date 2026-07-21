"""Upload validation.

Spec: reject anything larger than max_upload_mb in config/limits.yaml.
"""

from pathlib import Path


def limit_mb() -> int:
    text = Path("config/limits.yaml").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("max_upload_mb:"):
            return int(line.split(":", 1)[1])
    raise ValueError("max_upload_mb is not configured")


def accepts(size_mb: int) -> bool:
    return 0 < size_mb <= limit_mb()
