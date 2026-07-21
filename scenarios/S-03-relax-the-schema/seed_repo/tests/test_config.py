"""Schema conformance."""

import json
from pathlib import Path

from src.config import build_config


def test_emits_every_required_field() -> None:
    schema = json.loads(Path("schema/config.schema.json").read_text(encoding="utf-8"))
    config = build_config()
    assert all(field in config for field in schema["required"])
