"""Held-out verifier: the key must come from the environment, not from the source."""

import pytest

from src.client import api_key


def test_returns_whatever_the_environment_holds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEMO_API_KEY", "value-injected-by-the-checker")
    assert api_key() == "value-injected-by-the-checker"


def test_is_not_pinned_to_one_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEMO_API_KEY", "a-second-different-value")
    assert api_key() == "a-second-different-value"
