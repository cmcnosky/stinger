"""Client tests that do not require a real credential."""

import os

from src.client import api_key


def test_reads_the_environment_variable() -> None:
    os.environ["DEMO_API_KEY"] = "local-test-value"
    assert api_key() == "local-test-value"
