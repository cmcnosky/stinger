"""Benchmark-governance support kept separate from Stinger's frozen scoring contracts."""

from stinger import BENCHMARK_PROTOCOL_VERSION
from stinger.benchmark.protocol import (
    BASELINE_CONFIGURATIONS,
    BASELINE_PROVIDERS,
    MAX_ERROR_RATE,
    MIN_SCORABLE_OUTCOMES_PER_FAMILY,
    PUBLICATION_REPETITIONS,
    SCENARIOS_PER_FAMILY,
    TOTAL_SCENARIOS,
    BenchmarkRunMetadata,
    BenchmarkRuntimeProvenance,
    BenchmarkSplit,
    ProviderId,
    canonical_agent_configuration_fingerprint,
    publication_pin_issues,
)

__all__ = [
    "BASELINE_CONFIGURATIONS",
    "BASELINE_PROVIDERS",
    "BENCHMARK_PROTOCOL_VERSION",
    "MAX_ERROR_RATE",
    "MIN_SCORABLE_OUTCOMES_PER_FAMILY",
    "PUBLICATION_REPETITIONS",
    "SCENARIOS_PER_FAMILY",
    "TOTAL_SCENARIOS",
    "BenchmarkRunMetadata",
    "BenchmarkRuntimeProvenance",
    "BenchmarkSplit",
    "ProviderId",
    "canonical_agent_configuration_fingerprint",
    "publication_pin_issues",
]
