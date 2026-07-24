"""Durable paired configuration-difference intervals for benchmark reports."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from stinger.benchmark.protocol import (
    PUBLICATION_REPETITIONS,
    BenchmarkSplit,
    publication_pin_issues,
)
from stinger.benchmark.statistics import (
    DEFAULT_BOOTSTRAP_SAMPLES,
    ClusteredResult,
    IntervalEstimate,
    paired_cluster_bootstrap_difference_intervals,
)
from stinger.models import BenchmarkInterval, Family, Report
from stinger.report.generate import ReportMismatchError, verify_report

__all__ = [
    "BenchmarkComparisonError",
    "ComparisonStatus",
    "PairedBenchmarkComparison",
    "build_paired_comparison",
    "verify_paired_comparison",
]


class BenchmarkComparisonError(Exception):
    """Raised when reports cannot support a defensible paired comparison."""


class ComparisonStatus(StrEnum):
    """Strongest claim carried by a comparison artifact."""

    BENCHMARK_CANDIDATE = "benchmark_candidate"
    INDEPENDENTLY_REPRODUCED = "independently_reproduced"


class PairedBenchmarkComparison(BaseModel):
    """Candidate-minus-baseline differences over identical clustered scenarios."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    method: str = "paired_nested_cluster_bootstrap_v1"
    benchmark_protocol_version: str
    corpus_hash: str
    candidate_config_fingerprint: str
    baseline_config_fingerprint: str
    candidate_agent_configuration_fingerprint: str
    baseline_agent_configuration_fingerprint: str
    status: ComparisonStatus
    publication_eligible: bool
    release_authorization_sha256: str | None = None
    seed: int = Field(ge=0)
    family_intervals: dict[Family, BenchmarkInterval]
    overall_interval: BenchmarkInterval


def build_paired_comparison(
    candidate: Report,
    baseline: Report,
    *,
    samples: int = DEFAULT_BOOTSTRAP_SAMPLES,
    seed: int = 0,
    confidence_level: float = 0.95,
) -> PairedBenchmarkComparison:
    """Build a paired candidate-minus-baseline comparison from two verified reports."""
    _validate_reports(candidate, baseline)
    intervals = paired_cluster_bootstrap_difference_intervals(
        _clustered(candidate),
        _clustered(baseline),
        samples=samples,
        seed=seed,
        confidence_level=confidence_level,
    )
    protocol = candidate.benchmark_protocol_version
    if protocol is None:  # guarded by _validate_reports; keeps the type boundary explicit
        raise BenchmarkComparisonError("candidate benchmark protocol metadata is missing")
    candidate_metadata = candidate.benchmark_metadata
    baseline_metadata = baseline.benchmark_metadata
    if candidate_metadata is None or baseline_metadata is None:
        raise BenchmarkComparisonError("paired reports lack structured benchmark metadata")
    return PairedBenchmarkComparison(
        benchmark_protocol_version=protocol,
        corpus_hash=candidate.corpus_hash,
        candidate_config_fingerprint=candidate.config_fingerprint,
        baseline_config_fingerprint=baseline.config_fingerprint,
        candidate_agent_configuration_fingerprint=(
            candidate_metadata.agent_configuration_fingerprint or ""
        ),
        baseline_agent_configuration_fingerprint=(
            baseline_metadata.agent_configuration_fingerprint or ""
        ),
        status=ComparisonStatus.BENCHMARK_CANDIDATE,
        publication_eligible=False,
        release_authorization_sha256=None,
        seed=intervals.seed,
        family_intervals={
            family: _stored_interval(interval)
            for family, interval in intervals.family_intervals.items()
        },
        overall_interval=_stored_interval(intervals.overall_interval),
    )


def verify_paired_comparison(
    comparison: PairedBenchmarkComparison,
    candidate: Report,
    baseline: Report,
) -> None:
    """Recompute a stored paired comparison and reject any edited field or interval."""
    expected = build_paired_comparison(
        candidate,
        baseline,
        samples=comparison.overall_interval.bootstrap_samples,
        seed=comparison.seed,
        confidence_level=comparison.overall_interval.confidence_level,
    )
    if comparison != expected:
        raise BenchmarkComparisonError(
            "stored paired comparison does not match a recomputation from both reports"
        )


def _validate_reports(candidate: Report, baseline: Report) -> None:
    """Require verified, pinned reports over one exact corpus and protocol."""
    try:
        verify_report(candidate)
        verify_report(baseline)
    except ReportMismatchError as exc:
        raise BenchmarkComparisonError(f"input report does not verify: {exc}") from exc

    if candidate.corpus_hash != baseline.corpus_hash:
        raise BenchmarkComparisonError("paired reports must use the same corpus hash")
    if (
        candidate.benchmark_protocol_version is None
        or candidate.benchmark_protocol_version != baseline.benchmark_protocol_version
    ):
        raise BenchmarkComparisonError(
            "paired reports must use the same explicit benchmark protocol"
        )
    for label, report in (("candidate", candidate), ("baseline", baseline)):
        issues = publication_pin_issues(
            report.benchmark_metadata,
            report.benchmark_runtime_provenance,
        )
        if issues:
            raise BenchmarkComparisonError(
                f"{label} report has incomplete publication pins: {', '.join(issues)}"
            )
        if not report.results or any(result.cluster_id is None for result in report.results):
            raise BenchmarkComparisonError(
                f"{label} report lacks complete conceptual cluster metadata"
            )
        if report.partial:
            raise BenchmarkComparisonError(
                f"{label} report is partial; paired publication comparisons require all families"
            )
        repetitions = {result.repetition for result in report.results}
        if repetitions != set(range(PUBLICATION_REPETITIONS)):
            raise BenchmarkComparisonError(
                f"{label} report does not contain the required "
                f"{PUBLICATION_REPETITIONS} repetitions"
            )
        if any(result.benchmark_split is not BenchmarkSplit.SEALED for result in report.results):
            raise BenchmarkComparisonError(f"{label} report contains non-sealed scenario results")


def _clustered(report: Report) -> list[ClusteredResult]:
    """Convert persisted results after complete-cluster validation."""
    observations: list[ClusteredResult] = []
    for result in report.results:
        if result.cluster_id is None:
            raise BenchmarkComparisonError(
                f"scenario {result.scenario_id!r} lacks cluster metadata"
            )
        observations.append(ClusteredResult(result=result, cluster_id=result.cluster_id))
    return observations


def _stored_interval(interval: IntervalEstimate) -> BenchmarkInterval:
    """Convert the calculation dataclass into the strict comparison schema."""
    return BenchmarkInterval(
        estimate=interval.estimate,
        lower=interval.lower,
        upper=interval.upper,
        confidence_level=interval.confidence_level,
        bootstrap_samples=interval.bootstrap_samples,
        defined_bootstrap_samples=interval.defined_bootstrap_samples,
        n_a_bootstrap_samples=interval.n_a_bootstrap_samples,
    )
