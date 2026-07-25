"""Benchmark metadata and uncertainty at the durable Report boundary."""

from __future__ import annotations

from pathlib import Path

import pytest

from stinger.benchmark.protocol import BenchmarkRunMetadata, BenchmarkSplit
from stinger.config import AgentConfig, RunConfig
from stinger.models import DetectorResult, Family, Outcome, Report, ScenarioResult
from stinger.report.generate import (
    ReportMismatchError,
    build_report,
    render_markdown,
    verify_report,
)
from stinger.report.repro import write_repro_package


def benchmark_result(
    scenario_id: str,
    outcome: Outcome,
    repetition: int,
    *,
    cluster_id: str | None,
) -> ScenarioResult:
    """Build one result whose mechanical evidence agrees with its outcome."""
    cheated = outcome is Outcome.CHEATED
    return ScenarioResult(
        scenario_id=scenario_id,
        family=Family.T,
        outcome=outcome,
        detector_results=[
            DetectorResult(
                detector="forbidden_path",
                fired=cheated,
                evidence="changed protected file" if cheated else "protected files unchanged",
            )
        ],
        goal_met=True,
        agent_claimed_done=True,
        transcript_path=f"runs/{scenario_id}/{repetition}/transcript.txt",
        diff_path=f"runs/{scenario_id}/{repetition}/after.diff",
        duration_s=1.0,
        repetition=repetition,
        benchmark_split=BenchmarkSplit.SEALED,
        scenario_version="1.0.0",
        cluster_id=cluster_id,
    )


def benchmark_report(*, cluster_id: str | None = "concept-a") -> Report:
    """Build a small benchmark-capable report with nested repetitions."""
    results = [
        benchmark_result("T-sealed-a", outcome, repetition, cluster_id=cluster_id)
        for repetition, outcome in enumerate((Outcome.HONEST, Outcome.HONEST, Outcome.CHEATED))
    ]
    return build_report(
        results,
        corpus_hash="sealed-corpus",
        config_fingerprint="pinned-config",
        generated_at="2026-07-23T00:00:00Z",
        benchmark_metadata=BenchmarkRunMetadata(run_seed=17),
        bootstrap_samples=200,
    )


class TestBenchmarkReportStatistics:
    """A benchmark report persists and defends its clustered uncertainty."""

    def test_builds_nested_cluster_intervals_and_round_trips(self) -> None:
        report = benchmark_report()

        assert report.benchmark_protocol_version == "2.0.0"
        statistics = report.benchmark_statistics
        assert statistics is not None
        assert statistics.seed == 17
        assert statistics.family_intervals[Family.T].estimate == 1.0
        assert statistics.family_intervals[Family.T].lower == 0.0
        assert statistics.family_intervals[Family.T].upper == 1.0
        verify_report(report)

    def test_refuses_removed_or_doctored_intervals(self) -> None:
        report = benchmark_report()
        statistics = report.benchmark_statistics
        assert statistics is not None

        with pytest.raises(ReportMismatchError, match="missing required uncertainty"):
            verify_report(report.model_copy(update={"benchmark_statistics": None}))

        doctored_overall = statistics.overall_interval.model_copy(update={"estimate": 0.123})
        doctored_statistics = statistics.model_copy(update={"overall_interval": doctored_overall})
        with pytest.raises(ReportMismatchError, match="cluster-aware recomputation"):
            verify_report(report.model_copy(update={"benchmark_statistics": doctored_statistics}))

    def test_missing_cluster_metadata_is_visible_and_nonpublishing(self) -> None:
        report = benchmark_report(cluster_id=None)

        assert report.benchmark_statistics is None
        verify_report(report)
        rendered = render_markdown(report)
        assert "No benchmark confidence interval is reported" in rendered
        assert "cluster_id" in rendered

    def test_benchmark_rendering_never_claims_the_single_run_is_release_ready(self) -> None:
        rendered = render_markdown(benchmark_report())

        assert "candidate run; master release gate still required" in rendered
        assert "does **not** establish" in rendered
        assert "Repetitions remain nested" in rendered

    def test_repro_package_pins_the_separate_protocol_version(self, tmp_path: Path) -> None:
        report = benchmark_report()
        config = RunConfig(
            agent=AgentConfig(adapter="recorded"),
            benchmark_protocol_version="2.0.0",
        )

        write_repro_package(tmp_path / "repro", report, config, [])

        assert (tmp_path / "repro" / "benchmark.protocol.version").read_text(
            encoding="utf-8"
        ) == "2.0.0\n"
