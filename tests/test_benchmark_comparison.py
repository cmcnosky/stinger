"""Durable paired differences between two complete benchmark configurations."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from stinger.benchmark.comparison import (
    BenchmarkComparisonError,
    build_paired_comparison,
    verify_paired_comparison,
)
from stinger.benchmark.protocol import (
    BenchmarkRunMetadata,
    BenchmarkRuntimeProvenance,
    BenchmarkSplit,
    ProviderId,
    canonical_agent_configuration_fingerprint,
)
from stinger.cli import main
from stinger.models import DetectorResult, Family, Outcome, Report, ScenarioResult
from stinger.report.generate import build_report

DIGEST_A = f"sha256:{'a' * 64}"
DIGEST_B = f"sha256:{'b' * 64}"


def metadata(provider: ProviderId, seed: int) -> BenchmarkRunMetadata:
    """Return a fully pinned test configuration."""
    model_id = f"{provider.value}-model"
    fingerprint = canonical_agent_configuration_fingerprint(
        provider=provider,
        model_id=model_id,
        agent_adapter="recorded",
        agent_cli_version="1.0.0",
        reasoning_effort="high",
        inference_settings={"temperature": 0.0},
        agent_container_digest=DIGEST_A,
    )
    return BenchmarkRunMetadata(
        provider=provider,
        model_id=model_id,
        agent_adapter="recorded",
        agent_cli_version="1.0.0",
        reasoning_effort="high",
        inference_settings={"temperature": 0.0},
        stinger_commit="c" * 40,
        agent_container_digest=DIGEST_A,
        verification_image_digest=DIGEST_B,
        run_seed=seed,
        agent_configuration_fingerprint=fingerprint,
    )


def runtime(provider: ProviderId) -> BenchmarkRuntimeProvenance:
    """Return observed provenance matching a test configuration."""
    model_id = f"{provider.value}-model"
    return BenchmarkRuntimeProvenance(
        requested_provider=provider,
        requested_model_id=model_id,
        stinger_commit="c" * 40,
        agent_cli_version="1.0.0",
        agent_container_image_id=DIGEST_A,
        verification_image_id=DIGEST_B,
        resolved_agent_invocation=("recorded", "--model", model_id, "{prompt}"),
        resolved_version_invocation=("recorded", "--version"),
        reasoning_effort="high",
        inference_settings={"temperature": 0.0},
        verified=True,
    )


def report(outcome: Outcome, provider: ProviderId, fingerprint: str) -> Report:
    """Build one complete five-family, five-repetition sealed report."""
    cheated = outcome is Outcome.CHEATED
    results = [
        ScenarioResult(
            scenario_id=f"{family.value}-sealed",
            family=family,
            outcome=outcome,
            detector_results=[
                DetectorResult(
                    detector="forbidden_path",
                    fired=cheated,
                    evidence="shortcut" if cheated else "clean",
                )
            ],
            goal_met=True,
            agent_claimed_done=True,
            transcript_path=f"runs/{family.value}/{repetition}/transcript.txt",
            diff_path=f"runs/{family.value}/{repetition}/after.diff",
            duration_s=1.0,
            repetition=repetition,
            benchmark_split=BenchmarkSplit.SEALED,
            scenario_version="1.0.0",
            cluster_id=f"{family.value.lower()}.independent",
        )
        for family in Family
        for repetition in range(5)
    ]
    return build_report(
        results,
        corpus_hash="same-sealed-corpus",
        config_fingerprint=fingerprint,
        generated_at="2026-07-23T00:00:00Z",
        benchmark_metadata=metadata(provider, 7),
        benchmark_runtime_provenance=runtime(provider),
        bootstrap_samples=40,
    )


def test_paired_comparison_is_persistable_and_recomputable() -> None:
    candidate = report(Outcome.HONEST, ProviderId.OPENAI, "candidate-config")
    baseline = report(Outcome.CHEATED, ProviderId.ANTHROPIC, "baseline-config")

    comparison = build_paired_comparison(candidate, baseline, samples=100, seed=11)

    assert comparison.overall_interval.estimate == 1.0
    assert comparison.overall_interval.lower == 1.0
    assert comparison.overall_interval.upper == 1.0
    assert comparison.status == "benchmark_candidate"
    assert comparison.publication_eligible is False
    verify_paired_comparison(comparison, candidate, baseline)

    doctored = comparison.model_copy(
        update={
            "overall_interval": comparison.overall_interval.model_copy(update={"estimate": 0.0})
        }
    )
    with pytest.raises(BenchmarkComparisonError, match="does not match"):
        verify_paired_comparison(doctored, candidate, baseline)


def test_comparison_refuses_a_different_corpus_or_partial_report() -> None:
    candidate = report(Outcome.HONEST, ProviderId.OPENAI, "candidate-config")
    baseline = report(Outcome.CHEATED, ProviderId.ANTHROPIC, "baseline-config")
    partial = build_report(
        [result for result in candidate.results if result.family is Family.T],
        corpus_hash=candidate.corpus_hash,
        config_fingerprint=candidate.config_fingerprint,
        generated_at=candidate.generated_at,
        benchmark_metadata=candidate.benchmark_metadata,
        benchmark_runtime_provenance=candidate.benchmark_runtime_provenance,
        bootstrap_samples=20,
    )

    with pytest.raises(BenchmarkComparisonError, match="same corpus"):
        build_paired_comparison(
            candidate,
            baseline.model_copy(update={"corpus_hash": "different"}),
            samples=20,
        )
    with pytest.raises(BenchmarkComparisonError, match="partial"):
        build_paired_comparison(
            partial,
            baseline,
            samples=20,
        )


def test_cli_emits_candidate_minus_baseline_json(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.json"
    baseline = tmp_path / "baseline.json"
    candidate.write_text(
        report(Outcome.HONEST, ProviderId.OPENAI, "candidate-config").model_dump_json(),
        encoding="utf-8",
    )
    baseline.write_text(
        report(Outcome.CHEATED, ProviderId.ANTHROPIC, "baseline-config").model_dump_json(),
        encoding="utf-8",
    )

    outcome = CliRunner().invoke(
        main,
        [
            "benchmark",
            "compare",
            str(candidate),
            str(baseline),
            "--samples",
            "50",
            "--seed",
            "3",
        ],
    )

    assert outcome.exit_code == 0, outcome.output
    assert '"method": "paired_nested_cluster_bootstrap_v1"' in outcome.output
    assert '"estimate": 1.0' in outcome.output
    assert '"status": "benchmark_candidate"' in outcome.output
    assert '"publication_eligible": false' in outcome.output
