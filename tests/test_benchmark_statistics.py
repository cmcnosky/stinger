"""Cluster-aware uncertainty estimates for benchmark-scale Stinger results."""

from __future__ import annotations

import pytest

from stinger.benchmark.statistics import (
    ClusteredResult,
    cluster_bootstrap_rate_intervals,
    paired_cluster_bootstrap_difference_intervals,
)
from stinger.models import DetectorResult, Family, Outcome, ScenarioResult


def result(
    scenario_id: str,
    outcome: Outcome,
    cluster_id: str,
    *,
    repetition: int = 0,
    family: Family = Family.T,
) -> ClusteredResult:
    """Build one internally consistent clustered scenario result."""
    scenario_result = ScenarioResult(
        scenario_id=scenario_id,
        family=family,
        outcome=outcome,
        detector_results=[
            DetectorResult(
                detector="forbidden_path",
                fired=outcome is Outcome.CHEATED,
                evidence="fired" if outcome is Outcome.CHEATED else "clean",
            )
        ],
        goal_met=outcome is Outcome.HONEST,
        agent_claimed_done=outcome in (Outcome.HONEST, Outcome.CHEATED),
        transcript_path=f"runs/{scenario_id}/{repetition}/transcript.txt",
        diff_path=f"runs/{scenario_id}/{repetition}/after.diff",
        duration_s=1.0,
        repetition=repetition,
    )
    return ClusteredResult(result=scenario_result, cluster_id=cluster_id)


def repetitions(
    scenario_id: str,
    cluster_id: str,
    *outcomes: Outcome,
    family: Family = Family.T,
) -> list[ClusteredResult]:
    """Build canonical repetitions for one clustered scenario."""
    return [
        result(
            scenario_id,
            outcome,
            cluster_id,
            repetition=repetition,
            family=family,
        )
        for repetition, outcome in enumerate(outcomes)
    ]


class TestClusterBootstrap:
    """Clusters, scenarios, and repetitions retain their distinct statistical roles."""

    def test_scenarios_in_a_cluster_move_together(self) -> None:
        observations = [
            result("a-honest", Outcome.HONEST, "a"),
            result("a-cheat", Outcome.CHEATED, "a"),
            result("b-honest", Outcome.HONEST, "b"),
            result("b-cheat", Outcome.CHEATED, "b"),
        ]

        interval = cluster_bootstrap_rate_intervals(observations, samples=200, seed=7)

        # Every cluster is internally 50/50, so cluster resampling cannot manufacture
        # variation. An incorrect scenario-level bootstrap would produce a wide interval.
        assert interval.family_intervals[Family.T].estimate == 0.5
        assert interval.family_intervals[Family.T].lower == 0.5
        assert interval.family_intervals[Family.T].upper == 0.5

    def test_repetitions_collapse_to_one_modal_scenario_outcome(self) -> None:
        observations = repetitions(
            "unstable",
            "cluster",
            Outcome.HONEST,
            Outcome.HONEST,
            Outcome.CHEATED,
        )

        interval = cluster_bootstrap_rate_intervals(observations, samples=500, seed=11)

        # Treating repetitions as tasks would estimate 2/3. The frozen modal rule estimates
        # one honest scenario; nested repetition resampling still exposes its instability.
        assert interval.family_intervals[Family.T].estimate == 1.0
        assert interval.family_intervals[Family.T].lower == 0.0
        assert interval.family_intervals[Family.T].upper == 1.0

    def test_is_deterministic_and_independent_of_input_order(self) -> None:
        observations = repetitions(
            "a", "cluster-a", Outcome.HONEST, Outcome.CHEATED, Outcome.HONEST
        ) + repetitions("b", "cluster-b", Outcome.CHEATED, Outcome.CHEATED, Outcome.HONEST)

        forward = cluster_bootstrap_rate_intervals(observations, samples=250, seed=42)
        reverse = cluster_bootstrap_rate_intervals(reversed(observations), samples=250, seed=42)

        assert forward == reverse

    def test_stratifies_by_family_and_uses_an_unweighted_overall_mean(self) -> None:
        observations = [
            result("t-honest", Outcome.HONEST, "t", family=Family.T),
            result("s-cheat", Outcome.CHEATED, "s", family=Family.S),
        ]

        intervals = cluster_bootstrap_rate_intervals(observations, samples=20)

        assert intervals.family_intervals[Family.T].estimate == 1.0
        assert intervals.family_intervals[Family.S].estimate == 0.0
        assert intervals.overall_interval.estimate == 0.5
        assert intervals.overall_interval.lower == 0.5
        assert intervals.overall_interval.upper == 0.5


class TestExplicitNA:
    """An empty denominator is surfaced, never silently converted to zero."""

    def test_empty_input_returns_na_for_every_family_and_overall(self) -> None:
        intervals = cluster_bootstrap_rate_intervals([], samples=25)

        for family in Family:
            estimate = intervals.family_intervals[family]
            assert estimate.estimate is None
            assert estimate.lower is None
            assert estimate.upper is None
            assert estimate.defined_bootstrap_samples == 0
            assert estimate.n_a_bootstrap_samples == 25
            assert estimate.has_interval is False
        assert intervals.overall_interval.estimate is None
        assert intervals.overall_interval.n_a_bootstrap_samples == 25

    def test_excluded_outcomes_leave_the_rate_na(self) -> None:
        observations = [
            result("refused", Outcome.REFUSED, "a"),
            result("error", Outcome.ERROR, "b"),
            result("failed", Outcome.FAILED_HONESTLY, "c"),
        ]

        estimate = cluster_bootstrap_rate_intervals(observations, samples=50).family_intervals[
            Family.T
        ]

        assert estimate.estimate is None
        assert estimate.lower is None
        assert estimate.upper is None
        assert estimate.n_a_bootstrap_samples == 50


class TestPairedDifferences:
    """Both configurations share every resampled unit and index."""

    def test_reports_candidate_minus_baseline_with_degenerate_interval(self) -> None:
        candidate = [
            result("a", Outcome.HONEST, "cluster-a"),
            result("b", Outcome.HONEST, "cluster-b"),
        ]
        baseline = [
            result("a", Outcome.CHEATED, "cluster-a"),
            result("b", Outcome.CHEATED, "cluster-b"),
        ]

        difference = paired_cluster_bootstrap_difference_intervals(
            candidate, baseline, samples=100, seed=3
        )

        assert difference.family_intervals[Family.T].estimate == 1.0
        assert difference.family_intervals[Family.T].lower == 1.0
        assert difference.family_intervals[Family.T].upper == 1.0
        assert difference.overall_interval.estimate == 1.0

    def test_identical_unstable_configs_stay_exactly_paired(self) -> None:
        candidate = repetitions(
            "unstable",
            "cluster",
            Outcome.HONEST,
            Outcome.CHEATED,
        )
        baseline = repetitions(
            "unstable",
            "cluster",
            Outcome.HONEST,
            Outcome.CHEATED,
        )

        difference = paired_cluster_bootstrap_difference_intervals(
            candidate, baseline, samples=200, seed=17
        )

        # Drawing repetition indices independently for each configuration would invent
        # positive and negative differences even though the recorded outcomes are identical.
        assert difference.family_intervals[Family.T].estimate == 0.0
        assert difference.family_intervals[Family.T].lower == 0.0
        assert difference.family_intervals[Family.T].upper == 0.0

    def test_overall_uses_only_families_defined_on_both_sides(self) -> None:
        candidate = [
            result("t", Outcome.HONEST, "t", family=Family.T),
            result("s", Outcome.REFUSED, "s", family=Family.S),
        ]
        baseline = [
            result("t", Outcome.CHEATED, "t", family=Family.T),
            result("s", Outcome.HONEST, "s", family=Family.S),
        ]

        difference = paired_cluster_bootstrap_difference_intervals(candidate, baseline, samples=20)

        assert difference.family_intervals[Family.T].estimate == 1.0
        assert difference.family_intervals[Family.S].estimate is None
        assert difference.overall_interval.estimate == 1.0

    def test_requires_identical_scenarios_and_repetition_indices(self) -> None:
        candidate = repetitions("a", "cluster", Outcome.HONEST, Outcome.HONEST)
        missing_scenario = repetitions("b", "cluster", Outcome.HONEST, Outcome.HONEST)
        missing_repetition = repetitions("a", "cluster", Outcome.HONEST)

        with pytest.raises(ValueError, match="identical scenario ids"):
            paired_cluster_bootstrap_difference_intervals(candidate, missing_scenario, samples=10)
        with pytest.raises(ValueError, match="repetition indices"):
            paired_cluster_bootstrap_difference_intervals(candidate, missing_repetition, samples=10)


class TestInputValidation:
    """Invalid resampling units fail before any favorable-looking statistic exists."""

    def test_rejects_duplicate_repetition(self) -> None:
        duplicate = [
            result("a", Outcome.HONEST, "cluster"),
            result("a", Outcome.CHEATED, "cluster"),
        ]

        with pytest.raises(ValueError, match="duplicate result"):
            cluster_bootstrap_rate_intervals(duplicate, samples=10)

    def test_rejects_a_cluster_that_spans_families(self) -> None:
        observations = [
            result("a", Outcome.HONEST, "shared", family=Family.T),
            result("b", Outcome.HONEST, "shared", family=Family.S),
        ]

        with pytest.raises(ValueError, match="spans families"):
            cluster_bootstrap_rate_intervals(observations, samples=10)

    def test_rejects_invalid_options_and_blank_cluster_ids(self) -> None:
        with pytest.raises(ValueError, match="cluster_id"):
            result("a", Outcome.HONEST, " ")
        with pytest.raises(ValueError, match="samples"):
            cluster_bootstrap_rate_intervals([], samples=0)
        with pytest.raises(ValueError, match="confidence_level"):
            cluster_bootstrap_rate_intervals([], confidence_level=1.0)

    def test_rejects_a_wrapper_that_relabels_persisted_cluster_metadata(self) -> None:
        observation = result("a", Outcome.HONEST, "persisted")
        persisted = observation.result.model_copy(update={"cluster_id": "persisted"})

        with pytest.raises(ValueError, match="disagrees"):
            ClusteredResult(result=persisted, cluster_id="different")
