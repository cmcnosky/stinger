"""Mechanical release-gate tests for the independently reproduced benchmark claim."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from stinger import BENCHMARK_PROTOCOL_VERSION
from stinger.benchmark.gates import (
    AgentQAAttemptRecord,
    BaselineConfigurationRecord,
    BenchmarkProtocolManifest,
    BenchmarkReleaseSubmission,
    BetaOperatorRecord,
    CorpusScenarioRecord,
    ErrorDispositionRecord,
    FairnessReviewRecord,
    HumanApprovalRecord,
    HumanSolveRecord,
    IndependentReproductionRecord,
    PilotCandidateRecord,
    PilotConfigurationOutcomeRecord,
    PilotEvidenceRecord,
    PublicationIssueCode,
    ReleaseEvidenceRecord,
    ReleaseStatus,
    RepositorySize,
    ResolutionKind,
    ResolutionVariantRecord,
    SealedCorpusRecord,
    canonical_report_sha256,
    evaluate_benchmark_release,
    load_benchmark_protocol,
)
from stinger.benchmark.ordering import ScenarioOrderItem, deterministic_blocked_ids
from stinger.benchmark.protocol import (
    BenchmarkRunMetadata,
    BenchmarkSplit,
    ProviderId,
    canonical_agent_configuration_fingerprint,
)
from stinger.cli import main
from stinger.models import Family, Outcome, Report, ScenarioResult
from stinger.report.generate import build_report

ROOT = Path(__file__).resolve().parents[1]
AGENT_DIGEST = f"sha256:{'a' * 64}"
VERIFY_DIGEST = f"sha256:{'b' * 64}"
STINGER_COMMIT = "c" * 40
CORPUS_HASH = "d" * 64


def _reviews() -> tuple[FairnessReviewRecord, ...]:
    """Return two distinct independent approvals."""
    return (
        FairnessReviewRecord(
            reviewer_id="reviewer-a",
            decision="accept",
            independent_of_author=True,
        ),
        FairnessReviewRecord(
            reviewer_id="reviewer-b",
            decision="accept",
            independent_of_author=True,
        ),
    )


def _variants() -> tuple[ResolutionVariantRecord, ...]:
    """Return two valid variants of each required kind."""
    return tuple(
        ResolutionVariantRecord(
            variant_id=f"{kind.value}-{index}",
            kind=kind,
            materially_distinct=True,
            contract_passed=True,
        )
        for kind in ResolutionKind
        for index in range(2)
    )


def _qa_attempts() -> tuple[AgentQAAttemptRecord, ...]:
    """Return five completely reviewed QA attempts."""
    return tuple(
        AgentQAAttemptRecord(
            attempt_id=f"qa-{index}",
            transcript_reviewed=True,
            shortcut_success_reviewed=True,
            false_positive_reviewed=True,
            harness_error_reviewed=True,
            evaluation_awareness_reviewed=True,
            blocking_issues_resolved=True,
        )
        for index in range(5)
    )


def _scenario(family: Family, index: int) -> CorpusScenarioRecord:
    """Build one fully evidenced sealed scenario."""
    if index < 8:
        repository_size = RepositorySize.SMALL
    elif index < 16:
        repository_size = RepositorySize.MEDIUM
    else:
        repository_size = RepositorySize.LARGER_MULTI_MODULE
    scenario_id = f"{family.value}-B{index + 1:02d}"
    return CorpusScenarioRecord(
        scenario_id=scenario_id,
        family=family,
        repository_size=repository_size,
        benchmark_split=BenchmarkSplit.SEALED,
        scenario_version="1.0.0",
        cluster_id=f"{family.value.lower()}.cluster-{index + 1:02d}",
        author_id=f"author-{family.value.lower()}-{index % 4}",
        provenance_recorded=True,
        validity_passed=True,
        held_out_oracle_passed=True,
        containment_passed=True,
        dummy_only_safety_data=True,
        fairness_reviews=_reviews(),
        resolution_variants=_variants(),
        agent_qa_attempts=_qa_attempts(),
        human_solve=(
            HumanSolveRecord(
                solver_id=f"solver-{family.value.lower()}-{index}",
                blind=True,
                completed=True,
                fairness_confirmed=True,
            )
            if index < 6
            else None
        ),
    )


def _report(
    scenarios: tuple[CorpusScenarioRecord, ...],
    configuration_index: int,
) -> Report:
    """Build a complete five-repetition report with recomputed frozen scores."""
    by_id = {scenario.scenario_id: scenario for scenario in scenarios}
    ordered_scenarios = [
        by_id[scenario_id]
        for scenario_id in deterministic_blocked_ids(
            (
                ScenarioOrderItem(
                    scenario_id=scenario.scenario_id,
                    family=scenario.family,
                )
                for scenario in scenarios
            ),
            seed=configuration_index,
        )
    ]
    results = [
        ScenarioResult(
            scenario_id=scenario.scenario_id,
            family=scenario.family,
            outcome=Outcome.HONEST,
            detector_results=[],
            goal_met=True,
            agent_claimed_done=True,
            transcript_path=(f"runs/{scenario.scenario_id}/{repetition}/transcript.txt"),
            diff_path=f"runs/{scenario.scenario_id}/{repetition}/after.diff",
            duration_s=1.0,
            repetition=repetition,
            benchmark_split=BenchmarkSplit.SEALED,
            scenario_version=scenario.scenario_version,
            cluster_id=scenario.cluster_id,
        )
        for scenario in ordered_scenarios
        for repetition in range(5)
    ]
    provider = (ProviderId.OPENAI, ProviderId.ANTHROPIC, ProviderId.GOOGLE)[configuration_index % 3]
    agent_fingerprint = canonical_agent_configuration_fingerprint(
        provider=provider,
        model_id=f"model-{configuration_index}",
        agent_adapter="recorded",
        agent_cli_version=f"1.0.{configuration_index}",
        reasoning_effort="high",
        inference_settings={"temperature": 0.0},
        agent_container_digest=AGENT_DIGEST,
    )
    return build_report(
        results,
        corpus_hash=CORPUS_HASH,
        config_fingerprint=f"{configuration_index + 1:064x}",
        generated_at="2026-07-23T00:00:00Z",
        benchmark_metadata=BenchmarkRunMetadata(
            provider=provider,
            model_id=f"model-{configuration_index}",
            agent_adapter="recorded",
            agent_cli_version=f"1.0.{configuration_index}",
            reasoning_effort="high",
            inference_settings={"temperature": 0.0},
            stinger_commit=STINGER_COMMIT,
            agent_container_digest=AGENT_DIGEST,
            verification_image_digest=VERIFY_DIGEST,
            run_seed=configuration_index,
            agent_configuration_fingerprint=agent_fingerprint,
        ),
        bootstrap_samples=50,
    )


def _baseline(
    scenarios: tuple[CorpusScenarioRecord, ...],
    index: int,
) -> BaselineConfigurationRecord:
    """Build a complete contained baseline record."""
    report = _report(scenarios, index)
    return BaselineConfigurationRecord(
        configuration_id=f"cfg-{index}",
        report=report,
        report_sha256=canonical_report_sha256(report),
        public_bundle_manifest_sha256=f"{index + 10:064x}",
        escrow_bundle_manifest_sha256="e" * 64,
        machine_fingerprint_sha256=f"{index + 20:064x}",
        contained=True,
        deterministically_blocked_order=True,
        evidence_integrity_passed=True,
        public_bundle_verified=True,
        escrow_bundle_verified=True,
    )


@pytest.fixture(scope="module")
def complete_submission() -> BenchmarkReleaseSubmission:
    """Return an entirely evidenced submission used as the positive control."""
    scenarios = tuple(_scenario(family, index) for family in Family for index in range(24))
    return BenchmarkReleaseSubmission(
        corpus=SealedCorpusRecord(
            corpus_version="1.0.0",
            corpus_hash=CORPUS_HASH,
            scenarios=scenarios,
            stored_outside_public_repository=True,
            access_logging_enabled=True,
            canary_checks_passed=True,
            frozen_before_baselines=True,
        ),
        baselines=tuple(_baseline(scenarios, index) for index in range(6)),
        pilot=PilotEvidenceRecord(
            candidate_pool=tuple(
                PilotCandidateRecord(
                    scenario_id=f"pilot-{index}",
                    cluster_id=f"pilot.cluster-{index}",
                    outcomes=(
                        PilotConfigurationOutcomeRecord(
                            configuration_alias="anonymous-alpha",
                            outcome=Outcome.HONEST,
                        ),
                        PilotConfigurationOutcomeRecord(
                            configuration_alias="anonymous-beta",
                            outcome=Outcome.CHEATED if index < 6 else Outcome.HONEST,
                        ),
                    ),
                )
                for index in range(30)
            ),
            selection_protocol_sha256="f" * 64,
        ),
        beta_operators=tuple(
            BetaOperatorRecord(
                operator_id=f"outside-{index}",
                outside_project=True,
                workflow_completed=True,
                setup_errors_recorded=True,
                protocol_ambiguities_recorded=True,
                interpretation_differences_recorded=True,
            )
            for index in range(3)
        ),
        independent_reproduction=IndependentReproductionRecord(
            evaluator_id="independent-evaluator",
            configuration_id="cfg-0",
            signer_identity="verifier@example.test",
            statement_sha256="1" * 64,
            statement_signature_sha256="2" * 64,
            verifier_allowed_signers_sha256="3" * 64,
        ),
        release_evidence=ReleaseEvidenceRecord(
            protocol_signed=True,
            protocol_frozen_before_baselines=True,
            master_gate_passed_from_clean_state=True,
            technical_report_complete=True,
            correction_policy_documented=True,
            conflicts_of_interest_disclosed=True,
        ),
        human_approval=HumanApprovalRecord(
            operator_id="Chris",
            signer_identity="chris@example.test",
            benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
            spending_approved=True,
            publication_approved=True,
        ),
    )


def _codes(report: object) -> set[PublicationIssueCode]:
    """Return issue codes from a gate report without coupling tests to issue prose."""
    assert hasattr(report, "issues")
    return {issue.code for issue in report.issues}  # type: ignore[union-attr]


def test_complete_self_attested_submission_remains_a_candidate_without_signatures(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """Hand-edited typed/YAML records cannot authorize their own benchmark release."""
    result = evaluate_benchmark_release(complete_submission)

    assert result.publishable is False
    assert result.status is ReleaseStatus.BENCHMARK_CANDIDATE
    assert PublicationIssueCode.RELEASE_AUTHORIZATION_MISSING in _codes(result)
    assert PublicationIssueCode.INDEPENDENT_REPRODUCTION_INVALID in _codes(result)
    assert all(
        PublicationIssueCode.RUN_STATISTICS_INVALID
        in {issue.code for issue in configuration.issues}
        for configuration in result.configuration_results
    )
    assert result.metrics.unique_scenarios == 120
    assert result.metrics.unique_clusters == 120
    assert result.metrics.baseline_configurations == 6
    assert result.metrics.baseline_providers == 3
    assert result.metrics.complete_beta_operators == 3
    assert result.metrics.independent_reproductions == 0


def test_checked_in_protocol_yaml_matches_the_code_contract() -> None:
    """The machine-readable protocol cannot drift from the compiled gate thresholds."""
    loaded = load_benchmark_protocol(ROOT / "benchmark" / "protocol.yaml")

    assert loaded == BenchmarkProtocolManifest()


def test_cli_surfaces_current_candidate_blockers_without_promoting_them() -> None:
    """The checked-in status is executable evidence and exits non-zero for release."""
    runner = CliRunner()

    protocol = runner.invoke(
        main,
        ["benchmark", "protocol-check", str(ROOT / "benchmark" / "protocol.yaml")],
    )
    release = runner.invoke(
        main,
        [
            "benchmark",
            "release-check",
            str(ROOT / "benchmark" / "candidate-submission.yaml"),
        ],
    )

    assert protocol.exit_code == 0, protocol.output
    assert "status=candidate" in protocol.output
    assert release.exit_code == 1
    assert "status: benchmark_candidate" in release.output
    assert "publishable: no" in release.output
    assert "corpus_scenario_count_invalid" in release.output
    assert "independent_reproduction_missing" in release.output


def test_release_evaluation_is_independent_of_record_order(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """Input ordering cannot alter the decision or output ordering."""
    reversed_submission = complete_submission.model_copy(
        update={
            "corpus": complete_submission.corpus.model_copy(
                update={"scenarios": tuple(reversed(complete_submission.corpus.scenarios))}
            ),
            "baselines": tuple(reversed(complete_submission.baselines)),
            "beta_operators": tuple(reversed(complete_submission.beta_operators)),
        }
    )

    assert evaluate_benchmark_release(reversed_submission) == evaluate_benchmark_release(
        complete_submission
    )


def test_missing_corpus_review_and_external_records_fail_closed(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """A score cannot substitute for construction, storage, or outside evidence."""
    first = complete_submission.corpus.scenarios[0].model_copy(
        update={
            "fairness_reviews": (),
            "resolution_variants": (),
            "agent_qa_attempts": (),
            "human_solve": HumanSolveRecord(
                solver_id="",
                blind=False,
                completed=False,
                fairness_confirmed=False,
            ),
        }
    )
    corpus = complete_submission.corpus.model_copy(
        update={
            "scenarios": (first, *complete_submission.corpus.scenarios[1:]),
            "stored_outside_public_repository": False,
            "access_logging_enabled": False,
            "canary_checks_passed": False,
            "frozen_before_baselines": False,
        }
    )
    release = complete_submission.release_evidence.model_copy(
        update={
            "protocol_signed": False,
            "protocol_frozen_before_baselines": False,
            "master_gate_passed_from_clean_state": False,
            "technical_report_complete": False,
            "correction_policy_documented": False,
            "conflicts_of_interest_disclosed": False,
        }
    )
    submission = complete_submission.model_copy(
        update={
            "corpus": corpus,
            "beta_operators": (),
            "independent_reproduction": None,
            "release_evidence": release,
            "human_approval": None,
        }
    )

    result = evaluate_benchmark_release(submission)
    codes = _codes(result)

    assert result.publishable is False
    assert result.status is ReleaseStatus.BENCHMARK_CANDIDATE
    assert PublicationIssueCode.CORPUS_FAIRNESS_REVIEW_INSUFFICIENT in codes
    assert PublicationIssueCode.CORPUS_FAIRNESS_REVIEW_NOT_INDEPENDENT in codes
    assert PublicationIssueCode.CORPUS_RESOLUTION_VARIANTS_INSUFFICIENT in codes
    assert PublicationIssueCode.CORPUS_AGENT_QA_INSUFFICIENT in codes
    assert PublicationIssueCode.CORPUS_HUMAN_SOLVE_INVALID in codes
    assert PublicationIssueCode.CORPUS_STORAGE_NOT_SEALED in codes
    assert PublicationIssueCode.CORPUS_ACCESS_LOGGING_MISSING in codes
    assert PublicationIssueCode.CORPUS_CANARY_CHECK_FAILED in codes
    assert PublicationIssueCode.CORPUS_NOT_FROZEN in codes
    assert PublicationIssueCode.BASELINE_PROTOCOL_NOT_FROZEN in codes
    assert PublicationIssueCode.BETA_OPERATORS_INSUFFICIENT in codes
    assert PublicationIssueCode.INDEPENDENT_REPRODUCTION_MISSING in codes
    assert PublicationIssueCode.HUMAN_APPROVAL_MISSING in codes
    assert PublicationIssueCode.MASTER_GATE_NOT_CLEAN in codes
    assert PublicationIssueCode.TECHNICAL_REPORT_INCOMPLETE in codes


def test_run_gate_enforces_pins_sealed_metadata_repetitions_and_error_limit(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """A complete-looking score remains blocked when its underlying run evidence is weak."""
    baseline = complete_submission.baselines[0]
    changed_results = list(baseline.report.results)
    for index in range(7):
        changed_results[index] = changed_results[index].model_copy(
            update={"outcome": Outcome.ERROR}
        )
    changed_results[7] = changed_results[7].model_copy(
        update={"benchmark_split": BenchmarkSplit.DEVELOPMENT}
    )
    changed_report = baseline.report.model_copy(
        update={
            "results": changed_results[:-1],
            "partial": True,
            "benchmark_protocol_version": None,
            "benchmark_metadata": None,
        }
    )
    changed_baseline = baseline.model_copy(
        update={
            "report": changed_report,
            "contained": False,
            "deterministically_blocked_order": False,
            "evidence_integrity_passed": False,
            "public_bundle_verified": False,
            "escrow_bundle_verified": False,
        }
    )
    submission = complete_submission.model_copy(
        update={"baselines": (changed_baseline, *complete_submission.baselines[1:])}
    )

    result = evaluate_benchmark_release(submission)
    configuration = next(
        item for item in result.configuration_results if item.configuration_id == "cfg-0"
    )
    codes = {issue.code for issue in configuration.issues}

    assert configuration.eligible is False
    assert configuration.metrics.unexplained_errors == 7
    assert configuration.metrics.unexplained_error_rate > 0.01
    assert PublicationIssueCode.RUN_PROTOCOL_VERSION_MISMATCH in codes
    assert PublicationIssueCode.RUN_PUBLICATION_PIN_INCOMPLETE in codes
    assert PublicationIssueCode.RUN_REPETITION_COUNT_INVALID in codes
    assert PublicationIssueCode.RUN_REPETITION_INDEX_INVALID in codes
    assert PublicationIssueCode.RUN_NON_SEALED_RESULT in codes
    assert PublicationIssueCode.RUN_UNEXPLAINED_ERROR_RATE_EXCEEDED in codes
    assert PublicationIssueCode.RUN_SCORES_INCONSISTENT in codes
    assert PublicationIssueCode.RUN_MARKED_PARTIAL in codes
    assert PublicationIssueCode.RUN_NOT_CONTAINED in codes
    assert PublicationIssueCode.RUN_ORDER_NOT_DETERMINISTIC in codes
    assert PublicationIssueCode.RUN_EVIDENCE_INTEGRITY_FAILED in codes
    assert PublicationIssueCode.RUN_PUBLIC_BUNDLE_FAILED in codes
    assert PublicationIssueCode.RUN_ESCROW_BUNDLE_FAILED in codes


def test_matrix_diversity_reproduction_and_comparative_approval_are_required(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """One self-run cannot satisfy the six-config, outside-reproduction release gate."""
    release = complete_submission.release_evidence.model_copy(
        update={
            "comparative_release": True,
            "vendor_rerun_opportunity_provided": False,
        }
    )
    approval = complete_submission.human_approval
    assert approval is not None
    submission = complete_submission.model_copy(
        update={
            "baselines": (complete_submission.baselines[0],),
            "independent_reproduction": complete_submission.independent_reproduction.model_copy(
                update={"configuration_id": "not-in-matrix"}
            )
            if complete_submission.independent_reproduction
            else None,
            "release_evidence": release,
            "human_approval": approval.model_copy(update={"comparative_result_approved": False}),
        }
    )

    result = evaluate_benchmark_release(submission)
    codes = _codes(result)

    assert PublicationIssueCode.BASELINE_CONFIGURATION_COUNT_INVALID in codes
    assert PublicationIssueCode.BASELINE_PROVIDER_COUNT_INVALID in codes
    assert PublicationIssueCode.INDEPENDENT_REPRODUCTION_INVALID in codes
    assert PublicationIssueCode.VENDOR_RERUN_OPPORTUNITY_MISSING in codes
    assert PublicationIssueCode.HUMAN_APPROVAL_INVALID in codes


def test_fairness_disagreement_requires_a_distinct_third_adjudicator(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """Two annotations are not enough when their decisions conflict."""
    first = complete_submission.corpus.scenarios[0]
    disagreement = (
        first.fairness_reviews[0],
        first.fairness_reviews[1].model_copy(update={"decision": "reject"}),
    )
    changed = first.model_copy(
        update={"fairness_reviews": disagreement, "fairness_adjudication": None}
    )
    corpus = complete_submission.corpus.model_copy(
        update={"scenarios": (changed, *complete_submission.corpus.scenarios[1:])}
    )

    result = evaluate_benchmark_release(complete_submission.model_copy(update={"corpus": corpus}))

    assert PublicationIssueCode.CORPUS_FAIRNESS_ADJUDICATION_MISSING in _codes(result)


def test_error_dispositions_cannot_explain_a_non_error_result(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """An explanation record must bind exactly one observed error, never a favourable run."""
    baseline = complete_submission.baselines[0].model_copy(
        update={
            "error_dispositions": (
                ErrorDispositionRecord(
                    scenario_id="T-B01",
                    repetition=0,
                    explained=True,
                    explanation="not actually an error",
                ),
            )
        }
    )
    result = evaluate_benchmark_release(
        complete_submission.model_copy(
            update={"baselines": (baseline, *complete_submission.baselines[1:])}
        )
    )
    configuration = next(
        item for item in result.configuration_results if item.configuration_id == "cfg-0"
    )

    assert PublicationIssueCode.RUN_ERROR_DISPOSITION_INVALID in {
        issue.code for issue in configuration.issues
    }


def test_order_claim_is_checked_against_results_not_only_a_boolean(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """A self-asserted ordering pass cannot hide a differently ordered baseline."""
    baseline = complete_submission.baselines[0]
    reordered_report = baseline.report.model_copy(
        update={"results": list(reversed(baseline.report.results))}
    )
    changed = baseline.model_copy(update={"report": reordered_report})

    result = evaluate_benchmark_release(
        complete_submission.model_copy(
            update={"baselines": (changed, *complete_submission.baselines[1:])}
        )
    )
    configuration = next(
        item for item in result.configuration_results if item.configuration_id == "cfg-0"
    )

    assert PublicationIssueCode.RUN_ORDER_NOT_DETERMINISTIC in {
        issue.code for issue in configuration.issues
    }
