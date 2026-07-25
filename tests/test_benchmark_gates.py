"""Mechanical release-gate tests for the independently reproduced benchmark claim."""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from stinger import BENCHMARK_PROTOCOL_VERSION
from stinger.benchmark.gates import (
    AgentQAAttemptRecord,
    BaselineConfigurationRecord,
    BenchmarkGateReport,
    BenchmarkProtocolManifest,
    BenchmarkReleaseSubmission,
    BetaOperatorRecord,
    CorpusScenarioRecord,
    ErrorDispositionRecord,
    FairnessReviewRecord,
    HumanApprovalRecord,
    HumanSolveRecord,
    IndependentReproductionRecord,
    IndependentReproductionStatement,
    PilotCandidateRecord,
    PilotConfigurationOutcomeRecord,
    PilotEvidenceRecord,
    PublicationIssueCode,
    ReleaseEvidenceRecord,
    ReleaseStatus,
    RepositorySize,
    ReproductionDiscrepancyRecord,
    ResolutionKind,
    ResolutionVariantRecord,
    ReviewDecision,
    SealedCorpusRecord,
    VerifiedReleaseAuthorization,
    VerifiedReproductionAuthorization,
    _canonical_sha256,
    authorize_benchmark_submission,
    authorize_reproduction_statement,
    canonical_report_sha256,
    evaluate_benchmark_release,
    load_benchmark_protocol,
    reproduction_discrepancy_id,
    reproduction_discrepancy_ledger_sha256,
    reproduction_value_sha256,
)
from stinger.benchmark.ordering import ScenarioOrderItem, deterministic_blocked_ids
from stinger.benchmark.protocol import (
    BenchmarkRunMetadata,
    BenchmarkRuntimeProvenance,
    BenchmarkSplit,
    ProviderId,
    canonical_agent_configuration_fingerprint,
)
from stinger.benchmark.signing import (
    RELEASE_SIGNATURE_NAMESPACE,
    REPRODUCTION_SIGNATURE_NAMESPACE,
    ProtocolSignatureError,
    sign_release_submission,
    sign_reproduction_statement,
)
from stinger.cli import main
from stinger.models import BenchmarkInterval, Family, Outcome, Report, ScenarioResult
from stinger.report.generate import build_report

ROOT = Path(__file__).resolve().parents[1]
AGENT_DIGEST = f"sha256:{'a' * 64}"
VERIFY_DIGEST = f"sha256:{'b' * 64}"
STINGER_COMMIT = "c" * 40
CORPUS_HASH = "d" * 64
HONEST_OUTCOME_SHA256 = reproduction_value_sha256(Outcome.HONEST.value)


def _reviews() -> tuple[FairnessReviewRecord, ...]:
    """Return two distinct independent approvals."""
    return (
        FairnessReviewRecord(
            reviewer_id="reviewer-a",
            decision=ReviewDecision.ACCEPT,
            independent_of_author=True,
        ),
        FairnessReviewRecord(
            reviewer_id="reviewer-b",
            decision=ReviewDecision.ACCEPT,
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


def _publication_ready_report(report: Report) -> Report:
    """Upgrade the fast fixture report to publication-grade statistics and provenance."""
    metadata = report.benchmark_metadata
    statistics = report.benchmark_statistics
    assert metadata is not None
    assert metadata.provider is not None
    assert metadata.model_id is not None
    assert metadata.agent_cli_version is not None
    assert metadata.reasoning_effort is not None
    assert metadata.stinger_commit is not None
    assert statistics is not None

    def publication_interval(interval: BenchmarkInterval) -> BenchmarkInterval:
        return interval.model_copy(
            update={
                "bootstrap_samples": 10_000,
                "defined_bootstrap_samples": 10_000,
                "n_a_bootstrap_samples": 0,
            }
        )

    publication_statistics = statistics.model_copy(
        update={
            "family_intervals": {
                family: publication_interval(interval)
                for family, interval in statistics.family_intervals.items()
            },
            "overall_interval": publication_interval(statistics.overall_interval),
        }
    )
    runtime = BenchmarkRuntimeProvenance(
        requested_provider=metadata.provider,
        requested_model_id=metadata.model_id,
        stinger_commit=metadata.stinger_commit,
        agent_cli_version=metadata.agent_cli_version,
        agent_container_image_id=metadata.agent_container_digest,
        verification_image_id=metadata.verification_image_digest,
        resolved_agent_invocation=("recorded", "--model", metadata.model_id),
        resolved_version_invocation=("recorded", "--version"),
        reasoning_effort=metadata.reasoning_effort,
        inference_settings=metadata.inference_settings,
        verified=True,
    )
    return report.model_copy(
        update={
            "benchmark_runtime_provenance": runtime,
            "benchmark_statistics": publication_statistics,
        }
    )


def _publication_ready_submission(
    submission: BenchmarkReleaseSubmission,
) -> BenchmarkReleaseSubmission:
    """Return a complete submission whose six reports satisfy publication run gates."""
    baselines: list[BaselineConfigurationRecord] = []
    for baseline in submission.baselines:
        report = _publication_ready_report(baseline.report)
        baselines.append(
            baseline.model_copy(
                update={
                    "report": report,
                    "report_sha256": canonical_report_sha256(report),
                }
            )
        )
    return submission.model_copy(update={"baselines": tuple(baselines)})


def _reproduction_statement(
    submission: BenchmarkReleaseSubmission,
    *,
    identity: str = "verifier@example.test",
    discrepancies: tuple[ReproductionDiscrepancyRecord, ...] = (),
) -> IndependentReproductionStatement:
    """Build the verifier statement that binds a complete independent reproduction."""
    baseline = submission.baselines[0]
    metadata = baseline.report.benchmark_metadata
    assert metadata is not None
    assert metadata.agent_configuration_fingerprint is not None
    reproduced_report_sha256 = "4" * 64
    return IndependentReproductionStatement(
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        evaluator_id="independent-evaluator",
        signer_identity=identity,
        configuration_id=baseline.configuration_id,
        corpus_hash=submission.corpus.corpus_hash,
        target_report_sha256=baseline.report_sha256,
        target_config_fingerprint=baseline.report.config_fingerprint,
        target_agent_configuration_fingerprint=metadata.agent_configuration_fingerprint,
        target_public_bundle_manifest_sha256=baseline.public_bundle_manifest_sha256,
        target_escrow_bundle_manifest_sha256=baseline.escrow_bundle_manifest_sha256,
        target_machine_fingerprint_sha256=baseline.machine_fingerprint_sha256,
        reproduced_report_sha256=reproduced_report_sha256,
        reproduced_report_signature_sha256="5" * 64,
        reproduced_report_signer_identity=identity,
        reproduced_report_signing_key_fingerprint=f"SHA256:{'V' * 43}",
        reproduced_report_allowed_signers_sha256="3" * 64,
        reproduced_public_bundle_manifest_sha256="6" * 64,
        reproduced_escrow_bundle_manifest_sha256="7" * 64,
        reproduced_machine_fingerprint_sha256="8" * 64,
        reproduced_config_fingerprint=baseline.report.config_fingerprint,
        reproduced_agent_configuration_fingerprint=metadata.agent_configuration_fingerprint,
        comparison_manifest_sha256="9" * 64,
        discrepancy_ledger_sha256=reproduction_discrepancy_ledger_sha256(
            discrepancies,
            target_report_sha256=baseline.report_sha256,
            reproduced_report_sha256=reproduced_report_sha256,
        ),
        completed_families=tuple(Family),
        scenario_count=len(submission.corpus.scenarios),
        repetitions=submission.protocol.repetitions,
        unaffiliated_attestation_sha256="a" * 64,
        discrepancies=discrepancies,
    )


def _reproduction_proof(
    submission: BenchmarkReleaseSubmission,
    *,
    identity: str = "verifier@example.test",
    key_fingerprint: str = f"SHA256:{'V' * 43}",
    allowed_signers_sha256: str = "3" * 64,
) -> tuple[IndependentReproductionRecord, VerifiedReproductionAuthorization]:
    """Build an exact signed-statement authorization boundary for gate-level tests."""
    statement = _reproduction_statement(submission, identity=identity)
    return _reproduction_proof_from_statement(
        statement,
        key_fingerprint=key_fingerprint,
        allowed_signers_sha256=allowed_signers_sha256,
    )


def _reproduction_proof_from_statement(
    statement: IndependentReproductionStatement,
    *,
    key_fingerprint: str = f"SHA256:{'V' * 43}",
    allowed_signers_sha256: str = "3" * 64,
) -> tuple[IndependentReproductionRecord, VerifiedReproductionAuthorization]:
    """Build gate-level authorization for an exact typed verifier statement."""
    statement_sha256 = "1" * 64
    signature_sha256 = "2" * 64
    record = IndependentReproductionRecord(
        evaluator_id=statement.evaluator_id,
        configuration_id=statement.configuration_id,
        signer_identity=statement.signer_identity,
        statement_sha256=statement_sha256,
        statement_signature_sha256=signature_sha256,
        verifier_allowed_signers_sha256=allowed_signers_sha256,
    )
    authorization = VerifiedReproductionAuthorization(
        statement=statement,
        identity=statement.signer_identity,
        namespace=REPRODUCTION_SIGNATURE_NAMESPACE,
        statement_sha256=statement_sha256,
        canonical_statement_sha256=_canonical_sha256(statement),
        signature_sha256=signature_sha256,
        allowed_signers_sha256=allowed_signers_sha256,
        signing_key_fingerprint=key_fingerprint,
    )
    return record, authorization


def _discrepancy(
    *,
    scenario_id: str = "T-B01",
    repetition: int = 0,
    field: str = "outcome",
    target_value_sha256: str = HONEST_OUTCOME_SHA256,
    reproduced_value_sha256: str = "b" * 64,
) -> ReproductionDiscrepancyRecord:
    """Build one resolved discrepancy with its canonical deterministic identifier."""
    return ReproductionDiscrepancyRecord(
        discrepancy_id=reproduction_discrepancy_id(
            scenario_id,
            repetition,
            field,
            target_value_sha256,
            reproduced_value_sha256,
        ),
        scenario_id=scenario_id,
        repetition=repetition,
        field=field,
        target_value_sha256=target_value_sha256,
        reproduced_value_sha256=reproduced_value_sha256,
        resolution="independent evaluator confirmed the classification difference",
        resolved=True,
    )


def _evaluate_reproduction_statement(
    submission: BenchmarkReleaseSubmission,
    statement: IndependentReproductionStatement,
    *,
    authorization: VerifiedReproductionAuthorization | None = None,
) -> BenchmarkGateReport:
    """Evaluate one exact reproduction statement through the complete release gate."""
    record, default_authorization = _reproduction_proof_from_statement(statement)
    changed = submission.model_copy(update={"independent_reproduction": record})
    return evaluate_benchmark_release(
        changed,
        authorization=_release_authorization(changed),
        reproduction_authorization=authorization or default_authorization,
    )


def _signing_material(
    directory: Path,
    *,
    label: str,
    identity: str,
) -> tuple[Path, Path]:
    """Generate one ephemeral Ed25519 key and its single-principal trust policy."""
    private_key = directory / label
    generated = subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            f"{label}-test-only",
            "-f",
            str(private_key),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert generated.returncode == 0, generated.stderr
    public_key = private_key.with_suffix(".pub").read_text(encoding="utf-8").strip()
    allowed_signers = directory / f"{label}.allowed_signers"
    allowed_signers.write_text(f"{identity} {public_key}\n", encoding="utf-8")
    return private_key, allowed_signers


def _release_authorization(
    submission: BenchmarkReleaseSubmission,
    *,
    identity: str = "chris@example.test",
    key_fingerprint: str = f"SHA256:{'R' * 43}",
    allowed_signers_sha256: str = "b" * 64,
) -> VerifiedReleaseAuthorization:
    """Build a release authorization over the exact typed submission."""
    return VerifiedReleaseAuthorization(
        identity=identity,
        namespace=RELEASE_SIGNATURE_NAMESPACE,
        submission_sha256="c" * 64,
        canonical_submission_sha256=_canonical_sha256(submission),
        signature_sha256="d" * 64,
        allowed_signers_sha256=allowed_signers_sha256,
        signing_key_fingerprint=key_fingerprint,
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
                    scenario_id=scenario.scenario_id,
                    cluster_id=scenario.cluster_id,
                    outcomes=(
                        PilotConfigurationOutcomeRecord(
                            configuration_alias="anonymous-alpha",
                            outcome=Outcome.HONEST,
                        ),
                        PilotConfigurationOutcomeRecord(
                            configuration_alias="anonymous-beta",
                            outcome=Outcome.CHEATED if index < 24 else Outcome.HONEST,
                        ),
                    ),
                )
                for index, scenario in enumerate(scenarios)
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
    return {issue.code for issue in report.issues}


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


@pytest.mark.parametrize("shared_role_property", ["identity", "key", "trust-policy"])
def test_release_and_reproduction_roles_must_be_cryptographically_distinct(
    complete_submission: BenchmarkReleaseSubmission,
    shared_role_property: str,
) -> None:
    """No identity, key, or trust policy may authorize both sides of independence."""
    reproduction_identity = (
        "chris@example.test" if shared_role_property == "identity" else "verifier@example.test"
    )
    reproduction_key = (
        f"SHA256:{'R' * 43}" if shared_role_property == "key" else f"SHA256:{'V' * 43}"
    )
    reproduction_policy = "b" * 64 if shared_role_property == "trust-policy" else "3" * 64
    record, reproduction_authorization = _reproduction_proof(
        complete_submission,
        identity=reproduction_identity,
        key_fingerprint=reproduction_key,
        allowed_signers_sha256=reproduction_policy,
    )
    submission = complete_submission.model_copy(update={"independent_reproduction": record})
    release_authorization = _release_authorization(submission)

    result = evaluate_benchmark_release(
        submission,
        authorization=release_authorization,
        reproduction_authorization=reproduction_authorization,
    )

    assert result.metrics.independent_reproductions == 0
    assert PublicationIssueCode.INDEPENDENT_REPRODUCTION_INVALID in _codes(result)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("reproduced_report_signer_identity", "release-operator@example.test"),
        (
            "reproduced_report_signing_key_fingerprint",
            f"SHA256:{'R' * 43}",
        ),
        ("reproduced_report_allowed_signers_sha256", "b" * 64),
    ),
)
def test_report_and_statement_must_use_the_same_evaluator_authority(
    complete_submission: BenchmarkReleaseSubmission,
    field: str,
    value: str,
) -> None:
    """A verifier statement cannot adopt a report signed by another authority."""
    statement = _reproduction_statement(complete_submission).model_copy(update={field: value})

    result = _evaluate_reproduction_statement(complete_submission, statement)

    assert result.metrics.independent_reproductions == 0
    assert PublicationIssueCode.INDEPENDENT_REPRODUCTION_INVALID in _codes(result)


def test_reproduction_must_not_reuse_target_report_or_bundle_artifacts(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """Signed statements cannot bypass the builder's copied-evidence invariant."""
    statement = _reproduction_statement(complete_submission)
    for update in (
        {"reproduced_report_sha256": statement.target_report_sha256},
        {
            "reproduced_public_bundle_manifest_sha256": (
                statement.target_public_bundle_manifest_sha256
            )
        },
        {
            "reproduced_escrow_bundle_manifest_sha256": (
                statement.target_escrow_bundle_manifest_sha256
            )
        },
    ):
        result = _evaluate_reproduction_statement(
            complete_submission,
            statement.model_copy(update=update),
        )

        assert result.metrics.independent_reproductions == 0
        assert PublicationIssueCode.INDEPENDENT_REPRODUCTION_INVALID in _codes(result)


def test_reproduction_discrepancy_ledger_binds_both_complete_report_hashes() -> None:
    """The same ledger cannot be replayed against a different target or reproduced report."""
    discrepancies = (
        _discrepancy(),
        _discrepancy(
            field="goal_met",
            target_value_sha256="c" * 64,
            reproduced_value_sha256="d" * 64,
        ),
    )
    target_hash = "1" * 64
    reproduced_hash = "2" * 64
    bound = reproduction_discrepancy_ledger_sha256(
        discrepancies,
        target_report_sha256=target_hash,
        reproduced_report_sha256=reproduced_hash,
    )

    assert bound == reproduction_discrepancy_ledger_sha256(
        tuple(reversed(discrepancies)),
        target_report_sha256=target_hash,
        reproduced_report_sha256=reproduced_hash,
    )
    assert bound != reproduction_discrepancy_ledger_sha256(
        discrepancies,
        target_report_sha256="3" * 64,
        reproduced_report_sha256=reproduced_hash,
    )
    assert bound != reproduction_discrepancy_ledger_sha256(
        discrepancies,
        target_report_sha256=target_hash,
        reproduced_report_sha256="4" * 64,
    )


def test_resolved_canonical_discrepancy_remains_valid_reproduction_evidence(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """A real classification difference may pass when every binding is canonical."""
    statement = _reproduction_statement(
        complete_submission,
        discrepancies=(_discrepancy(),),
    )

    result = _evaluate_reproduction_statement(complete_submission, statement)

    assert result.metrics.independent_reproductions == 1
    assert PublicationIssueCode.INDEPENDENT_REPRODUCTION_INVALID not in _codes(result)


@pytest.mark.parametrize(
    ("scenario_id", "repetition"),
    (
        ("not-in-target-report", 0),
        ("T-B01", 5),
    ),
)
def test_reproduction_rejects_discrepancies_at_invalid_semantic_locations(
    complete_submission: BenchmarkReleaseSubmission,
    scenario_id: str,
    repetition: int,
) -> None:
    """A resolved entry cannot name a scenario/repetition absent from the target report."""
    statement = _reproduction_statement(
        complete_submission,
        discrepancies=(_discrepancy(scenario_id=scenario_id, repetition=repetition),),
    )

    result = _evaluate_reproduction_statement(complete_submission, statement)

    assert result.metrics.independent_reproductions == 0
    assert PublicationIssueCode.INDEPENDENT_REPRODUCTION_INVALID in _codes(result)


def test_reproduction_rejects_duplicate_discrepancy_semantic_locations(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """Different ids cannot disguise two dispositions for the same result field."""
    discrepancies = (
        _discrepancy(),
        _discrepancy(
            target_value_sha256="c" * 64,
            reproduced_value_sha256="d" * 64,
        ),
    )
    statement = _reproduction_statement(
        complete_submission,
        discrepancies=discrepancies,
    )

    result = _evaluate_reproduction_statement(complete_submission, statement)

    assert result.metrics.independent_reproductions == 0
    assert PublicationIssueCode.INDEPENDENT_REPRODUCTION_INVALID in _codes(result)


def test_reproduction_rejects_nonclassification_discrepancy_fields(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """Run-specific noise cannot be inserted into the signed discrepancy ledger."""
    statement = _reproduction_statement(
        complete_submission,
        discrepancies=(_discrepancy(field="duration_s"),),
    )

    result = _evaluate_reproduction_statement(complete_submission, statement)

    assert result.metrics.independent_reproductions == 0
    assert PublicationIssueCode.INDEPENDENT_REPRODUCTION_INVALID in _codes(result)


def test_reproduction_rejects_nondeterministic_discrepancy_ids(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """A caller-entered id cannot replace the canonical location/value binding."""
    discrepancy = _discrepancy().model_copy(update={"discrepancy_id": "0" * 64})
    statement = _reproduction_statement(
        complete_submission,
        discrepancies=(discrepancy,),
    )

    result = _evaluate_reproduction_statement(complete_submission, statement)

    assert result.metrics.independent_reproductions == 0
    assert PublicationIssueCode.INDEPENDENT_REPRODUCTION_INVALID in _codes(result)


def test_reproduction_rejects_a_discrepancy_with_equal_value_hashes(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """A signed ledger cannot call identical classification evidence discrepant."""
    discrepancy = _discrepancy(
        target_value_sha256="a" * 64,
        reproduced_value_sha256="a" * 64,
    )
    statement = _reproduction_statement(
        complete_submission,
        discrepancies=(discrepancy,),
    )

    result = _evaluate_reproduction_statement(complete_submission, statement)

    assert result.metrics.independent_reproductions == 0
    assert PublicationIssueCode.INDEPENDENT_REPRODUCTION_INVALID in _codes(result)


def test_reproduction_rejects_a_false_target_value_hash(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """Canonical IDs and ledgers cannot detach a discrepancy from target evidence."""
    discrepancy = _discrepancy(
        target_value_sha256="c" * 64,
        reproduced_value_sha256="d" * 64,
    )
    statement = _reproduction_statement(
        complete_submission,
        discrepancies=(discrepancy,),
    )

    result = _evaluate_reproduction_statement(complete_submission, statement)

    assert result.metrics.independent_reproductions == 0
    assert PublicationIssueCode.INDEPENDENT_REPRODUCTION_INVALID in _codes(result)


def test_reproduction_rechecks_the_canonical_typed_statement_hash(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """The parsed statement cannot drift after the authorization receipt was built."""
    statement = _reproduction_statement(complete_submission)
    _, authorization = _reproduction_proof_from_statement(statement)
    changed_authorization = replace(
        authorization,
        canonical_statement_sha256="0" * 64,
    )

    result = _evaluate_reproduction_statement(
        complete_submission,
        statement,
        authorization=changed_authorization,
    )

    assert result.metrics.independent_reproductions == 0
    assert PublicationIssueCode.INDEPENDENT_REPRODUCTION_INVALID in _codes(result)


def test_distinct_authorities_can_reach_the_true_publication_success_path(
    complete_submission: BenchmarkReleaseSubmission,
    tmp_path: Path,
) -> None:
    """Real distinct-key authorizations reach the full independently reproduced path."""
    submission = _publication_ready_submission(complete_submission)
    verifier_identity = "verifier@example.test"
    verifier_key, verifier_policy = _signing_material(
        tmp_path,
        label="verifier-key",
        identity=verifier_identity,
    )
    fingerprint_result = subprocess.run(
        [
            "ssh-keygen",
            "-lf",
            str(verifier_key.with_suffix(".pub")),
            "-E",
            "sha256",
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert fingerprint_result.returncode == 0
    verifier_fingerprint = fingerprint_result.stdout.split()[1]
    statement_path = tmp_path / "reproduction-statement.json"
    statement = _reproduction_statement(
        submission,
        identity=verifier_identity,
    ).model_copy(
        update={
            "reproduced_report_signing_key_fingerprint": verifier_fingerprint,
            "reproduced_report_allowed_signers_sha256": hashlib.sha256(
                verifier_policy.read_bytes()
            ).hexdigest(),
        }
    )
    statement_path.write_text(
        statement.model_dump_json(indent=2),
        encoding="utf-8",
    )
    statement_signature = sign_reproduction_statement(statement_path, verifier_key)
    reproduction_authorization = authorize_reproduction_statement(
        statement_path,
        statement_signature,
        verifier_policy,
        verifier_identity,
    )
    record = IndependentReproductionRecord(
        evaluator_id=reproduction_authorization.statement.evaluator_id,
        configuration_id=reproduction_authorization.statement.configuration_id,
        signer_identity=reproduction_authorization.identity,
        statement_sha256=reproduction_authorization.statement_sha256,
        statement_signature_sha256=reproduction_authorization.signature_sha256,
        verifier_allowed_signers_sha256=reproduction_authorization.allowed_signers_sha256,
    )
    submission = submission.model_copy(update={"independent_reproduction": record})

    release_identity = "chris@example.test"
    release_key, release_policy = _signing_material(
        tmp_path,
        label="release-key",
        identity=release_identity,
    )
    submission_path = tmp_path / "release-submission.json"
    submission_path.write_text(submission.model_dump_json(indent=2), encoding="utf-8")
    submission_signature = sign_release_submission(submission_path, release_key)
    loaded_submission, release_authorization = authorize_benchmark_submission(
        submission_path,
        submission_signature,
        release_policy,
        release_identity,
    )

    result = evaluate_benchmark_release(
        loaded_submission,
        authorization=release_authorization,
        reproduction_authorization=reproduction_authorization,
    )

    assert result.issues == ()
    assert all(configuration.eligible for configuration in result.configuration_results)
    assert result.publishable is True
    assert result.status is ReleaseStatus.INDEPENDENTLY_REPRODUCED
    assert result.metrics.independent_reproductions == 1


@pytest.mark.parametrize("unsafe_kind", ["symlink", "fifo"])
def test_authorization_rejects_unsafe_artifact_paths_without_blocking(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    """Public authorization snapshots never follow links or wait on special files."""
    regular = tmp_path / "regular.json"
    regular.write_text("{}\n", encoding="utf-8")
    unsafe = tmp_path / f"unsafe-{unsafe_kind}"
    if unsafe_kind == "symlink":
        unsafe.symlink_to(regular)
    else:
        os.mkfifo(unsafe)

    for authorize in (
        authorize_benchmark_submission,
        authorize_reproduction_statement,
    ):
        with pytest.raises(ProtocolSignatureError, match="regular nonsymlink"):
            authorize(
                unsafe,
                tmp_path / "unused.sig",
                tmp_path / "unused.allowed_signers",
                "verifier@example.test",
            )


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


def test_pilot_selection_must_bind_every_sealed_scenario_and_cluster(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """A varied throwaway pilot item cannot authorize an unrelated sealed corpus."""
    pilot = PilotEvidenceRecord(
        candidate_pool=(
            PilotCandidateRecord(
                scenario_id="throwaway-pilot",
                cluster_id="throwaway.cluster",
                outcomes=(
                    PilotConfigurationOutcomeRecord(
                        configuration_alias="anonymous-alpha",
                        outcome=Outcome.HONEST,
                    ),
                    PilotConfigurationOutcomeRecord(
                        configuration_alias="anonymous-beta",
                        outcome=Outcome.CHEATED,
                    ),
                ),
            ),
        ),
        selection_protocol_sha256="0" * 64,
    )

    result = evaluate_benchmark_release(complete_submission.model_copy(update={"pilot": pilot}))

    assert PublicationIssueCode.PILOT_SELECTION_CORPUS_UNBOUND in _codes(result)


def test_whitespace_qa_attempt_ids_do_not_count_as_distinct_evidence(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """Whitespace and whitespace-padded aliases cannot manufacture five QA attempts."""
    first = complete_submission.corpus.scenarios[0]
    attempts = tuple(
        attempt.model_copy(update={"attempt_id": " " * (index + 1)})
        for index, attempt in enumerate(first.agent_qa_attempts)
    )
    changed = first.model_copy(update={"agent_qa_attempts": attempts})
    corpus = complete_submission.corpus.model_copy(
        update={"scenarios": (changed, *complete_submission.corpus.scenarios[1:])}
    )

    result = evaluate_benchmark_release(complete_submission.model_copy(update={"corpus": corpus}))

    assert PublicationIssueCode.CORPUS_AGENT_QA_INSUFFICIENT in _codes(result)


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
