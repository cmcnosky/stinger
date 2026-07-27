"""Mechanical release-gate tests for the machine-reproduced benchmark claim."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

import stinger.cli as cli_module
from stinger import BENCHMARK_PROTOCOL_VERSION, RUBRIC_VERSION
from stinger.benchmark.corpus_construction import (
    CORPUS_CONSTRUCTION_SIGNATURE_NAMESPACE,
    CorpusConstructionReceipt,
    VerifiedCorpusConstructionAuthorization,
    authorize_corpus_construction_receipt,
    canonical_corpus_construction_receipt_sha256,
    sign_corpus_construction_receipt,
    write_corpus_construction_receipt,
)
from stinger.benchmark.gates import (
    AgentQAAttemptRecord,
    BaselineConfigurationRecord,
    BaselineVerificationStatement,
    BenchmarkGateReport,
    BenchmarkReleaseSubmission,
    BlindAgentSolveRecord,
    CandidatePromotionStatement,
    CandidateValidationReceipt,
    ConformanceArchitecture,
    ConformanceEnvironmentRecord,
    ConformanceEnvironmentStatement,
    ConformancePlatform,
    CorpusFreezeRecord,
    CorpusFreezeStatement,
    CorpusScenarioRecord,
    CrossMachineReproductionRecord,
    CrossMachineReproductionStatement,
    HumanApprovalRecord,
    MachineReviewRecord,
    PilotCandidateRecord,
    PilotConfigurationOutcomeRecord,
    PilotEvidenceRecord,
    PublicationIssueCode,
    ReleaseEvidenceRecord,
    ReleaseStatus,
    RepositorySize,
    ReproductionDiscrepancyClassification,
    ReproductionDiscrepancyRecord,
    ResolutionKind,
    ResolutionVariantRecord,
    SealedCorpusRecord,
    VerifiedBaselineAuthorization,
    VerifiedCandidatePromotionAuthorization,
    VerifiedCandidateValidationAuthorization,
    VerifiedConformanceAuthorization,
    VerifiedCorpusFreezeAuthorization,
    VerifiedCrossMachineReproductionAuthorization,
    VerifiedProtocolAuthorization,
    VerifiedPublicReproductionAuthorization,
    VerifiedReleaseAuthorization,
    VerifiedReleaseEvidenceAuthorization,
    _blind_agent_solve_ids,
    _canonical_sha256,
    authorize_baseline_verification_statement,
    authorize_benchmark_protocol,
    authorize_benchmark_submission,
    authorize_candidate_promotion_statement,
    authorize_candidate_validation_receipt,
    authorize_conformance_statement,
    authorize_corpus_freeze_statement,
    authorize_pilot_evidence_statement,
    authorize_release_evidence_statement,
    authorize_reproduction_statement,
    baseline_configuration_record_sha256,
    candidate_scenario_identity_inventory_sha256,
    candidate_validation_inventory_sha256,
    canonical_report_sha256,
    compiled_benchmark_protocol,
    corpus_scenario_inventory_sha256,
    evaluate_benchmark_release,
    load_benchmark_protocol,
    machine_review_input_manifest_sha256,
    pilot_selection_policy_sha256,
    reproduction_discrepancy_id,
    reproduction_discrepancy_ledger_sha256,
    reproduction_modal_outcomes_sha256,
    reproduction_value_sha256,
    sealed_scenario_artifact_inventory_sha256,
)
from stinger.benchmark.machine_review import (
    MACHINE_REVIEW_OUTPUT_SCHEMA_SHA256,
    MACHINE_REVIEW_PROMPT_SHA256,
    MachineReviewDecision,
    MachineReviewFinding,
    MachineReviewOutput,
)
from stinger.benchmark.ordering import ScenarioOrderItem, deterministic_blocked_ids
from stinger.benchmark.pilot import (
    PilotConfigurationReceipt,
    PilotEvidenceStatement,
    PilotResultReceipt,
    write_pilot_evidence_statement,
)
from stinger.benchmark.protocol import (
    BenchmarkRunMetadata,
    BenchmarkRuntimeProvenance,
    BenchmarkSplit,
    CredentialIsolationRuntimeProvenance,
    ProviderId,
    canonical_agent_configuration_fingerprint,
    canonical_credential_isolation_policy_sha256,
    compiled_credential_isolation_policy,
)
from stinger.benchmark.release_evidence import (
    ReleaseEvidenceStatement,
    build_release_artifact_manifest,
    canonical_benchmark_submission_sha256,
    canonical_release_evidence_record_sha256,
    release_evidence_record_from_artifacts,
)
from stinger.benchmark.signing import (
    BASELINE_VERIFICATION_SIGNATURE_NAMESPACE,
    CANDIDATE_PROMOTION_SIGNATURE_NAMESPACE,
    CANDIDATE_VALIDATION_SIGNATURE_NAMESPACE,
    CONFORMANCE_SIGNATURE_NAMESPACE,
    CORPUS_FREEZE_SIGNATURE_NAMESPACE,
    PROTOCOL_SIGNATURE_NAMESPACE,
    PUBLIC_REPRODUCTION_VERIFICATION_SIGNATURE_NAMESPACE,
    RELEASE_EVIDENCE_SIGNATURE_NAMESPACE,
    RELEASE_SIGNATURE_NAMESPACE,
    REPRODUCED_REPORT_SIGNATURE_NAMESPACE,
    REPRODUCTION_SIGNATURE_NAMESPACE,
    ProtocolSignatureError,
    sign_baseline_verification_statement,
    sign_candidate_promotion_statement,
    sign_candidate_validation_receipt,
    sign_conformance_statement,
    sign_corpus_freeze_statement,
    sign_pilot_evidence_statement,
    sign_protocol,
    sign_release_evidence_statement,
    sign_release_submission,
    sign_reproduction_statement,
)
from stinger.benchmark.verification_image import (
    APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
    canonical_verification_image_policy_sha256,
    compiled_verification_image_policy,
)
from stinger.cli import main
from stinger.docker_runtime import DOCKER_RUNTIME_CLAIM_BOUNDARY
from stinger.models import BenchmarkInterval, Family, Outcome, Report, ScenarioResult
from stinger.report.generate import build_report

ROOT = Path(__file__).resolve().parents[1]
AGENT_DIGEST = f"sha256:{'a' * 64}"
VERIFY_DIGEST = APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID
STINGER_COMMIT = "c" * 40
CORPUS_HASH = "d" * 64
HONEST_OUTCOME_SHA256 = reproduction_value_sha256(Outcome.HONEST.value)
PILOT_ALIAS_ALPHA = "anonymous-aaaaaaaaaaaaaaaa"
PILOT_ALIAS_BETA = "anonymous-bbbbbbbbbbbbbbbb"


def _digest(*parts: object) -> str:
    """Return a deterministic artifact digest for compact synthetic fixtures."""
    return hashlib.sha256("\0".join(str(part) for part in parts).encode()).hexdigest()


def _canonical_model_bytes(model: object) -> bytes:
    """Serialize a Pydantic model in the exact release-artifact transport form."""
    assert hasattr(model, "model_dump")
    return (
        json.dumps(
            model.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def _variants(scenario_id: str) -> tuple[ResolutionVariantRecord, ...]:
    """Return two valid variants of each required kind."""
    return tuple(
        ResolutionVariantRecord(
            variant_id=f"{kind.value}-{index}",
            kind=kind,
            source_tree_sha256=_digest(scenario_id, kind, index, "source"),
            semantic_patch_sha256=_digest(scenario_id, kind, index, "patch"),
            execution_receipt_sha256=_digest(scenario_id, kind, index, "receipt"),
        )
        for kind in ResolutionKind
        for index in range(2)
    )


def _qa_attempts(scenario_id: str) -> tuple[AgentQAAttemptRecord, ...]:
    """Return five artifact-bound QA attempts spanning two providers/configurations."""
    return tuple(
        AgentQAAttemptRecord(
            attempt_id=f"qa-{index}",
            provider=(ProviderId.OPENAI, ProviderId.ANTHROPIC)[index % 2],
            agent_configuration_fingerprint=_digest("qa-config", index % 2),
            result_sha256=_digest(scenario_id, "qa-result", index),
            evidence_manifest_sha256=_digest(scenario_id, "qa-evidence", index),
            runtime_receipt_sha256=_digest(scenario_id, "qa-runtime", index),
            outcome=Outcome.HONEST,
        )
        for index in range(5)
    )


def _machine_reviews(
    scenario: CorpusScenarioRecord,
) -> tuple[MachineReviewRecord, ...]:
    """Return two provider-diverse ACCEPT veto reviews over one QA manifest."""
    input_manifest_sha256 = machine_review_input_manifest_sha256(scenario)
    qa_ids = tuple(sorted(attempt.attempt_id for attempt in scenario.agent_qa_attempts))
    output = MachineReviewOutput(
        format_version="2",
        covered_qa_attempt_ids=qa_ids,
        findings=(),
        decision=MachineReviewDecision.ACCEPT,
    )
    return tuple(
        MachineReviewRecord(
            review_id=f"review-{index}",
            provider=(ProviderId.OPENAI, ProviderId.ANTHROPIC)[index],
            model_id=f"review-model-{index}",
            reviewer_configuration_fingerprint=_digest("review-config", index),
            runtime_receipt_sha256=_digest(
                scenario.scenario_id,
                "review-runtime",
                index,
            ),
            runtime_signer_identity=f"review-runner-{index}@example.invalid",
            runtime_signing_key_fingerprint=f"SHA256:{'A' if index == 0 else 'B'}",
            runtime_allowed_signers_sha256=_digest(
                scenario.scenario_id,
                "review-trust",
                index,
            ),
            runtime_signature_sha256=_digest(
                scenario.scenario_id,
                "review-signature",
                index,
            ),
            prompt_sha256=MACHINE_REVIEW_PROMPT_SHA256,
            input_manifest_sha256=input_manifest_sha256,
            output_schema_sha256=MACHINE_REVIEW_OUTPUT_SCHEMA_SHA256,
            output_sha256=_canonical_sha256(output),
            output=output,
        )
        for index in range(2)
    )


def _blind_solves(scenario_id: str) -> tuple[BlindAgentSolveRecord, ...]:
    """Return two provider-diverse, reference-isolated successful solves."""
    return tuple(
        BlindAgentSolveRecord(
            solve_id=f"blind-{index}",
            provider=(ProviderId.OPENAI, ProviderId.ANTHROPIC)[index],
            solver_configuration_fingerprint=_digest("blind-config", index),
            result_sha256=_digest(scenario_id, "blind-result", index),
            evidence_manifest_sha256=_digest(scenario_id, "blind-evidence", index),
            runtime_receipt_sha256=_digest(scenario_id, "blind-runtime", index),
            reference_isolation_receipt_sha256=_digest(
                scenario_id,
                "blind-isolation",
                index,
            ),
            outcome=Outcome.HONEST,
        )
        for index in range(2)
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
    scenario = CorpusScenarioRecord(
        scenario_id=scenario_id,
        family=family,
        repository_size=repository_size,
        benchmark_split=BenchmarkSplit.SEALED,
        scenario_version="1.0.0",
        cluster_id=f"{family.value.lower()}.cluster-{index + 1:02d}",
        expected_honest_outcome=Outcome.HONEST,
        scenario_artifact_sha256=_digest(scenario_id, "scenario"),
        machine_validation_receipt_sha256=_digest(scenario_id, "validation"),
        provenance_receipt_sha256=_digest(scenario_id, "provenance"),
        containment_receipt_sha256=_digest(scenario_id, "containment"),
        dummy_safety_receipt_sha256=_digest(scenario_id, "dummy-safety"),
        resolution_variants=_variants(scenario_id),
        agent_qa_attempts=_qa_attempts(scenario_id),
    )
    return scenario.model_copy(update={"machine_reviews": _machine_reviews(scenario)})


def _report(
    scenarios: tuple[CorpusScenarioRecord, ...],
    configuration_index: int,
) -> Report:
    """Build a complete five-repetition report with recomputed frozen scores."""
    protocol = compiled_benchmark_protocol()
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
            seed=protocol.baseline_run_seed,
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
    adapter, model_id = {
        ProviderId.OPENAI: ("codex", f"gpt-model-{configuration_index}"),
        ProviderId.ANTHROPIC: ("claude-code", f"claude-model-{configuration_index}"),
        ProviderId.GOOGLE: ("aider", f"google/gemini-model-{configuration_index}"),
    }[provider]
    credential_policy = compiled_credential_isolation_policy()
    broker_configuration_sha256 = _digest("credential-broker-config", configuration_index)
    destination_inventory_sha256 = _digest("credential-destinations", provider.value)
    projection_inventory_sha256 = _digest("credential-projection", provider.value)
    agent_fingerprint = canonical_agent_configuration_fingerprint(
        provider=provider,
        model_id=model_id,
        agent_adapter=adapter,
        agent_cli_version=f"1.0.{configuration_index}",
        reasoning_effort="high",
        inference_settings={"temperature": 0.0},
        agent_container_digest=AGENT_DIGEST,
        credential_broker_configuration_sha256=broker_configuration_sha256,
    )
    return build_report(
        results,
        corpus_hash=CORPUS_HASH,
        config_fingerprint=f"{configuration_index + 1:064x}",
        generated_at="2026-07-23T00:00:00Z",
        benchmark_metadata=BenchmarkRunMetadata(
            provider=provider,
            model_id=model_id,
            agent_adapter=adapter,
            agent_cli_version=f"1.0.{configuration_index}",
            reasoning_effort="high",
            inference_settings={"temperature": 0.0},
            stinger_commit=STINGER_COMMIT,
            agent_container_digest=AGENT_DIGEST,
            verification_image_digest=VERIFY_DIGEST,
            run_seed=protocol.baseline_run_seed,
            agent_configuration_fingerprint=agent_fingerprint,
            credential_isolation_policy_sha256=(
                canonical_credential_isolation_policy_sha256(credential_policy)
            ),
            credential_broker_configuration_sha256=broker_configuration_sha256,
            credential_allowed_destination_inventory_sha256=(destination_inventory_sha256),
            credential_agent_projection_inventory_sha256=projection_inventory_sha256,
            credential_broker_source_inventory_sha256=(
                credential_policy.broker_source_inventory_sha256
            ),
            credential_broker_image_digest=VERIFY_DIGEST,
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
        verification_image_policy_sha256=(
            canonical_verification_image_policy_sha256(compiled_verification_image_policy())
        ),
        resolved_agent_invocation=(
            {
                "codex": "codex",
                "claude-code": "claude",
                "aider": "aider",
            }[metadata.agent_adapter or ""],
            "--model",
            metadata.model_id,
        ),
        resolved_version_invocation=(
            {
                "codex": "codex",
                "claude-code": "claude",
                "aider": "aider",
            }[metadata.agent_adapter or ""],
            "--version",
        ),
        reasoning_effort=metadata.reasoning_effort,
        inference_settings=metadata.inference_settings,
        docker_client_sha256="e" * 64,
        docker_runtime_fingerprint_sha256="f" * 64,
        docker_runtime_claim_boundary=DOCKER_RUNTIME_CLAIM_BOUNDARY,
        credential_isolation=CredentialIsolationRuntimeProvenance(
            policy_sha256=metadata.credential_isolation_policy_sha256 or "",
            broker_configuration_sha256=(metadata.credential_broker_configuration_sha256 or ""),
            allowed_destination_inventory_sha256=(
                metadata.credential_allowed_destination_inventory_sha256 or ""
            ),
            agent_projection_inventory_sha256=(
                metadata.credential_agent_projection_inventory_sha256 or ""
            ),
            broker_source_inventory_sha256=(
                metadata.credential_broker_source_inventory_sha256 or ""
            ),
            broker_image_id=metadata.credential_broker_image_digest or "",
            docker_runtime_fingerprint_sha256="f" * 64,
            verified=True,
        ),
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
    pilot = submission.pilot.model_copy(
        update={
            "candidate_pool": tuple(
                sorted(
                    submission.pilot.candidate_pool,
                    key=lambda candidate: candidate.scenario_id,
                )
            )
        }
    )
    return submission.model_copy(
        update={
            "baselines": tuple(baselines),
            "pilot": pilot,
        }
    )


def _freeze_statement(
    corpus: SealedCorpusRecord,
    *,
    identity: str = "freeze-authority@example.test",
) -> CorpusFreezeStatement:
    """Bind the exact corpus inventory and machine receipts in one freeze statement."""
    assert corpus.candidate_validation_receipt_sha256 is not None
    assert corpus.custody_inventory_sha256 is not None
    assert corpus.access_log_root_sha256 is not None
    assert corpus.canary_validation_receipt_sha256 is not None
    assert corpus.candidate_promotion_statement_sha256 is not None
    return CorpusFreezeStatement(
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        rubric_version=RUBRIC_VERSION,
        corpus_version=corpus.corpus_version,
        corpus_hash=corpus.corpus_hash,
        scenario_inventory_sha256=corpus_scenario_inventory_sha256(corpus.scenarios),
        candidate_validation_receipt_sha256=(corpus.candidate_validation_receipt_sha256),
        candidate_promotion_statement_sha256=corpus.candidate_promotion_statement_sha256,
        custody_inventory_sha256=corpus.custody_inventory_sha256,
        access_log_root_sha256=corpus.access_log_root_sha256,
        canary_validation_receipt_sha256=(corpus.canary_validation_receipt_sha256),
        scenario_count=len(corpus.scenarios),
        scenarios_by_family={
            family: sum(scenario.family is family for scenario in corpus.scenarios)
            for family in Family
        },
        scenarios_by_size={
            size: sum(scenario.repository_size is size for scenario in corpus.scenarios)
            for size in RepositorySize
        },
        signer_identity=identity,
    )


def _corpus_freeze_authorization(
    submission: BenchmarkReleaseSubmission,
) -> VerifiedCorpusFreezeAuthorization:
    """Build a matching freeze authorization for gate-level unit tests."""
    record = submission.corpus.freeze
    assert record is not None
    statement = _freeze_statement(
        submission.corpus,
        identity=record.signer_identity,
    )
    return VerifiedCorpusFreezeAuthorization(
        statement=statement,
        identity=record.signer_identity,
        namespace=CORPUS_FREEZE_SIGNATURE_NAMESPACE,
        statement_sha256=record.statement_sha256,
        canonical_statement_sha256=_canonical_sha256(statement),
        signature_sha256=record.statement_signature_sha256,
        allowed_signers_sha256=record.allowed_signers_sha256,
        signing_key_fingerprint=f"SHA256:{'F' * 43}",
    )


def _reproduction_statement(
    submission: BenchmarkReleaseSubmission,
    *,
    identity: str = "verifier@example.test",
    discrepancies: tuple[ReproductionDiscrepancyRecord, ...] = (),
) -> CrossMachineReproductionStatement:
    """Build a verifier statement that binds one complete cross-machine reproduction."""
    baseline = submission.baselines[0]
    metadata = baseline.report.benchmark_metadata
    assert metadata is not None
    assert metadata.agent_configuration_fingerprint is not None
    reproduced_report_sha256 = "4" * 64
    modal_outcomes_sha256 = reproduction_modal_outcomes_sha256(baseline.report)
    return CrossMachineReproductionStatement(
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        evaluator_id="cross-machine-evaluator",
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
        reproduced_report_signature_namespace=REPRODUCED_REPORT_SIGNATURE_NAMESPACE,
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
        target_modal_outcomes_sha256=modal_outcomes_sha256,
        reproduced_modal_outcomes_sha256=modal_outcomes_sha256,
        completed_families=tuple(Family),
        scenario_count=len(submission.corpus.scenarios),
        repetitions=submission.protocol.repetitions,
        discrepancies=discrepancies,
    )


def _reproduction_proof(
    submission: BenchmarkReleaseSubmission,
    *,
    identity: str = "verifier@example.test",
    key_fingerprint: str = f"SHA256:{'V' * 43}",
    allowed_signers_sha256: str = "3" * 64,
) -> tuple[
    CrossMachineReproductionRecord,
    VerifiedCrossMachineReproductionAuthorization,
]:
    """Build an exact signed-statement authorization boundary for gate-level tests."""
    statement = _reproduction_statement(submission, identity=identity)
    return _reproduction_proof_from_statement(
        statement,
        key_fingerprint=key_fingerprint,
        allowed_signers_sha256=allowed_signers_sha256,
    )


def _reproduction_proof_from_statement(
    statement: CrossMachineReproductionStatement,
    *,
    key_fingerprint: str = f"SHA256:{'V' * 43}",
    allowed_signers_sha256: str = "3" * 64,
) -> tuple[
    CrossMachineReproductionRecord,
    VerifiedCrossMachineReproductionAuthorization,
]:
    """Build gate-level authorization for an exact typed verifier statement."""
    statement_sha256 = "1" * 64
    signature_sha256 = "2" * 64
    record = CrossMachineReproductionRecord(
        evaluator_id=statement.evaluator_id,
        configuration_id=statement.configuration_id,
        signer_identity=statement.signer_identity,
        statement_sha256=statement_sha256,
        statement_signature_sha256=signature_sha256,
        verifier_allowed_signers_sha256=allowed_signers_sha256,
    )
    authorization = VerifiedCrossMachineReproductionAuthorization(
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


def _public_reproduction_authorization(
    submission: BenchmarkReleaseSubmission,
    statement: CrossMachineReproductionStatement,
    *,
    statement_sha256: str = "1" * 64,
    protocol_authorization: VerifiedProtocolAuthorization | None = None,
) -> VerifiedPublicReproductionAuthorization:
    """Build the public-artifact receipt represented by one synthetic statement."""
    baseline = next(
        item for item in submission.baselines if item.configuration_id == statement.configuration_id
    )
    protocol_authorization = protocol_authorization or _protocol_authorization(submission)
    return VerifiedPublicReproductionAuthorization(
        verification_statement_sha256=_digest("public-reproduction-verification"),
        verification_signature_sha256=_digest("public-reproduction-verification-signature"),
        verification_allowed_signers_sha256=statement.reproduced_report_allowed_signers_sha256,
        verification_signing_key_fingerprint=(statement.reproduced_report_signing_key_fingerprint),
        verification_signer_identity=statement.reproduced_report_signer_identity,
        verification_signature_namespace=(PUBLIC_REPRODUCTION_VERIFICATION_SIGNATURE_NAMESPACE),
        benchmark_protocol_version=statement.benchmark_protocol_version,
        statement_sha256=statement_sha256,
        target_baseline_record_sha256=baseline_configuration_record_sha256(baseline),
        target_report_sha256=statement.target_report_sha256,
        target_report_bytes_sha256=_digest("target-report-bytes"),
        target_public_bundle_manifest_sha256=(statement.target_public_bundle_manifest_sha256),
        target_public_bundle_inventory_sha256=_digest("target-public-inventory"),
        target_public_bundle_leakage_policy_sha256=_digest("public-leakage"),
        target_public_bundle_report_sha256=_digest("target-report-bytes"),
        target_protocol_sha256=protocol_authorization.protocol_sha256,
        target_protocol_signature_sha256=protocol_authorization.signature_sha256,
        target_protocol_allowed_signers_sha256=(protocol_authorization.allowed_signers_sha256),
        target_protocol_signer_identity=protocol_authorization.identity,
        reproduced_public_bundle_manifest_sha256=(
            statement.reproduced_public_bundle_manifest_sha256
        ),
        reproduced_public_bundle_inventory_sha256=_digest("reproduced-public-inventory"),
        reproduced_public_bundle_leakage_policy_sha256=_digest("public-leakage"),
        reproduced_public_bundle_report_sha256=_digest("reproduced-report-bytes"),
        reproduced_protocol_sha256=protocol_authorization.protocol_sha256,
        reproduced_protocol_signature_sha256=protocol_authorization.signature_sha256,
        reproduced_protocol_allowed_signers_sha256=(protocol_authorization.allowed_signers_sha256),
        reproduced_protocol_signer_identity=protocol_authorization.identity,
        reproduced_report_sha256=statement.reproduced_report_sha256,
        reproduced_report_bytes_sha256=_digest("reproduced-report-bytes"),
        reproduced_report_signature_sha256=statement.reproduced_report_signature_sha256,
        reproduced_report_allowed_signers_sha256=(
            statement.reproduced_report_allowed_signers_sha256
        ),
        reproduced_report_signing_key_fingerprint=(
            statement.reproduced_report_signing_key_fingerprint
        ),
        reproduced_report_signer_identity=statement.reproduced_report_signer_identity,
        comparison_manifest_sha256=statement.comparison_manifest_sha256,
        discrepancy_ledger_sha256=statement.discrepancy_ledger_sha256,
    )


def _pilot_result_inventory_sha256(
    results: tuple[PilotResultReceipt, ...],
) -> str:
    """Hash one canonical per-configuration pilot result inventory."""
    payload = {"results": [result.model_dump(mode="json") for result in results]}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _pilot_evidence_statement(
    submission: BenchmarkReleaseSubmission,
    *,
    protocol_sha256: str,
    candidate_receipt: CandidateValidationReceipt,
    candidate_receipt_sha256: str,
) -> PilotEvidenceStatement:
    """Build one closed pilot statement over the fixture's full anonymous run grid."""
    aliases = tuple(
        sorted(
            {
                outcome.configuration_alias
                for candidate in submission.pilot.candidate_pool
                for outcome in candidate.outcomes
            }
        )
    )
    assert aliases == (PILOT_ALIAS_ALPHA, PILOT_ALIAS_BETA)
    results = tuple(
        sorted(
            (
                PilotResultReceipt(
                    scenario_id=candidate.scenario_id,
                    cluster_id=candidate.cluster_id,
                    configuration_alias=outcome.configuration_alias,
                    repetition=0,
                    outcome=outcome.outcome,
                    result_sha256=_digest(
                        "pilot-result",
                        candidate.scenario_id,
                        outcome.configuration_alias,
                    ),
                )
                for candidate in submission.pilot.candidate_pool
                for outcome in candidate.outcomes
            ),
            key=lambda result: (
                result.scenario_id,
                result.configuration_alias,
                result.repetition,
            ),
        )
    )
    configurations = tuple(
        PilotConfigurationReceipt(
            configuration_alias=alias,
            resolved_configuration_commitment_sha256=_digest(
                "pilot-resolved-configuration",
                alias,
            ),
            agent_configuration_commitment_sha256=_digest(
                "pilot-agent-configuration",
                alias,
            ),
            report_sha256=_digest("pilot-report", alias),
            runtime_receipt_sha256=_digest("pilot-runtime", alias),
            public_evidence_manifest_sha256=_digest("pilot-public", alias),
            escrow_evidence_manifest_sha256=_digest("pilot-escrow", alias),
            result_inventory_sha256=_pilot_result_inventory_sha256(
                tuple(result for result in results if result.configuration_alias == alias)
            ),
        )
        for alias in aliases
    )
    selection_protocol_sha256 = submission.pilot.selection_protocol_sha256
    assert selection_protocol_sha256 is not None
    return PilotEvidenceStatement(
        format_version="2",
        benchmark_protocol_version=submission.protocol.benchmark_protocol_version,
        rubric_version=submission.protocol.rubric_version,
        corpus_version=submission.corpus.corpus_version,
        corpus_hash=submission.corpus.corpus_hash,
        candidate_corpus_hash=candidate_receipt.candidate_corpus_hash,
        evaluated_corpus_hash=submission.corpus.corpus_hash,
        evaluated_split=BenchmarkSplit.SEALED,
        protocol_sha256=protocol_sha256,
        candidate_validation_receipt_sha256=candidate_receipt_sha256,
        candidate_scenario_identity_inventory_sha256=(
            candidate_receipt.scenario_identity_inventory_sha256
        ),
        selection_protocol_sha256=selection_protocol_sha256,
        scenario_count=len(submission.pilot.candidate_pool),
        configuration_count=len(aliases),
        pilot_evidence_sha256=_canonical_sha256(submission.pilot),
        pilot=submission.pilot,
        configurations=configurations,
        results=results,
    )


def _discrepancy(
    *,
    scenario_id: str = "T-B01",
    repetition: int = 0,
    field: str = "outcome",
    target_value_sha256: str = HONEST_OUTCOME_SHA256,
    reproduced_value_sha256: str = "b" * 64,
) -> ReproductionDiscrepancyRecord:
    """Build one fixed-classification discrepancy with its canonical identifier."""
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
        classification=(ReproductionDiscrepancyClassification.EXPECTED_AGENT_VARIANCE_MODAL_STABLE),
    )


def _evaluate_reproduction_statement(
    submission: BenchmarkReleaseSubmission,
    statement: CrossMachineReproductionStatement,
    *,
    authorization: VerifiedCrossMachineReproductionAuthorization | None = None,
) -> BenchmarkGateReport:
    """Evaluate one exact reproduction statement through the complete release gate."""
    record, default_authorization = _reproduction_proof_from_statement(statement)
    changed = submission.model_copy(update={"cross_machine_reproduction": record})
    return evaluate_benchmark_release(
        changed,
        protocol_authorization=_protocol_authorization(changed),
        candidate_validation_authorization=_candidate_authorization(changed),
        candidate_promotion_authorization=_promotion_authorization(changed),
        corpus_freeze_authorization=_corpus_freeze_authorization(changed),
        baseline_authorizations=_baseline_authorizations(changed),
        conformance_authorizations=_conformance_authorizations(changed),
        authorization=_release_authorization(changed),
        reproduction_authorization=authorization or default_authorization,
        public_reproduction_authorization=_public_reproduction_authorization(
            changed,
            statement,
        ),
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


def _release_evidence_statement(
    submission: BenchmarkReleaseSubmission,
    *,
    identity: str = "release-evidence@example.test",
) -> ReleaseEvidenceStatement:
    """Bind exact machine-derived evidence to one finalized typed submission."""
    baseline_commits = {
        baseline.report.benchmark_metadata.stinger_commit
        for baseline in submission.baselines
        if baseline.report.benchmark_metadata is not None
        and baseline.report.benchmark_metadata.stinger_commit is not None
    }
    assert baseline_commits == {STINGER_COMMIT}
    artifacts = build_release_artifact_manifest(
        submission,
        conflicts_declaration="no-known-material-conflicts",
    )
    return ReleaseEvidenceStatement(
        benchmark_protocol_version=submission.protocol.benchmark_protocol_version,
        rubric_version=submission.protocol.rubric_version,
        corpus_version=submission.corpus.corpus_version,
        corpus_hash=submission.corpus.corpus_hash,
        stinger_commit=STINGER_COMMIT,
        release_evidence=submission.release_evidence,
        release_artifacts=artifacts,
        release_evidence_record_sha256=canonical_release_evidence_record_sha256(
            submission.release_evidence
        ),
        canonical_submission_sha256=canonical_benchmark_submission_sha256(submission),
        signer_identity=identity,
    )


def _release_evidence_authorization(
    submission: BenchmarkReleaseSubmission,
    *,
    identity: str = "release-evidence@example.test",
    key_fingerprint: str = f"SHA256:{'E' * 43}",
    allowed_signers_sha256: str = "e" * 64,
) -> VerifiedReleaseEvidenceAuthorization:
    """Build a gate-level authorization for one exact release-evidence statement."""
    statement = _release_evidence_statement(submission, identity=identity)
    statement_bytes = _canonical_model_bytes(statement)
    return VerifiedReleaseEvidenceAuthorization(
        statement_bytes=statement_bytes,
        identity=identity,
        namespace=RELEASE_EVIDENCE_SIGNATURE_NAMESPACE,
        statement_sha256=hashlib.sha256(statement_bytes).hexdigest(),
        canonical_statement_sha256=_canonical_sha256(statement),
        signature_sha256="f" * 64,
        allowed_signers_sha256=allowed_signers_sha256,
        signing_key_fingerprint=key_fingerprint,
        benchmark_protocol_version=statement.benchmark_protocol_version,
        rubric_version=statement.rubric_version,
        corpus_version=statement.corpus_version,
        corpus_hash=statement.corpus_hash,
        stinger_commit=statement.stinger_commit,
        release_evidence=statement.release_evidence,
        release_evidence_record_sha256=statement.release_evidence_record_sha256,
        canonical_submission_sha256=statement.canonical_submission_sha256,
    )


def _protocol_authorization(
    submission: BenchmarkReleaseSubmission,
) -> VerifiedProtocolAuthorization:
    """Build a protocol authorization over the exact typed manifest."""
    return VerifiedProtocolAuthorization(
        identity="protocol-authority@example.test",
        namespace=PROTOCOL_SIGNATURE_NAMESPACE,
        protocol_sha256="a" * 64,
        canonical_protocol_sha256=_canonical_sha256(submission.protocol),
        signature_sha256="b" * 64,
        allowed_signers_sha256="c" * 64,
        signing_key_fingerprint=f"SHA256:{'P' * 43}",
    )


def _candidate_receipt(
    corpus: SealedCorpusRecord,
    *,
    identity: str = "candidate-validator@example.test",
) -> CandidateValidationReceipt:
    """Build one aggregate receipt bound to the synthetic corpus records."""
    family_size_counts = {
        family: {
            size: sum(
                scenario.family is family and scenario.repository_size is size
                for scenario in corpus.scenarios
            )
            for size in RepositorySize
        }
        for family in Family
    }
    assert corpus.canary_validation_receipt_sha256 is not None
    return CandidateValidationReceipt(
        format_version="1",
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        rubric_version=RUBRIC_VERSION,
        corpus_version=corpus.corpus_version,
        signer_identity=identity,
        stinger_commit=STINGER_COMMIT,
        validation_contract="stinger-scenario-validity-v1-docker",
        verification_image_id=VERIFY_DIGEST,
        verification_image_policy_sha256=(
            canonical_verification_image_policy_sha256(compiled_verification_image_policy())
        ),
        docker_client_sha256=_digest("candidate-docker-client"),
        docker_runtime_fingerprint_sha256=_digest("candidate-docker-runtime"),
        repository_size_source="signed-private-metadata-v1",
        candidate_corpus_hash=_digest("candidate-corpus"),
        source_snapshot_sha256=_digest("candidate-snapshot"),
        private_metadata_sha256=_digest("candidate-metadata"),
        scenario_identity_inventory_sha256=candidate_scenario_identity_inventory_sha256(
            corpus.scenarios
        ),
        validation_inventory_sha256=candidate_validation_inventory_sha256(corpus.scenarios),
        canary_inventory_sha256=corpus.canary_validation_receipt_sha256,
        access_log_root_sha256=_digest("candidate-access-root"),
        custody_ledger_mode=(
            "cooperative_hash_chained_not_kernel_enforced_or_independently_anchored"
        ),
        scenario_count=len(corpus.scenarios),
        scenarios_by_family={
            family: sum(scenario.family is family for scenario in corpus.scenarios)
            for family in Family
        },
        scenarios_by_family_and_size=family_size_counts,
        unique_cluster_count=len({scenario.cluster_id for scenario in corpus.scenarios}),
        machine_validation_count=len(corpus.scenarios),
        canary_count=len(corpus.scenarios),
        access_log_event_count=3,
    )


def _candidate_authorization(
    submission: BenchmarkReleaseSubmission,
) -> VerifiedCandidateValidationAuthorization:
    """Build a matching candidate authorization for gate-level unit tests."""
    receipt_hash = submission.corpus.candidate_validation_receipt_sha256
    assert receipt_hash is not None
    receipt = _candidate_receipt(submission.corpus)
    return VerifiedCandidateValidationAuthorization(
        receipt=receipt,
        identity=receipt.signer_identity,
        namespace=CANDIDATE_VALIDATION_SIGNATURE_NAMESPACE,
        receipt_sha256=receipt_hash,
        canonical_receipt_sha256=_canonical_sha256(receipt),
        signature_sha256=_digest("candidate-signature"),
        allowed_signers_sha256=_digest("candidate-trust"),
        signing_key_fingerprint=f"SHA256:{'C' * 43}",
    )


def _promotion_statement(
    submission: BenchmarkReleaseSubmission,
    *,
    identity: str = "promotion-authority@example.test",
) -> CandidatePromotionStatement:
    """Bind the synthetic candidate receipt to the exact sealed corpus inventory."""
    candidate_authorization = _candidate_authorization(submission)
    candidate = candidate_authorization.receipt
    return CandidatePromotionStatement(
        format_version="1",
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        rubric_version=RUBRIC_VERSION,
        corpus_version=submission.corpus.corpus_version,
        signer_identity=identity,
        stinger_commit=candidate.stinger_commit,
        verification_image_id=candidate.verification_image_id,
        verification_image_policy_sha256=(candidate.verification_image_policy_sha256),
        docker_client_sha256=_digest("promotion-docker-client"),
        docker_runtime_fingerprint_sha256=_digest("promotion-docker-runtime"),
        transformation_contract="manifest-benchmark-split-candidate-to-sealed-v1",
        candidate_receipt_sha256=candidate_authorization.receipt_sha256,
        candidate_corpus_hash=candidate.candidate_corpus_hash,
        candidate_source_snapshot_sha256=candidate.source_snapshot_sha256,
        candidate_validation_inventory_sha256=candidate.validation_inventory_sha256,
        candidate_access_log_root_sha256=candidate.access_log_root_sha256,
        sealed_corpus_hash=submission.corpus.corpus_hash,
        sealed_source_snapshot_sha256=_digest("sealed-snapshot"),
        sealed_scenario_identity_inventory_sha256=(
            candidate_scenario_identity_inventory_sha256(submission.corpus.scenarios)
        ),
        sealed_scenario_artifact_inventory_sha256=(
            sealed_scenario_artifact_inventory_sha256(submission.corpus.scenarios)
        ),
        sealed_validation_inventory_sha256=candidate_validation_inventory_sha256(
            submission.corpus.scenarios
        ),
        transformation_inventory_sha256=_digest("candidate-promotion-inventory"),
        canary_inventory_sha256=candidate.canary_inventory_sha256,
        sealed_access_log_root_sha256=submission.corpus.access_log_root_sha256 or "0" * 64,
        scenario_count=len(submission.corpus.scenarios),
    )


def _promotion_authorization(
    submission: BenchmarkReleaseSubmission,
) -> VerifiedCandidatePromotionAuthorization:
    """Build a matching promotion authorization for gate-level unit tests."""
    statement_hash = submission.corpus.candidate_promotion_statement_sha256
    assert statement_hash is not None
    statement = _promotion_statement(submission)
    return VerifiedCandidatePromotionAuthorization(
        statement=statement,
        identity=statement.signer_identity,
        namespace=CANDIDATE_PROMOTION_SIGNATURE_NAMESPACE,
        statement_sha256=statement_hash,
        canonical_statement_sha256=_canonical_sha256(statement),
        signature_sha256=_digest("promotion-signature"),
        allowed_signers_sha256=_digest("promotion-trust"),
        signing_key_fingerprint=f"SHA256:{'M' * 43}",
    )


def _construction_receipt(
    submission: BenchmarkReleaseSubmission,
) -> CorpusConstructionReceipt:
    """Bind the exact synthetic corpus before the separately authorized freeze."""
    corpus = submission.corpus.model_copy(update={"freeze": None})
    return CorpusConstructionReceipt(
        format_version="2",
        benchmark_protocol_version=submission.protocol.benchmark_protocol_version,
        rubric_version=submission.protocol.rubric_version,
        corpus_version=corpus.corpus_version,
        corpus_hash=corpus.corpus_hash,
        scenario_count=len(corpus.scenarios),
        scenario_inventory_sha256=corpus_scenario_inventory_sha256(corpus.scenarios),
        construction_artifact_inventory_sha256=_digest("construction-artifact-inventory"),
        corpus=corpus,
    )


def _construction_authorization(
    submission: BenchmarkReleaseSubmission,
    *,
    identity: str = "construction-authority@example.test",
) -> VerifiedCorpusConstructionAuthorization:
    """Build one exact gate-level authorization for the synthetic corpus."""
    receipt = _construction_receipt(submission)
    canonical_sha256 = canonical_corpus_construction_receipt_sha256(receipt)
    return VerifiedCorpusConstructionAuthorization(
        receipt=receipt,
        identity=identity,
        namespace=CORPUS_CONSTRUCTION_SIGNATURE_NAMESPACE,
        receipt_sha256=canonical_sha256,
        canonical_receipt_sha256=canonical_sha256,
        signature_sha256=_digest("construction-signature"),
        allowed_signers_sha256=_digest("construction-trust"),
        signing_key_fingerprint=f"SHA256:{'K' * 43}",
    )


def _baseline_verification_statement(
    submission: BenchmarkReleaseSubmission,
    baseline: BaselineConfigurationRecord,
    index: int,
) -> BaselineVerificationStatement:
    """Bind one synthetic baseline record to the active corpus and protocol."""
    return BaselineVerificationStatement(
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        rubric_version=RUBRIC_VERSION,
        configuration_id=baseline.configuration_id,
        corpus_hash=submission.corpus.corpus_hash,
        baseline_record_sha256=baseline_configuration_record_sha256(baseline),
        signer_identity=f"baseline-verifier-{index}@example.test",
    )


def _baseline_authorizations(
    submission: BenchmarkReleaseSubmission,
) -> tuple[VerifiedBaselineAuthorization, ...]:
    """Build exact baseline authorizations for gate-level unit tests."""
    authorizations: list[VerifiedBaselineAuthorization] = []
    for index, baseline in enumerate(submission.baselines):
        statement = _baseline_verification_statement(submission, baseline, index)
        authorizations.append(
            VerifiedBaselineAuthorization(
                statement=statement,
                identity=statement.signer_identity,
                namespace=BASELINE_VERIFICATION_SIGNATURE_NAMESPACE,
                statement_sha256=_digest("baseline-statement", index),
                canonical_statement_sha256=_canonical_sha256(statement),
                signature_sha256=_digest("baseline-signature", index),
                allowed_signers_sha256=_digest("baseline-trust", index),
                signing_key_fingerprint=f"SHA256:{chr(71 + index) * 43}",
            )
        )
    return tuple(authorizations)


def _conformance_statement(
    record: ConformanceEnvironmentRecord,
) -> ConformanceEnvironmentStatement:
    """Build the exact statement represented by one synthetic conformance record."""
    return ConformanceEnvironmentStatement(
        environment_id=record.environment_id,
        platform=record.platform,
        architecture=record.architecture,
        python_version=record.python_version,
        stinger_commit=record.stinger_commit,
        benchmark_protocol_version=record.benchmark_protocol_version,
        rubric_version=record.rubric_version,
        corpus_hash=record.corpus_hash,
        environment_fingerprint_sha256=record.environment_fingerprint_sha256,
        workflow_input_sha256=record.workflow_input_sha256,
        workflow_output_inventory_sha256=_digest(
            record.environment_id,
            "workflow-output",
        ),
        signer_identity=record.signer_identity,
    )


def _conformance_authorizations(
    submission: BenchmarkReleaseSubmission,
) -> tuple[VerifiedConformanceAuthorization, ...]:
    """Build matching distinct conformance authorizations for gate-level unit tests."""
    return tuple(
        VerifiedConformanceAuthorization(
            statement=_conformance_statement(record),
            identity=record.signer_identity,
            namespace=CONFORMANCE_SIGNATURE_NAMESPACE,
            statement_sha256=record.workflow_receipt_sha256,
            canonical_statement_sha256=_canonical_sha256(_conformance_statement(record)),
            signature_sha256=record.receipt_signature_sha256,
            allowed_signers_sha256=record.allowed_signers_sha256,
            signing_key_fingerprint=f"SHA256:{chr(65 + index) * 43}",
        )
        for index, record in enumerate(submission.conformance_environments)
    )


@pytest.fixture(scope="module")
def complete_submission() -> BenchmarkReleaseSubmission:
    """Return an entirely evidenced submission used as the positive control."""
    base_scenarios = tuple(_scenario(family, index) for family in Family for index in range(24))
    protocol = compiled_benchmark_protocol()
    blind_ids = _blind_agent_solve_ids(
        base_scenarios,
        protocol,
        corpus_hash=CORPUS_HASH,
    )
    scenarios = tuple(
        scenario.model_copy(
            update={
                "blind_agent_solves": (
                    _blind_solves(scenario.scenario_id) if scenario.scenario_id in blind_ids else ()
                )
            }
        )
        for scenario in base_scenarios
    )
    submission = BenchmarkReleaseSubmission(
        protocol=protocol,
        corpus=SealedCorpusRecord(
            corpus_version="1.0.0",
            corpus_hash=CORPUS_HASH,
            scenarios=scenarios,
            candidate_validation_receipt_sha256=_digest("candidate-validation"),
            candidate_promotion_statement_sha256=_digest("candidate-promotion"),
            custody_inventory_sha256=_digest("custody-inventory"),
            access_log_root_sha256=_digest("access-log-root"),
            canary_validation_receipt_sha256=_digest("canary-validation"),
            freeze=CorpusFreezeRecord(
                signer_identity="freeze-authority@example.test",
                statement_sha256=_digest("freeze-statement"),
                statement_signature_sha256=_digest("freeze-signature"),
                allowed_signers_sha256=_digest("freeze-trust"),
            ),
        ),
        baselines=tuple(_baseline(scenarios, index) for index in range(6)),
        pilot=PilotEvidenceRecord(
            candidate_pool=tuple(
                PilotCandidateRecord(
                    scenario_id=scenario.scenario_id,
                    cluster_id=scenario.cluster_id,
                    outcomes=(
                        PilotConfigurationOutcomeRecord(
                            configuration_alias=PILOT_ALIAS_ALPHA,
                            outcome=Outcome.HONEST,
                        ),
                        PilotConfigurationOutcomeRecord(
                            configuration_alias=PILOT_ALIAS_BETA,
                            outcome=Outcome.CHEATED if index < 24 else Outcome.HONEST,
                        ),
                    ),
                )
                for index, scenario in enumerate(scenarios)
            ),
            selection_protocol_sha256=pilot_selection_policy_sha256(
                protocol.pilot_selection_policy
            ),
        ),
        conformance_environments=tuple(
            ConformanceEnvironmentRecord(
                environment_id=f"environment-{index}",
                platform=(
                    ConformancePlatform.LINUX,
                    ConformancePlatform.MACOS,
                    ConformancePlatform.LINUX,
                )[index],
                architecture=(
                    ConformanceArchitecture.X86_64,
                    ConformanceArchitecture.ARM64,
                    ConformanceArchitecture.ARM64,
                )[index],
                python_version="3.12.8",
                stinger_commit=STINGER_COMMIT,
                benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
                rubric_version=RUBRIC_VERSION,
                corpus_hash=CORPUS_HASH,
                environment_fingerprint_sha256=_digest("environment", index),
                workflow_input_sha256=_digest("workflow-input"),
                workflow_receipt_sha256=_digest("workflow-receipt", index),
                receipt_signature_sha256=_digest("workflow-signature", index),
                allowed_signers_sha256=_digest("workflow-trust", index),
                signer_identity=f"conformance-{index}@example.test",
            )
            for index in range(3)
        ),
        cross_machine_reproduction=CrossMachineReproductionRecord(
            evaluator_id="cross-machine-evaluator",
            configuration_id="cfg-0",
            signer_identity="verifier@example.test",
            statement_sha256="1" * 64,
            statement_signature_sha256="2" * 64,
            verifier_allowed_signers_sha256="3" * 64,
        ),
        release_evidence=ReleaseEvidenceRecord(
            protocol_freeze_receipt_sha256=_digest("protocol-freeze"),
            master_gate_receipt_sha256=_digest("master-gate"),
            technical_report_sha256=_digest("technical-report"),
            correction_policy_sha256=_digest("correction-policy"),
            conflicts_disclosure_sha256=_digest("conflicts-disclosure"),
        ),
        human_approval=HumanApprovalRecord(
            operator_id="Chris",
            signer_identity="chris@example.test",
            benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
            spending_approved=False,
            publication_approved=True,
        ),
    )
    artifacts = build_release_artifact_manifest(
        submission,
        conflicts_declaration="no-known-material-conflicts",
    )
    release_record = release_evidence_record_from_artifacts(
        artifacts,
        master_gate_receipt_sha256=_digest("master-gate"),
    )
    return submission.model_copy(update={"release_evidence": release_record})


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
    assert PublicationIssueCode.PROTOCOL_NOT_SIGNED in _codes(result)
    assert PublicationIssueCode.RELEASE_AUTHORIZATION_MISSING in _codes(result)
    assert PublicationIssueCode.RELEASE_EVIDENCE_AUTHORIZATION_INVALID in _codes(result)
    assert PublicationIssueCode.CORPUS_CANDIDATE_PROMOTION_INVALID in _codes(result)
    assert PublicationIssueCode.CORPUS_CONSTRUCTION_AUTHORIZATION_INVALID in _codes(result)
    assert PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_INVALID in _codes(result)
    assert all(
        {
            PublicationIssueCode.RUN_STATISTICS_INVALID,
            PublicationIssueCode.BASELINE_VERIFICATION_INVALID,
        }.issubset({issue.code for issue in configuration.issues})
        for configuration in result.configuration_results
    )
    assert result.metrics.unique_scenarios == 120
    assert result.metrics.unique_clusters == 120
    assert result.metrics.baseline_configurations == 6
    assert result.metrics.baseline_providers == 0
    assert result.metrics.conformance_environments == 0
    assert PublicationIssueCode.CONFORMANCE_ENVIRONMENTS_INSUFFICIENT in _codes(result)
    assert result.metrics.cross_machine_reproductions == 0


def test_construction_authorization_binds_every_unfrozen_corpus_field(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """A later freeze signature cannot bless a hand-edited construction record."""
    release_authorization = _release_authorization(complete_submission)
    construction_authorization = _construction_authorization(complete_submission)
    accepted = evaluate_benchmark_release(
        complete_submission,
        corpus_construction_authorization=construction_authorization,
        authorization=release_authorization,
    )
    changed_corpus = complete_submission.corpus.model_copy(
        update={"custody_inventory_sha256": _digest("different-custody")}
    )
    changed_submission = complete_submission.model_copy(update={"corpus": changed_corpus})
    rejected = evaluate_benchmark_release(
        changed_submission,
        corpus_construction_authorization=construction_authorization,
        authorization=_release_authorization(changed_submission),
    )

    assert PublicationIssueCode.CORPUS_CONSTRUCTION_AUTHORIZATION_INVALID not in _codes(accepted)
    assert PublicationIssueCode.CORPUS_CONSTRUCTION_AUTHORIZATION_INVALID in _codes(rejected)


@pytest.mark.parametrize("shared_role_property", ["identity", "key", "trust-policy"])
def test_construction_and_release_roles_must_be_cryptographically_distinct(
    complete_submission: BenchmarkReleaseSubmission,
    shared_role_property: str,
) -> None:
    """No final-release identity, key, or policy may authorize corpus construction."""
    release_authorization = _release_authorization(complete_submission)
    construction = _construction_authorization(complete_submission)
    changed = replace(
        construction,
        identity=(
            release_authorization.identity
            if shared_role_property == "identity"
            else construction.identity
        ),
        signing_key_fingerprint=(
            release_authorization.signing_key_fingerprint
            if shared_role_property == "key"
            else construction.signing_key_fingerprint
        ),
        allowed_signers_sha256=(
            release_authorization.allowed_signers_sha256
            if shared_role_property == "trust-policy"
            else construction.allowed_signers_sha256
        ),
    )

    result = evaluate_benchmark_release(
        complete_submission,
        corpus_construction_authorization=changed,
        authorization=release_authorization,
    )

    assert PublicationIssueCode.CORPUS_CONSTRUCTION_AUTHORIZATION_INVALID in _codes(result)


@pytest.mark.parametrize("shared_role_property", ["identity", "key", "trust-policy"])
def test_construction_and_review_runtime_roles_must_be_cryptographically_distinct(
    complete_submission: BenchmarkReleaseSubmission,
    shared_role_property: str,
) -> None:
    """Corpus construction may not reuse any machine-review runtime authority."""
    review = complete_submission.corpus.scenarios[0].machine_reviews[0]
    construction = _construction_authorization(complete_submission)
    changed = replace(
        construction,
        identity=(
            review.runtime_signer_identity
            if shared_role_property == "identity"
            else construction.identity
        ),
        signing_key_fingerprint=(
            review.runtime_signing_key_fingerprint
            if shared_role_property == "key"
            else construction.signing_key_fingerprint
        ),
        allowed_signers_sha256=(
            review.runtime_allowed_signers_sha256
            if shared_role_property == "trust-policy"
            else construction.allowed_signers_sha256
        ),
    )

    result = evaluate_benchmark_release(
        complete_submission,
        corpus_construction_authorization=changed,
        authorization=_release_authorization(complete_submission),
    )

    assert PublicationIssueCode.CORPUS_CONSTRUCTION_AUTHORIZATION_INVALID in _codes(result)


@pytest.mark.parametrize(
    ("field_name", "wrong_value"),
    (
        ("canonical_submission_sha256", "0" * 64),
        ("corpus_hash", "0" * 64),
        ("stinger_commit", "0" * 40),
        ("release_evidence_record_sha256", "0" * 64),
    ),
)
def test_release_evidence_authorization_rejects_wrong_bindings(
    complete_submission: BenchmarkReleaseSubmission,
    field_name: str,
    wrong_value: str,
) -> None:
    """A signed-looking receipt cannot authorize evidence bound to different release bytes."""
    submission = complete_submission
    release_authorization = _release_authorization(submission)
    valid_authorization = _release_evidence_authorization(submission)
    valid_result = evaluate_benchmark_release(
        submission,
        authorization=release_authorization,
        release_evidence_authorization=valid_authorization,
    )
    if field_name == "canonical_submission_sha256":
        changed_authorization = replace(
            valid_authorization,
            canonical_submission_sha256=wrong_value,
        )
    elif field_name == "corpus_hash":
        changed_authorization = replace(valid_authorization, corpus_hash=wrong_value)
    elif field_name == "stinger_commit":
        changed_authorization = replace(valid_authorization, stinger_commit=wrong_value)
    else:
        assert field_name == "release_evidence_record_sha256"
        changed_authorization = replace(
            valid_authorization,
            release_evidence_record_sha256=wrong_value,
        )

    result = evaluate_benchmark_release(
        submission,
        authorization=release_authorization,
        release_evidence_authorization=changed_authorization,
    )

    assert PublicationIssueCode.RELEASE_EVIDENCE_AUTHORIZATION_INVALID not in _codes(valid_result)
    assert PublicationIssueCode.RELEASE_EVIDENCE_AUTHORIZATION_INVALID in _codes(result)
    assert result.publishable is False


@pytest.mark.parametrize("shared_role_property", ["identity", "key", "trust-policy"])
def test_release_and_reproduction_roles_must_be_cryptographically_distinct(
    complete_submission: BenchmarkReleaseSubmission,
    shared_role_property: str,
) -> None:
    """No identity, key, or trust policy may authorize both signed roles."""
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
    submission = complete_submission.model_copy(update={"cross_machine_reproduction": record})
    release_authorization = _release_authorization(submission)

    result = evaluate_benchmark_release(
        submission,
        authorization=release_authorization,
        reproduction_authorization=reproduction_authorization,
    )

    assert result.metrics.cross_machine_reproductions == 0
    assert PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_INVALID in _codes(result)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("reproduced_report_signer_identity", "release-operator@example.test"),
        (
            "reproduced_report_signing_key_fingerprint",
            f"SHA256:{'R' * 43}",
        ),
        ("reproduced_report_allowed_signers_sha256", "b" * 64),
        ("reproduced_report_signature_namespace", REPRODUCTION_SIGNATURE_NAMESPACE),
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

    assert result.metrics.cross_machine_reproductions == 0
    assert PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_INVALID in _codes(result)


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

        assert result.metrics.cross_machine_reproductions == 0
        assert PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_INVALID in _codes(result)


def test_reproduction_requires_identical_modal_outcome_commitments(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """Per-run variance cannot hide a changed per-scenario modal classification."""
    statement = _reproduction_statement(complete_submission).model_copy(
        update={"reproduced_modal_outcomes_sha256": "0" * 64}
    )

    result = _evaluate_reproduction_statement(complete_submission, statement)

    assert result.metrics.cross_machine_reproductions == 0
    assert PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_INVALID in _codes(result)


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


def test_fixed_canonical_discrepancy_remains_valid_reproduction_evidence(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """A real classification difference may pass when every binding is canonical."""
    statement = _reproduction_statement(
        complete_submission,
        discrepancies=(_discrepancy(),),
    )

    result = _evaluate_reproduction_statement(complete_submission, statement)

    assert result.metrics.cross_machine_reproductions == 1
    assert PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_INVALID not in _codes(result)


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
    """A generated entry cannot name a scenario/repetition absent from the target report."""
    statement = _reproduction_statement(
        complete_submission,
        discrepancies=(_discrepancy(scenario_id=scenario_id, repetition=repetition),),
    )

    result = _evaluate_reproduction_statement(complete_submission, statement)

    assert result.metrics.cross_machine_reproductions == 0
    assert PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_INVALID in _codes(result)


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

    assert result.metrics.cross_machine_reproductions == 0
    assert PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_INVALID in _codes(result)


def test_reproduction_rejects_nonclassification_discrepancy_fields(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """Run-specific noise cannot be inserted into the signed discrepancy ledger."""
    statement = _reproduction_statement(
        complete_submission,
        discrepancies=(_discrepancy(field="duration_s"),),
    )

    result = _evaluate_reproduction_statement(complete_submission, statement)

    assert result.metrics.cross_machine_reproductions == 0
    assert PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_INVALID in _codes(result)


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

    assert result.metrics.cross_machine_reproductions == 0
    assert PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_INVALID in _codes(result)


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

    assert result.metrics.cross_machine_reproductions == 0
    assert PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_INVALID in _codes(result)


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

    assert result.metrics.cross_machine_reproductions == 0
    assert PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_INVALID in _codes(result)


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

    assert result.metrics.cross_machine_reproductions == 0
    assert PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_INVALID in _codes(result)


def test_distinct_authorities_can_reach_the_true_publication_success_path(
    complete_submission: BenchmarkReleaseSubmission,
    tmp_path: Path,
) -> None:
    """Real distinct-key authorizations reach the full machine-reproduced path."""
    submission = _publication_ready_submission(complete_submission)
    protocol_identity = "protocol-authority@example.test"
    protocol_key, protocol_policy = _signing_material(
        tmp_path,
        label="protocol-key",
        identity=protocol_identity,
    )
    protocol_path = tmp_path / "protocol.json"
    protocol_path.write_text(
        submission.protocol.model_dump_json(indent=2),
        encoding="utf-8",
    )
    protocol_signature = sign_protocol(protocol_path, protocol_key)
    loaded_protocol, protocol_authorization = authorize_benchmark_protocol(
        protocol_path,
        protocol_signature,
        protocol_policy,
        protocol_identity,
    )
    assert loaded_protocol == submission.protocol

    candidate_identity = "candidate-validator@example.test"
    candidate_key, candidate_policy = _signing_material(
        tmp_path,
        label="candidate-key",
        identity=candidate_identity,
    )
    candidate_path = tmp_path / "candidate-validation-receipt.json"
    candidate_path.write_text(
        _candidate_receipt(
            submission.corpus,
            identity=candidate_identity,
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    candidate_signature = sign_candidate_validation_receipt(
        candidate_path,
        candidate_key,
    )
    candidate_authorization = authorize_candidate_validation_receipt(
        candidate_path,
        candidate_signature,
        candidate_policy,
        candidate_identity,
    )
    submission = submission.model_copy(
        update={
            "corpus": submission.corpus.model_copy(
                update={
                    "candidate_validation_receipt_sha256": (candidate_authorization.receipt_sha256)
                }
            )
        }
    )

    promotion_identity = "promotion-authority@example.test"
    promotion_key, promotion_policy = _signing_material(
        tmp_path,
        label="promotion-key",
        identity=promotion_identity,
    )
    promotion_path = tmp_path / "candidate-promotion-statement.json"
    promotion_path.write_text(
        _promotion_statement(
            submission,
            identity=promotion_identity,
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    promotion_signature = sign_candidate_promotion_statement(
        promotion_path,
        promotion_key,
    )
    promotion_authorization = authorize_candidate_promotion_statement(
        promotion_path,
        promotion_signature,
        promotion_policy,
        promotion_identity,
    )
    submission = submission.model_copy(
        update={
            "corpus": submission.corpus.model_copy(
                update={
                    "candidate_promotion_statement_sha256": (
                        promotion_authorization.statement_sha256
                    )
                }
            )
        }
    )

    construction_identity = "construction-authority@example.test"
    construction_key, construction_policy = _signing_material(
        tmp_path,
        label="construction-key",
        identity=construction_identity,
    )
    construction_path = tmp_path / "corpus-construction-receipt.json"
    write_corpus_construction_receipt(
        construction_path,
        _construction_receipt(submission),
    )
    construction_signature = sign_corpus_construction_receipt(
        construction_path,
        construction_key,
    )
    construction_authorization = authorize_corpus_construction_receipt(
        construction_path,
        construction_signature,
        construction_policy,
        construction_identity,
    )

    pilot_identity = "pilot-verifier@example.test"
    pilot_key, pilot_policy = _signing_material(
        tmp_path,
        label="pilot-key",
        identity=pilot_identity,
    )
    pilot_path = tmp_path / "pilot-evidence-statement.json"
    write_pilot_evidence_statement(
        pilot_path,
        _pilot_evidence_statement(
            submission,
            protocol_sha256=protocol_authorization.protocol_sha256,
            candidate_receipt=candidate_authorization.receipt,
            candidate_receipt_sha256=candidate_authorization.receipt_sha256,
        ),
    )
    pilot_signature = sign_pilot_evidence_statement(pilot_path, pilot_key)
    pilot_authorization = authorize_pilot_evidence_statement(
        pilot_path,
        pilot_signature,
        pilot_policy,
        pilot_identity,
    )

    freeze_identity = "freeze-authority@example.test"
    freeze_key, freeze_policy = _signing_material(
        tmp_path,
        label="freeze-key",
        identity=freeze_identity,
    )
    freeze_statement_path = tmp_path / "corpus-freeze-statement.json"
    freeze_statement_path.write_text(
        _freeze_statement(
            submission.corpus,
            identity=freeze_identity,
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    freeze_signature = sign_corpus_freeze_statement(
        freeze_statement_path,
        freeze_key,
    )
    freeze_authorization = authorize_corpus_freeze_statement(
        freeze_statement_path,
        freeze_signature,
        freeze_policy,
        freeze_identity,
    )
    freeze_record = CorpusFreezeRecord(
        signer_identity=freeze_authorization.identity,
        statement_sha256=freeze_authorization.statement_sha256,
        statement_signature_sha256=freeze_authorization.signature_sha256,
        allowed_signers_sha256=freeze_authorization.allowed_signers_sha256,
    )
    submission = submission.model_copy(
        update={"corpus": submission.corpus.model_copy(update={"freeze": freeze_record})}
    )

    baseline_identity = "baseline-verifier@example.test"
    baseline_key, baseline_policy = _signing_material(
        tmp_path,
        label="baseline-key",
        identity=baseline_identity,
    )
    baseline_authorizations: list[VerifiedBaselineAuthorization] = []
    for index, baseline in enumerate(submission.baselines):
        baseline_statement = BaselineVerificationStatement(
            benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
            rubric_version=RUBRIC_VERSION,
            configuration_id=baseline.configuration_id,
            corpus_hash=submission.corpus.corpus_hash,
            baseline_record_sha256=baseline_configuration_record_sha256(baseline),
            signer_identity=baseline_identity,
        )
        baseline_path = tmp_path / f"baseline-verification-{index}.json"
        baseline_path.write_text(
            baseline_statement.model_dump_json(indent=2),
            encoding="utf-8",
        )
        baseline_signature = sign_baseline_verification_statement(
            baseline_path,
            baseline_key,
        )
        baseline_authorizations.append(
            authorize_baseline_verification_statement(
                baseline_path,
                baseline_signature,
                baseline_policy,
                baseline_identity,
            )
        )

    conformance_records: list[ConformanceEnvironmentRecord] = []
    conformance_authorizations: list[VerifiedConformanceAuthorization] = []
    for index, environment in enumerate(submission.conformance_environments):
        conformance_key, conformance_policy = _signing_material(
            tmp_path,
            label=f"conformance-key-{index}",
            identity=environment.signer_identity,
        )
        conformance_path = tmp_path / f"conformance-{index}.json"
        conformance_path.write_text(
            _conformance_statement(environment).model_dump_json(indent=2),
            encoding="utf-8",
        )
        conformance_signature = sign_conformance_statement(
            conformance_path,
            conformance_key,
        )
        conformance_authorization = authorize_conformance_statement(
            conformance_path,
            conformance_signature,
            conformance_policy,
            environment.signer_identity,
        )
        conformance_authorizations.append(conformance_authorization)
        conformance_records.append(
            environment.model_copy(
                update={
                    "workflow_receipt_sha256": (
                        conformance_authorization.statement.workflow_output_inventory_sha256
                    ),
                    "receipt_signature_sha256": conformance_authorization.signature_sha256,
                    "allowed_signers_sha256": (conformance_authorization.allowed_signers_sha256),
                }
            )
        )
    submission = submission.model_copy(
        update={"conformance_environments": tuple(conformance_records)}
    )

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
    record = CrossMachineReproductionRecord(
        evaluator_id=reproduction_authorization.statement.evaluator_id,
        configuration_id=reproduction_authorization.statement.configuration_id,
        signer_identity=reproduction_authorization.identity,
        statement_sha256=reproduction_authorization.statement_sha256,
        statement_signature_sha256=reproduction_authorization.signature_sha256,
        verifier_allowed_signers_sha256=reproduction_authorization.allowed_signers_sha256,
    )
    submission = submission.model_copy(update={"cross_machine_reproduction": record})
    public_reproduction_authorization = _public_reproduction_authorization(
        submission,
        reproduction_authorization.statement,
        statement_sha256=reproduction_authorization.statement_sha256,
        protocol_authorization=protocol_authorization,
    )
    finalized_release_artifacts = build_release_artifact_manifest(
        submission,
        conflicts_declaration="no-known-material-conflicts",
    )
    submission = submission.model_copy(
        update={
            "release_evidence": release_evidence_record_from_artifacts(
                finalized_release_artifacts,
                master_gate_receipt_sha256=_digest("master-gate"),
            )
        }
    )

    release_evidence_identity = "release-evidence@example.test"
    release_evidence_key, release_evidence_policy = _signing_material(
        tmp_path,
        label="release-evidence-key",
        identity=release_evidence_identity,
    )
    release_evidence_path = tmp_path / "release-evidence-statement.json"
    release_evidence_path.write_text(
        _release_evidence_statement(
            submission,
            identity=release_evidence_identity,
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    release_evidence_signature = sign_release_evidence_statement(
        release_evidence_path,
        release_evidence_key,
    )
    release_evidence_authorization = authorize_release_evidence_statement(
        release_evidence_path,
        release_evidence_signature,
        release_evidence_policy,
        release_evidence_identity,
    )

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
        protocol_authorization=protocol_authorization,
        candidate_validation_authorization=candidate_authorization,
        candidate_promotion_authorization=promotion_authorization,
        corpus_construction_authorization=construction_authorization,
        corpus_freeze_authorization=freeze_authorization,
        baseline_authorizations=tuple(baseline_authorizations),
        conformance_authorizations=tuple(conformance_authorizations),
        pilot_authorization=pilot_authorization,
        authorization=release_authorization,
        release_evidence_authorization=release_evidence_authorization,
        reproduction_authorization=reproduction_authorization,
        public_reproduction_authorization=public_reproduction_authorization,
    )

    assert result.issues == ()
    assert all(configuration.eligible for configuration in result.configuration_results)
    assert result.publishable is True
    assert result.status is ReleaseStatus.MACHINE_REPRODUCED
    assert result.metrics.cross_machine_reproductions == 1


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
        authorize_benchmark_protocol,
        authorize_benchmark_submission,
        authorize_baseline_verification_statement,
        authorize_candidate_promotion_statement,
        authorize_candidate_validation_receipt,
        authorize_conformance_statement,
        authorize_corpus_construction_receipt,
        authorize_corpus_freeze_statement,
        authorize_pilot_evidence_statement,
        authorize_release_evidence_statement,
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

    assert loaded == compiled_benchmark_protocol()


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
    assert "benchmark protocol 2.0.0 is structurally valid" in protocol.output
    assert "release remains gate-controlled" in protocol.output
    assert release.exit_code == 1
    assert "status: benchmark_candidate" in release.output
    assert "publishable: no" in release.output
    assert "corpus_scenario_count_invalid" in release.output
    assert "cross_machine_reproduction_missing" in release.output


def test_cli_requires_complete_corpus_construction_authorization_group() -> None:
    """A partial construction trust group fails before the release gate can run."""
    candidate = ROOT / "benchmark" / "candidate-submission.yaml"

    result = CliRunner().invoke(
        main,
        [
            "benchmark",
            "release-check",
            str(candidate),
            "--corpus-construction-receipt",
            str(candidate),
        ],
    )

    assert result.exit_code != 0
    assert (
        "all corpus construction receipt/signature/trust options are required together"
        in result.output
    )


def test_release_cli_uses_only_signed_public_reproduction_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """release-check never opens bundles, leakage material, reports, or escrow."""
    submission_path = tmp_path / "submission.json"
    submission_path.write_text(complete_submission.model_dump_json(), encoding="utf-8")
    placeholder = tmp_path / "public-input"
    placeholder.write_text("{}\n", encoding="utf-8")
    _, reproduction_authorization = _reproduction_proof(complete_submission)
    public_authorization = _public_reproduction_authorization(
        complete_submission,
        reproduction_authorization.statement,
    )
    monkeypatch.setattr(
        cli_module,
        "authorize_reproduction_statement",
        lambda *_args: reproduction_authorization,
    )
    monkeypatch.setattr(
        cli_module,
        "authorize_public_reproduction_verification_statement",
        lambda *_args: public_authorization,
    )

    def forbidden_full_verifier(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("release-check invoked the private/full verifier")

    monkeypatch.setattr(
        cli_module,
        "verify_public_reproduction",
        forbidden_full_verifier,
    )
    result = CliRunner().invoke(
        main,
        [
            "benchmark",
            "release-check",
            str(submission_path),
            "--reproduction-statement",
            str(placeholder),
            "--reproduction-signature",
            str(placeholder),
            "--verifier-allowed-signers",
            str(placeholder),
            "--verifier-identity",
            reproduction_authorization.identity,
            "--public-reproduction-verification-statement",
            str(placeholder),
            "--public-reproduction-verification-signature",
            str(placeholder),
        ],
    )

    assert not isinstance(result.exception, AssertionError)
    assert result.exit_code == 1
    help_result = CliRunner().invoke(main, ["benchmark", "release-check", "--help"])
    assert help_result.exit_code == 0
    assert "--reproduced-forbidden-source" not in help_result.output
    assert "--reproduced-marker-file" not in help_result.output
    assert "--reproduced-public-bundle" not in help_result.output


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
            "conformance_environments": tuple(
                reversed(complete_submission.conformance_environments)
            ),
        }
    )

    assert evaluate_benchmark_release(reversed_submission) == evaluate_benchmark_release(
        complete_submission
    )


def test_missing_corpus_review_and_external_records_fail_closed(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """A score cannot substitute for machine construction or cross-environment evidence."""
    selected = next(
        scenario for scenario in complete_submission.corpus.scenarios if scenario.blind_agent_solves
    )
    changed = selected.model_copy(
        update={
            "machine_reviews": (),
            "resolution_variants": (),
            "agent_qa_attempts": (),
            "blind_agent_solves": (),
            "scenario_artifact_sha256": "",
            "machine_validation_receipt_sha256": "",
            "provenance_receipt_sha256": "",
            "containment_receipt_sha256": "",
            "dummy_safety_receipt_sha256": "",
        }
    )
    corpus = complete_submission.corpus.model_copy(
        update={
            "scenarios": tuple(
                changed if scenario.scenario_id == changed.scenario_id else scenario
                for scenario in complete_submission.corpus.scenarios
            ),
            "candidate_validation_receipt_sha256": None,
            "custody_inventory_sha256": None,
            "access_log_root_sha256": None,
            "canary_validation_receipt_sha256": None,
            "freeze": None,
        }
    )
    release = complete_submission.release_evidence.model_copy(
        update={
            "protocol_freeze_receipt_sha256": None,
            "master_gate_receipt_sha256": None,
            "technical_report_sha256": None,
            "correction_policy_sha256": None,
            "conflicts_disclosure_sha256": None,
        }
    )
    submission = complete_submission.model_copy(
        update={
            "corpus": corpus,
            "conformance_environments": (),
            "cross_machine_reproduction": None,
            "release_evidence": release,
            "human_approval": None,
        }
    )

    result = evaluate_benchmark_release(submission)
    codes = _codes(result)

    assert result.publishable is False
    assert result.status is ReleaseStatus.BENCHMARK_CANDIDATE
    assert PublicationIssueCode.CORPUS_SCENARIO_ARTIFACT_MISSING in codes
    assert PublicationIssueCode.CORPUS_MACHINE_VALIDATION_RECEIPT_MISSING in codes
    assert PublicationIssueCode.CORPUS_PROVENANCE_MISSING in codes
    assert PublicationIssueCode.CORPUS_CONTAINMENT_RECEIPT_MISSING in codes
    assert PublicationIssueCode.CORPUS_DUMMY_SAFETY_RECEIPT_MISSING in codes
    assert PublicationIssueCode.CORPUS_MACHINE_REVIEW_INSUFFICIENT in codes
    assert PublicationIssueCode.CORPUS_MACHINE_REVIEW_DIVERSITY_INVALID in codes
    assert PublicationIssueCode.CORPUS_RESOLUTION_VARIANTS_INSUFFICIENT in codes
    assert PublicationIssueCode.CORPUS_AGENT_QA_INSUFFICIENT in codes
    assert PublicationIssueCode.CORPUS_BLIND_SOLVE_INVALID in codes
    assert PublicationIssueCode.CORPUS_CANDIDATE_VALIDATION_RECEIPT_MISSING in codes
    assert PublicationIssueCode.CORPUS_CUSTODY_INVENTORY_MISSING in codes
    assert PublicationIssueCode.CORPUS_ACCESS_LOG_ROOT_MISSING in codes
    assert PublicationIssueCode.CORPUS_CANARY_VALIDATION_RECEIPT_MISSING in codes
    assert PublicationIssueCode.CORPUS_NOT_FROZEN in codes
    assert PublicationIssueCode.BASELINE_PROTOCOL_NOT_FROZEN in codes
    assert PublicationIssueCode.CONFORMANCE_ENVIRONMENTS_INSUFFICIENT in codes
    assert PublicationIssueCode.CONFORMANCE_PLATFORM_DIVERSITY_INSUFFICIENT in codes
    assert PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_MISSING in codes
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
                        configuration_alias=PILOT_ALIAS_ALPHA,
                        outcome=Outcome.HONEST,
                    ),
                    PilotConfigurationOutcomeRecord(
                        configuration_alias=PILOT_ALIAS_BETA,
                        outcome=Outcome.CHEATED,
                    ),
                ),
            ),
        ),
        selection_protocol_sha256=complete_submission.pilot.selection_protocol_sha256,
    )

    result = evaluate_benchmark_release(complete_submission.model_copy(update={"pilot": pilot}))

    assert PublicationIssueCode.PILOT_SELECTION_CORPUS_UNBOUND in _codes(result)


def test_pilot_rejects_arbitrary_post_hoc_selection_hash(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    pilot = complete_submission.pilot.model_copy(update={"selection_protocol_sha256": "f" * 64})

    result = evaluate_benchmark_release(complete_submission.model_copy(update={"pilot": pilot}))

    assert PublicationIssueCode.PILOT_SELECTION_POLICY_INVALID in _codes(result)


def test_unrelated_pilot_items_cannot_dilute_the_sealed_variation_rate(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """Extra varied items cannot turn a stable sealed selection into a passing pilot."""
    stable_sealed = tuple(
        item.model_copy(
            update={
                "outcomes": tuple(
                    outcome.model_copy(update={"outcome": Outcome.HONEST})
                    for outcome in item.outcomes
                )
            }
        )
        for item in complete_submission.pilot.candidate_pool
    )
    unrelated = tuple(
        PilotCandidateRecord(
            scenario_id=f"unrelated-{index}",
            cluster_id=f"unrelated.cluster-{index}",
            outcomes=(
                PilotConfigurationOutcomeRecord(
                    configuration_alias=PILOT_ALIAS_ALPHA,
                    outcome=Outcome.HONEST,
                ),
                PilotConfigurationOutcomeRecord(
                    configuration_alias=PILOT_ALIAS_BETA,
                    outcome=Outcome.CHEATED,
                ),
            ),
        )
        for index in range(40)
    )
    pilot = complete_submission.pilot.model_copy(
        update={"candidate_pool": (*stable_sealed, *unrelated)}
    )

    result = evaluate_benchmark_release(complete_submission.model_copy(update={"pilot": pilot}))

    assert PublicationIssueCode.PILOT_EVIDENCE_INSUFFICIENT in _codes(result)


def test_conformance_records_require_one_bound_workflow_and_platform_diversity(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """Distinct labels cannot replace workflow binding or real platform diversity."""
    environments = tuple(
        environment.model_copy(
            update={
                "platform": ConformancePlatform.LINUX,
                "architecture": ConformanceArchitecture.X86_64,
                "workflow_input_sha256": (
                    _digest("different-workflow")
                    if index == 0
                    else environment.workflow_input_sha256
                ),
            }
        )
        for index, environment in enumerate(complete_submission.conformance_environments)
    )

    result = evaluate_benchmark_release(
        complete_submission.model_copy(update={"conformance_environments": environments})
    )
    codes = _codes(result)

    assert PublicationIssueCode.CONFORMANCE_ENVIRONMENTS_INSUFFICIENT in codes
    assert PublicationIssueCode.CONFORMANCE_PLATFORM_DIVERSITY_INSUFFICIENT in codes


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


def test_machine_review_hashes_and_qa_execution_receipts_are_not_self_attestations(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """A forged review output hash or reused QA execution receipt fails closed."""
    first = complete_submission.corpus.scenarios[0]
    attempts = tuple(
        attempt.model_copy(
            update={"runtime_receipt_sha256": first.agent_qa_attempts[0].runtime_receipt_sha256}
        )
        for attempt in first.agent_qa_attempts
    )
    reviews = (
        first.machine_reviews[0].model_copy(update={"output_sha256": "0" * 64}),
        first.machine_reviews[1],
    )
    changed = first.model_copy(
        update={
            "agent_qa_attempts": attempts,
            "machine_reviews": reviews,
        }
    )
    corpus = complete_submission.corpus.model_copy(
        update={"scenarios": (changed, *complete_submission.corpus.scenarios[1:])}
    )

    result = evaluate_benchmark_release(complete_submission.model_copy(update={"corpus": corpus}))
    codes = _codes(result)

    assert PublicationIssueCode.CORPUS_AGENT_QA_DIVERSITY_INVALID in codes
    assert PublicationIssueCode.CORPUS_MACHINE_REVIEW_BINDING_INVALID in codes


@pytest.mark.parametrize(
    "field",
    [
        "runtime_signer_identity",
        "runtime_signing_key_fingerprint",
        "runtime_allowed_signers_sha256",
        "runtime_signature_sha256",
    ],
)
def test_machine_review_runtime_authorities_must_be_distinct(
    complete_submission: BenchmarkReleaseSubmission,
    field: str,
) -> None:
    """Different model labels cannot conceal one reused runtime authorization."""
    first = complete_submission.corpus.scenarios[0]
    reviews = (
        first.machine_reviews[0],
        first.machine_reviews[1].model_copy(
            update={field: getattr(first.machine_reviews[0], field)}
        ),
    )
    changed = first.model_copy(update={"machine_reviews": reviews})
    corpus = complete_submission.corpus.model_copy(
        update={"scenarios": (changed, *complete_submission.corpus.scenarios[1:])}
    )

    result = evaluate_benchmark_release(complete_submission.model_copy(update={"corpus": corpus}))

    assert PublicationIssueCode.CORPUS_MACHINE_REVIEW_DIVERSITY_INVALID in _codes(result)


def test_run_gate_emits_a_specific_credential_isolation_failure(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    submission = _publication_ready_submission(complete_submission)
    baseline = submission.baselines[0]
    runtime = baseline.report.benchmark_runtime_provenance
    assert runtime is not None
    changed_report = baseline.report.model_copy(
        update={
            "benchmark_runtime_provenance": runtime.model_copy(
                update={"credential_isolation": None}
            )
        }
    )
    changed_baseline = baseline.model_copy(
        update={
            "report": changed_report,
            "report_sha256": canonical_report_sha256(changed_report),
        }
    )
    changed_submission = submission.model_copy(
        update={"baselines": (changed_baseline, *submission.baselines[1:])}
    )

    result = evaluate_benchmark_release(changed_submission)
    configuration = next(
        item for item in result.configuration_results if item.configuration_id == "cfg-0"
    )

    assert PublicationIssueCode.RUN_CREDENTIAL_ISOLATION_FAILED in {
        issue.code for issue in configuration.issues
    }


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
    assert configuration.metrics.errors == 7
    assert configuration.metrics.error_rate > 0.0
    assert PublicationIssueCode.RUN_PROTOCOL_VERSION_MISMATCH in codes
    assert PublicationIssueCode.RUN_PUBLICATION_PIN_INCOMPLETE in codes
    assert PublicationIssueCode.RUN_REPETITION_COUNT_INVALID in codes
    assert PublicationIssueCode.RUN_REPETITION_INDEX_INVALID in codes
    assert PublicationIssueCode.RUN_NON_SEALED_RESULT in codes
    assert PublicationIssueCode.RUN_ERROR_RATE_EXCEEDED in codes
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
    """One self-run cannot satisfy the six-config, cross-machine release gate."""
    release = complete_submission.release_evidence.model_copy(
        update={
            "comparative_release": True,
            "vendor_rerun_receipt_sha256": None,
        }
    )
    approval = complete_submission.human_approval
    assert approval is not None
    submission = complete_submission.model_copy(
        update={
            "baselines": (complete_submission.baselines[0],),
            "cross_machine_reproduction": (
                complete_submission.cross_machine_reproduction.model_copy(
                    update={"configuration_id": "not-in-matrix"}
                )
            )
            if complete_submission.cross_machine_reproduction
            else None,
            "release_evidence": release,
            "human_approval": approval.model_copy(update={"comparative_result_approved": False}),
        }
    )

    result = evaluate_benchmark_release(submission)
    codes = _codes(result)

    assert PublicationIssueCode.BASELINE_CONFIGURATION_COUNT_INVALID in codes
    assert PublicationIssueCode.BASELINE_PROVIDER_COUNT_INVALID in codes
    assert PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_INVALID in codes
    assert PublicationIssueCode.VENDOR_RERUN_OPPORTUNITY_MISSING in codes
    assert PublicationIssueCode.HUMAN_APPROVAL_INVALID in codes


def test_machine_review_block_or_uncertainty_vetoes_the_scenario(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """Machine reviews are veto-only: any non-ACCEPT decision blocks release."""
    first = complete_submission.corpus.scenarios[0]
    uncertain_output = first.machine_reviews[1].output.model_copy(
        update={
            "findings": (MachineReviewFinding.EVIDENCE_INCOMPLETE,),
            "decision": MachineReviewDecision.UNCERTAIN,
        }
    )
    blocked_reviews = (
        first.machine_reviews[0],
        first.machine_reviews[1].model_copy(
            update={
                "output": uncertain_output,
                "output_sha256": _canonical_sha256(uncertain_output),
            }
        ),
    )
    changed = first.model_copy(update={"machine_reviews": blocked_reviews})
    corpus = complete_submission.corpus.model_copy(
        update={"scenarios": (changed, *complete_submission.corpus.scenarios[1:])}
    )

    result = evaluate_benchmark_release(complete_submission.model_copy(update={"corpus": corpus}))

    assert PublicationIssueCode.CORPUS_MACHINE_REVIEW_BLOCKED in _codes(result)


def test_every_error_counts_without_a_disposition_escape_hatch(
    complete_submission: BenchmarkReleaseSubmission,
) -> None:
    """Even one ERROR is reported in the metric; callers cannot explain it away."""
    baseline = complete_submission.baselines[0]
    results = list(baseline.report.results)
    results[0] = results[0].model_copy(update={"outcome": Outcome.ERROR})
    changed = baseline.model_copy(
        update={"report": baseline.report.model_copy(update={"results": results})}
    )
    result = evaluate_benchmark_release(
        complete_submission.model_copy(
            update={"baselines": (changed, *complete_submission.baselines[1:])}
        )
    )
    configuration = next(
        item for item in result.configuration_results if item.configuration_id == "cfg-0"
    )

    assert configuration.metrics.errors == 1
    assert configuration.metrics.error_rate == pytest.approx(1 / 600)
    assert PublicationIssueCode.RUN_ERROR_RATE_EXCEEDED in {
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
