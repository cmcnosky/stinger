"""Artifact-derived cross-machine reproduction evidence for Benchmark Protocol 2.

This module proves every hash in the signed statement from verified target and reproduced
evidence, creates an automatic immutable discrepancy ledger, and refuses to emit favourable
records from caller-entered hashes or booleans.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from stinger.benchmark.comparison import (
    BenchmarkComparisonError,
    PairedBenchmarkComparison,
    build_paired_comparison,
    verify_paired_comparison,
)
from stinger.benchmark.evidence import (
    EvidenceBundleError,
    PublicLeakagePolicy,
    VerifiedArtifactReceipt,
    verify_evidence_bundle_pair,
)
from stinger.benchmark.gates import (
    BaselineConfigurationRecord,
    BenchmarkProtocolManifest,
    CrossMachineReproductionRecord,
    CrossMachineReproductionStatement,
    RepositorySize,
    ReproductionDiscrepancyClassification,
    ReproductionDiscrepancyRecord,
    SealedCorpusRecord,
    authorize_reproduction_statement,
    canonical_report_sha256,
    compiled_benchmark_protocol,
    reproduction_discrepancy_id,
    reproduction_discrepancy_ledger_sha256,
    reproduction_modal_outcomes_sha256,
    reproduction_value_sha256,
)
from stinger.benchmark.machine_environment import (
    MACHINE_ENVIRONMENT_CLAIM_BOUNDARY,
    MachineAttestationError,
    MachineWorkflowEvidencePaths,
    VerifiedMachineWorkflowAttestation,
    verify_machine_workflow_attestation,
)
from stinger.benchmark.records import (
    BaselineRecordError,
    _build_baseline_configuration_record_from_receipt,
)
from stinger.benchmark.signing import (
    REPRODUCED_REPORT_SIGNATURE_NAMESPACE,
    ArtifactSignatureVerification,
    ProtocolSignatureError,
    verify_reproduced_report_signature,
)
from stinger.models import (
    DetectorResult,
    Family,
    FamilyScore,
    JudgeReport,
    Report,
    ScenarioResult,
)
from stinger.report.generate import ReportMismatchError, verify_report

REPRODUCTION_FORMAT_VERSION: Literal["1"] = "1"
REPRODUCTION_DIFF_METHOD: Literal["classification_relevant_result_diff_v1"] = (
    "classification_relevant_result_diff_v1"
)
CLASSIFICATION_FIELDS = (
    "outcome",
    "detector_results",
    "goal_met",
    "agent_claimed_done",
    "run_error",
)
EXCLUDED_RUN_FIELDS = (
    "generated_at",
    "duration_s",
    "transcript_path",
    "diff_path",
)
COMPARISON_MANIFEST_FILE = "comparison.manifest.json"
DISCREPANCY_LEDGER_FILE = "discrepancy-ledger.json"
REPRODUCTION_STATEMENT_FILE = "reproduction-statement.json"

__all__ = [
    "CLASSIFICATION_FIELDS",
    "COMPARISON_MANIFEST_FILE",
    "DISCREPANCY_LEDGER_FILE",
    "EXCLUDED_RUN_FIELDS",
    "REPRODUCTION_STATEMENT_FILE",
    "ReproductionBuilderError",
    "ReproductionComparisonManifest",
    "ReproductionDiffTemplate",
    "build_reproduction_diff",
    "build_reproduction_record",
    "build_reproduction_statement",
    "load_reproduction_diff",
    "write_reproduction_diff",
    "write_reproduction_record",
]


class ReproductionBuilderError(Exception):
    """Raised when artifacts cannot support cross-machine reproduction evidence."""


class _FrozenModel(BaseModel):
    """Closed immutable schema for private builder artifacts."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class ReproductionDiffTemplate(_FrozenModel):
    """Immutable machine-generated ledger binding one exact report pair."""

    format_version: Literal["1"] = REPRODUCTION_FORMAT_VERSION
    method: Literal["classification_relevant_result_diff_v1"] = REPRODUCTION_DIFF_METHOD
    target_report_sha256: str
    reproduced_report_sha256: str
    target_modal_outcomes_sha256: str
    reproduced_modal_outcomes_sha256: str
    discrepancies: tuple[ReproductionDiscrepancyRecord, ...] = ()

    @field_validator(
        "target_report_sha256",
        "reproduced_report_sha256",
        "target_modal_outcomes_sha256",
        "reproduced_modal_outcomes_sha256",
    )
    @classmethod
    def _valid_report_hash(cls, value: str) -> str:
        """Require exact lowercase report hashes in review templates."""
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ValueError("report hash must be 64 lowercase hexadecimal characters")
        return value


class ReproductionComparisonManifest(_FrozenModel):
    """Standalone comparison artifact referenced by the signed statement."""

    format_version: Literal["1"] = REPRODUCTION_FORMAT_VERSION
    method: Literal["classification_relevant_result_diff_v1"] = REPRODUCTION_DIFF_METHOD
    benchmark_protocol_version: str
    rubric_version: str
    corpus_hash: str
    configuration_id: str
    config_fingerprint: str
    agent_configuration_fingerprint: str
    target_report_sha256: str
    reproduced_report_sha256: str
    target_modal_outcomes_sha256: str
    reproduced_modal_outcomes_sha256: str
    target_report_bytes_sha256: str
    reproduced_report_bytes_sha256: str
    target_public_bundle_manifest_sha256: str
    target_escrow_bundle_manifest_sha256: str
    reproduced_public_bundle_manifest_sha256: str
    reproduced_escrow_bundle_manifest_sha256: str
    reproduced_report_signature_sha256: str
    reproduced_report_signature_namespace: str
    reproduced_report_signer_identity: str
    reproduced_report_signing_key_fingerprint: str
    reproduced_report_allowed_signers_sha256: str
    classification_fields: tuple[str, ...]
    excluded_run_fields: tuple[str, ...]
    discrepancy_ledger_sha256: str
    discrepancy_count: int
    paired_comparison: PairedBenchmarkComparison


def build_reproduction_diff(
    target_report: Report,
    reproduced_report: Report,
) -> ReproductionDiffTemplate:
    """Create an immutable automatic ledger for one modal-stable report pair."""
    _verify_reports_and_structure(target_report, reproduced_report)
    _require_modal_outcomes_match(target_report, reproduced_report)
    target_hash = canonical_report_sha256(target_report)
    reproduced_hash = canonical_report_sha256(reproduced_report)
    target_modal_hash = reproduction_modal_outcomes_sha256(target_report)
    reproduced_modal_hash = reproduction_modal_outcomes_sha256(reproduced_report)
    discrepancies = _classification_discrepancies(target_report, reproduced_report)
    return ReproductionDiffTemplate(
        target_report_sha256=target_hash,
        reproduced_report_sha256=reproduced_hash,
        target_modal_outcomes_sha256=target_modal_hash,
        reproduced_modal_outcomes_sha256=reproduced_modal_hash,
        discrepancies=discrepancies,
    )


def write_reproduction_diff(
    destination: Path,
    template: ReproductionDiffTemplate,
) -> None:
    """Create one canonical automatic ledger without overwriting a path."""
    _atomic_create_file(destination, _canonical_model_bytes(template))


def load_reproduction_diff(path: Path) -> ReproductionDiffTemplate:
    """Load one closed automatic ledger from a regular nonsymlink JSON file."""
    try:
        raw = json.loads(
            _read_regular_bytes(path, label="reproduction discrepancy ledger").decode("utf-8")
        )
        return ReproductionDiffTemplate.model_validate(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ReproductionBuilderError(
            "reproduction discrepancy ledger is not valid closed JSON"
        ) from exc


def build_reproduction_statement(
    evaluator_id: str,
    *,
    configuration_id: str,
    corpus: SealedCorpusRecord,
    target_baseline_record: BaselineConfigurationRecord,
    target_public_bundle: Path,
    target_escrow_bundle: Path,
    target_machine_workflow_evidence: MachineWorkflowEvidencePaths,
    reproduced_public_bundle: Path,
    reproduced_escrow_bundle: Path,
    reproduced_machine_workflow_evidence: MachineWorkflowEvidencePaths,
    leakage_policy: PublicLeakagePolicy,
    protocol_allowed_signers: Path,
    protocol_signer_identity: str,
    reproduced_report_signature: Path,
    evaluator_allowed_signers: Path,
    evaluator_signer_identity: str,
    output_directory: Path,
) -> CrossMachineReproductionStatement:
    """Verify both evidence pairs and atomically create a signed-statement input package.

    Cross-machine evidence is a signed application-scoped operating-system environment
    pseudonym bound to exact config and report bytes. It is not TPM, physical-hardware,
    cloud-provider, organizational-independence, or anti-cloning proof.
    """
    _require_identifier(evaluator_id, label="evaluator_id")
    _require_identifier(evaluator_signer_identity, label="evaluator signer identity")
    _require_distinct_evidence_paths(
        target_public_bundle,
        target_escrow_bundle,
        reproduced_public_bundle,
        reproduced_escrow_bundle,
    )
    input_paths = (
        target_public_bundle,
        target_escrow_bundle,
        *_machine_workflow_paths(target_machine_workflow_evidence),
        reproduced_public_bundle,
        reproduced_escrow_bundle,
        *_machine_workflow_paths(reproduced_machine_workflow_evidence),
        protocol_allowed_signers,
        reproduced_report_signature,
        evaluator_allowed_signers,
        *leakage_policy.forbidden_sources,
    )
    _require_output_separate_from_inputs(output_directory, input_paths)
    try:
        target_receipt = verify_evidence_bundle_pair(
            target_public_bundle,
            target_escrow_bundle,
            leakage_policy,
            trusted_allowed_signers=protocol_allowed_signers,
            expected_signer_identity=protocol_signer_identity,
        )
        reproduced_receipt = verify_evidence_bundle_pair(
            reproduced_public_bundle,
            reproduced_escrow_bundle,
            leakage_policy,
            trusted_allowed_signers=protocol_allowed_signers,
            expected_signer_identity=protocol_signer_identity,
        )
    except (EvidenceBundleError, OSError, ValueError) as exc:
        raise ReproductionBuilderError("evidence bundle verification failed") from exc

    _cross_bind_protocol_trust(target_receipt, reproduced_receipt)
    _require_distinguishable_evidence(target_receipt, reproduced_receipt)
    _require_publication_corpus_shape(corpus, target_receipt.protocol)
    sensitive_paths = input_paths
    target_machine_workflow = _verify_receipt_machine_workflow(
        target_receipt,
        target_machine_workflow_evidence,
        label="target",
    )
    reproduced_machine_workflow = _verify_receipt_machine_workflow(
        reproduced_receipt,
        reproduced_machine_workflow_evidence,
        label="reproduced",
    )
    try:
        rebuilt_target = _build_baseline_configuration_record_from_receipt(
            configuration_id,
            corpus=corpus,
            receipt=target_receipt,
            machine_workflow_evidence=target_machine_workflow_evidence,
            sensitive_paths=sensitive_paths,
            sensitive_markers=leakage_policy.forbidden_markers,
        )
        rebuilt_reproduced = _build_baseline_configuration_record_from_receipt(
            configuration_id,
            corpus=corpus,
            receipt=reproduced_receipt,
            machine_workflow_evidence=reproduced_machine_workflow_evidence,
            sensitive_paths=sensitive_paths,
            sensitive_markers=leakage_policy.forbidden_markers,
        )
    except BaselineRecordError as exc:
        raise ReproductionBuilderError("report pair is not publication-grade") from exc
    if rebuilt_target != target_baseline_record:
        raise ReproductionBuilderError(
            "supplied target baseline record does not match verified artifacts"
        )
    _require_independent_machine_workflows(
        target_machine_workflow,
        reproduced_machine_workflow,
        target_fingerprint=rebuilt_target.machine_fingerprint_sha256,
        reproduced_fingerprint=rebuilt_reproduced.machine_fingerprint_sha256,
    )

    _reject_unknown_report_fields(
        target_receipt.public_bundle.report_bytes,
        label="target report",
    )
    _reject_unknown_report_fields(
        reproduced_receipt.public_bundle.report_bytes,
        label="reproduced report",
    )
    _require_structural_match(
        rebuilt_target.report,
        rebuilt_reproduced.report,
    )
    _require_modal_outcomes_match(rebuilt_target.report, rebuilt_reproduced.report)
    discrepancies = _classification_discrepancies(
        rebuilt_target.report,
        rebuilt_reproduced.report,
    )
    target_report_hash = rebuilt_target.report_sha256
    reproduced_report_hash = rebuilt_reproduced.report_sha256
    target_modal_hash = reproduction_modal_outcomes_sha256(rebuilt_target.report)
    reproduced_modal_hash = reproduction_modal_outcomes_sha256(rebuilt_reproduced.report)
    ledger_hash = reproduction_discrepancy_ledger_sha256(
        discrepancies,
        target_report_sha256=target_report_hash,
        reproduced_report_sha256=reproduced_report_hash,
    )

    report_signature = _verify_receipt_report_signature(
        reproduced_receipt,
        reproduced_report_signature,
        evaluator_allowed_signers,
        evaluator_signer_identity,
    )
    try:
        comparison = build_paired_comparison(
            rebuilt_reproduced.report,
            rebuilt_target.report,
            samples=10_000,
            seed=0,
            confidence_level=0.95,
        )
        verify_paired_comparison(
            comparison,
            rebuilt_reproduced.report,
            rebuilt_target.report,
        )
    except BenchmarkComparisonError as exc:
        raise ReproductionBuilderError("paired reproduction comparison failed") from exc

    target_metadata = rebuilt_target.report.benchmark_metadata
    reproduced_metadata = rebuilt_reproduced.report.benchmark_metadata
    if target_metadata is None or reproduced_metadata is None:
        raise ReproductionBuilderError("publication metadata is unavailable")
    target_agent_fingerprint = target_metadata.agent_configuration_fingerprint
    reproduced_agent_fingerprint = reproduced_metadata.agent_configuration_fingerprint
    if (
        target_agent_fingerprint is None
        or reproduced_agent_fingerprint is None
        or target_agent_fingerprint != reproduced_agent_fingerprint
        or rebuilt_target.report.config_fingerprint != rebuilt_reproduced.report.config_fingerprint
    ):
        raise ReproductionBuilderError(
            "target and reproduced configuration identities do not match"
        )

    comparison_manifest = ReproductionComparisonManifest(
        benchmark_protocol_version=target_receipt.protocol.benchmark_protocol_version,
        rubric_version=rebuilt_target.report.rubric_version,
        corpus_hash=rebuilt_target.report.corpus_hash,
        configuration_id=configuration_id,
        config_fingerprint=rebuilt_target.report.config_fingerprint,
        agent_configuration_fingerprint=target_agent_fingerprint,
        target_report_sha256=target_report_hash,
        reproduced_report_sha256=reproduced_report_hash,
        target_modal_outcomes_sha256=target_modal_hash,
        reproduced_modal_outcomes_sha256=reproduced_modal_hash,
        target_report_bytes_sha256=_sha256(target_receipt.public_bundle.report_bytes),
        reproduced_report_bytes_sha256=_sha256(reproduced_receipt.public_bundle.report_bytes),
        target_public_bundle_manifest_sha256=(target_receipt.public_bundle.manifest_sha256),
        target_escrow_bundle_manifest_sha256=(target_receipt.escrow_bundle.manifest_sha256),
        reproduced_public_bundle_manifest_sha256=(reproduced_receipt.public_bundle.manifest_sha256),
        reproduced_escrow_bundle_manifest_sha256=(reproduced_receipt.escrow_bundle.manifest_sha256),
        reproduced_report_signature_sha256=report_signature.signature_sha256,
        reproduced_report_signature_namespace=report_signature.namespace,
        reproduced_report_signer_identity=report_signature.identity,
        reproduced_report_signing_key_fingerprint=(report_signature.signing_key_fingerprint),
        reproduced_report_allowed_signers_sha256=(report_signature.allowed_signers_sha256),
        classification_fields=CLASSIFICATION_FIELDS,
        excluded_run_fields=EXCLUDED_RUN_FIELDS,
        discrepancy_ledger_sha256=ledger_hash,
        discrepancy_count=len(discrepancies),
        paired_comparison=comparison,
    )
    ledger_bytes = _discrepancy_ledger_bytes(
        discrepancies,
        target_report_sha256=target_report_hash,
        reproduced_report_sha256=reproduced_report_hash,
    )
    if _sha256(ledger_bytes) != ledger_hash:
        raise ReproductionBuilderError("discrepancy ledger serialization is inconsistent")
    comparison_bytes = _canonical_model_bytes(comparison_manifest)
    completed_families = tuple(
        family
        for family in Family
        if any(result.family is family for result in rebuilt_reproduced.report.results)
    )
    scenario_count = len({result.scenario_id for result in rebuilt_reproduced.report.results})
    statement = CrossMachineReproductionStatement(
        benchmark_protocol_version=target_receipt.protocol.benchmark_protocol_version,
        evaluator_id=evaluator_id,
        signer_identity=evaluator_signer_identity,
        configuration_id=configuration_id,
        corpus_hash=rebuilt_target.report.corpus_hash,
        target_report_sha256=target_report_hash,
        target_config_fingerprint=rebuilt_target.report.config_fingerprint,
        target_agent_configuration_fingerprint=target_agent_fingerprint,
        target_public_bundle_manifest_sha256=(target_receipt.public_bundle.manifest_sha256),
        target_escrow_bundle_manifest_sha256=(target_receipt.escrow_bundle.manifest_sha256),
        target_machine_fingerprint_sha256=(rebuilt_target.machine_fingerprint_sha256),
        reproduced_report_sha256=reproduced_report_hash,
        reproduced_report_signature_sha256=report_signature.signature_sha256,
        reproduced_report_signature_namespace=report_signature.namespace,
        reproduced_report_signer_identity=report_signature.identity,
        reproduced_report_signing_key_fingerprint=(report_signature.signing_key_fingerprint),
        reproduced_report_allowed_signers_sha256=(report_signature.allowed_signers_sha256),
        reproduced_public_bundle_manifest_sha256=(reproduced_receipt.public_bundle.manifest_sha256),
        reproduced_escrow_bundle_manifest_sha256=(reproduced_receipt.escrow_bundle.manifest_sha256),
        reproduced_machine_fingerprint_sha256=(rebuilt_reproduced.machine_fingerprint_sha256),
        reproduced_config_fingerprint=rebuilt_reproduced.report.config_fingerprint,
        reproduced_agent_configuration_fingerprint=reproduced_agent_fingerprint,
        comparison_manifest_sha256=_sha256(comparison_bytes),
        discrepancy_ledger_sha256=ledger_hash,
        target_modal_outcomes_sha256=target_modal_hash,
        reproduced_modal_outcomes_sha256=reproduced_modal_hash,
        completed_families=completed_families,
        scenario_count=scenario_count,
        repetitions=target_receipt.protocol.repetitions,
        discrepancies=discrepancies,
    )
    statement_bytes = _canonical_model_bytes(statement)
    _reject_sensitive_outputs(
        (comparison_manifest, statement),
        sensitive_paths=sensitive_paths,
        sensitive_markers=leakage_policy.forbidden_markers,
    )
    _atomic_create_directory(
        output_directory,
        {
            COMPARISON_MANIFEST_FILE: comparison_bytes,
            DISCREPANCY_LEDGER_FILE: ledger_bytes,
            REPRODUCTION_STATEMENT_FILE: statement_bytes,
        },
    )
    return statement


def build_reproduction_record(
    statement: Path,
    signature: Path,
    allowed_signers: Path,
    signer_identity: str,
) -> CrossMachineReproductionRecord:
    """Authorize an evaluator-signed canonical statement and derive its release record."""
    try:
        statement_bytes = _read_regular_bytes(statement, label="reproduction statement")
        authorization = authorize_reproduction_statement(
            statement,
            signature,
            allowed_signers,
            signer_identity,
        )
    except (
        OSError,
        UnicodeDecodeError,
        ValueError,
        ProtocolSignatureError,
        ReproductionBuilderError,
    ) as exc:
        raise ReproductionBuilderError("reproduction statement authorization failed") from exc
    if statement_bytes != _canonical_model_bytes(authorization.statement):
        raise ReproductionBuilderError("signed reproduction statement was not created canonically")
    if (
        authorization.statement.signer_identity != authorization.identity
        or authorization.statement.signer_identity != signer_identity
    ):
        raise ReproductionBuilderError("reproduction statement signer identity is inconsistent")
    if (
        authorization.statement.reproduced_report_signer_identity != authorization.identity
        or authorization.statement.reproduced_report_signature_namespace
        != REPRODUCED_REPORT_SIGNATURE_NAMESPACE
        or authorization.statement.reproduced_report_signing_key_fingerprint
        != authorization.signing_key_fingerprint
        or authorization.statement.reproduced_report_allowed_signers_sha256
        != authorization.allowed_signers_sha256
    ):
        raise ReproductionBuilderError(
            "reproduced report and statement authorities are inconsistent"
        )
    return CrossMachineReproductionRecord(
        evaluator_id=authorization.statement.evaluator_id,
        configuration_id=authorization.statement.configuration_id,
        signer_identity=authorization.identity,
        statement_sha256=authorization.statement_sha256,
        statement_signature_sha256=authorization.signature_sha256,
        verifier_allowed_signers_sha256=authorization.allowed_signers_sha256,
    )


def write_reproduction_record(
    destination: Path,
    record: CrossMachineReproductionRecord,
) -> None:
    """Create one canonical reproduction record without overwriting a path."""
    _atomic_create_file(destination, _canonical_model_bytes(record))


def _verify_reports_and_structure(target: Report, reproduced: Report) -> None:
    """Verify both reports and reject every non-run-specific structural mismatch."""
    try:
        verify_report(target)
        verify_report(reproduced)
    except ReportMismatchError as exc:
        raise ReproductionBuilderError(
            "a compared report failed deterministic verification"
        ) from exc
    _require_structural_match(target, reproduced)


def _require_modal_outcomes_match(target: Report, reproduced: Report) -> None:
    """Reject a reproduction whose per-scenario modal classifications changed."""
    if reproduction_modal_outcomes_sha256(target) != reproduction_modal_outcomes_sha256(reproduced):
        raise ReproductionBuilderError(
            "compared reports have different per-scenario modal outcomes"
        )


def _require_structural_match(target: Report, reproduced: Report) -> None:
    """Reject every structural mismatch before classification-field comparison."""
    target_metadata = target.benchmark_metadata
    reproduced_metadata = reproduced.benchmark_metadata
    if (
        target.benchmark_protocol_version is None
        or target.benchmark_protocol_version != reproduced.benchmark_protocol_version
        or target.rubric_version != reproduced.rubric_version
        or target.corpus_hash != reproduced.corpus_hash
        or target.config_fingerprint != reproduced.config_fingerprint
        or target_metadata is None
        or reproduced_metadata is None
        or target_metadata.agent_configuration_fingerprint is None
        or target_metadata.agent_configuration_fingerprint
        != reproduced_metadata.agent_configuration_fingerprint
    ):
        raise ReproductionBuilderError("compared reports have a structural identity mismatch")

    target_results = _result_index(target)
    reproduced_results = _result_index(reproduced)
    if set(target_results) != set(reproduced_results):
        raise ReproductionBuilderError("compared reports have different scenario repetitions")
    for key in sorted(target_results):
        target_result = target_results[key]
        reproduced_result = reproduced_results[key]
        if (
            target_result.family is not reproduced_result.family
            or target_result.benchmark_split is not reproduced_result.benchmark_split
            or target_result.scenario_version != reproduced_result.scenario_version
            or target_result.cluster_id != reproduced_result.cluster_id
        ):
            raise ReproductionBuilderError("compared reports have mismatched scenario metadata")


def _result_index(report: Report) -> dict[tuple[str, int], ScenarioResult]:
    """Index unique semantic result locations without accepting duplicate evidence."""
    indexed: dict[tuple[str, int], ScenarioResult] = {}
    for result in report.results:
        key = (result.scenario_id, result.repetition)
        if key in indexed:
            raise ReproductionBuilderError("a compared report contains duplicate results")
        indexed[key] = result
    return indexed


def _classification_discrepancies(
    target: Report,
    reproduced: Report,
) -> tuple[ReproductionDiscrepancyRecord, ...]:
    """Hash only fields capable of changing Stinger's classification evidence."""
    target_results = _result_index(target)
    reproduced_results = _result_index(reproduced)
    discrepancies: list[ReproductionDiscrepancyRecord] = []
    for scenario_id, repetition in sorted(target_results):
        target_result = target_results[(scenario_id, repetition)]
        reproduced_result = reproduced_results[(scenario_id, repetition)]
        target_payload = target_result.model_dump(mode="json")
        reproduced_payload = reproduced_result.model_dump(mode="json")
        for field in CLASSIFICATION_FIELDS:
            target_hash = reproduction_value_sha256(target_payload[field])
            reproduced_hash = reproduction_value_sha256(reproduced_payload[field])
            if target_hash == reproduced_hash:
                continue
            discrepancies.append(
                ReproductionDiscrepancyRecord(
                    discrepancy_id=reproduction_discrepancy_id(
                        scenario_id,
                        repetition,
                        field,
                        target_hash,
                        reproduced_hash,
                    ),
                    scenario_id=scenario_id,
                    repetition=repetition,
                    field=field,
                    target_value_sha256=target_hash,
                    reproduced_value_sha256=reproduced_hash,
                    classification=(
                        ReproductionDiscrepancyClassification.EXPECTED_AGENT_VARIANCE_MODAL_STABLE
                    ),
                )
            )
    return tuple(discrepancies)


def _machine_workflow_paths(
    evidence: MachineWorkflowEvidencePaths,
) -> tuple[Path, Path, Path, Path]:
    """Return every private path consumed by one machine-workflow verification."""
    return (
        evidence.identity_artifact,
        evidence.attestation,
        evidence.signature,
        evidence.allowed_signers,
    )


def _verify_receipt_machine_workflow(
    receipt: VerifiedArtifactReceipt,
    evidence: MachineWorkflowEvidencePaths,
    *,
    label: Literal["target", "reproduced"],
) -> VerifiedMachineWorkflowAttestation:
    """Verify signed machine evidence against exact config and report snapshots."""
    metadata = receipt.report.benchmark_metadata
    if metadata is None or metadata.stinger_commit is None:
        raise ReproductionBuilderError(
            f"{label} report lacks the commit required by machine workflow evidence"
        )
    try:
        with tempfile.TemporaryDirectory(
            prefix=f"stinger-reproduction-{label}-machine-"
        ) as temporary:
            root = Path(temporary)
            config = root / "config.resolved.json"
            report = root / "report.json"
            config.write_bytes(receipt.escrow_bundle.config_bytes)
            report.write_bytes(receipt.public_bundle.report_bytes)
            return verify_machine_workflow_attestation(
                machine_identity_artifact=evidence.identity_artifact,
                workflow_input=config,
                workflow_receipt=report,
                attestation=evidence.attestation,
                signature=evidence.signature,
                allowed_signers=evidence.allowed_signers,
                signer_identity=evidence.signer_identity,
                expected_stinger_commit=metadata.stinger_commit,
            )
    except MachineAttestationError as exc:
        raise ReproductionBuilderError(
            f"{label} signed machine workflow evidence failed verification"
        ) from exc


def _require_independent_machine_workflows(
    target: VerifiedMachineWorkflowAttestation,
    reproduced: VerifiedMachineWorkflowAttestation,
    *,
    target_fingerprint: str,
    reproduced_fingerprint: str,
) -> None:
    """Require distinct environment commitments and separately trusted authorities.

    These checks establish independently signed operating-system environment pseudonyms.
    They deliberately preserve :data:`MACHINE_ENVIRONMENT_CLAIM_BOUNDARY`: neither
    pseudonym is TPM, physical-hardware, cloud-provider, organizational-independence, or
    anti-cloning proof.
    """
    if (
        target.statement.claim_boundary != MACHINE_ENVIRONMENT_CLAIM_BOUNDARY
        or reproduced.statement.claim_boundary != MACHINE_ENVIRONMENT_CLAIM_BOUNDARY
        or target_fingerprint != target.statement.machine_identity_sha256
        or reproduced_fingerprint != reproduced.statement.machine_identity_sha256
    ):
        raise ReproductionBuilderError(
            "derived machine fingerprints do not match signed workflow evidence"
        )
    if (
        target_fingerprint == reproduced_fingerprint
        or target.statement.host_identity_commitment_sha256
        == reproduced.statement.host_identity_commitment_sha256
    ):
        raise ReproductionBuilderError(
            "target and reproduced host commitments and machine fingerprints must differ"
        )
    if (
        target.signer_identity == reproduced.signer_identity
        or target.signing_key_fingerprint == reproduced.signing_key_fingerprint
        or target.allowed_signers_sha256 == reproduced.allowed_signers_sha256
    ):
        raise ReproductionBuilderError(
            "target and reproduced machine-attestation signer identity, key, and trust "
            "policy must all differ"
        )


def _cross_bind_protocol_trust(
    target: VerifiedArtifactReceipt,
    reproduced: VerifiedArtifactReceipt,
) -> None:
    """Require both separately verified runs to use one frozen protocol trust root."""
    if (
        target.protocol != compiled_benchmark_protocol()
        or target.public_bundle.protocol_bytes != reproduced.public_bundle.protocol_bytes
        or target.public_bundle.protocol_signature_bytes
        != reproduced.public_bundle.protocol_signature_bytes
        or target.public_bundle.allowed_signers_bytes
        != reproduced.public_bundle.allowed_signers_bytes
        or target.public_bundle.manifest.protocol_signer_identity
        != reproduced.public_bundle.manifest.protocol_signer_identity
        or target.protocol != reproduced.protocol
    ):
        raise ReproductionBuilderError(
            "target and reproduced evidence use different protocol trust"
        )


def _require_distinct_evidence_paths(
    target_public: Path,
    target_escrow: Path,
    reproduced_public: Path,
    reproduced_escrow: Path,
) -> None:
    """Reject target/reproduced path aliasing while allowing equal verified bytes."""
    target_paths = {
        target_public.resolve(strict=False),
        target_escrow.resolve(strict=False),
    }
    reproduced_paths = {
        reproduced_public.resolve(strict=False),
        reproduced_escrow.resolve(strict=False),
    }
    if target_paths & reproduced_paths:
        raise ReproductionBuilderError(
            "target and reproduced evidence must use distinct bundle paths"
        )


def _require_distinguishable_evidence(
    target: VerifiedArtifactReceipt,
    reproduced: VerifiedArtifactReceipt,
) -> None:
    """Reject copied target evidence even when it was placed under different paths."""
    if (
        target.public_bundle.manifest_sha256 == reproduced.public_bundle.manifest_sha256
        or target.escrow_bundle.manifest_sha256 == reproduced.escrow_bundle.manifest_sha256
        or target.public_bundle.report_bytes == reproduced.public_bundle.report_bytes
        or canonical_report_sha256(target.report) == canonical_report_sha256(reproduced.report)
    ):
        raise ReproductionBuilderError(
            "reproduced evidence is indistinguishable from the target run"
        )


def _require_output_separate_from_inputs(
    output: Path,
    input_paths: tuple[Path, ...],
) -> None:
    """Keep builder publication outside every verified or private input tree."""
    resolved_output = output.resolve(strict=False)
    for input_path in input_paths:
        resolved_input = input_path.resolve(strict=False)
        if resolved_output == resolved_input or resolved_input in resolved_output.parents:
            raise ReproductionBuilderError(
                "output directory must be separate from every input path"
            )


def _require_publication_corpus_shape(
    corpus: SealedCorpusRecord,
    protocol: BenchmarkProtocolManifest,
) -> None:
    """Require the exact frozen 120-scenario, 24-per-family publication shape."""
    total_scenarios = protocol.total_scenarios
    scenarios_per_family = protocol.scenarios_per_family
    if total_scenarios != 120 or scenarios_per_family != 24:
        raise ReproductionBuilderError("active protocol does not describe Benchmark v1 scale")
    scenario_ids = [scenario.scenario_id for scenario in corpus.scenarios]
    cluster_ids = [scenario.cluster_id for scenario in corpus.scenarios]
    family_counts = Counter(scenario.family for scenario in corpus.scenarios)
    size_counts = Counter(
        (scenario.family, scenario.repository_size) for scenario in corpus.scenarios
    )
    if (
        len(scenario_ids) != total_scenarios
        or len(set(scenario_ids)) != total_scenarios
        or len(set(cluster_ids)) != total_scenarios
        or any(family_counts[family] != scenarios_per_family for family in Family)
        or any(
            size_counts[(family, repository_size)] != protocol.repositories_per_size_per_family
            for family in Family
            for repository_size in RepositorySize
        )
    ):
        raise ReproductionBuilderError(
            "sealed corpus does not have the required independent 120-scenario strata"
        )


def _verify_receipt_report_signature(
    receipt: VerifiedArtifactReceipt,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> ArtifactSignatureVerification:
    """Verify OpenSSH against the exact report bytes retained by the bundle receipt."""
    with tempfile.TemporaryDirectory(prefix="stinger-reproduced-report-") as temporary:
        report = Path(temporary) / "report.json"
        report.write_bytes(receipt.public_bundle.report_bytes)
        report.chmod(0o600)
        try:
            verification = verify_reproduced_report_signature(
                report,
                signature,
                allowed_signers,
                identity,
            )
        except ProtocolSignatureError as exc:
            raise ReproductionBuilderError(
                "reproduced report signature verification failed"
            ) from exc
    if verification.artifact_sha256 != _sha256(receipt.public_bundle.report_bytes):
        raise ReproductionBuilderError(
            "reproduced report signature does not bind verified report bytes"
        )
    return verification


def _reject_unknown_report_fields(content: bytes, *, label: str) -> None:
    """Reject ignored JSON fields without changing the normative report schema."""
    try:
        raw = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReproductionBuilderError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(raw, dict):
        raise ReproductionBuilderError(f"{label} root must be a JSON object")
    _require_known_keys(raw, Report, label=label)
    results = raw.get("results")
    if not isinstance(results, list):
        raise ReproductionBuilderError(f"{label} results must be a list")
    for result in results:
        if not isinstance(result, dict):
            raise ReproductionBuilderError(f"{label} result must be an object")
        _require_known_keys(result, ScenarioResult, label=label)
        detector_results = result.get("detector_results")
        if not isinstance(detector_results, list):
            raise ReproductionBuilderError(f"{label} detector results must be a list")
        for detector in detector_results:
            if not isinstance(detector, dict):
                raise ReproductionBuilderError(f"{label} detector result must be an object")
            _require_known_keys(detector, DetectorResult, label=label)
    family_scores = raw.get("family_scores")
    if not isinstance(family_scores, dict):
        raise ReproductionBuilderError(f"{label} family scores must be an object")
    for score in family_scores.values():
        if not isinstance(score, dict):
            raise ReproductionBuilderError(f"{label} family score must be an object")
        _require_known_keys(score, FamilyScore, label=label)
    judge = raw.get("judge_assisted")
    if judge is not None:
        if not isinstance(judge, dict):
            raise ReproductionBuilderError(f"{label} judge block must be an object")
        _require_known_keys(judge, JudgeReport, label=label)


def _require_known_keys(
    raw: Mapping[str, object],
    model: type[BaseModel],
    *,
    label: str,
) -> None:
    """Reject keys Pydantic's legacy report models would otherwise ignore."""
    if not set(raw).issubset(model.model_fields):
        raise ReproductionBuilderError(f"{label} contains unknown fields")


def _read_regular_bytes(path: Path, *, label: str) -> bytes:
    """Read exact bytes from a nonempty regular nonsymlink file without FIFO blocking."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReproductionBuilderError(
            f"{label} must be a readable regular nonsymlink file"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ReproductionBuilderError(f"{label} must be a readable regular nonsymlink file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    content = b"".join(chunks)
    if not content:
        raise ReproductionBuilderError(f"{label} must not be empty")
    return content


def _reject_sensitive_outputs(
    models: tuple[BaseModel, ...],
    *,
    sensitive_paths: tuple[Path, ...],
    sensitive_markers: tuple[str | bytes, ...],
) -> None:
    """Reject private paths, canaries, or bait values before output publication."""
    values = tuple(_string_values(model.model_dump(mode="python")) for model in models)
    flattened = tuple(value for group in values for value in group)
    path_markers: set[str] = set()
    for path in sensitive_paths:
        for candidate in (path, path.absolute(), path.resolve(strict=False)):
            text = str(candidate)
            if text and text not in {".", "/"}:
                path_markers.add(text)
    if any(marker in value for marker in path_markers for value in flattened):
        raise ReproductionBuilderError("builder output contains sensitive material")
    for marker in sensitive_markers:
        if isinstance(marker, bytes):
            try:
                text_marker = marker.decode("utf-8")
            except UnicodeDecodeError:
                continue
        else:
            text_marker = marker
        if text_marker and any(text_marker in value for value in flattened):
            raise ReproductionBuilderError("builder output contains sensitive material")


def _string_values(value: object) -> list[str]:
    """Collect mapping keys and values from JSON-shaped output models."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [
            string for child in (*value.keys(), *value.values()) for string in _string_values(child)
        ]
    if isinstance(value, (list, tuple)):
        return [string for child in value for string in _string_values(child)]
    return []


def _discrepancy_ledger_bytes(
    discrepancies: tuple[ReproductionDiscrepancyRecord, ...],
    *,
    target_report_sha256: str,
    reproduced_report_sha256: str,
) -> bytes:
    """Serialize the exact canonical payload hashed by the public ledger helper."""
    ordered = tuple(
        sorted(
            discrepancies,
            key=lambda item: (
                item.scenario_id,
                item.repetition,
                item.field,
                item.discrepancy_id,
            ),
        )
    )
    return _canonical_payload_bytes(
        {
            "target_report_sha256": target_report_sha256,
            "reproduced_report_sha256": reproduced_report_sha256,
            "discrepancies": [item.model_dump(mode="json") for item in ordered],
        }
    )


def _canonical_model_bytes(model: BaseModel) -> bytes:
    """Serialize one closed model in canonical JSON with a final newline."""
    return _canonical_payload_bytes(model.model_dump(mode="json")) + b"\n"


def _canonical_payload_bytes(payload: object) -> bytes:
    """Serialize JSON without incidental whitespace or key-order dependence."""
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(content: bytes) -> str:
    """Return the lowercase SHA-256 digest of exact bytes."""
    return hashlib.sha256(content).hexdigest()


def _require_identifier(value: str, *, label: str) -> None:
    """Require one stable nonblank identifier without whitespace ambiguity."""
    if (
        not value.strip()
        or value != value.strip()
        or any(character.isspace() for character in value)
    ):
        raise ReproductionBuilderError(f"{label} must be a nonblank identifier without whitespace")


def _atomic_create_file(destination: Path, content: bytes) -> None:
    """Create a canonical file exactly once using a same-directory hard-link publish."""
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ReproductionBuilderError("output parent must be an existing real directory")
    if destination.is_symlink() or destination.exists():
        raise ReproductionBuilderError("output path already exists")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise ReproductionBuilderError("output path already exists") from exc
        _fsync_directory(parent)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_create_directory(
    destination: Path,
    files: Mapping[str, bytes],
) -> None:
    """Publish a complete scanned output directory with one atomic rename."""
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ReproductionBuilderError("output parent must be an existing real directory")
    if destination.is_symlink() or destination.exists():
        raise ReproductionBuilderError("output directory already exists")
    staging = Path(
        tempfile.mkdtemp(
            dir=parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
    )
    try:
        staging.chmod(0o700)
        for name, content in sorted(files.items()):
            if "/" in name or name in {"", ".", ".."}:
                raise ReproductionBuilderError("output artifact name is unsafe")
            path = staging / name
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        _fsync_directory(staging)
        _rename_directory_noreplace(staging, destination)
        _fsync_directory(parent)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def _rename_directory_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish a directory while refusing every existing destination."""
    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin":
        rename = library.renamex_np
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(source_bytes, destination_bytes, 0x00000004)
    elif sys.platform.startswith("linux"):
        try:
            rename = library.renameat2
        except AttributeError as exc:
            raise ReproductionBuilderError(
                "atomic create-only directory publication is unavailable"
            ) from exc
        rename.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename.restype = ctypes.c_int
        result = rename(-100, source_bytes, -100, destination_bytes, 0x00000001)
    else:
        raise ReproductionBuilderError("atomic create-only directory publication is unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ReproductionBuilderError("output directory already exists")
    raise ReproductionBuilderError("could not atomically publish output directory") from OSError(
        error_number,
        os.strerror(error_number),
    )


def _fsync_directory(path: Path) -> None:
    """Persist directory entries before returning a completed builder artifact."""
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
