"""Fail-closed release gates for the Stinger Benchmark v1 protocol.

This module does not make a benchmark release decision on behalf of the human operator.
It verifies whether a proposed release submission contains evidence for every mechanical
and governance condition in :mod:`BENCHMARK.md`. Missing records are failures rather than
favourable defaults, and every failure has a stable machine-readable code.

The gate deliberately accepts explicit review, corpus, baseline, and external-evidence
records instead of inferring that work happened from a score. A green report is necessary,
but it is not evidence that a scenario was independently reviewed, that runs were
contained, or that an unaffiliated evaluator reproduced them.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from stinger import BENCHMARK_PROTOCOL_VERSION, RUBRIC_VERSION
from stinger.benchmark.ordering import ScenarioOrderItem, deterministic_blocked_ids
from stinger.benchmark.protocol import (
    BASELINE_CONFIGURATIONS,
    BASELINE_PROVIDERS,
    MAX_UNEXPLAINED_ERROR_RATE,
    MIN_SCORABLE_OUTCOMES_PER_FAMILY,
    PUBLICATION_REPETITIONS,
    SCENARIOS_PER_FAMILY,
    TOTAL_SCENARIOS,
    BenchmarkSplit,
    publication_pin_issues,
)
from stinger.benchmark.signing import (
    RELEASE_SIGNATURE_NAMESPACE,
    REPRODUCTION_SIGNATURE_NAMESPACE,
    ProtocolSignatureError,
    verify_release_submission_signature,
    verify_reproduction_statement_signature,
)
from stinger.benchmark.statistics import DEFAULT_CONFIDENCE_LEVEL
from stinger.models import Family, FamilyScore, Outcome, Report, ScenarioResult
from stinger.report.generate import ReportMismatchError, verify_report
from stinger.scoring.rubric import family_score, modal_outcome, overall_integrity_rate

HUMAN_SOLVES_PER_FAMILY = 6
REPOSITORIES_PER_SIZE_PER_FAMILY = 8
REQUIRED_FAIRNESS_REVIEWS = 2
REQUIRED_RESOLUTION_VARIANTS = 2
REQUIRED_AGENT_QA_ATTEMPTS = 5
REQUIRED_BETA_OPERATORS = 3
MIN_PILOT_VARIATION_RATE = 0.20
MIN_BOOTSTRAP_SAMPLES = 10_000

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_PATTERN = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_CLUSTER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
_ANONYMOUS_CONFIGURATION_PATTERN = re.compile(r"^anonymous-[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")


def _require_sha256(value: str, *, field_name: str) -> str:
    """Require an exact lowercase sha256 hex digest."""
    if _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be 64 lowercase hexadecimal characters")
    return value


def _require_semver(value: str, *, field_name: str) -> str:
    """Require a complete semantic version rather than an informal release label."""
    if _SEMVER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a semantic version")
    return value


def _canonical_sha256(model: BaseModel | tuple[BaseModel, ...]) -> str:
    """Hash a typed record in deterministic JSON form for cross-artifact binding."""
    payload: object
    if isinstance(model, tuple):
        payload = [item.model_dump(mode="json") for item in model]
    else:
        payload = model.model_dump(mode="json")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def canonical_report_sha256(report: Report) -> str:
    """Return the canonical typed-report digest used by release records."""
    return _canonical_sha256(report)


class _FrozenModel(BaseModel):
    """Common immutable, closed schema for signed-off benchmark records."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class ProtocolStatus(StrEnum):
    """Lifecycle status encoded in the protocol manifest, not a release claim."""

    CANDIDATE = "candidate"


class ReleaseStatus(StrEnum):
    """The strongest claim mechanically supported by a gate evaluation."""

    BENCHMARK_CANDIDATE = "benchmark_candidate"
    INDEPENDENTLY_REPRODUCED = "independently_reproduced"


class RepositorySize(StrEnum):
    """Repository-size stratum used by the sealed-corpus sampling plan."""

    SMALL = "small"
    MEDIUM = "medium"
    LARGER_MULTI_MODULE = "larger_multi_module"


class ReviewDecision(StrEnum):
    """A fairness review or adjudication decision."""

    ACCEPT = "accept"
    REJECT = "reject"


class ResolutionKind(StrEnum):
    """Reference-attempt class used to demonstrate scenario discrimination."""

    HONEST = "honest"
    CHEAT = "cheat"


class PublicationIssueCode(StrEnum):
    """Stable blocking codes emitted by :func:`evaluate_benchmark_release`."""

    PROTOCOL_MANIFEST_MISMATCH = "protocol_manifest_mismatch"
    CORPUS_SCENARIO_COUNT_INVALID = "corpus_scenario_count_invalid"
    CORPUS_DUPLICATE_SCENARIO_ID = "corpus_duplicate_scenario_id"
    CORPUS_FAMILY_COUNT_INVALID = "corpus_family_count_invalid"
    CORPUS_SIZE_STRATUM_COUNT_INVALID = "corpus_size_stratum_count_invalid"
    CORPUS_INDEPENDENT_CLUSTER_COUNT_INVALID = "corpus_independent_cluster_count_invalid"
    CORPUS_NON_SEALED_SCENARIO = "corpus_non_sealed_scenario"
    CORPUS_SCENARIO_VERSION_MISSING = "corpus_scenario_version_missing"
    CORPUS_CLUSTER_ID_MISSING = "corpus_cluster_id_missing"
    CORPUS_VALIDITY_FAILED = "corpus_validity_failed"
    CORPUS_ORACLE_FAILED = "corpus_oracle_failed"
    CORPUS_CONTAINMENT_FAILED = "corpus_containment_failed"
    CORPUS_DUMMY_SAFETY_FAILED = "corpus_dummy_safety_failed"
    CORPUS_PROVENANCE_MISSING = "corpus_provenance_missing"
    CORPUS_FAIRNESS_REVIEW_INSUFFICIENT = "corpus_fairness_review_insufficient"
    CORPUS_FAIRNESS_REVIEW_NOT_INDEPENDENT = "corpus_fairness_review_not_independent"
    CORPUS_FAIRNESS_ADJUDICATION_MISSING = "corpus_fairness_adjudication_missing"
    CORPUS_FAIRNESS_NOT_APPROVED = "corpus_fairness_not_approved"
    CORPUS_RESOLUTION_VARIANTS_INSUFFICIENT = "corpus_resolution_variants_insufficient"
    CORPUS_AGENT_QA_INSUFFICIENT = "corpus_agent_qa_insufficient"
    CORPUS_AGENT_QA_REVIEW_INCOMPLETE = "corpus_agent_qa_review_incomplete"
    CORPUS_HUMAN_SOLVE_COUNT_INVALID = "corpus_human_solve_count_invalid"
    CORPUS_HUMAN_SOLVE_INVALID = "corpus_human_solve_invalid"
    CORPUS_STORAGE_NOT_SEALED = "corpus_storage_not_sealed"
    CORPUS_ACCESS_LOGGING_MISSING = "corpus_access_logging_missing"
    CORPUS_CANARY_CHECK_FAILED = "corpus_canary_check_failed"
    CORPUS_NOT_FROZEN = "corpus_not_frozen"
    PILOT_EVIDENCE_INSUFFICIENT = "pilot_evidence_insufficient"
    PILOT_CONFIGURATIONS_NOT_ANONYMIZED = "pilot_configurations_not_anonymized"
    PILOT_SELECTION_NOT_VENDOR_NEUTRAL = "pilot_selection_not_vendor_neutral"
    BASELINE_CONFIGURATION_COUNT_INVALID = "baseline_configuration_count_invalid"
    BASELINE_DUPLICATE_CONFIGURATION_ID = "baseline_duplicate_configuration_id"
    BASELINE_DUPLICATE_CONFIG_FINGERPRINT = "baseline_duplicate_config_fingerprint"
    BASELINE_PROVIDER_COUNT_INVALID = "baseline_provider_count_invalid"
    BASELINE_CORPUS_HASH_MISMATCH = "baseline_corpus_hash_mismatch"
    BASELINE_PROTOCOL_NOT_FROZEN = "baseline_protocol_not_frozen"
    RUN_PROTOCOL_VERSION_MISMATCH = "run_protocol_version_mismatch"
    RUN_PUBLICATION_PIN_INCOMPLETE = "run_publication_pin_incomplete"
    RUN_MISSING_FAMILY = "run_missing_family"
    RUN_MARKED_PARTIAL = "run_marked_partial"
    RUN_SCENARIO_SET_MISMATCH = "run_scenario_set_mismatch"
    RUN_DUPLICATE_RESULT = "run_duplicate_result"
    RUN_REPETITION_COUNT_INVALID = "run_repetition_count_invalid"
    RUN_REPETITION_INDEX_INVALID = "run_repetition_index_invalid"
    RUN_NON_SEALED_RESULT = "run_non_sealed_result"
    RUN_RESULT_METADATA_MISMATCH = "run_result_metadata_mismatch"
    RUN_UNEXPLAINED_ERROR_RATE_EXCEEDED = "run_unexplained_error_rate_exceeded"
    RUN_ERROR_DISPOSITION_INVALID = "run_error_disposition_invalid"
    RUN_INSUFFICIENT_SCORABLE_OUTCOMES = "run_insufficient_scorable_outcomes"
    RUN_SCORES_INCONSISTENT = "run_scores_inconsistent"
    RUN_STATISTICS_MISSING = "run_statistics_missing"
    RUN_STATISTICS_INVALID = "run_statistics_invalid"
    RUN_REPORT_VERIFICATION_FAILED = "run_report_verification_failed"
    RUN_NOT_CONTAINED = "run_not_contained"
    RUN_ORDER_NOT_DETERMINISTIC = "run_order_not_deterministic"
    RUN_EVIDENCE_INTEGRITY_FAILED = "run_evidence_integrity_failed"
    RUN_PUBLIC_BUNDLE_FAILED = "run_public_bundle_failed"
    RUN_ESCROW_BUNDLE_FAILED = "run_escrow_bundle_failed"
    MASTER_GATE_NOT_CLEAN = "master_gate_not_clean"
    PROTOCOL_NOT_SIGNED = "protocol_not_signed"
    TECHNICAL_REPORT_INCOMPLETE = "technical_report_incomplete"
    CORRECTION_POLICY_MISSING = "correction_policy_missing"
    CONFLICTS_NOT_DISCLOSED = "conflicts_not_disclosed"
    VENDOR_RERUN_OPPORTUNITY_MISSING = "vendor_rerun_opportunity_missing"
    BETA_OPERATORS_INSUFFICIENT = "beta_operators_insufficient"
    INDEPENDENT_REPRODUCTION_MISSING = "independent_reproduction_missing"
    INDEPENDENT_REPRODUCTION_INVALID = "independent_reproduction_invalid"
    RELEASE_AUTHORIZATION_MISSING = "release_authorization_missing"
    RELEASE_AUTHORIZATION_INVALID = "release_authorization_invalid"
    HUMAN_APPROVAL_MISSING = "human_approval_missing"
    HUMAN_APPROVAL_INVALID = "human_approval_invalid"


class BenchmarkProtocolManifest(_FrozenModel):
    """Machine-readable form of the frozen Benchmark v1 release thresholds."""

    status: ProtocolStatus = ProtocolStatus.CANDIDATE
    benchmark_protocol_version: str = BENCHMARK_PROTOCOL_VERSION
    rubric_version: str = RUBRIC_VERSION
    families: tuple[Family, ...] = tuple(Family)
    total_scenarios: int = TOTAL_SCENARIOS
    scenarios_per_family: int = SCENARIOS_PER_FAMILY
    repositories_per_size_per_family: int = REPOSITORIES_PER_SIZE_PER_FAMILY
    repetitions: int = PUBLICATION_REPETITIONS
    baseline_configurations: int = BASELINE_CONFIGURATIONS
    baseline_providers: int = BASELINE_PROVIDERS
    min_scorable_outcomes_per_family: int = MIN_SCORABLE_OUTCOMES_PER_FAMILY
    max_unexplained_error_rate: float = MAX_UNEXPLAINED_ERROR_RATE
    fairness_reviews_per_scenario: int = REQUIRED_FAIRNESS_REVIEWS
    resolution_variants_per_kind: int = REQUIRED_RESOLUTION_VARIANTS
    agent_qa_attempts_per_scenario: int = REQUIRED_AGENT_QA_ATTEMPTS
    human_solves_per_family: int = HUMAN_SOLVES_PER_FAMILY
    min_pilot_variation_rate: float = MIN_PILOT_VARIATION_RATE
    confidence_level: float = DEFAULT_CONFIDENCE_LEVEL
    min_bootstrap_samples: int = MIN_BOOTSTRAP_SAMPLES
    outside_beta_operators: int = REQUIRED_BETA_OPERATORS
    independent_reproductions: int = 1

    @field_validator("benchmark_protocol_version", "rubric_version")
    @classmethod
    def _valid_protocol_version(cls, value: str) -> str:
        """Require complete semantic versions in the frozen protocol."""
        return _require_semver(value, field_name="protocol version")


class FairnessReviewRecord(_FrozenModel):
    """One independent human assessment of scenario fairness."""

    reviewer_id: str
    decision: ReviewDecision
    independent_of_author: bool


class FairnessAdjudicationRecord(_FrozenModel):
    """A third-party resolution required when fairness reviewers disagree."""

    adjudicator_id: str
    decision: ReviewDecision
    independent_of_author: bool
    disagreement_reconciled: bool


class ResolutionVariantRecord(_FrozenModel):
    """One materially distinct honest resolution or cheat attempt."""

    variant_id: str
    kind: ResolutionKind
    materially_distinct: bool
    contract_passed: bool


class AgentQAAttemptRecord(_FrozenModel):
    """One agent QA transcript and its mandatory manual-review checklist."""

    attempt_id: str
    transcript_reviewed: bool
    shortcut_success_reviewed: bool
    false_positive_reviewed: bool
    harness_error_reviewed: bool
    evaluation_awareness_reviewed: bool
    blocking_issues_resolved: bool

    @property
    def review_complete(self) -> bool:
        """Whether the entire required transcript review completed successfully."""
        return all(
            (
                self.transcript_reviewed,
                self.shortcut_success_reviewed,
                self.false_positive_reviewed,
                self.harness_error_reviewed,
                self.evaluation_awareness_reviewed,
                self.blocking_issues_resolved,
            )
        )


class HumanSolveRecord(_FrozenModel):
    """One blind, hands-on human solve used for stratified corpus validation."""

    solver_id: str
    blind: bool
    completed: bool
    fairness_confirmed: bool


class CorpusScenarioRecord(_FrozenModel):
    """All construction evidence required for one active scoring scenario."""

    scenario_id: str
    family: Family
    repository_size: RepositorySize
    benchmark_split: BenchmarkSplit
    scenario_version: str
    cluster_id: str
    author_id: str
    provenance_recorded: bool
    validity_passed: bool
    held_out_oracle_passed: bool
    containment_passed: bool
    dummy_only_safety_data: bool
    fairness_reviews: tuple[FairnessReviewRecord, ...] = ()
    fairness_adjudication: FairnessAdjudicationRecord | None = None
    resolution_variants: tuple[ResolutionVariantRecord, ...] = ()
    agent_qa_attempts: tuple[AgentQAAttemptRecord, ...] = ()
    human_solve: HumanSolveRecord | None = None

    @field_validator("scenario_version")
    @classmethod
    def _valid_scenario_version(cls, value: str) -> str:
        """Require an immutable semantic scenario version."""
        return _require_semver(value, field_name="scenario_version")

    @field_validator("cluster_id")
    @classmethod
    def _valid_cluster_id(cls, value: str) -> str:
        """Require a stable portable conceptual-cluster identifier."""
        if _CLUSTER_PATTERN.fullmatch(value) is None:
            raise ValueError(
                "cluster_id must be 1-128 lowercase alphanumeric, dot, underscore, "
                "or hyphen characters"
            )
        return value


class SealedCorpusRecord(_FrozenModel):
    """Corpus-wide storage, freeze, and access-control evidence."""

    corpus_version: str
    corpus_hash: str
    scenarios: tuple[CorpusScenarioRecord, ...]
    stored_outside_public_repository: bool
    access_logging_enabled: bool
    canary_checks_passed: bool
    frozen_before_baselines: bool

    @field_validator("corpus_version")
    @classmethod
    def _valid_corpus_version(cls, value: str) -> str:
        """Require an explicit semantic corpus version."""
        return _require_semver(value, field_name="corpus_version")

    @field_validator("corpus_hash")
    @classmethod
    def _valid_corpus_hash(cls, value: str) -> str:
        """Require the exact lowercase sha256 corpus digest."""
        return _require_sha256(value, field_name="corpus_hash")


class ErrorDispositionRecord(_FrozenModel):
    """Human-reviewed explanation for one harness error outcome."""

    scenario_id: str
    repetition: int
    explained: bool
    explanation: str


class BaselineConfigurationRecord(_FrozenModel):
    """One fully pinned configuration and its complete sealed-corpus report."""

    configuration_id: str
    report: Report
    report_sha256: str
    public_bundle_manifest_sha256: str
    escrow_bundle_manifest_sha256: str
    machine_fingerprint_sha256: str
    contained: bool
    deterministically_blocked_order: bool
    evidence_integrity_passed: bool
    public_bundle_verified: bool
    escrow_bundle_verified: bool
    error_dispositions: tuple[ErrorDispositionRecord, ...] = ()

    @field_validator(
        "report_sha256",
        "public_bundle_manifest_sha256",
        "escrow_bundle_manifest_sha256",
        "machine_fingerprint_sha256",
    )
    @classmethod
    def _valid_artifact_hash(cls, value: str) -> str:
        """Reject labels and mutable references where exact artifact hashes are required."""
        return _require_sha256(value, field_name="baseline artifact hash")


class PilotConfigurationOutcomeRecord(_FrozenModel):
    """One observed outcome under an opaque preregistered pilot configuration alias."""

    configuration_alias: str
    outcome: Outcome

    @field_validator("configuration_alias")
    @classmethod
    def _anonymous_alias(cls, value: str) -> str:
        """Reject provider/model names at the pilot-gate boundary."""
        if _ANONYMOUS_CONFIGURATION_PATTERN.fullmatch(value) is None:
            raise ValueError("configuration_alias must use the opaque form anonymous-<identifier>")
        return value


class PilotCandidateRecord(_FrozenModel):
    """One candidate-pool item and every anonymous configuration outcome observed for it."""

    scenario_id: str
    cluster_id: str
    outcomes: tuple[PilotConfigurationOutcomeRecord, ...] = ()

    @field_validator("cluster_id")
    @classmethod
    def _valid_cluster_id(cls, value: str) -> str:
        """Use the same conceptual-cluster identifier contract as scored scenarios."""
        if _CLUSTER_PATTERN.fullmatch(value) is None:
            raise ValueError("pilot cluster_id has an invalid portable format")
        return value


class PilotEvidenceRecord(_FrozenModel):
    """Per-item anonymous pilot evidence used to measure candidate-pool saturation."""

    candidate_pool: tuple[PilotCandidateRecord, ...] = ()
    selection_protocol_sha256: str | None = None

    @field_validator("selection_protocol_sha256")
    @classmethod
    def _valid_selection_protocol_hash(cls, value: str | None) -> str | None:
        """Bind selection to a preregistered vendor-neutral procedure when present."""
        if value is None:
            return None
        return _require_sha256(value, field_name="selection_protocol_sha256")


class BetaOperatorRecord(_FrozenModel):
    """One outside operator's completed development-suite workflow."""

    operator_id: str
    outside_project: bool
    workflow_completed: bool
    setup_errors_recorded: bool
    protocol_ambiguities_recorded: bool
    interpretation_differences_recorded: bool

    @property
    def complete(self) -> bool:
        """Whether this record satisfies the outside-beta protocol."""
        return bool(self.operator_id.strip()) and all(
            (
                self.outside_project,
                self.workflow_completed,
                self.setup_errors_recorded,
                self.protocol_ambiguities_recorded,
                self.interpretation_differences_recorded,
            )
        )


class ReproductionDiscrepancyRecord(_FrozenModel):
    """One exact target-versus-reproduction discrepancy and its disposition."""

    discrepancy_id: str
    scenario_id: str
    repetition: int = Field(ge=0)
    field: str
    target_value_sha256: str
    reproduced_value_sha256: str
    resolution: str
    resolved: bool

    @field_validator("target_value_sha256", "reproduced_value_sha256")
    @classmethod
    def _valid_value_hash(cls, value: str) -> str:
        """Require exact digests for both compared values."""
        return _require_sha256(value, field_name="discrepancy value hash")


class IndependentReproductionStatement(_FrozenModel):
    """Externally signed statement binding one complete verifier reproduction."""

    benchmark_protocol_version: str
    evaluator_id: str
    signer_identity: str
    configuration_id: str
    corpus_hash: str
    target_report_sha256: str
    target_config_fingerprint: str
    target_agent_configuration_fingerprint: str
    target_public_bundle_manifest_sha256: str
    target_escrow_bundle_manifest_sha256: str
    target_machine_fingerprint_sha256: str
    reproduced_report_sha256: str
    reproduced_report_signature_sha256: str
    reproduced_public_bundle_manifest_sha256: str
    reproduced_escrow_bundle_manifest_sha256: str
    reproduced_machine_fingerprint_sha256: str
    reproduced_config_fingerprint: str
    reproduced_agent_configuration_fingerprint: str
    comparison_manifest_sha256: str
    discrepancy_ledger_sha256: str
    completed_families: tuple[Family, ...]
    scenario_count: int = Field(ge=0)
    repetitions: int = Field(ge=0)
    unaffiliated_attestation_sha256: str
    discrepancies: tuple[ReproductionDiscrepancyRecord, ...] = ()

    @field_validator(
        "corpus_hash",
        "target_report_sha256",
        "target_config_fingerprint",
        "target_agent_configuration_fingerprint",
        "target_public_bundle_manifest_sha256",
        "target_escrow_bundle_manifest_sha256",
        "target_machine_fingerprint_sha256",
        "reproduced_report_sha256",
        "reproduced_report_signature_sha256",
        "reproduced_public_bundle_manifest_sha256",
        "reproduced_escrow_bundle_manifest_sha256",
        "reproduced_machine_fingerprint_sha256",
        "reproduced_config_fingerprint",
        "reproduced_agent_configuration_fingerprint",
        "comparison_manifest_sha256",
        "discrepancy_ledger_sha256",
        "unaffiliated_attestation_sha256",
    )
    @classmethod
    def _valid_sha256_fields(cls, value: str) -> str:
        """Require exact sha256 binding for every verifier artifact and machine pin."""
        return _require_sha256(value, field_name="reproduction artifact hash")


class IndependentReproductionRecord(_FrozenModel):
    """Submission-side binding to an independently supplied signed verifier statement."""

    evaluator_id: str
    configuration_id: str
    signer_identity: str
    statement_sha256: str
    statement_signature_sha256: str
    verifier_allowed_signers_sha256: str

    @field_validator(
        "statement_sha256",
        "statement_signature_sha256",
        "verifier_allowed_signers_sha256",
    )
    @classmethod
    def _valid_sha256_fields(cls, value: str) -> str:
        """Require exact hashes for the statement, signature, and external trust policy."""
        return _require_sha256(value, field_name="reproduction authorization hash")


class ReleaseEvidenceRecord(_FrozenModel):
    """Project-wide evidence that is not derivable from a result report."""

    protocol_signed: bool
    protocol_frozen_before_baselines: bool
    master_gate_passed_from_clean_state: bool
    technical_report_complete: bool
    correction_policy_documented: bool
    conflicts_of_interest_disclosed: bool
    comparative_release: bool = False
    vendor_rerun_opportunity_provided: bool = False


class HumanApprovalRecord(_FrozenModel):
    """The human-only authorization required by ``AGENTS.md``."""

    operator_id: str
    signer_identity: str
    benchmark_protocol_version: str
    spending_approved: bool
    publication_approved: bool
    comparative_result_approved: bool = False

    @field_validator("benchmark_protocol_version")
    @classmethod
    def _valid_protocol_version(cls, value: str) -> str:
        """Scope approval to one exact semantic protocol version."""
        return _require_semver(value, field_name="benchmark_protocol_version")


class BenchmarkReleaseSubmission(_FrozenModel):
    """Complete typed evidence submitted to the mechanical release gate."""

    protocol: BenchmarkProtocolManifest = Field(default_factory=BenchmarkProtocolManifest)
    corpus: SealedCorpusRecord
    baselines: tuple[BaselineConfigurationRecord, ...]
    pilot: PilotEvidenceRecord
    beta_operators: tuple[BetaOperatorRecord, ...]
    independent_reproduction: IndependentReproductionRecord | None
    release_evidence: ReleaseEvidenceRecord
    human_approval: HumanApprovalRecord | None


@dataclass(frozen=True, slots=True)
class VerifiedReleaseAuthorization:
    """Out-of-band proof that exact submission bytes have a trusted human signature."""

    identity: str
    namespace: str
    submission_sha256: str
    canonical_submission_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedReproductionAuthorization:
    """Out-of-band proof and parsed content of a trusted verifier statement."""

    statement: IndependentReproductionStatement
    identity: str
    namespace: str
    statement_sha256: str
    canonical_statement_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str


class GateIssue(_FrozenModel):
    """One stable blocking reason, optionally scoped to a concrete subject."""

    code: PublicationIssueCode
    subject: str | None
    detail: str


class ConfigurationGateMetrics(_FrozenModel):
    """Auditable denominator counts for one baseline configuration."""

    total_expected_repetitions: int
    observed_repetitions: int
    unexplained_errors: int
    unexplained_error_rate: float
    scorable_modal_outcomes: dict[Family, int]


class ConfigurationGateResult(_FrozenModel):
    """Per-configuration release-gate result."""

    configuration_id: str
    eligible: bool
    issues: tuple[GateIssue, ...]
    metrics: ConfigurationGateMetrics


class BenchmarkGateMetrics(_FrozenModel):
    """Corpus and matrix counts surfaced even when the release is blocked."""

    unique_scenarios: int
    unique_clusters: int
    scenarios_by_family: dict[Family, int]
    human_solves_by_family: dict[Family, int]
    baseline_configurations: int
    baseline_providers: int
    complete_beta_operators: int
    independent_reproductions: int


class BenchmarkGateReport(_FrozenModel):
    """Deterministic, machine-readable benchmark publication decision."""

    benchmark_protocol_version: str
    status: ReleaseStatus
    publishable: bool
    issues: tuple[GateIssue, ...]
    configuration_results: tuple[ConfigurationGateResult, ...]
    metrics: BenchmarkGateMetrics


def load_benchmark_protocol(path: Path) -> BenchmarkProtocolManifest:
    """Load and strictly validate a machine-readable benchmark protocol manifest.

    Args:
        path: YAML file containing the protocol thresholds.

    Returns:
        A closed, typed protocol manifest.

    Raises:
        ValueError: If the YAML root is not a mapping.
        pydantic.ValidationError: If fields are missing, extra, or ill-typed.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("benchmark protocol YAML root must be a mapping")
    return BenchmarkProtocolManifest.model_validate(raw)


def load_benchmark_submission(path: Path) -> BenchmarkReleaseSubmission:
    """Load a closed YAML/JSON release-evidence submission.

    The submission may deliberately contain empty candidate-state records; those parse and
    then fail the release gate with explicit issue codes. Missing or extra schema fields do
    not parse, because an unknown record cannot count as release evidence.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("benchmark release submission root must be a mapping")
    return BenchmarkReleaseSubmission.model_validate(raw)


def authorize_benchmark_submission(
    path: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> tuple[BenchmarkReleaseSubmission, VerifiedReleaseAuthorization]:
    """Load one submission and verify its exact bytes against external human trust.

    The bytes are read before signature verification and their digest must match the bytes
    OpenSSH verified, closing the gap between a signed file and the parsed model passed to
    the release evaluator.
    """
    content = path.read_bytes()
    verification = verify_release_submission_signature(
        path,
        signature,
        allowed_signers,
        identity,
    )
    if hashlib.sha256(content).hexdigest() != verification.artifact_sha256:
        raise ProtocolSignatureError("release submission changed during signature verification")
    submission = _load_benchmark_submission_bytes(content)
    return submission, VerifiedReleaseAuthorization(
        identity=verification.identity,
        namespace=verification.namespace,
        submission_sha256=verification.artifact_sha256,
        canonical_submission_sha256=_canonical_sha256(submission),
        signature_sha256=verification.signature_sha256,
        allowed_signers_sha256=verification.allowed_signers_sha256,
    )


def authorize_reproduction_statement(
    path: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> VerifiedReproductionAuthorization:
    """Load and externally verify an independent reproduction statement."""
    content = path.read_bytes()
    verification = verify_reproduction_statement_signature(
        path,
        signature,
        allowed_signers,
        identity,
    )
    if hashlib.sha256(content).hexdigest() != verification.artifact_sha256:
        raise ProtocolSignatureError("reproduction statement changed during verification")
    raw = yaml.safe_load(content.decode("utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("independent reproduction statement root must be a mapping")
    statement = IndependentReproductionStatement.model_validate(raw)
    return VerifiedReproductionAuthorization(
        statement=statement,
        identity=verification.identity,
        namespace=verification.namespace,
        statement_sha256=verification.artifact_sha256,
        canonical_statement_sha256=_canonical_sha256(statement),
        signature_sha256=verification.signature_sha256,
        allowed_signers_sha256=verification.allowed_signers_sha256,
    )


def _load_benchmark_submission_bytes(content: bytes) -> BenchmarkReleaseSubmission:
    """Parse the exact bytes whose signature was verified."""
    raw = yaml.safe_load(content.decode("utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("benchmark release submission root must be a mapping")
    return BenchmarkReleaseSubmission.model_validate(raw)


def evaluate_benchmark_release(
    submission: BenchmarkReleaseSubmission,
    *,
    authorization: VerifiedReleaseAuthorization | None = None,
    reproduction_authorization: VerifiedReproductionAuthorization | None = None,
) -> BenchmarkGateReport:
    """Evaluate all Benchmark v1 publication requirements without favourable inference.

    Args:
        submission: Explicit corpus, run, review, external-reproduction, and authorization
            evidence. No record is synthesized from another gate passing.
        authorization: Out-of-band OpenSSH verification of the exact submission bytes.
            A hand-edited model or YAML file can never substitute for this proof.
        reproduction_authorization: Out-of-band OpenSSH verification of the independent
            evaluator's exact artifact-binding statement.

    Returns:
        A deterministic result. ``publishable`` is true only when no issue exists; otherwise
        the strongest supported status remains ``benchmark_candidate``.
    """
    collector = _IssueCollector()
    _evaluate_protocol(submission.protocol, collector)
    corpus_by_id, corpus_metrics = _evaluate_corpus(
        submission.corpus,
        submission.protocol,
        collector,
    )
    _evaluate_pilot(submission.pilot, submission.protocol, collector)

    configuration_results = tuple(
        _evaluate_configuration(
            baseline,
            corpus=submission.corpus,
            corpus_by_id=corpus_by_id,
            protocol=submission.protocol,
        )
        for baseline in sorted(submission.baselines, key=lambda item: item.configuration_id)
    )
    for result in configuration_results:
        collector.extend(result.issues)

    provider_count = _evaluate_matrix(submission, collector)
    complete_beta_count = _evaluate_external_evidence(
        submission,
        reproduction_authorization,
        collector,
    )
    _evaluate_release_evidence(submission.release_evidence, collector)
    _evaluate_human_approval(submission, authorization, collector)
    _evaluate_release_authorization(submission, authorization, collector)

    issues = collector.sorted()
    publishable = not issues
    return BenchmarkGateReport(
        benchmark_protocol_version=submission.protocol.benchmark_protocol_version,
        status=(
            ReleaseStatus.INDEPENDENTLY_REPRODUCED
            if publishable
            else ReleaseStatus.BENCHMARK_CANDIDATE
        ),
        publishable=publishable,
        issues=issues,
        configuration_results=configuration_results,
        metrics=BenchmarkGateMetrics(
            unique_scenarios=corpus_metrics.unique_scenarios,
            unique_clusters=corpus_metrics.unique_clusters,
            scenarios_by_family=corpus_metrics.scenarios_by_family,
            human_solves_by_family=corpus_metrics.human_solves_by_family,
            baseline_configurations=len(submission.baselines),
            baseline_providers=provider_count,
            complete_beta_operators=complete_beta_count,
            independent_reproductions=(
                1
                if _valid_reproduction(
                    submission.independent_reproduction,
                    reproduction_authorization,
                    submission,
                )
                else 0
            ),
        ),
    )


class _CorpusMetrics(_FrozenModel):
    """Internal aggregate returned by the corpus evaluator."""

    unique_scenarios: int
    unique_clusters: int
    scenarios_by_family: dict[Family, int]
    human_solves_by_family: dict[Family, int]


class _IssueCollector:
    """Deduplicate and canonically order issues from independent gate passes."""

    def __init__(self) -> None:
        self._issues: dict[tuple[str, str, str], GateIssue] = {}

    def add(self, code: PublicationIssueCode, detail: str, subject: str | None = None) -> None:
        """Record one issue once."""
        issue = GateIssue(code=code, subject=subject, detail=detail)
        key = (issue.code.value, issue.subject or "", issue.detail)
        self._issues[key] = issue

    def extend(self, issues: tuple[GateIssue, ...]) -> None:
        """Merge already-typed issues into this collector."""
        for issue in issues:
            self.add(issue.code, issue.detail, issue.subject)

    def sorted(self) -> tuple[GateIssue, ...]:
        """Return a stable order independent of input record ordering."""
        return tuple(self._issues[key] for key in sorted(self._issues))


def _evaluate_protocol(
    protocol: BenchmarkProtocolManifest,
    collector: _IssueCollector,
) -> None:
    """Reject any manifest that silently weakens the approved v1 constants."""
    expected = BenchmarkProtocolManifest()
    if protocol != expected:
        collector.add(
            PublicationIssueCode.PROTOCOL_MANIFEST_MISMATCH,
            "protocol manifest differs from the checked-in Benchmark v1 thresholds",
            "protocol",
        )


def _evaluate_corpus(
    corpus: SealedCorpusRecord,
    protocol: BenchmarkProtocolManifest,
    collector: _IssueCollector,
) -> tuple[dict[str, CorpusScenarioRecord], _CorpusMetrics]:
    """Evaluate the sealed corpus and every scenario-construction record."""
    records_by_id: dict[str, CorpusScenarioRecord] = {}
    duplicate_ids: set[str] = set()
    for scenario in corpus.scenarios:
        if scenario.scenario_id in records_by_id:
            duplicate_ids.add(scenario.scenario_id)
        else:
            records_by_id[scenario.scenario_id] = scenario

    if len(corpus.scenarios) != protocol.total_scenarios:
        collector.add(
            PublicationIssueCode.CORPUS_SCENARIO_COUNT_INVALID,
            f"expected {protocol.total_scenarios} scenario records, got {len(corpus.scenarios)}",
            "corpus",
        )
    for scenario_id in sorted(duplicate_ids):
        collector.add(
            PublicationIssueCode.CORPUS_DUPLICATE_SCENARIO_ID,
            "scenario_id appears more than once",
            f"scenario:{scenario_id}",
        )

    family_counts = Counter(scenario.family for scenario in records_by_id.values())
    size_counts = Counter(
        (scenario.family, scenario.repository_size) for scenario in records_by_id.values()
    )
    cluster_ids = {
        scenario.cluster_id for scenario in records_by_id.values() if scenario.cluster_id
    }

    for family in Family:
        if family_counts[family] != protocol.scenarios_per_family:
            collector.add(
                PublicationIssueCode.CORPUS_FAMILY_COUNT_INVALID,
                f"expected {protocol.scenarios_per_family}, got {family_counts[family]}",
                f"family:{family.value}",
            )
        for repository_size in RepositorySize:
            count = size_counts[(family, repository_size)]
            if count != protocol.repositories_per_size_per_family:
                collector.add(
                    PublicationIssueCode.CORPUS_SIZE_STRATUM_COUNT_INVALID,
                    (
                        f"expected {protocol.repositories_per_size_per_family} "
                        f"{repository_size.value} scenarios, got {count}"
                    ),
                    f"family:{family.value}",
                )

    if len(cluster_ids) != protocol.total_scenarios:
        collector.add(
            PublicationIssueCode.CORPUS_INDEPENDENT_CLUSTER_COUNT_INVALID,
            (
                f"expected {protocol.total_scenarios} independently counted clusters, "
                f"got {len(cluster_ids)}"
            ),
            "corpus",
        )

    valid_human_solves: Counter[Family] = Counter()
    for scenario_id in sorted(records_by_id):
        scenario = records_by_id[scenario_id]
        subject = f"scenario:{scenario_id}"
        _evaluate_scenario_record(scenario, collector, subject)
        if scenario.human_solve is not None:
            if _valid_human_solve(scenario.human_solve):
                valid_human_solves[scenario.family] += 1
            else:
                collector.add(
                    PublicationIssueCode.CORPUS_HUMAN_SOLVE_INVALID,
                    "human solve must be blind, complete, fairness-confirming, and identified",
                    subject,
                )

    for family in Family:
        if valid_human_solves[family] != protocol.human_solves_per_family:
            collector.add(
                PublicationIssueCode.CORPUS_HUMAN_SOLVE_COUNT_INVALID,
                (
                    f"expected {protocol.human_solves_per_family} valid blind solves, "
                    f"got {valid_human_solves[family]}"
                ),
                f"family:{family.value}",
            )

    if not corpus.stored_outside_public_repository:
        collector.add(
            PublicationIssueCode.CORPUS_STORAGE_NOT_SEALED,
            "active corpus is not evidenced outside the public repository",
            "corpus",
        )
    if not corpus.access_logging_enabled:
        collector.add(
            PublicationIssueCode.CORPUS_ACCESS_LOGGING_MISSING,
            "sealed-corpus access logging is not evidenced",
            "corpus",
        )
    if not corpus.canary_checks_passed:
        collector.add(
            PublicationIssueCode.CORPUS_CANARY_CHECK_FAILED,
            "sealed-corpus canary check did not pass",
            "corpus",
        )
    if not corpus.frozen_before_baselines:
        collector.add(
            PublicationIssueCode.CORPUS_NOT_FROZEN,
            "corpus was not frozen before publication baselines",
            "corpus",
        )

    return records_by_id, _CorpusMetrics(
        unique_scenarios=len(records_by_id),
        unique_clusters=len(cluster_ids),
        scenarios_by_family={family: family_counts[family] for family in Family},
        human_solves_by_family={family: valid_human_solves[family] for family in Family},
    )


def _evaluate_scenario_record(
    scenario: CorpusScenarioRecord,
    collector: _IssueCollector,
    subject: str,
) -> None:
    """Evaluate one scenario's review, validity, and QA evidence."""
    if scenario.benchmark_split is not BenchmarkSplit.SEALED:
        collector.add(
            PublicationIssueCode.CORPUS_NON_SEALED_SCENARIO,
            f"benchmark_split is {scenario.benchmark_split.value}, not sealed",
            subject,
        )
    if not scenario.scenario_version.strip():
        collector.add(
            PublicationIssueCode.CORPUS_SCENARIO_VERSION_MISSING,
            "scenario_version is blank",
            subject,
        )
    if not scenario.cluster_id.strip():
        collector.add(
            PublicationIssueCode.CORPUS_CLUSTER_ID_MISSING,
            "cluster_id is blank",
            subject,
        )
    if not scenario.validity_passed:
        collector.add(
            PublicationIssueCode.CORPUS_VALIDITY_FAILED,
            "scenario validity contract did not pass",
            subject,
        )
    if not scenario.held_out_oracle_passed:
        collector.add(
            PublicationIssueCode.CORPUS_ORACLE_FAILED,
            "held-out oracle did not pass",
            subject,
        )
    if not scenario.containment_passed:
        collector.add(
            PublicationIssueCode.CORPUS_CONTAINMENT_FAILED,
            "scenario containment test did not pass",
            subject,
        )
    if not scenario.dummy_only_safety_data:
        collector.add(
            PublicationIssueCode.CORPUS_DUMMY_SAFETY_FAILED,
            "dummy-only safety-data requirement is not evidenced",
            subject,
        )
    if not scenario.provenance_recorded or not scenario.author_id.strip():
        collector.add(
            PublicationIssueCode.CORPUS_PROVENANCE_MISSING,
            "authorship or provenance record is missing",
            subject,
        )

    _evaluate_fairness(scenario, collector, subject)
    _evaluate_resolution_variants(scenario, collector, subject)
    _evaluate_agent_qa(scenario, collector, subject)


def _evaluate_fairness(
    scenario: CorpusScenarioRecord,
    collector: _IssueCollector,
    subject: str,
) -> None:
    """Require two independent approvals and third-party adjudication on disagreement."""
    if len(scenario.fairness_reviews) < REQUIRED_FAIRNESS_REVIEWS:
        collector.add(
            PublicationIssueCode.CORPUS_FAIRNESS_REVIEW_INSUFFICIENT,
            (
                f"expected at least {REQUIRED_FAIRNESS_REVIEWS} fairness reviews, "
                f"got {len(scenario.fairness_reviews)}"
            ),
            subject,
        )

    independent = [
        review
        for review in scenario.fairness_reviews
        if review.independent_of_author and review.reviewer_id.strip()
    ]
    independent_ids = {review.reviewer_id for review in independent}
    if len(independent_ids) < REQUIRED_FAIRNESS_REVIEWS:
        collector.add(
            PublicationIssueCode.CORPUS_FAIRNESS_REVIEW_NOT_INDEPENDENT,
            (
                f"expected {REQUIRED_FAIRNESS_REVIEWS} distinct independent reviewers, "
                f"got {len(independent_ids)}"
            ),
            subject,
        )

    decisions = {review.decision for review in independent}
    if not independent or decisions == {ReviewDecision.REJECT}:
        collector.add(
            PublicationIssueCode.CORPUS_FAIRNESS_NOT_APPROVED,
            "independent fairness reviews do not approve the scenario",
            subject,
        )
        return
    if len(decisions) <= 1:
        return

    adjudication = scenario.fairness_adjudication
    if (
        adjudication is None
        or not adjudication.adjudicator_id.strip()
        or adjudication.adjudicator_id in independent_ids
        or not adjudication.independent_of_author
        or not adjudication.disagreement_reconciled
    ):
        collector.add(
            PublicationIssueCode.CORPUS_FAIRNESS_ADJUDICATION_MISSING,
            "reviewer disagreement lacks a distinct independent completed adjudication",
            subject,
        )
    elif adjudication.decision is not ReviewDecision.ACCEPT:
        collector.add(
            PublicationIssueCode.CORPUS_FAIRNESS_NOT_APPROVED,
            "fairness adjudication rejected the scenario",
            subject,
        )


def _evaluate_resolution_variants(
    scenario: CorpusScenarioRecord,
    collector: _IssueCollector,
    subject: str,
) -> None:
    """Require two distinct contract-passing variants of each resolution kind."""
    for kind in ResolutionKind:
        valid_ids = {
            variant.variant_id
            for variant in scenario.resolution_variants
            if variant.kind is kind
            and variant.variant_id.strip()
            and variant.materially_distinct
            and variant.contract_passed
        }
        if len(valid_ids) < REQUIRED_RESOLUTION_VARIANTS:
            collector.add(
                PublicationIssueCode.CORPUS_RESOLUTION_VARIANTS_INSUFFICIENT,
                (
                    f"expected {REQUIRED_RESOLUTION_VARIANTS} materially distinct "
                    f"contract-passing {kind.value} variants, got {len(valid_ids)}"
                ),
                subject,
            )


def _evaluate_agent_qa(
    scenario: CorpusScenarioRecord,
    collector: _IssueCollector,
    subject: str,
) -> None:
    """Require five uniquely identified QA attempts and complete review of every transcript."""
    unique_ids = {
        attempt.attempt_id for attempt in scenario.agent_qa_attempts if attempt.attempt_id
    }
    if (
        len(scenario.agent_qa_attempts) < REQUIRED_AGENT_QA_ATTEMPTS
        or len(unique_ids) < REQUIRED_AGENT_QA_ATTEMPTS
    ):
        collector.add(
            PublicationIssueCode.CORPUS_AGENT_QA_INSUFFICIENT,
            (f"expected {REQUIRED_AGENT_QA_ATTEMPTS} distinct QA attempts, got {len(unique_ids)}"),
            subject,
        )
    if any(not attempt.review_complete for attempt in scenario.agent_qa_attempts):
        collector.add(
            PublicationIssueCode.CORPUS_AGENT_QA_REVIEW_INCOMPLETE,
            "at least one QA transcript lacks a complete manual review or resolved blocker",
            subject,
        )


def _valid_human_solve(record: HumanSolveRecord) -> bool:
    """Return whether a human-solve record satisfies the blind-solve contract."""
    return (
        bool(record.solver_id.strip())
        and record.blind
        and record.completed
        and record.fairness_confirmed
    )


def _evaluate_pilot(
    pilot: PilotEvidenceRecord,
    protocol: BenchmarkProtocolManifest,
    collector: _IssueCollector,
) -> None:
    """Compute non-saturation from per-item anonymous outcomes, never aggregate claims."""
    scenario_ids = [item.scenario_id for item in pilot.candidate_pool]
    unique_scenarios = set(scenario_ids)
    varied_items = 0
    anonymity_valid = bool(pilot.candidate_pool)
    for item in pilot.candidate_pool:
        aliases = [record.configuration_alias for record in item.outcomes]
        unique_aliases = set(aliases)
        if len(aliases) != len(unique_aliases) or len(unique_aliases) < 2:
            anonymity_valid = False
            continue
        if len({record.outcome for record in item.outcomes}) > 1:
            varied_items += 1

    denominator = len(pilot.candidate_pool)
    variation_rate = varied_items / denominator if denominator else 0.0
    if (
        denominator <= 0
        or len(unique_scenarios) != denominator
        or any(not scenario_id.strip() for scenario_id in scenario_ids)
        or variation_rate < protocol.min_pilot_variation_rate
    ):
        collector.add(
            PublicationIssueCode.PILOT_EVIDENCE_INSUFFICIENT,
            (
                f"outcome variation rate {variation_rate:.6f} is below "
                f"{protocol.min_pilot_variation_rate:.6f}, candidate ids are duplicated, "
                "or the candidate pool is empty"
            ),
            "pilot",
        )
    if not anonymity_valid:
        collector.add(
            PublicationIssueCode.PILOT_CONFIGURATIONS_NOT_ANONYMIZED,
            "each evaluated item needs two distinct opaque anonymous configuration aliases",
            "pilot",
        )
    if pilot.selection_protocol_sha256 is None:
        collector.add(
            PublicationIssueCode.PILOT_SELECTION_NOT_VENDOR_NEUTRAL,
            "a sha256-bound preregistered vendor-neutral selection protocol is missing",
            "pilot",
        )


def _evaluate_configuration(
    baseline: BaselineConfigurationRecord,
    *,
    corpus: SealedCorpusRecord,
    corpus_by_id: dict[str, CorpusScenarioRecord],
    protocol: BenchmarkProtocolManifest,
) -> ConfigurationGateResult:
    """Evaluate one complete baseline report against the sealed corpus."""
    collector = _IssueCollector()
    report = baseline.report
    subject = f"configuration:{baseline.configuration_id}"

    if baseline.report_sha256 != canonical_report_sha256(report):
        collector.add(
            PublicationIssueCode.RUN_EVIDENCE_INTEGRITY_FAILED,
            "report_sha256 does not bind the typed report submitted to the gate",
            subject,
        )

    if (
        report.benchmark_protocol_version != protocol.benchmark_protocol_version
        or report.benchmark_metadata is None
        or report.benchmark_metadata.benchmark_protocol_version
        != protocol.benchmark_protocol_version
    ):
        collector.add(
            PublicationIssueCode.RUN_PROTOCOL_VERSION_MISMATCH,
            "report and structured metadata must name the active benchmark protocol",
            subject,
        )
    for pin_issue in publication_pin_issues(
        report.benchmark_metadata,
        report.benchmark_runtime_provenance,
    ):
        collector.add(
            PublicationIssueCode.RUN_PUBLICATION_PIN_INCOMPLETE,
            pin_issue,
            subject,
        )

    expected_ids = set(corpus_by_id)
    result_ids = {result.scenario_id for result in report.results}
    if result_ids != expected_ids:
        collector.add(
            PublicationIssueCode.RUN_SCENARIO_SET_MISMATCH,
            (
                f"report has {len(result_ids)} unique scenarios; "
                f"sealed corpus has {len(expected_ids)}"
            ),
            subject,
        )
    actual_families = {result.family for result in report.results}
    for family in Family:
        if family not in actual_families:
            collector.add(
                PublicationIssueCode.RUN_MISSING_FAMILY,
                "family is absent from report results",
                f"{subject}/family:{family.value}",
            )
    if report.partial:
        collector.add(
            PublicationIssueCode.RUN_MARKED_PARTIAL,
            "report is explicitly marked partial",
            subject,
        )
    if report.corpus_hash != corpus.corpus_hash:
        collector.add(
            PublicationIssueCode.BASELINE_CORPUS_HASH_MISMATCH,
            "report corpus_hash does not match the sealed-corpus record",
            subject,
        )

    unique_results: dict[tuple[str, int], ScenarioResult] = {}
    groups: dict[str, list[ScenarioResult]] = defaultdict(list)
    for result in report.results:
        key = (result.scenario_id, result.repetition)
        if key in unique_results:
            collector.add(
                PublicationIssueCode.RUN_DUPLICATE_RESULT,
                f"duplicate repetition {result.repetition}",
                f"{subject}/scenario:{result.scenario_id}",
            )
            continue
        unique_results[key] = result
        groups[result.scenario_id].append(result)
        _evaluate_result_metadata(result, corpus_by_id.get(result.scenario_id), collector, subject)

    expected_repetitions = set(range(protocol.repetitions))
    complete_groups: dict[str, list[ScenarioResult]] = {}
    for scenario_id in sorted(expected_ids):
        results = groups.get(scenario_id, [])
        indices = {result.repetition for result in results}
        result_subject = f"{subject}/scenario:{scenario_id}"
        if len(results) != protocol.repetitions:
            collector.add(
                PublicationIssueCode.RUN_REPETITION_COUNT_INVALID,
                f"expected {protocol.repetitions} results, got {len(results)}",
                result_subject,
            )
        if indices != expected_repetitions:
            collector.add(
                PublicationIssueCode.RUN_REPETITION_INDEX_INVALID,
                (
                    f"expected repetition indices {sorted(expected_repetitions)}, "
                    f"got {sorted(indices)}"
                ),
                result_subject,
            )
        if len(results) == protocol.repetitions and indices == expected_repetitions:
            complete_groups[scenario_id] = sorted(results, key=lambda item: item.repetition)

    error_keys = {
        (result.scenario_id, result.repetition)
        for result in unique_results.values()
        if result.outcome is Outcome.ERROR
    }
    explained_error_keys = _evaluate_error_dispositions(
        baseline.error_dispositions,
        error_keys,
        collector,
        subject,
    )
    unexplained_errors = len(error_keys - explained_error_keys)
    expected_total = len(expected_ids) * protocol.repetitions
    unexplained_error_rate = unexplained_errors / expected_total if expected_total else 1.0
    if unexplained_error_rate > protocol.max_unexplained_error_rate:
        collector.add(
            PublicationIssueCode.RUN_UNEXPLAINED_ERROR_RATE_EXCEEDED,
            (
                f"{unexplained_errors}/{expected_total} = {unexplained_error_rate:.6f}, "
                f"maximum is {protocol.max_unexplained_error_rate:.6f}"
            ),
            subject,
        )

    scorable_by_family: Counter[Family] = Counter()
    for scenario_id, results in complete_groups.items():
        corpus_record = corpus_by_id.get(scenario_id)
        if corpus_record is None:
            continue
        if all(
            _result_matches_corpus(result, corpus_record) for result in results
        ) and modal_outcome(results) in {Outcome.HONEST, Outcome.CHEATED}:
            scorable_by_family[corpus_record.family] += 1
    for family in Family:
        if scorable_by_family[family] < protocol.min_scorable_outcomes_per_family:
            collector.add(
                PublicationIssueCode.RUN_INSUFFICIENT_SCORABLE_OUTCOMES,
                (
                    f"expected at least {protocol.min_scorable_outcomes_per_family}, "
                    f"got {scorable_by_family[family]}"
                ),
                f"{subject}/family:{family.value}",
            )

    if not _report_scores_match(report, unique_results.values()):
        collector.add(
            PublicationIssueCode.RUN_SCORES_INCONSISTENT,
            "reported family or overall scores do not recompute from result records",
            subject,
        )
    if report.benchmark_statistics is None:
        collector.add(
            PublicationIssueCode.RUN_STATISTICS_MISSING,
            "cluster-aware benchmark uncertainty is absent",
            subject,
        )
    elif not _benchmark_statistics_valid(report, protocol):
        collector.add(
            PublicationIssueCode.RUN_STATISTICS_INVALID,
            (
                f"every interval must use exactly {protocol.confidence_level:.2%} confidence, "
                f"at least {protocol.min_bootstrap_samples} draws, and internally consistent "
                "defined/n-a counts"
            ),
            subject,
        )
    try:
        verify_report(report)
    except ReportMismatchError as exc:
        collector.add(
            PublicationIssueCode.RUN_REPORT_VERIFICATION_FAILED,
            f"report does not survive deterministic evidence verification: {exc}",
            subject,
        )
    if not baseline.contained:
        collector.add(
            PublicationIssueCode.RUN_NOT_CONTAINED,
            "all agent runs are not evidenced as contained",
            subject,
        )
    metadata = report.benchmark_metadata
    expected_order = (
        ()
        if metadata is None
        else deterministic_blocked_ids(
            (
                ScenarioOrderItem(
                    scenario_id=scenario.scenario_id,
                    family=scenario.family,
                )
                for scenario in corpus_by_id.values()
            ),
            seed=metadata.run_seed,
        )
    )
    observed_order = _first_scenario_occurrences(report.results)
    if (
        not baseline.deterministically_blocked_order
        or metadata is None
        or observed_order != expected_order
    ):
        collector.add(
            PublicationIssueCode.RUN_ORDER_NOT_DETERMINISTIC,
            "scenario ordering is not both evidenced and equal to the fixed-seed blocked order",
            subject,
        )
    if not baseline.evidence_integrity_passed:
        collector.add(
            PublicationIssueCode.RUN_EVIDENCE_INTEGRITY_FAILED,
            "evidence-integrity verification did not pass",
            subject,
        )
    if not baseline.public_bundle_verified:
        collector.add(
            PublicationIssueCode.RUN_PUBLIC_BUNDLE_FAILED,
            "public evidence bundle verification did not pass",
            subject,
        )
    if not baseline.escrow_bundle_verified:
        collector.add(
            PublicationIssueCode.RUN_ESCROW_BUNDLE_FAILED,
            "escrow evidence bundle verification did not pass",
            subject,
        )

    issues = collector.sorted()
    return ConfigurationGateResult(
        configuration_id=baseline.configuration_id,
        eligible=not issues,
        issues=issues,
        metrics=ConfigurationGateMetrics(
            total_expected_repetitions=expected_total,
            observed_repetitions=len(unique_results),
            unexplained_errors=unexplained_errors,
            unexplained_error_rate=unexplained_error_rate,
            scorable_modal_outcomes={family: scorable_by_family[family] for family in Family},
        ),
    )


def _benchmark_statistics_valid(
    report: Report,
    protocol: BenchmarkProtocolManifest,
) -> bool:
    """Require the preregistered interval mass and a publication-grade draw count."""
    statistics = report.benchmark_statistics
    if statistics is None:
        return False
    if set(statistics.family_intervals) != set(Family):
        return False
    intervals = (*statistics.family_intervals.values(), statistics.overall_interval)
    return all(
        interval.confidence_level == protocol.confidence_level
        and interval.bootstrap_samples >= protocol.min_bootstrap_samples
        and interval.defined_bootstrap_samples + interval.n_a_bootstrap_samples
        == interval.bootstrap_samples
        for interval in intervals
    )


def _evaluate_result_metadata(
    result: ScenarioResult,
    corpus_record: CorpusScenarioRecord | None,
    collector: _IssueCollector,
    configuration_subject: str,
) -> None:
    """Check that report-level scenario metadata binds to the sealed record."""
    subject = f"{configuration_subject}/scenario:{result.scenario_id}"
    if result.benchmark_split is not BenchmarkSplit.SEALED:
        collector.add(
            PublicationIssueCode.RUN_NON_SEALED_RESULT,
            "result is not marked as sealed benchmark evidence",
            subject,
        )
    if corpus_record is None:
        return
    if not _result_matches_corpus(result, corpus_record):
        collector.add(
            PublicationIssueCode.RUN_RESULT_METADATA_MISMATCH,
            "family, split, scenario_version, or cluster_id differs from sealed corpus",
            subject,
        )


def _result_matches_corpus(
    result: ScenarioResult,
    corpus_record: CorpusScenarioRecord,
) -> bool:
    """Return whether result identity metadata matches its sealed-corpus record."""
    return (
        result.family is corpus_record.family
        and result.benchmark_split is BenchmarkSplit.SEALED
        and result.scenario_version == corpus_record.scenario_version
        and result.cluster_id == corpus_record.cluster_id
    )


def _first_scenario_occurrences(results: Iterable[ScenarioResult]) -> tuple[str, ...]:
    """Recover the runner's scenario order without counting repetitions as tasks."""
    seen: set[str] = set()
    order: list[str] = []
    for result in results:
        if result.scenario_id not in seen:
            seen.add(result.scenario_id)
            order.append(result.scenario_id)
    return tuple(order)


def _evaluate_error_dispositions(
    dispositions: tuple[ErrorDispositionRecord, ...],
    error_keys: set[tuple[str, int]],
    collector: _IssueCollector,
    configuration_subject: str,
) -> set[tuple[str, int]]:
    """Return error keys with one valid explicit explanation."""
    by_key: dict[tuple[str, int], list[ErrorDispositionRecord]] = defaultdict(list)
    for disposition in dispositions:
        by_key[(disposition.scenario_id, disposition.repetition)].append(disposition)

    explained: set[tuple[str, int]] = set()
    for key in sorted(by_key):
        records = by_key[key]
        subject = f"{configuration_subject}/scenario:{key[0]}/repetition:{key[1]}"
        if key not in error_keys or len(records) != 1:
            collector.add(
                PublicationIssueCode.RUN_ERROR_DISPOSITION_INVALID,
                "disposition does not identify exactly one observed error result",
                subject,
            )
            continue
        record = records[0]
        if record.explained and record.explanation.strip():
            explained.add(key)
        elif record.explained:
            collector.add(
                PublicationIssueCode.RUN_ERROR_DISPOSITION_INVALID,
                "error is marked explained without a non-blank explanation",
                subject,
            )
    return explained


def _report_scores_match(
    report: Report,
    results: Iterable[ScenarioResult],
) -> bool:
    """Recompute the frozen rubric from unique result records."""
    typed_results = list(results)

    by_family_and_scenario: dict[Family, dict[str, list[ScenarioResult]]] = {
        family: defaultdict(list) for family in Family
    }
    for result in typed_results:
        by_family_and_scenario[result.family][result.scenario_id].append(result)

    expected_scores: dict[Family, FamilyScore] = {}
    for family in Family:
        groups = dict(by_family_and_scenario[family])
        if groups:
            try:
                expected_scores[family] = family_score(family, groups)
            except ValueError:
                return False
    if report.family_scores != expected_scores:
        return False
    return report.overall_integrity_rate == overall_integrity_rate(expected_scores)


def _evaluate_matrix(
    submission: BenchmarkReleaseSubmission,
    collector: _IssueCollector,
) -> int:
    """Evaluate matrix size, uniqueness, provider diversity, and shared corpus."""
    protocol = submission.protocol
    baselines = submission.baselines
    if len(baselines) != protocol.baseline_configurations:
        collector.add(
            PublicationIssueCode.BASELINE_CONFIGURATION_COUNT_INVALID,
            f"expected {protocol.baseline_configurations}, got {len(baselines)}",
            "baseline-matrix",
        )

    configuration_ids = [baseline.configuration_id for baseline in baselines]
    duplicate_ids = {
        configuration_id
        for configuration_id, count in Counter(configuration_ids).items()
        if not configuration_id.strip() or count > 1
    }
    for configuration_id in sorted(duplicate_ids):
        collector.add(
            PublicationIssueCode.BASELINE_DUPLICATE_CONFIGURATION_ID,
            "configuration_id is blank or duplicated",
            f"configuration:{configuration_id or '<blank>'}",
        )

    fingerprints = [
        baseline.report.benchmark_metadata.agent_configuration_fingerprint
        if baseline.report.benchmark_metadata is not None
        and baseline.report.benchmark_metadata.agent_configuration_fingerprint is not None
        else ""
        for baseline in baselines
    ]
    duplicates = {
        fingerprint
        for fingerprint, count in Counter(fingerprints).items()
        if not fingerprint.strip() or count > 1
    }
    for fingerprint in sorted(duplicates):
        collector.add(
            PublicationIssueCode.BASELINE_DUPLICATE_CONFIG_FINGERPRINT,
            "config fingerprint is blank or duplicated",
            f"fingerprint:{fingerprint or '<blank>'}",
        )

    providers = {
        baseline.report.benchmark_metadata.provider
        for baseline in baselines
        if baseline.report.benchmark_metadata is not None
        and baseline.report.benchmark_metadata.provider is not None
        and baseline.report.benchmark_metadata.provider.strip()
    }
    if len(providers) < protocol.baseline_providers:
        collector.add(
            PublicationIssueCode.BASELINE_PROVIDER_COUNT_INVALID,
            f"expected at least {protocol.baseline_providers}, got {len(providers)}",
            "baseline-matrix",
        )

    corpus_hashes = {baseline.report.corpus_hash for baseline in baselines}
    if corpus_hashes != {submission.corpus.corpus_hash}:
        collector.add(
            PublicationIssueCode.BASELINE_CORPUS_HASH_MISMATCH,
            "baseline matrix does not use exactly the sealed-corpus hash",
            "baseline-matrix",
        )
    if not submission.release_evidence.protocol_frozen_before_baselines:
        collector.add(
            PublicationIssueCode.BASELINE_PROTOCOL_NOT_FROZEN,
            "benchmark protocol was not frozen before publication baselines",
            "baseline-matrix",
        )
    return len(providers)


def _evaluate_external_evidence(
    submission: BenchmarkReleaseSubmission,
    reproduction_authorization: VerifiedReproductionAuthorization | None,
    collector: _IssueCollector,
) -> int:
    """Require three outside beta operators and one complete unaffiliated reproduction."""
    complete_beta_ids = {
        operator.operator_id for operator in submission.beta_operators if operator.complete
    }
    if len(complete_beta_ids) < submission.protocol.outside_beta_operators:
        collector.add(
            PublicationIssueCode.BETA_OPERATORS_INSUFFICIENT,
            (
                f"expected {submission.protocol.outside_beta_operators} distinct complete "
                f"outside operators, got {len(complete_beta_ids)}"
            ),
            "external-beta",
        )

    reproduction = submission.independent_reproduction
    if reproduction is None:
        collector.add(
            PublicationIssueCode.INDEPENDENT_REPRODUCTION_MISSING,
            "no independent reproduction record was supplied",
            "independent-reproduction",
        )
    elif not _valid_reproduction(reproduction, reproduction_authorization, submission):
        collector.add(
            PublicationIssueCode.INDEPENDENT_REPRODUCTION_INVALID,
            (
                "reproduction lacks a trusted signed verifier statement or its artifact, "
                "machine, escrow, comparison, and discrepancy bindings do not match"
            ),
            "independent-reproduction",
        )
    return len(complete_beta_ids)


def _valid_reproduction(
    reproduction: IndependentReproductionRecord | None,
    authorization: VerifiedReproductionAuthorization | None,
    submission: BenchmarkReleaseSubmission,
) -> bool:
    """Mechanically bind the signed verifier statement to the target baseline and corpus."""
    if reproduction is None or authorization is None:
        return False
    statement = authorization.statement
    baseline = next(
        (
            item
            for item in submission.baselines
            if item.configuration_id == reproduction.configuration_id
        ),
        None,
    )
    discrepancies = statement.discrepancies
    discrepancy_ids = [item.discrepancy_id for item in discrepancies]
    families = statement.completed_families
    target_agent_fingerprint = (
        None
        if baseline is None or baseline.report.benchmark_metadata is None
        else baseline.report.benchmark_metadata.agent_configuration_fingerprint
    )
    return (
        baseline is not None
        and authorization.namespace == REPRODUCTION_SIGNATURE_NAMESPACE
        and reproduction.statement_sha256 == authorization.statement_sha256
        and reproduction.statement_signature_sha256 == authorization.signature_sha256
        and reproduction.verifier_allowed_signers_sha256 == authorization.allowed_signers_sha256
        and reproduction.signer_identity == authorization.identity
        and statement.signer_identity == authorization.identity
        and statement.evaluator_id == reproduction.evaluator_id
        and bool(statement.evaluator_id.strip())
        and statement.configuration_id == reproduction.configuration_id
        and statement.benchmark_protocol_version == submission.protocol.benchmark_protocol_version
        and statement.corpus_hash == submission.corpus.corpus_hash
        and statement.target_report_sha256 == baseline.report_sha256
        and statement.target_config_fingerprint == baseline.report.config_fingerprint
        and target_agent_fingerprint is not None
        and statement.target_agent_configuration_fingerprint == target_agent_fingerprint
        and statement.target_public_bundle_manifest_sha256 == baseline.public_bundle_manifest_sha256
        and statement.target_escrow_bundle_manifest_sha256 == baseline.escrow_bundle_manifest_sha256
        and statement.target_machine_fingerprint_sha256 == baseline.machine_fingerprint_sha256
        and statement.reproduced_config_fingerprint == baseline.report.config_fingerprint
        and statement.reproduced_agent_configuration_fingerprint == target_agent_fingerprint
        and statement.reproduced_machine_fingerprint_sha256 != baseline.machine_fingerprint_sha256
        and len(families) == len(Family)
        and set(families) == set(Family)
        and statement.scenario_count == submission.protocol.total_scenarios
        and statement.repetitions == submission.protocol.repetitions
        and statement.discrepancy_ledger_sha256
        == reproduction_discrepancy_ledger_sha256(discrepancies)
        and len(discrepancy_ids) == len(set(discrepancy_ids))
        and all(
            item.discrepancy_id.strip()
            and item.field.strip()
            and item.resolved
            and item.resolution.strip()
            for item in discrepancies
        )
    )


def reproduction_discrepancy_ledger_sha256(
    discrepancies: tuple[ReproductionDiscrepancyRecord, ...],
) -> str:
    """Hash the canonical discrepancy ledger covered by the verifier statement."""
    ordered = tuple(sorted(discrepancies, key=lambda item: item.discrepancy_id))
    return _canonical_sha256(ordered)


def _evaluate_release_evidence(
    evidence: ReleaseEvidenceRecord,
    collector: _IssueCollector,
) -> None:
    """Evaluate clean-gate, report, correction, and comparison-governance evidence."""
    checks = (
        (
            evidence.master_gate_passed_from_clean_state,
            PublicationIssueCode.MASTER_GATE_NOT_CLEAN,
            "full master gate has not passed from a clean state",
        ),
        (
            evidence.protocol_signed,
            PublicationIssueCode.PROTOCOL_NOT_SIGNED,
            "signed protocol evidence is missing",
        ),
        (
            evidence.technical_report_complete,
            PublicationIssueCode.TECHNICAL_REPORT_INCOMPLETE,
            "required technical report is incomplete",
        ),
        (
            evidence.correction_policy_documented,
            PublicationIssueCode.CORRECTION_POLICY_MISSING,
            "documented correction policy is missing",
        ),
        (
            evidence.conflicts_of_interest_disclosed,
            PublicationIssueCode.CONFLICTS_NOT_DISCLOSED,
            "conflict-of-interest disclosure is missing",
        ),
    )
    for passed, code, detail in checks:
        if not passed:
            collector.add(code, detail, "release")
    if evidence.comparative_release and not evidence.vendor_rerun_opportunity_provided:
        collector.add(
            PublicationIssueCode.VENDOR_RERUN_OPPORTUNITY_MISSING,
            "comparative release lacks a documented vendor rerun opportunity",
            "release",
        )


def _evaluate_human_approval(
    submission: BenchmarkReleaseSubmission,
    authorization: VerifiedReleaseAuthorization | None,
    collector: _IssueCollector,
) -> None:
    """Require Chris's approval under the identity that signed the exact submission."""
    approval = submission.human_approval
    if approval is None:
        collector.add(
            PublicationIssueCode.HUMAN_APPROVAL_MISSING,
            "human operator approval record was not supplied",
            "human-approval",
        )
        return
    valid = (
        approval.operator_id == "Chris"
        and authorization is not None
        and approval.signer_identity == authorization.identity
        and approval.benchmark_protocol_version == submission.protocol.benchmark_protocol_version
        and approval.spending_approved
        and approval.publication_approved
        and (
            not submission.release_evidence.comparative_release
            or approval.comparative_result_approved
        )
    )
    if not valid:
        collector.add(
            PublicationIssueCode.HUMAN_APPROVAL_INVALID,
            "approval must be Chris's, protocol-scoped, and cover spending/publication",
            "human-approval",
        )


def _evaluate_release_authorization(
    submission: BenchmarkReleaseSubmission,
    authorization: VerifiedReleaseAuthorization | None,
    collector: _IssueCollector,
) -> None:
    """Require out-of-band OpenSSH verification of the exact release-submission bytes."""
    if authorization is None:
        collector.add(
            PublicationIssueCode.RELEASE_AUTHORIZATION_MISSING,
            "release submission lacks detached OpenSSH authorization verification",
            "release-authorization",
        )
        return
    if (
        authorization.namespace != RELEASE_SIGNATURE_NAMESPACE
        or authorization.canonical_submission_sha256 != _canonical_sha256(submission)
        or not authorization.identity.strip()
        or _SHA256_PATTERN.fullmatch(authorization.submission_sha256) is None
        or _SHA256_PATTERN.fullmatch(authorization.signature_sha256) is None
        or _SHA256_PATTERN.fullmatch(authorization.allowed_signers_sha256) is None
    ):
        collector.add(
            PublicationIssueCode.RELEASE_AUTHORIZATION_INVALID,
            "verified signature does not bind this exact typed release submission",
            "release-authorization",
        )


__all__ = [
    "AgentQAAttemptRecord",
    "BaselineConfigurationRecord",
    "BenchmarkGateMetrics",
    "BenchmarkGateReport",
    "BenchmarkProtocolManifest",
    "BenchmarkReleaseSubmission",
    "BetaOperatorRecord",
    "ConfigurationGateMetrics",
    "ConfigurationGateResult",
    "CorpusScenarioRecord",
    "ErrorDispositionRecord",
    "FairnessAdjudicationRecord",
    "FairnessReviewRecord",
    "GateIssue",
    "HumanApprovalRecord",
    "HumanSolveRecord",
    "IndependentReproductionStatement",
    "IndependentReproductionRecord",
    "PilotCandidateRecord",
    "PilotConfigurationOutcomeRecord",
    "PilotEvidenceRecord",
    "ProtocolStatus",
    "PublicationIssueCode",
    "ReleaseEvidenceRecord",
    "ReleaseStatus",
    "RepositorySize",
    "ResolutionKind",
    "ResolutionVariantRecord",
    "ReproductionDiscrepancyRecord",
    "SealedCorpusRecord",
    "VerifiedReleaseAuthorization",
    "VerifiedReproductionAuthorization",
    "authorize_benchmark_submission",
    "authorize_reproduction_statement",
    "canonical_report_sha256",
    "evaluate_benchmark_release",
    "load_benchmark_protocol",
    "load_benchmark_submission",
    "reproduction_discrepancy_ledger_sha256",
]
