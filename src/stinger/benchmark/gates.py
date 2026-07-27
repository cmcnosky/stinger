"""Fail-closed release gates for Stinger Benchmark Protocol 2.

The gate verifies machine-derived corpus, execution, conformance, reproduction, and
authorization evidence. Missing records are failures rather than favourable defaults, and
every failure has a stable machine-readable code. Machine reviews are veto-only; they never
alter deterministic outcomes or the frozen scoring rubric.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from stinger import BENCHMARK_PROTOCOL_VERSION, RUBRIC_VERSION
from stinger.benchmark.machine_review import (
    MACHINE_REVIEW_OUTPUT_SCHEMA_SHA256,
    MACHINE_REVIEW_PROMPT_SHA256,
    MachineReviewDecision,
    MachineReviewOutput,
)
from stinger.benchmark.ordering import (
    ScenarioOrderItem,
    deterministic_blocked_ids,
    observed_scenario_order,
)
from stinger.benchmark.protocol import (
    BASELINE_CONFIGURATIONS,
    BASELINE_PROVIDERS,
    MAX_ERROR_RATE,
    MIN_SCORABLE_OUTCOMES_PER_FAMILY,
    PUBLICATION_REPETITIONS,
    SCENARIOS_PER_FAMILY,
    TOTAL_SCENARIOS,
    BenchmarkSplit,
    CredentialIsolationPolicy,
    ProviderId,
    canonical_local_provider_binding_issues,
    compiled_credential_isolation_policy,
    publication_pin_issues,
)
from stinger.benchmark.signing import (
    BASELINE_VERIFICATION_SIGNATURE_NAMESPACE,
    CANDIDATE_PROMOTION_SIGNATURE_NAMESPACE,
    CANDIDATE_VALIDATION_SIGNATURE_NAMESPACE,
    CONFORMANCE_SIGNATURE_NAMESPACE,
    CORPUS_FREEZE_SIGNATURE_NAMESPACE,
    PILOT_EVIDENCE_SIGNATURE_NAMESPACE,
    PROTOCOL_SIGNATURE_NAMESPACE,
    PUBLIC_REPRODUCTION_VERIFICATION_SIGNATURE_NAMESPACE,
    RELEASE_EVIDENCE_SIGNATURE_NAMESPACE,
    RELEASE_SIGNATURE_NAMESPACE,
    REPRODUCED_REPORT_SIGNATURE_NAMESPACE,
    REPRODUCTION_SIGNATURE_NAMESPACE,
    ProtocolSignatureError,
    verify_baseline_verification_statement_signature,
    verify_candidate_promotion_statement_signature,
    verify_candidate_validation_receipt_signature,
    verify_conformance_statement_signature,
    verify_corpus_freeze_statement_signature,
    verify_pilot_evidence_statement_signature,
    verify_protocol_signature,
    verify_release_evidence_statement_signature,
    verify_release_submission_signature,
    verify_reproduction_statement_signature,
)
from stinger.benchmark.statistics import DEFAULT_CONFIDENCE_LEVEL
from stinger.benchmark.verification_image import (
    VerificationImagePolicy,
    canonical_verification_image_policy_sha256,
    compiled_verification_image_policy,
    verification_image_id_is_approved,
)
from stinger.models import Family, FamilyScore, Outcome, Report, ScenarioResult
from stinger.report.generate import ReportMismatchError, verify_report
from stinger.scoring.rubric import family_score, modal_outcome, overall_integrity_rate

if TYPE_CHECKING:
    from stinger.benchmark.corpus_construction import (
        VerifiedCorpusConstructionAuthorization,
    )

REPOSITORIES_PER_SIZE_PER_FAMILY = 8
REQUIRED_MACHINE_REVIEWS = 2
REQUIRED_MACHINE_REVIEW_PROVIDERS = 2
REQUIRED_RESOLUTION_VARIANTS = 2
REQUIRED_AGENT_QA_ATTEMPTS = 5
REQUIRED_AGENT_QA_CONFIGURATIONS = 2
REQUIRED_AGENT_QA_PROVIDERS = 2
BLIND_AGENT_SOLVES_PER_FAMILY = 6
BLIND_AGENT_SOLVERS_PER_SCENARIO = 2
BLIND_AGENT_SOLVER_CONFIGURATIONS = 2
BLIND_AGENT_SOLVER_PROVIDERS = 2
BLIND_AGENT_SOLVE_SELECTION_SEED = 17
REQUIRED_CONFORMANCE_ENVIRONMENTS = 3
REQUIRED_CONFORMANCE_PLATFORMS = 2
MIN_PILOT_VARIATION_RATE = 0.20
MIN_BOOTSTRAP_SAMPLES = 10_000
BASELINE_RUN_SEED = 17
BOOTSTRAP_SEED = 17
PILOT_SELECTION_POLICY_FORMAT_VERSION: Literal["1"] = "1"
CANDIDATE_RECEIPT_FORMAT_VERSION = "1"
CANDIDATE_VALIDATION_CONTRACT = "stinger-scenario-validity-v1-docker"
CANDIDATE_PROMOTION_FORMAT_VERSION = "1"
CANDIDATE_PROMOTION_CONTRACT = "manifest-benchmark-split-candidate-to-sealed-v1"
REPOSITORY_SIZE_SOURCE_VERSION = "signed-private-metadata-v1"

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_PATTERN = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_CLUSTER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
_ANONYMOUS_CONFIGURATION_PATTERN = re.compile(r"^anonymous-[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
_SSH_KEY_FINGERPRINT_PATTERN = re.compile(r"^SHA256:[A-Za-z0-9+/]+={0,2}$")
_REPRODUCTION_DISCREPANCY_FIELDS = frozenset(
    {
        "outcome",
        "detector_results",
        "goal_met",
        "agent_claimed_done",
        "run_error",
    }
)


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


def _require_identifier(value: str, *, field_name: str) -> str:
    """Require a canonical nonblank identifier with no whitespace."""
    if not value or value != value.strip() or any(character.isspace() for character in value):
        raise ValueError(f"{field_name} must be a nonblank identifier without whitespace")
    return value


def _canonical_sha256(model: BaseModel | tuple[BaseModel, ...]) -> str:
    """Hash a typed record in deterministic JSON form for cross-artifact binding."""
    payload: object
    if isinstance(model, tuple):
        payload = [item.model_dump(mode="json") for item in model]
    else:
        payload = model.model_dump(mode="json")
    return _canonical_payload_sha256(payload)


def _canonical_payload_sha256(payload: object) -> str:
    """Hash one JSON-compatible payload with stable ordering and no incidental whitespace."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def canonical_report_sha256(report: Report) -> str:
    """Return the canonical typed-report digest used by release records.

    ``ScenarioResult.run_error`` is additive. Omitting its legacy-compatible ``None`` default
    keeps an already-bound historical report at the same digest, while a genuine persisted
    error remains part of the signed report payload.
    """
    payload = report.model_dump(mode="json")
    results = payload.get("results")
    if isinstance(results, list):
        for result in results:
            if isinstance(result, dict) and result.get("run_error") is None:
                result.pop("run_error", None)
    return _canonical_payload_sha256(payload)


class _FrozenModel(BaseModel):
    """Common immutable, closed schema for signed-off benchmark records."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class ReleaseStatus(StrEnum):
    """The strongest claim mechanically supported by a gate evaluation."""

    BENCHMARK_CANDIDATE = "benchmark_candidate"
    MACHINE_REPRODUCED = "machine_reproduced"


class RepositorySize(StrEnum):
    """Repository-size stratum used by the sealed-corpus sampling plan."""

    SMALL = "small"
    MEDIUM = "medium"
    LARGER_MULTI_MODULE = "larger_multi_module"


class ConformancePlatform(StrEnum):
    """Canonical operating-system family for a clean conformance execution."""

    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"


class ConformanceArchitecture(StrEnum):
    """Canonical machine architecture for a clean conformance execution."""

    ARM64 = "arm64"
    X86_64 = "x86_64"


class ResolutionKind(StrEnum):
    """Reference-attempt class used to demonstrate scenario discrimination."""

    HONEST = "honest"
    CHEAT = "cheat"


class CandidateValidationReceipt(_FrozenModel):
    """Public, path-free proof that an exact private candidate corpus passed validation."""

    format_version: str
    benchmark_protocol_version: str
    rubric_version: str
    corpus_version: str
    signer_identity: str
    stinger_commit: str
    validation_contract: str
    verification_image_id: str
    verification_image_policy_sha256: str
    docker_client_sha256: str
    docker_runtime_fingerprint_sha256: str
    repository_size_source: str
    candidate_corpus_hash: str
    source_snapshot_sha256: str
    private_metadata_sha256: str
    scenario_identity_inventory_sha256: str
    validation_inventory_sha256: str
    canary_inventory_sha256: str
    access_log_root_sha256: str
    custody_ledger_mode: str
    scenario_count: int = Field(ge=0)
    scenarios_by_family: dict[Family, int]
    scenarios_by_family_and_size: dict[Family, dict[RepositorySize, int]]
    unique_cluster_count: int = Field(ge=0)
    machine_validation_count: int = Field(ge=0)
    canary_count: int = Field(ge=0)
    access_log_event_count: int = Field(ge=0)

    @field_validator("benchmark_protocol_version", "rubric_version", "corpus_version")
    @classmethod
    def _valid_version(cls, value: str) -> str:
        """Require complete protocol and rubric versions."""
        return _require_semver(value, field_name="candidate receipt version")

    @field_validator("signer_identity", "custody_ledger_mode")
    @classmethod
    def _valid_identifier(cls, value: str) -> str:
        """Require canonical signer and custody-mode identifiers."""
        return _require_identifier(value, field_name="candidate receipt identifier")

    @field_validator("stinger_commit")
    @classmethod
    def _valid_commit(cls, value: str) -> str:
        """Require an exact full Git object id for the validating implementation."""
        if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is None:
            raise ValueError("stinger_commit must be a full lowercase Git object id")
        return value

    @field_validator("verification_image_id")
    @classmethod
    def _valid_image_id(cls, value: str) -> str:
        """Require Docker's immutable local sha256 image identity."""
        if re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
            raise ValueError("verification_image_id must be an immutable sha256 digest")
        return value

    @field_validator(
        "candidate_corpus_hash",
        "verification_image_policy_sha256",
        "docker_client_sha256",
        "docker_runtime_fingerprint_sha256",
        "source_snapshot_sha256",
        "private_metadata_sha256",
        "scenario_identity_inventory_sha256",
        "validation_inventory_sha256",
        "canary_inventory_sha256",
        "access_log_root_sha256",
    )
    @classmethod
    def _valid_receipt_hash(cls, value: str) -> str:
        """Require exact content bindings for every candidate receipt artifact."""
        return _require_sha256(value, field_name="candidate receipt artifact hash")


class CandidatePromotionStatement(_FrozenModel):
    """Signed proof of the only allowed candidate-to-sealed corpus mutation."""

    format_version: str
    benchmark_protocol_version: str
    rubric_version: str
    corpus_version: str
    signer_identity: str
    stinger_commit: str
    verification_image_id: str
    verification_image_policy_sha256: str
    docker_client_sha256: str
    docker_runtime_fingerprint_sha256: str
    transformation_contract: str
    candidate_receipt_sha256: str
    candidate_corpus_hash: str
    candidate_source_snapshot_sha256: str
    candidate_validation_inventory_sha256: str
    candidate_access_log_root_sha256: str
    sealed_corpus_hash: str
    sealed_source_snapshot_sha256: str
    sealed_scenario_identity_inventory_sha256: str
    sealed_scenario_artifact_inventory_sha256: str
    sealed_validation_inventory_sha256: str
    transformation_inventory_sha256: str
    canary_inventory_sha256: str
    sealed_access_log_root_sha256: str
    scenario_count: int = Field(ge=0)

    @field_validator("benchmark_protocol_version", "rubric_version", "corpus_version")
    @classmethod
    def _valid_version(cls, value: str) -> str:
        """Require complete protocol, rubric, and corpus versions."""
        return _require_semver(value, field_name="candidate promotion version")

    @field_validator("signer_identity")
    @classmethod
    def _valid_identifier(cls, value: str) -> str:
        """Require a canonical promotion signer identity."""
        return _require_identifier(value, field_name="candidate promotion signer identity")

    @field_validator("stinger_commit")
    @classmethod
    def _valid_commit(cls, value: str) -> str:
        """Require the exact implementation commit that performed promotion."""
        if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is None:
            raise ValueError("stinger_commit must be a full lowercase Git object id")
        return value

    @field_validator("verification_image_id")
    @classmethod
    def _valid_image_id(cls, value: str) -> str:
        """Require one immutable Docker verification image identity."""
        if re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
            raise ValueError("verification_image_id must be an immutable sha256 digest")
        return value

    @field_validator(
        "candidate_receipt_sha256",
        "verification_image_policy_sha256",
        "docker_client_sha256",
        "docker_runtime_fingerprint_sha256",
        "candidate_corpus_hash",
        "candidate_source_snapshot_sha256",
        "candidate_validation_inventory_sha256",
        "candidate_access_log_root_sha256",
        "sealed_corpus_hash",
        "sealed_source_snapshot_sha256",
        "sealed_scenario_identity_inventory_sha256",
        "sealed_scenario_artifact_inventory_sha256",
        "sealed_validation_inventory_sha256",
        "transformation_inventory_sha256",
        "canary_inventory_sha256",
        "sealed_access_log_root_sha256",
    )
    @classmethod
    def _valid_hash(cls, value: str) -> str:
        """Require exact content commitments for every promotion artifact."""
        return _require_sha256(value, field_name="candidate promotion artifact hash")


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
    CORPUS_SCENARIO_ARTIFACT_MISSING = "corpus_scenario_artifact_missing"
    CORPUS_MACHINE_VALIDATION_RECEIPT_MISSING = "corpus_machine_validation_receipt_missing"
    CORPUS_CONTAINMENT_RECEIPT_MISSING = "corpus_containment_receipt_missing"
    CORPUS_DUMMY_SAFETY_RECEIPT_MISSING = "corpus_dummy_safety_receipt_missing"
    CORPUS_PROVENANCE_MISSING = "corpus_provenance_missing"
    CORPUS_MACHINE_REVIEW_INSUFFICIENT = "corpus_machine_review_insufficient"
    CORPUS_MACHINE_REVIEW_DIVERSITY_INVALID = "corpus_machine_review_diversity_invalid"
    CORPUS_MACHINE_REVIEW_BINDING_INVALID = "corpus_machine_review_binding_invalid"
    CORPUS_MACHINE_REVIEW_BLOCKED = "corpus_machine_review_blocked"
    CORPUS_RESOLUTION_VARIANTS_INSUFFICIENT = "corpus_resolution_variants_insufficient"
    CORPUS_RESOLUTION_VARIANTS_NOT_DISTINCT = "corpus_resolution_variants_not_distinct"
    CORPUS_AGENT_QA_INSUFFICIENT = "corpus_agent_qa_insufficient"
    CORPUS_AGENT_QA_DIVERSITY_INVALID = "corpus_agent_qa_diversity_invalid"
    CORPUS_AGENT_QA_INVALID = "corpus_agent_qa_invalid"
    CORPUS_BLIND_SOLVE_COUNT_INVALID = "corpus_blind_solve_count_invalid"
    CORPUS_BLIND_SOLVE_SELECTION_INVALID = "corpus_blind_solve_selection_invalid"
    CORPUS_BLIND_SOLVE_INVALID = "corpus_blind_solve_invalid"
    CORPUS_CANDIDATE_VALIDATION_RECEIPT_MISSING = "corpus_candidate_validation_receipt_missing"
    CORPUS_CANDIDATE_VALIDATION_RECEIPT_INVALID = "corpus_candidate_validation_receipt_invalid"
    CORPUS_CANDIDATE_PROMOTION_INVALID = "corpus_candidate_promotion_invalid"
    CORPUS_CONSTRUCTION_AUTHORIZATION_INVALID = "corpus_construction_authorization_invalid"
    CORPUS_VALIDATION_RUNTIME_UNBOUND = "corpus_validation_runtime_unbound"
    CORPUS_CUSTODY_INVENTORY_MISSING = "corpus_custody_inventory_missing"
    CORPUS_ACCESS_LOG_ROOT_MISSING = "corpus_access_log_root_missing"
    CORPUS_CANARY_VALIDATION_RECEIPT_MISSING = "corpus_canary_validation_receipt_missing"
    CORPUS_NOT_FROZEN = "corpus_not_frozen"
    PILOT_EVIDENCE_INSUFFICIENT = "pilot_evidence_insufficient"
    PILOT_CONFIGURATIONS_NOT_ANONYMIZED = "pilot_configurations_not_anonymized"
    PILOT_SELECTION_POLICY_INVALID = "pilot_selection_policy_invalid"
    PILOT_SELECTION_CORPUS_UNBOUND = "pilot_selection_corpus_unbound"
    PILOT_EVIDENCE_AUTHORIZATION_INVALID = "pilot_evidence_authorization_invalid"
    BASELINE_CONFIGURATION_COUNT_INVALID = "baseline_configuration_count_invalid"
    BASELINE_DUPLICATE_CONFIGURATION_ID = "baseline_duplicate_configuration_id"
    BASELINE_DUPLICATE_CONFIG_FINGERPRINT = "baseline_duplicate_config_fingerprint"
    BASELINE_PROVIDER_COUNT_INVALID = "baseline_provider_count_invalid"
    BASELINE_CORPUS_HASH_MISMATCH = "baseline_corpus_hash_mismatch"
    BASELINE_VERIFICATION_INVALID = "baseline_verification_invalid"
    BASELINE_PROTOCOL_NOT_FROZEN = "baseline_protocol_not_frozen"
    RUN_PROTOCOL_VERSION_MISMATCH = "run_protocol_version_mismatch"
    RUN_PUBLICATION_PIN_INCOMPLETE = "run_publication_pin_incomplete"
    RUN_CREDENTIAL_ISOLATION_FAILED = "run_credential_isolation_failed"
    RUN_MISSING_FAMILY = "run_missing_family"
    RUN_MARKED_PARTIAL = "run_marked_partial"
    RUN_SCENARIO_SET_MISMATCH = "run_scenario_set_mismatch"
    RUN_DUPLICATE_RESULT = "run_duplicate_result"
    RUN_REPETITION_COUNT_INVALID = "run_repetition_count_invalid"
    RUN_REPETITION_INDEX_INVALID = "run_repetition_index_invalid"
    RUN_NON_SEALED_RESULT = "run_non_sealed_result"
    RUN_RESULT_METADATA_MISMATCH = "run_result_metadata_mismatch"
    RUN_ERROR_RATE_EXCEEDED = "run_error_rate_exceeded"
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
    RELEASE_EVIDENCE_AUTHORIZATION_INVALID = "release_evidence_authorization_invalid"
    CONFORMANCE_ENVIRONMENTS_INSUFFICIENT = "conformance_environments_insufficient"
    CONFORMANCE_PLATFORM_DIVERSITY_INSUFFICIENT = "conformance_platform_diversity_insufficient"
    CROSS_MACHINE_REPRODUCTION_MISSING = "cross_machine_reproduction_missing"
    CROSS_MACHINE_REPRODUCTION_INVALID = "cross_machine_reproduction_invalid"
    RELEASE_AUTHORIZATION_MISSING = "release_authorization_missing"
    RELEASE_AUTHORIZATION_INVALID = "release_authorization_invalid"
    HUMAN_APPROVAL_MISSING = "human_approval_missing"
    HUMAN_APPROVAL_INVALID = "human_approval_invalid"


class PilotSelectionPolicy(_FrozenModel):
    """Protocol-frozen complete-corpus pilot selection and evaluation contract.

    This policy proves deterministic item inclusion and evaluation semantics. It does not
    claim that an operator chose configurations without preferences or that the policy was
    externally timestamped before execution.
    """

    format_version: Literal["1"]
    population: Literal["complete-candidate-to-sealed-identity-set"]
    scenario_selection: Literal["all-scenarios"]
    scenario_count: int = Field(gt=0)
    repetitions_per_configuration: Literal[1]
    minimum_anonymous_configurations: int = Field(ge=2)
    configuration_uniqueness: Literal["distinct-resolved-and-agent-configuration-fingerprints"]
    alias_disclosure: Literal["opaque-provider-model-free"]
    variation_measure: Literal["scenario-outcome-disagreement-rate"]
    minimum_variation_rate: float = Field(ge=0.0, le=1.0)


def pilot_selection_policy_sha256(policy: PilotSelectionPolicy) -> str:
    """Hash the exact closed pilot policy embedded in the signed protocol."""
    return _canonical_sha256(policy)


class BenchmarkProtocolManifest(_FrozenModel):
    """Explicit machine-readable form of the frozen Protocol 2 thresholds."""

    benchmark_protocol_version: str
    rubric_version: str
    verification_image_policy: VerificationImagePolicy
    credential_isolation_policy: CredentialIsolationPolicy
    pilot_selection_policy: PilotSelectionPolicy
    families: tuple[Family, ...]
    total_scenarios: int
    scenarios_per_family: int
    repositories_per_size_per_family: int
    repetitions: int
    baseline_configurations: int
    baseline_providers: int
    min_scorable_outcomes_per_family: int
    max_error_rate: float
    machine_reviews_per_scenario: int
    machine_review_providers_per_scenario: int
    machine_review_prompt_sha256: str
    machine_review_output_schema_sha256: str
    resolution_variants_per_kind: int
    agent_qa_attempts_per_scenario: int
    agent_qa_configurations_per_scenario: int
    agent_qa_providers_per_scenario: int
    blind_agent_solve_scenarios_per_family: int
    blind_agent_solvers_per_scenario: int
    blind_agent_solver_configurations_per_scenario: int
    blind_agent_solver_providers_per_scenario: int
    blind_agent_solve_selection_seed: int
    baseline_run_seed: int
    bootstrap_seed: int
    min_pilot_variation_rate: float
    confidence_level: float
    min_bootstrap_samples: int
    conformance_environments: int
    conformance_platforms: int
    cross_machine_reproductions: int

    @field_validator("benchmark_protocol_version", "rubric_version")
    @classmethod
    def _valid_protocol_version(cls, value: str) -> str:
        """Require complete semantic versions in the frozen protocol."""
        return _require_semver(value, field_name="protocol version")

    @field_validator(
        "machine_review_prompt_sha256",
        "machine_review_output_schema_sha256",
    )
    @classmethod
    def _valid_review_contract_hash(cls, value: str) -> str:
        """Require exact hashes for the frozen reviewer prompt and output contract."""
        return _require_sha256(value, field_name="machine review contract hash")

    @model_validator(mode="after")
    def _pilot_policy_matches_protocol_thresholds(self) -> BenchmarkProtocolManifest:
        """Prevent duplicated pilot thresholds from silently contradicting each other."""
        if (
            self.pilot_selection_policy.scenario_count != self.total_scenarios
            or self.pilot_selection_policy.minimum_variation_rate != self.min_pilot_variation_rate
        ):
            raise ValueError("pilot selection policy contradicts protocol thresholds")
        return self


def compiled_benchmark_protocol() -> BenchmarkProtocolManifest:
    """Return the one complete Protocol 2 manifest compiled into this release."""
    return BenchmarkProtocolManifest(
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        rubric_version=RUBRIC_VERSION,
        verification_image_policy=compiled_verification_image_policy(),
        credential_isolation_policy=compiled_credential_isolation_policy(),
        pilot_selection_policy=PilotSelectionPolicy(
            format_version=PILOT_SELECTION_POLICY_FORMAT_VERSION,
            population="complete-candidate-to-sealed-identity-set",
            scenario_selection="all-scenarios",
            scenario_count=TOTAL_SCENARIOS,
            repetitions_per_configuration=1,
            minimum_anonymous_configurations=2,
            configuration_uniqueness=("distinct-resolved-and-agent-configuration-fingerprints"),
            alias_disclosure="opaque-provider-model-free",
            variation_measure="scenario-outcome-disagreement-rate",
            minimum_variation_rate=MIN_PILOT_VARIATION_RATE,
        ),
        families=tuple(Family),
        total_scenarios=TOTAL_SCENARIOS,
        scenarios_per_family=SCENARIOS_PER_FAMILY,
        repositories_per_size_per_family=REPOSITORIES_PER_SIZE_PER_FAMILY,
        repetitions=PUBLICATION_REPETITIONS,
        baseline_configurations=BASELINE_CONFIGURATIONS,
        baseline_providers=BASELINE_PROVIDERS,
        min_scorable_outcomes_per_family=MIN_SCORABLE_OUTCOMES_PER_FAMILY,
        max_error_rate=MAX_ERROR_RATE,
        machine_reviews_per_scenario=REQUIRED_MACHINE_REVIEWS,
        machine_review_providers_per_scenario=REQUIRED_MACHINE_REVIEW_PROVIDERS,
        machine_review_prompt_sha256=MACHINE_REVIEW_PROMPT_SHA256,
        machine_review_output_schema_sha256=MACHINE_REVIEW_OUTPUT_SCHEMA_SHA256,
        resolution_variants_per_kind=REQUIRED_RESOLUTION_VARIANTS,
        agent_qa_attempts_per_scenario=REQUIRED_AGENT_QA_ATTEMPTS,
        agent_qa_configurations_per_scenario=REQUIRED_AGENT_QA_CONFIGURATIONS,
        agent_qa_providers_per_scenario=REQUIRED_AGENT_QA_PROVIDERS,
        blind_agent_solve_scenarios_per_family=BLIND_AGENT_SOLVES_PER_FAMILY,
        blind_agent_solvers_per_scenario=BLIND_AGENT_SOLVERS_PER_SCENARIO,
        blind_agent_solver_configurations_per_scenario=BLIND_AGENT_SOLVER_CONFIGURATIONS,
        blind_agent_solver_providers_per_scenario=BLIND_AGENT_SOLVER_PROVIDERS,
        blind_agent_solve_selection_seed=BLIND_AGENT_SOLVE_SELECTION_SEED,
        baseline_run_seed=BASELINE_RUN_SEED,
        bootstrap_seed=BOOTSTRAP_SEED,
        min_pilot_variation_rate=MIN_PILOT_VARIATION_RATE,
        confidence_level=DEFAULT_CONFIDENCE_LEVEL,
        min_bootstrap_samples=MIN_BOOTSTRAP_SAMPLES,
        conformance_environments=REQUIRED_CONFORMANCE_ENVIRONMENTS,
        conformance_platforms=REQUIRED_CONFORMANCE_PLATFORMS,
        cross_machine_reproductions=1,
    )


class ResolutionVariantRecord(_FrozenModel):
    """One artifact-bound honest resolution or cheat attempt."""

    variant_id: str
    kind: ResolutionKind
    source_tree_sha256: str
    semantic_patch_sha256: str
    execution_receipt_sha256: str

    @field_validator("variant_id")
    @classmethod
    def _valid_variant_id(cls, value: str) -> str:
        """Require one canonical resolution-variant identifier."""
        return _require_identifier(value, field_name="variant_id")

    @field_validator(
        "source_tree_sha256",
        "semantic_patch_sha256",
        "execution_receipt_sha256",
    )
    @classmethod
    def _valid_artifact_hash(cls, value: str) -> str:
        """Require exact content bindings rather than favorable booleans."""
        return _require_sha256(value, field_name="resolution artifact hash")


class AgentQAAttemptRecord(_FrozenModel):
    """One artifact-bound contained agent QA attempt."""

    attempt_id: str
    provider: ProviderId
    agent_configuration_fingerprint: str
    result_sha256: str
    evidence_manifest_sha256: str
    runtime_receipt_sha256: str
    outcome: Outcome

    @field_validator("attempt_id")
    @classmethod
    def _valid_attempt_id(cls, value: str) -> str:
        """Require one canonical QA attempt identifier."""
        return _require_identifier(value, field_name="attempt_id")

    @field_validator(
        "agent_configuration_fingerprint",
        "result_sha256",
        "evidence_manifest_sha256",
        "runtime_receipt_sha256",
    )
    @classmethod
    def _valid_artifact_hash(cls, value: str) -> str:
        """Require exact configuration and evidence bindings."""
        return _require_sha256(value, field_name="agent QA artifact hash")


class MachineReviewRecord(_FrozenModel):
    """One provider-diverse machine veto over an exact scenario and QA manifest."""

    review_id: str
    provider: ProviderId
    model_id: str
    reviewer_configuration_fingerprint: str
    runtime_receipt_sha256: str
    runtime_signer_identity: str
    runtime_signing_key_fingerprint: str
    runtime_allowed_signers_sha256: str
    runtime_signature_sha256: str
    prompt_sha256: str
    input_manifest_sha256: str
    output_schema_sha256: str
    output_sha256: str
    output: MachineReviewOutput

    @field_validator("review_id", "model_id", "runtime_signer_identity")
    @classmethod
    def _valid_review_identifier(cls, value: str) -> str:
        """Require canonical reviewer and model identifiers."""
        return _require_identifier(value, field_name="machine review identifier")

    @field_validator("runtime_signing_key_fingerprint")
    @classmethod
    def _valid_runtime_key_fingerprint(cls, value: str) -> str:
        """Require the exact OpenSSH fingerprint that authorized the runtime receipt."""
        if _SSH_KEY_FINGERPRINT_PATTERN.fullmatch(value) is None:
            raise ValueError("machine review runtime key fingerprint is invalid")
        return value

    @field_validator(
        "reviewer_configuration_fingerprint",
        "runtime_receipt_sha256",
        "runtime_allowed_signers_sha256",
        "runtime_signature_sha256",
        "prompt_sha256",
        "input_manifest_sha256",
        "output_schema_sha256",
        "output_sha256",
    )
    @classmethod
    def _valid_artifact_hash(cls, value: str) -> str:
        """Require exact reviewer configuration, runtime, input, and output bindings."""
        return _require_sha256(value, field_name="machine review artifact hash")


class BlindAgentSolveRecord(_FrozenModel):
    """One reference-isolated agent solve over a deterministically selected scenario."""

    solve_id: str
    provider: ProviderId
    solver_configuration_fingerprint: str
    result_sha256: str
    evidence_manifest_sha256: str
    runtime_receipt_sha256: str
    reference_isolation_receipt_sha256: str
    outcome: Outcome

    @field_validator("solve_id")
    @classmethod
    def _valid_solve_id(cls, value: str) -> str:
        """Require one canonical blind-solve identifier."""
        return _require_identifier(value, field_name="solve_id")

    @field_validator(
        "solver_configuration_fingerprint",
        "result_sha256",
        "evidence_manifest_sha256",
        "runtime_receipt_sha256",
        "reference_isolation_receipt_sha256",
    )
    @classmethod
    def _valid_artifact_hash(cls, value: str) -> str:
        """Require exact solve, runtime, and reference-isolation bindings."""
        return _require_sha256(value, field_name="blind agent solve artifact hash")


class CorpusScenarioRecord(_FrozenModel):
    """All construction evidence required for one active scoring scenario."""

    scenario_id: str
    family: Family
    repository_size: RepositorySize
    benchmark_split: BenchmarkSplit
    scenario_version: str
    cluster_id: str
    expected_honest_outcome: Outcome
    scenario_artifact_sha256: str
    machine_validation_receipt_sha256: str
    provenance_receipt_sha256: str
    containment_receipt_sha256: str
    dummy_safety_receipt_sha256: str
    resolution_variants: tuple[ResolutionVariantRecord, ...] = ()
    agent_qa_attempts: tuple[AgentQAAttemptRecord, ...] = ()
    machine_reviews: tuple[MachineReviewRecord, ...] = ()
    blind_agent_solves: tuple[BlindAgentSolveRecord, ...] = ()

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

    @field_validator(
        "scenario_artifact_sha256",
        "machine_validation_receipt_sha256",
        "provenance_receipt_sha256",
        "containment_receipt_sha256",
        "dummy_safety_receipt_sha256",
    )
    @classmethod
    def _valid_artifact_hash(cls, value: str) -> str:
        """Require exact scenario-construction receipt bindings."""
        return _require_sha256(value, field_name="scenario construction artifact hash")

    @field_validator("expected_honest_outcome")
    @classmethod
    def _valid_expected_honest_outcome(cls, value: Outcome) -> Outcome:
        """Restrict construction evidence to an honest completion or justified refusal."""
        if value not in {Outcome.HONEST, Outcome.REFUSED}:
            raise ValueError("expected_honest_outcome must be honest or refused")
        return value


class CorpusFreezeStatement(_FrozenModel):
    """Signed statement binding one exact sealed corpus and its machine receipts."""

    benchmark_protocol_version: str
    rubric_version: str
    corpus_version: str
    corpus_hash: str
    scenario_inventory_sha256: str
    candidate_validation_receipt_sha256: str
    candidate_promotion_statement_sha256: str
    custody_inventory_sha256: str
    access_log_root_sha256: str
    canary_validation_receipt_sha256: str
    scenario_count: int = Field(ge=0)
    scenarios_by_family: dict[Family, int]
    scenarios_by_size: dict[RepositorySize, int]
    signer_identity: str

    @field_validator(
        "benchmark_protocol_version",
        "rubric_version",
        "corpus_version",
    )
    @classmethod
    def _valid_version(cls, value: str) -> str:
        """Require semantic versions throughout the freeze statement."""
        return _require_semver(value, field_name="corpus freeze version")

    @field_validator(
        "corpus_hash",
        "scenario_inventory_sha256",
        "candidate_validation_receipt_sha256",
        "candidate_promotion_statement_sha256",
        "custody_inventory_sha256",
        "access_log_root_sha256",
        "canary_validation_receipt_sha256",
    )
    @classmethod
    def _valid_artifact_hash(cls, value: str) -> str:
        """Require exact content bindings for every frozen corpus artifact."""
        return _require_sha256(value, field_name="corpus freeze artifact")

    @field_validator("signer_identity")
    @classmethod
    def _valid_signer_identity(cls, value: str) -> str:
        """Require one canonical freeze signer identity."""
        return _require_identifier(value, field_name="corpus freeze signer identity")


class CorpusFreezeRecord(_FrozenModel):
    """Submission-side binding to a separately signed corpus-freeze statement."""

    signer_identity: str
    statement_sha256: str
    statement_signature_sha256: str
    allowed_signers_sha256: str

    @field_validator("signer_identity")
    @classmethod
    def _valid_signer_identity(cls, value: str) -> str:
        """Require one canonical freeze signer identity."""
        return _require_identifier(value, field_name="corpus freeze signer identity")

    @field_validator(
        "statement_sha256",
        "statement_signature_sha256",
        "allowed_signers_sha256",
    )
    @classmethod
    def _valid_artifact_hash(cls, value: str) -> str:
        """Require exact freeze statement, signature, and trust hashes."""
        return _require_sha256(value, field_name="corpus freeze authorization")


class SealedCorpusRecord(_FrozenModel):
    """Corpus-wide exact validation, custody, canary, access-log, and freeze bindings."""

    corpus_version: str
    corpus_hash: str
    scenarios: tuple[CorpusScenarioRecord, ...]
    candidate_validation_receipt_sha256: str | None = None
    candidate_promotion_statement_sha256: str | None = None
    custody_inventory_sha256: str | None = None
    access_log_root_sha256: str | None = None
    canary_validation_receipt_sha256: str | None = None
    freeze: CorpusFreezeRecord | None = None

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

    @field_validator(
        "candidate_validation_receipt_sha256",
        "candidate_promotion_statement_sha256",
        "custody_inventory_sha256",
        "access_log_root_sha256",
        "canary_validation_receipt_sha256",
    )
    @classmethod
    def _valid_optional_artifact_hash(cls, value: str | None) -> str | None:
        """Validate present corpus-wide receipt hashes while allowing truthful HOLD files."""
        if value is None:
            return None
        return _require_sha256(value, field_name="sealed corpus artifact hash")


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


class BaselineVerificationStatement(_FrozenModel):
    """Signed statement emitted only after rebuilding one baseline from exact bundles."""

    benchmark_protocol_version: str
    rubric_version: str
    configuration_id: str
    corpus_hash: str
    baseline_record_sha256: str
    signer_identity: str

    @field_validator("benchmark_protocol_version", "rubric_version")
    @classmethod
    def _valid_version(cls, value: str) -> str:
        """Require complete protocol and rubric versions."""
        return _require_semver(value, field_name="baseline statement version")

    @field_validator("configuration_id", "signer_identity")
    @classmethod
    def _valid_identifier(cls, value: str) -> str:
        """Require canonical baseline and signer identifiers."""
        return _require_identifier(value, field_name="baseline statement identifier")

    @field_validator("corpus_hash", "baseline_record_sha256")
    @classmethod
    def _valid_hash(cls, value: str) -> str:
        """Require exact corpus and rebuilt-record commitments."""
        return _require_sha256(value, field_name="baseline statement artifact hash")


def baseline_configuration_record_sha256(record: BaselineConfigurationRecord) -> str:
    """Hash one complete baseline record in canonical typed form."""
    return _canonical_sha256(record)


class PilotConfigurationOutcomeRecord(_FrozenModel):
    """One observed outcome under an opaque pilot configuration alias."""

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
        """Bind selection to the protocol-frozen closed pilot policy when present."""
        if value is None:
            return None
        return _require_sha256(value, field_name="selection_protocol_sha256")


class ConformanceEnvironmentStatement(_FrozenModel):
    """Signed artifact-derived statement for one clean-environment workflow run."""

    environment_id: str
    platform: ConformancePlatform
    architecture: ConformanceArchitecture
    python_version: str
    stinger_commit: str
    benchmark_protocol_version: str
    rubric_version: str
    corpus_hash: str
    environment_fingerprint_sha256: str
    workflow_input_sha256: str
    workflow_output_inventory_sha256: str
    signer_identity: str

    @field_validator("environment_id", "python_version", "signer_identity")
    @classmethod
    def _valid_identifier(cls, value: str) -> str:
        """Require canonical conformance and signer identifiers."""
        return _require_identifier(value, field_name="conformance statement identifier")

    @field_validator("benchmark_protocol_version", "rubric_version")
    @classmethod
    def _valid_version(cls, value: str) -> str:
        """Require complete protocol and rubric versions."""
        return _require_semver(value, field_name="conformance statement version")

    @field_validator(
        "corpus_hash",
        "environment_fingerprint_sha256",
        "workflow_input_sha256",
        "workflow_output_inventory_sha256",
    )
    @classmethod
    def _valid_artifact_hash(cls, value: str) -> str:
        """Require exact environment and workflow statement hashes."""
        return _require_sha256(value, field_name="conformance statement artifact hash")

    @field_validator("stinger_commit")
    @classmethod
    def _valid_commit(cls, value: str) -> str:
        """Require a full Git object id for the conformance workflow."""
        if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is None:
            raise ValueError("stinger_commit must be a full lowercase Git object id")
        return value


class ConformanceEnvironmentRecord(_FrozenModel):
    """One exact clean-environment execution of the public conformance workflow."""

    environment_id: str
    platform: ConformancePlatform
    architecture: ConformanceArchitecture
    python_version: str
    stinger_commit: str
    benchmark_protocol_version: str
    rubric_version: str
    corpus_hash: str
    environment_fingerprint_sha256: str
    workflow_input_sha256: str
    workflow_receipt_sha256: str
    receipt_signature_sha256: str
    allowed_signers_sha256: str
    signer_identity: str

    @field_validator(
        "environment_id",
        "python_version",
        "signer_identity",
    )
    @classmethod
    def _valid_identifier(cls, value: str) -> str:
        """Require canonical conformance and signer identifiers."""
        return _require_identifier(value, field_name="conformance identifier")

    @field_validator("benchmark_protocol_version", "rubric_version")
    @classmethod
    def _valid_version(cls, value: str) -> str:
        """Require complete protocol and rubric versions."""
        return _require_semver(value, field_name="conformance version")

    @field_validator(
        "corpus_hash",
        "environment_fingerprint_sha256",
        "workflow_input_sha256",
        "workflow_receipt_sha256",
        "receipt_signature_sha256",
        "allowed_signers_sha256",
    )
    @classmethod
    def _valid_artifact_hash(cls, value: str) -> str:
        """Require exact environment and workflow receipt hashes."""
        return _require_sha256(value, field_name="conformance environment artifact hash")

    @field_validator("stinger_commit")
    @classmethod
    def _valid_commit(cls, value: str) -> str:
        """Require a full Git object id for the clean conformance environment."""
        if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is None:
            raise ValueError("stinger_commit must be a full lowercase Git object id")
        return value


class ReproductionDiscrepancyClassification(StrEnum):
    """Only permitted explanation for per-run differences under a stable modal result."""

    EXPECTED_AGENT_VARIANCE_MODAL_STABLE = "expected_agent_variance_modal_stable"


class ReproductionDiscrepancyRecord(_FrozenModel):
    """One automatic target-versus-reproduction difference under a stable modal result."""

    discrepancy_id: str
    scenario_id: str
    repetition: int = Field(ge=0)
    field: str
    target_value_sha256: str
    reproduced_value_sha256: str
    classification: ReproductionDiscrepancyClassification

    @field_validator("target_value_sha256", "reproduced_value_sha256")
    @classmethod
    def _valid_value_hash(cls, value: str) -> str:
        """Require exact digests for both compared values."""
        return _require_sha256(value, field_name="discrepancy value hash")


class CrossMachineReproductionStatement(_FrozenModel):
    """Externally signed statement binding one complete cross-machine reproduction."""

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
    reproduced_report_signature_namespace: str
    reproduced_report_signer_identity: str
    reproduced_report_signing_key_fingerprint: str
    reproduced_report_allowed_signers_sha256: str
    reproduced_public_bundle_manifest_sha256: str
    reproduced_escrow_bundle_manifest_sha256: str
    reproduced_machine_fingerprint_sha256: str
    reproduced_config_fingerprint: str
    reproduced_agent_configuration_fingerprint: str
    comparison_manifest_sha256: str
    discrepancy_ledger_sha256: str
    target_modal_outcomes_sha256: str
    reproduced_modal_outcomes_sha256: str
    completed_families: tuple[Family, ...]
    scenario_count: int = Field(ge=0)
    repetitions: int = Field(ge=0)
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
        "reproduced_report_allowed_signers_sha256",
        "reproduced_public_bundle_manifest_sha256",
        "reproduced_escrow_bundle_manifest_sha256",
        "reproduced_machine_fingerprint_sha256",
        "reproduced_config_fingerprint",
        "reproduced_agent_configuration_fingerprint",
        "comparison_manifest_sha256",
        "discrepancy_ledger_sha256",
        "target_modal_outcomes_sha256",
        "reproduced_modal_outcomes_sha256",
    )
    @classmethod
    def _valid_sha256_fields(cls, value: str) -> str:
        """Require exact sha256 binding for every verifier artifact and machine pin."""
        return _require_sha256(value, field_name="reproduction artifact hash")


class CrossMachineReproductionRecord(_FrozenModel):
    """Submission-side binding to a separately signed cross-machine statement."""

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
    """Content-bound project-wide release evidence outside result reports."""

    protocol_freeze_receipt_sha256: str | None = None
    master_gate_receipt_sha256: str | None = None
    technical_report_sha256: str | None = None
    correction_policy_sha256: str | None = None
    conflicts_disclosure_sha256: str | None = None
    comparative_release: bool = False
    vendor_rerun_receipt_sha256: str | None = None

    @field_validator(
        "protocol_freeze_receipt_sha256",
        "master_gate_receipt_sha256",
        "technical_report_sha256",
        "correction_policy_sha256",
        "conflicts_disclosure_sha256",
        "vendor_rerun_receipt_sha256",
    )
    @classmethod
    def _valid_optional_receipt_hash(cls, value: str | None) -> str | None:
        """Require exact artifact bindings when release evidence is present."""
        if value is None:
            return None
        return _require_sha256(value, field_name="release evidence receipt")


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

    protocol: BenchmarkProtocolManifest
    corpus: SealedCorpusRecord
    baselines: tuple[BaselineConfigurationRecord, ...]
    pilot: PilotEvidenceRecord
    conformance_environments: tuple[ConformanceEnvironmentRecord, ...]
    cross_machine_reproduction: CrossMachineReproductionRecord | None
    release_evidence: ReleaseEvidenceRecord
    human_approval: HumanApprovalRecord | None


@dataclass(frozen=True, slots=True)
class VerifiedCorpusFreezeAuthorization:
    """Out-of-band proof and parsed content of a trusted corpus-freeze statement."""

    statement: CorpusFreezeStatement
    identity: str
    namespace: str
    statement_sha256: str
    canonical_statement_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str
    signing_key_fingerprint: str


@dataclass(frozen=True, slots=True)
class VerifiedCandidateValidationAuthorization:
    """Out-of-band proof and parsed content of a signed candidate receipt."""

    receipt: CandidateValidationReceipt
    identity: str
    namespace: str
    receipt_sha256: str
    canonical_receipt_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str
    signing_key_fingerprint: str


@dataclass(frozen=True, slots=True)
class VerifiedCandidatePromotionAuthorization:
    """Out-of-band proof and parsed content of a signed promotion statement."""

    statement: CandidatePromotionStatement
    identity: str
    namespace: str
    statement_sha256: str
    canonical_statement_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str
    signing_key_fingerprint: str


@dataclass(frozen=True, slots=True)
class VerifiedConformanceAuthorization:
    """Out-of-band proof and parsed content of a signed conformance statement."""

    statement: ConformanceEnvironmentStatement
    identity: str
    namespace: str
    statement_sha256: str
    canonical_statement_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str
    signing_key_fingerprint: str


@dataclass(frozen=True, slots=True)
class VerifiedBaselineAuthorization:
    """Out-of-band proof and parsed content of one rebuilt baseline statement."""

    statement: BaselineVerificationStatement
    identity: str
    namespace: str
    statement_sha256: str
    canonical_statement_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str
    signing_key_fingerprint: str


@dataclass(frozen=True, slots=True)
class VerifiedPilotEvidenceAuthorization:
    """Out-of-band proof of exact artifact-derived anonymous pilot evidence."""

    statement_bytes: bytes
    identity: str
    namespace: str
    statement_sha256: str
    canonical_statement_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str
    signing_key_fingerprint: str
    benchmark_protocol_version: str
    rubric_version: str
    corpus_version: str
    corpus_hash: str
    candidate_corpus_hash: str
    evaluated_corpus_hash: str
    evaluated_split: BenchmarkSplit
    protocol_sha256: str
    candidate_validation_receipt_sha256: str
    candidate_scenario_identity_inventory_sha256: str
    selection_protocol_sha256: str
    scenario_count: int
    configuration_count: int
    pilot_evidence_sha256: str
    pilot: PilotEvidenceRecord


@dataclass(frozen=True, slots=True)
class VerifiedReleaseEvidenceAuthorization:
    """Out-of-band proof of exact artifact-derived project release evidence."""

    statement_bytes: bytes
    identity: str
    namespace: str
    statement_sha256: str
    canonical_statement_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str
    signing_key_fingerprint: str
    benchmark_protocol_version: str
    rubric_version: str
    corpus_version: str
    corpus_hash: str
    stinger_commit: str
    release_evidence: ReleaseEvidenceRecord
    release_evidence_record_sha256: str
    canonical_submission_sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedProtocolAuthorization:
    """Out-of-band proof that exact Protocol 2 bytes have trusted signature authority."""

    identity: str
    namespace: str
    protocol_sha256: str
    canonical_protocol_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str
    signing_key_fingerprint: str


@dataclass(frozen=True, slots=True)
class VerifiedReleaseAuthorization:
    """Out-of-band proof that exact submission bytes have a trusted human signature."""

    identity: str
    namespace: str
    submission_sha256: str
    canonical_submission_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str
    signing_key_fingerprint: str


@dataclass(frozen=True, slots=True)
class VerifiedCrossMachineReproductionAuthorization:
    """Out-of-band proof and parsed content of a trusted cross-machine statement."""

    statement: CrossMachineReproductionStatement
    identity: str
    namespace: str
    statement_sha256: str
    canonical_statement_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str
    signing_key_fingerprint: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicReproductionAuthorization:
    """Direct verification receipt for every non-secret reproduction artifact."""

    verification_statement_sha256: str
    verification_signature_sha256: str
    verification_allowed_signers_sha256: str
    verification_signing_key_fingerprint: str
    verification_signer_identity: str
    verification_signature_namespace: str
    benchmark_protocol_version: str
    statement_sha256: str
    target_baseline_record_sha256: str
    target_report_sha256: str
    target_report_bytes_sha256: str
    target_public_bundle_manifest_sha256: str
    target_public_bundle_inventory_sha256: str
    target_public_bundle_leakage_policy_sha256: str
    target_public_bundle_report_sha256: str
    target_protocol_sha256: str
    target_protocol_signature_sha256: str
    target_protocol_allowed_signers_sha256: str
    target_protocol_signer_identity: str
    reproduced_public_bundle_manifest_sha256: str
    reproduced_public_bundle_inventory_sha256: str
    reproduced_public_bundle_leakage_policy_sha256: str
    reproduced_public_bundle_report_sha256: str
    reproduced_protocol_sha256: str
    reproduced_protocol_signature_sha256: str
    reproduced_protocol_allowed_signers_sha256: str
    reproduced_protocol_signer_identity: str
    reproduced_report_sha256: str
    reproduced_report_bytes_sha256: str
    reproduced_report_signature_sha256: str
    reproduced_report_allowed_signers_sha256: str
    reproduced_report_signing_key_fingerprint: str
    reproduced_report_signer_identity: str
    comparison_manifest_sha256: str
    discrepancy_ledger_sha256: str


class GateIssue(_FrozenModel):
    """One stable blocking reason, optionally scoped to a concrete subject."""

    code: PublicationIssueCode
    subject: str | None
    detail: str


class ConfigurationGateMetrics(_FrozenModel):
    """Auditable denominator counts for one baseline configuration."""

    total_expected_repetitions: int
    observed_repetitions: int
    errors: int
    error_rate: float
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
    blind_agent_solves_by_family: dict[Family, int]
    baseline_configurations: int
    baseline_providers: int
    conformance_environments: int
    cross_machine_reproductions: int


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
    raw = yaml.safe_load(_read_regular_file_bytes(path, label="benchmark protocol").decode("utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("benchmark protocol YAML root must be a mapping")
    return BenchmarkProtocolManifest.model_validate(raw)


def authorize_benchmark_protocol(
    path: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> tuple[BenchmarkProtocolManifest, VerifiedProtocolAuthorization]:
    """Load exact protocol bytes and verify their detached external signature."""
    try:
        content = _read_regular_file_bytes(path, label="benchmark protocol")
    except ValueError as exc:
        raise ProtocolSignatureError(
            "benchmark protocol must be a regular nonsymlink file"
        ) from exc
    verification = verify_protocol_signature(
        path,
        signature,
        allowed_signers,
        identity,
    )
    if hashlib.sha256(content).hexdigest() != verification.protocol_sha256:
        raise ProtocolSignatureError("benchmark protocol changed during signature verification")
    raw = yaml.safe_load(content.decode("utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("benchmark protocol YAML root must be a mapping")
    protocol = BenchmarkProtocolManifest.model_validate(raw)
    return protocol, VerifiedProtocolAuthorization(
        identity=verification.identity,
        namespace=verification.namespace,
        protocol_sha256=verification.protocol_sha256,
        canonical_protocol_sha256=_canonical_sha256(protocol),
        signature_sha256=verification.signature_sha256,
        allowed_signers_sha256=verification.allowed_signers_sha256,
        signing_key_fingerprint=verification.signing_key_fingerprint,
    )


def load_benchmark_submission(path: Path) -> BenchmarkReleaseSubmission:
    """Load a closed YAML/JSON release-evidence submission.

    The submission may deliberately contain empty candidate-state records; those parse and
    then fail the release gate with explicit issue codes. Missing or extra schema fields do
    not parse, because an unknown record cannot count as release evidence.
    """
    raw = yaml.safe_load(
        _read_regular_file_bytes(path, label="benchmark release submission").decode("utf-8")
    )
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
    try:
        content = _read_regular_file_bytes(path, label="release submission")
    except ValueError as exc:
        raise ProtocolSignatureError(
            "release submission must be a regular nonsymlink file"
        ) from exc
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
        signing_key_fingerprint=verification.signing_key_fingerprint,
    )


def authorize_corpus_freeze_statement(
    path: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> VerifiedCorpusFreezeAuthorization:
    """Load and externally verify one exact corpus-freeze statement."""
    try:
        content = _read_regular_file_bytes(path, label="corpus freeze statement")
    except ValueError as exc:
        raise ProtocolSignatureError(
            "corpus freeze statement must be a regular nonsymlink file"
        ) from exc
    verification = verify_corpus_freeze_statement_signature(
        path,
        signature,
        allowed_signers,
        identity,
    )
    if hashlib.sha256(content).hexdigest() != verification.artifact_sha256:
        raise ProtocolSignatureError("corpus freeze statement changed during verification")
    raw = yaml.safe_load(content.decode("utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("corpus freeze statement root must be a mapping")
    statement = CorpusFreezeStatement.model_validate(raw)
    return VerifiedCorpusFreezeAuthorization(
        statement=statement,
        identity=verification.identity,
        namespace=verification.namespace,
        statement_sha256=verification.artifact_sha256,
        canonical_statement_sha256=_canonical_sha256(statement),
        signature_sha256=verification.signature_sha256,
        allowed_signers_sha256=verification.allowed_signers_sha256,
        signing_key_fingerprint=verification.signing_key_fingerprint,
    )


def authorize_candidate_validation_receipt(
    path: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> VerifiedCandidateValidationAuthorization:
    """Load and externally verify one exact public candidate-validation receipt."""
    try:
        content = _read_regular_file_bytes(path, label="candidate validation receipt")
    except ValueError as exc:
        raise ProtocolSignatureError(
            "candidate validation receipt must be a regular nonsymlink file"
        ) from exc
    verification = verify_candidate_validation_receipt_signature(
        path,
        signature,
        allowed_signers,
        identity,
    )
    if hashlib.sha256(content).hexdigest() != verification.artifact_sha256:
        raise ProtocolSignatureError("candidate validation receipt changed during verification")
    raw = json.loads(content)
    if not isinstance(raw, dict):
        raise ValueError("candidate validation receipt root must be a mapping")
    receipt = CandidateValidationReceipt.model_validate(raw)
    return VerifiedCandidateValidationAuthorization(
        receipt=receipt,
        identity=verification.identity,
        namespace=verification.namespace,
        receipt_sha256=verification.artifact_sha256,
        canonical_receipt_sha256=_canonical_sha256(receipt),
        signature_sha256=verification.signature_sha256,
        allowed_signers_sha256=verification.allowed_signers_sha256,
        signing_key_fingerprint=verification.signing_key_fingerprint,
    )


def authorize_candidate_promotion_statement(
    path: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> VerifiedCandidatePromotionAuthorization:
    """Load and externally verify one exact candidate-to-sealed statement."""
    try:
        content = _read_regular_file_bytes(path, label="candidate promotion statement")
    except ValueError as exc:
        raise ProtocolSignatureError(
            "candidate promotion statement must be a regular nonsymlink file"
        ) from exc
    verification = verify_candidate_promotion_statement_signature(
        path,
        signature,
        allowed_signers,
        identity,
    )
    if hashlib.sha256(content).hexdigest() != verification.artifact_sha256:
        raise ProtocolSignatureError("candidate promotion statement changed during verification")
    raw = json.loads(content)
    if not isinstance(raw, dict):
        raise ValueError("candidate promotion statement root must be a mapping")
    statement = CandidatePromotionStatement.model_validate(raw)
    return VerifiedCandidatePromotionAuthorization(
        statement=statement,
        identity=verification.identity,
        namespace=verification.namespace,
        statement_sha256=verification.artifact_sha256,
        canonical_statement_sha256=_canonical_sha256(statement),
        signature_sha256=verification.signature_sha256,
        allowed_signers_sha256=verification.allowed_signers_sha256,
        signing_key_fingerprint=verification.signing_key_fingerprint,
    )


def authorize_conformance_statement(
    path: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> VerifiedConformanceAuthorization:
    """Load and externally verify one exact clean-environment statement."""
    try:
        content = _read_regular_file_bytes(path, label="conformance statement")
    except ValueError as exc:
        raise ProtocolSignatureError(
            "conformance statement must be a regular nonsymlink file"
        ) from exc
    verification = verify_conformance_statement_signature(
        path,
        signature,
        allowed_signers,
        identity,
    )
    if hashlib.sha256(content).hexdigest() != verification.artifact_sha256:
        raise ProtocolSignatureError("conformance statement changed during verification")
    raw = json.loads(content)
    if not isinstance(raw, dict):
        raise ValueError("conformance statement root must be a mapping")
    statement = ConformanceEnvironmentStatement.model_validate(raw)
    return VerifiedConformanceAuthorization(
        statement=statement,
        identity=verification.identity,
        namespace=verification.namespace,
        statement_sha256=verification.artifact_sha256,
        canonical_statement_sha256=_canonical_sha256(statement),
        signature_sha256=verification.signature_sha256,
        allowed_signers_sha256=verification.allowed_signers_sha256,
        signing_key_fingerprint=verification.signing_key_fingerprint,
    )


def authorize_baseline_verification_statement(
    path: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> VerifiedBaselineAuthorization:
    """Load and externally verify one exact artifact-derived baseline statement."""
    try:
        content = _read_regular_file_bytes(path, label="baseline verification statement")
    except ValueError as exc:
        raise ProtocolSignatureError(
            "baseline verification statement must be a regular nonsymlink file"
        ) from exc
    verification = verify_baseline_verification_statement_signature(
        path,
        signature,
        allowed_signers,
        identity,
    )
    if hashlib.sha256(content).hexdigest() != verification.artifact_sha256:
        raise ProtocolSignatureError("baseline verification statement changed during verification")
    raw = json.loads(content)
    if not isinstance(raw, dict):
        raise ValueError("baseline verification statement root must be a mapping")
    statement = BaselineVerificationStatement.model_validate(raw)
    return VerifiedBaselineAuthorization(
        statement=statement,
        identity=verification.identity,
        namespace=verification.namespace,
        statement_sha256=verification.artifact_sha256,
        canonical_statement_sha256=_canonical_sha256(statement),
        signature_sha256=verification.signature_sha256,
        allowed_signers_sha256=verification.allowed_signers_sha256,
        signing_key_fingerprint=verification.signing_key_fingerprint,
    )


def authorize_pilot_evidence_statement(
    path: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> VerifiedPilotEvidenceAuthorization:
    """Load and verify one exact artifact-derived anonymous pilot statement."""
    try:
        content = _read_regular_file_bytes(path, label="pilot evidence statement")
    except ValueError as exc:
        raise ProtocolSignatureError(
            "pilot evidence statement must be a regular nonsymlink file"
        ) from exc
    verification = verify_pilot_evidence_statement_signature(
        path,
        signature,
        allowed_signers,
        identity,
    )
    if hashlib.sha256(content).hexdigest() != verification.artifact_sha256:
        raise ProtocolSignatureError("pilot evidence statement changed during verification")
    raw = json.loads(content)
    if not isinstance(raw, dict):
        raise ValueError("pilot evidence statement root must be a mapping")
    from stinger.benchmark.pilot import (
        PilotEvidenceStatement,
        canonical_pilot_evidence_statement_sha256,
    )

    statement = PilotEvidenceStatement.model_validate(raw)
    return VerifiedPilotEvidenceAuthorization(
        statement_bytes=content,
        identity=verification.identity,
        namespace=verification.namespace,
        statement_sha256=verification.artifact_sha256,
        canonical_statement_sha256=canonical_pilot_evidence_statement_sha256(statement),
        signature_sha256=verification.signature_sha256,
        allowed_signers_sha256=verification.allowed_signers_sha256,
        signing_key_fingerprint=verification.signing_key_fingerprint,
        benchmark_protocol_version=statement.benchmark_protocol_version,
        rubric_version=statement.rubric_version,
        corpus_version=statement.corpus_version,
        corpus_hash=statement.corpus_hash,
        candidate_corpus_hash=statement.candidate_corpus_hash,
        evaluated_corpus_hash=statement.evaluated_corpus_hash,
        evaluated_split=statement.evaluated_split,
        protocol_sha256=statement.protocol_sha256,
        candidate_validation_receipt_sha256=(statement.candidate_validation_receipt_sha256),
        candidate_scenario_identity_inventory_sha256=(
            statement.candidate_scenario_identity_inventory_sha256
        ),
        selection_protocol_sha256=statement.selection_protocol_sha256,
        scenario_count=statement.scenario_count,
        configuration_count=statement.configuration_count,
        pilot_evidence_sha256=statement.pilot_evidence_sha256,
        pilot=statement.pilot,
    )


def authorize_release_evidence_statement(
    path: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> VerifiedReleaseEvidenceAuthorization:
    """Load and verify one exact artifact-derived release-evidence statement."""
    try:
        content = _read_regular_file_bytes(path, label="release evidence statement")
    except ValueError as exc:
        raise ProtocolSignatureError(
            "release evidence statement must be a regular nonsymlink file"
        ) from exc
    verification = verify_release_evidence_statement_signature(
        path,
        signature,
        allowed_signers,
        identity,
    )
    if hashlib.sha256(content).hexdigest() != verification.artifact_sha256:
        raise ProtocolSignatureError("release evidence statement changed during verification")
    from stinger.benchmark.release_evidence import ReleaseEvidenceStatement

    raw = json.loads(content)
    if not isinstance(raw, dict):
        raise ValueError("release evidence statement root must be a mapping")
    statement = ReleaseEvidenceStatement.model_validate(raw)
    return VerifiedReleaseEvidenceAuthorization(
        statement_bytes=content,
        identity=verification.identity,
        namespace=verification.namespace,
        statement_sha256=verification.artifact_sha256,
        canonical_statement_sha256=_canonical_sha256(statement),
        signature_sha256=verification.signature_sha256,
        allowed_signers_sha256=verification.allowed_signers_sha256,
        signing_key_fingerprint=verification.signing_key_fingerprint,
        benchmark_protocol_version=statement.benchmark_protocol_version,
        rubric_version=statement.rubric_version,
        corpus_version=statement.corpus_version,
        corpus_hash=statement.corpus_hash,
        stinger_commit=statement.stinger_commit,
        release_evidence=statement.release_evidence,
        release_evidence_record_sha256=statement.release_evidence_record_sha256,
        canonical_submission_sha256=statement.canonical_submission_sha256,
    )


def authorize_reproduction_statement(
    path: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> VerifiedCrossMachineReproductionAuthorization:
    """Load and externally verify a cross-machine reproduction statement."""
    try:
        content = _read_regular_file_bytes(path, label="reproduction statement")
    except ValueError as exc:
        raise ProtocolSignatureError(
            "reproduction statement must be a regular nonsymlink file"
        ) from exc
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
        raise ValueError("cross-machine reproduction statement root must be a mapping")
    statement = CrossMachineReproductionStatement.model_validate(raw)
    return VerifiedCrossMachineReproductionAuthorization(
        statement=statement,
        identity=verification.identity,
        namespace=verification.namespace,
        statement_sha256=verification.artifact_sha256,
        canonical_statement_sha256=_canonical_sha256(statement),
        signature_sha256=verification.signature_sha256,
        allowed_signers_sha256=verification.allowed_signers_sha256,
        signing_key_fingerprint=verification.signing_key_fingerprint,
    )


def _load_benchmark_submission_bytes(content: bytes) -> BenchmarkReleaseSubmission:
    """Parse the exact bytes whose signature was verified."""
    raw = yaml.safe_load(content.decode("utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("benchmark release submission root must be a mapping")
    return BenchmarkReleaseSubmission.model_validate(raw)


def _read_regular_file_bytes(path: Path, *, label: str) -> bytes:
    """Read exact nonempty bytes without following links or blocking on a FIFO."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} must be a regular nonsymlink file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} must be a regular nonsymlink file")
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
        raise ValueError(f"{label} must not be empty")
    return content


def evaluate_benchmark_release(
    submission: BenchmarkReleaseSubmission,
    *,
    protocol_authorization: VerifiedProtocolAuthorization | None = None,
    candidate_validation_authorization: VerifiedCandidateValidationAuthorization | None = None,
    candidate_promotion_authorization: VerifiedCandidatePromotionAuthorization | None = None,
    corpus_construction_authorization: VerifiedCorpusConstructionAuthorization | None = None,
    corpus_freeze_authorization: VerifiedCorpusFreezeAuthorization | None = None,
    pilot_authorization: VerifiedPilotEvidenceAuthorization | None = None,
    baseline_authorizations: tuple[VerifiedBaselineAuthorization, ...] = (),
    conformance_authorizations: tuple[VerifiedConformanceAuthorization, ...] = (),
    authorization: VerifiedReleaseAuthorization | None = None,
    release_evidence_authorization: VerifiedReleaseEvidenceAuthorization | None = None,
    reproduction_authorization: VerifiedCrossMachineReproductionAuthorization | None = None,
    public_reproduction_authorization: VerifiedPublicReproductionAuthorization | None = None,
) -> BenchmarkGateReport:
    """Evaluate all Benchmark Protocol 2 publication requirements without favorable inference.

    Args:
        submission: Explicit corpus, run, review, external-reproduction, and authorization
            evidence. No record is synthesized from another gate passing.
        authorization: Out-of-band OpenSSH verification of the exact submission bytes.
            A hand-edited model or YAML file can never substitute for this proof.
        reproduction_authorization: Out-of-band OpenSSH verification of the separate
            cross-machine evaluator's exact artifact-binding statement.

    Returns:
        A deterministic result. ``publishable`` is true only when no issue exists; otherwise
        the strongest supported status remains ``benchmark_candidate``.
    """
    collector = _IssueCollector()
    _evaluate_protocol(submission.protocol, protocol_authorization, collector)
    corpus_by_id, corpus_metrics = _evaluate_corpus(
        submission.corpus,
        submission.protocol,
        candidate_validation_authorization,
        candidate_promotion_authorization,
        corpus_freeze_authorization,
        collector,
    )
    _evaluate_corpus_construction_authorization(
        submission,
        corpus_construction_authorization,
        authorization,
        collector,
    )
    _evaluate_pilot(submission.pilot, submission.corpus, submission.protocol, collector)
    _evaluate_pilot_authorization(
        submission,
        pilot_authorization,
        protocol_authorization,
        candidate_validation_authorization,
        candidate_promotion_authorization,
        authorization,
        collector,
    )

    baseline_authorizations_by_id = {
        item.statement.configuration_id: item for item in baseline_authorizations
    }
    baseline_configuration_ids = {baseline.configuration_id for baseline in submission.baselines}
    baseline_authorization_set_valid = (
        len(baseline_authorizations_by_id) == len(baseline_authorizations)
        and set(baseline_authorizations_by_id) == baseline_configuration_ids
    )
    configuration_results = tuple(
        _evaluate_release_configuration(
            baseline,
            corpus=submission.corpus,
            corpus_by_id=corpus_by_id,
            protocol=submission.protocol,
            authorization=baseline_authorizations_by_id.get(baseline.configuration_id),
            authorization_set_valid=baseline_authorization_set_valid,
        )
        for baseline in sorted(submission.baselines, key=lambda item: item.configuration_id)
    )
    for result in configuration_results:
        collector.extend(result.issues)

    provider_count = _evaluate_matrix(
        submission,
        candidate_validation_authorization,
        collector,
    )
    conformance_count = _evaluate_external_evidence(
        submission,
        protocol_authorization,
        conformance_authorizations,
        reproduction_authorization,
        public_reproduction_authorization,
        authorization,
        collector,
    )
    _evaluate_release_evidence(
        submission,
        release_evidence_authorization,
        authorization,
        collector,
    )
    _evaluate_human_approval(submission, authorization, collector)
    _evaluate_release_authorization(submission, authorization, collector)

    issues = collector.sorted()
    publishable = not issues
    return BenchmarkGateReport(
        benchmark_protocol_version=submission.protocol.benchmark_protocol_version,
        status=(
            ReleaseStatus.MACHINE_REPRODUCED if publishable else ReleaseStatus.BENCHMARK_CANDIDATE
        ),
        publishable=publishable,
        issues=issues,
        configuration_results=configuration_results,
        metrics=BenchmarkGateMetrics(
            unique_scenarios=corpus_metrics.unique_scenarios,
            unique_clusters=corpus_metrics.unique_clusters,
            scenarios_by_family=corpus_metrics.scenarios_by_family,
            blind_agent_solves_by_family=corpus_metrics.blind_agent_solves_by_family,
            baseline_configurations=len(submission.baselines),
            baseline_providers=provider_count,
            conformance_environments=conformance_count,
            cross_machine_reproductions=(
                1
                if _valid_reproduction(
                    submission.cross_machine_reproduction,
                    reproduction_authorization,
                    public_reproduction_authorization,
                    authorization,
                    protocol_authorization,
                    submission,
                )
                else 0
            ),
        ),
    )


def evaluate_baseline_configuration_record(
    baseline: BaselineConfigurationRecord,
    *,
    corpus: SealedCorpusRecord,
    protocol: BenchmarkProtocolManifest,
) -> ConfigurationGateResult:
    """Run the release gate's exact per-configuration evaluator for one derived record.

    This is intentionally narrower than :func:`evaluate_benchmark_release`: artifact
    builders can prove one baseline is mechanically eligible without fabricating unrelated
    pilot, matrix, external-review, or human-approval records.

    Raises:
        ValueError: If the supplied corpus record contains duplicate scenario ids.
    """
    corpus_by_id = {scenario.scenario_id: scenario for scenario in corpus.scenarios}
    if len(corpus_by_id) != len(corpus.scenarios):
        raise ValueError("sealed corpus record contains duplicate scenario ids")
    return _evaluate_configuration(
        baseline,
        corpus=corpus,
        corpus_by_id=corpus_by_id,
        protocol=protocol,
    )


def evaluate_corpus_construction(
    corpus: SealedCorpusRecord,
    *,
    protocol: BenchmarkProtocolManifest,
    candidate_validation_authorization: VerifiedCandidateValidationAuthorization,
    candidate_promotion_authorization: VerifiedCandidatePromotionAuthorization,
) -> tuple[GateIssue, ...]:
    """Return construction issues before the corpus-freeze statement exists."""
    collector = _IssueCollector()
    _evaluate_corpus(
        corpus,
        protocol,
        candidate_validation_authorization,
        candidate_promotion_authorization,
        None,
        collector,
    )
    return tuple(
        issue
        for issue in collector.sorted()
        if issue.code is not PublicationIssueCode.CORPUS_NOT_FROZEN
    )


def _evaluate_corpus_construction_authorization(
    submission: BenchmarkReleaseSubmission,
    authorization: VerifiedCorpusConstructionAuthorization | None,
    release_authorization: VerifiedReleaseAuthorization | None,
    collector: _IssueCollector,
) -> None:
    """Require a role-separated signature over the artifact-derived corpus record."""
    from stinger.benchmark.corpus_construction import (
        CONSTRUCTION_RECEIPT_FORMAT_VERSION,
        CORPUS_CONSTRUCTION_SIGNATURE_NAMESPACE,
        canonical_corpus_construction_receipt_sha256,
    )

    valid = False
    if authorization is not None and release_authorization is not None:
        receipt = authorization.receipt
        submitted_unfrozen = submission.corpus.model_copy(update={"freeze": None})
        canonical_receipt_sha256 = canonical_corpus_construction_receipt_sha256(receipt)
        review_runtime_identities = {
            review.runtime_signer_identity
            for scenario in submission.corpus.scenarios
            for review in scenario.machine_reviews
        }
        review_runtime_keys = {
            review.runtime_signing_key_fingerprint
            for scenario in submission.corpus.scenarios
            for review in scenario.machine_reviews
        }
        review_runtime_trust_policies = {
            review.runtime_allowed_signers_sha256
            for scenario in submission.corpus.scenarios
            for review in scenario.machine_reviews
        }
        valid = (
            authorization.namespace == CORPUS_CONSTRUCTION_SIGNATURE_NAMESPACE
            and authorization.identity != release_authorization.identity
            and authorization.identity not in review_runtime_identities
            and authorization.signing_key_fingerprint
            != release_authorization.signing_key_fingerprint
            and authorization.signing_key_fingerprint not in review_runtime_keys
            and authorization.allowed_signers_sha256 != release_authorization.allowed_signers_sha256
            and authorization.allowed_signers_sha256 not in review_runtime_trust_policies
            and _SSH_KEY_FINGERPRINT_PATTERN.fullmatch(authorization.signing_key_fingerprint)
            is not None
            and _SHA256_PATTERN.fullmatch(authorization.receipt_sha256) is not None
            and _SHA256_PATTERN.fullmatch(authorization.signature_sha256) is not None
            and _SHA256_PATTERN.fullmatch(authorization.allowed_signers_sha256) is not None
            and authorization.receipt_sha256 == canonical_receipt_sha256
            and authorization.canonical_receipt_sha256 == canonical_receipt_sha256
            and receipt.format_version == CONSTRUCTION_RECEIPT_FORMAT_VERSION
            and receipt.benchmark_protocol_version == submission.protocol.benchmark_protocol_version
            and receipt.rubric_version == submission.protocol.rubric_version
            and receipt.corpus_version == submission.corpus.corpus_version
            and receipt.corpus_hash == submission.corpus.corpus_hash
            and receipt.scenario_count == submission.protocol.total_scenarios
            and receipt.scenario_count == len(submission.corpus.scenarios)
            and receipt.scenario_inventory_sha256
            == corpus_scenario_inventory_sha256(submission.corpus.scenarios)
            and receipt.corpus.freeze is None
            and receipt.corpus == submitted_unfrozen
        )
    if not valid:
        collector.add(
            PublicationIssueCode.CORPUS_CONSTRUCTION_AUTHORIZATION_INVALID,
            (
                "sealed corpus lacks a role-separated signature over the exact "
                "artifact-derived construction receipt"
            ),
            "corpus",
        )


class _CorpusMetrics(_FrozenModel):
    """Internal aggregate returned by the corpus evaluator."""

    unique_scenarios: int
    unique_clusters: int
    scenarios_by_family: dict[Family, int]
    blind_agent_solves_by_family: dict[Family, int]


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
    authorization: VerifiedProtocolAuthorization | None,
    collector: _IssueCollector,
) -> None:
    """Reject any manifest that silently weakens the approved Protocol 2 constants."""
    expected = compiled_benchmark_protocol()
    if protocol != expected:
        collector.add(
            PublicationIssueCode.PROTOCOL_MANIFEST_MISMATCH,
            "protocol manifest differs from the checked-in Benchmark Protocol 2 thresholds",
            "protocol",
        )
    if (
        authorization is None
        or authorization.namespace != PROTOCOL_SIGNATURE_NAMESPACE
        or authorization.canonical_protocol_sha256 != _canonical_sha256(protocol)
        or not authorization.identity
        or _SHA256_PATTERN.fullmatch(authorization.protocol_sha256) is None
        or _SHA256_PATTERN.fullmatch(authorization.signature_sha256) is None
        or _SHA256_PATTERN.fullmatch(authorization.allowed_signers_sha256) is None
        or _SSH_KEY_FINGERPRINT_PATTERN.fullmatch(authorization.signing_key_fingerprint) is None
    ):
        collector.add(
            PublicationIssueCode.PROTOCOL_NOT_SIGNED,
            "active protocol lacks trusted detached-signature authorization",
            "protocol",
        )


def _evaluate_corpus(
    corpus: SealedCorpusRecord,
    protocol: BenchmarkProtocolManifest,
    candidate_validation_authorization: VerifiedCandidateValidationAuthorization | None,
    candidate_promotion_authorization: VerifiedCandidatePromotionAuthorization | None,
    freeze_authorization: VerifiedCorpusFreezeAuthorization | None,
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

    selected_blind_ids = _blind_agent_solve_ids(
        records_by_id.values(),
        protocol,
        corpus_hash=corpus.corpus_hash,
    )
    valid_blind_solves: Counter[Family] = Counter()
    for scenario_id in sorted(records_by_id):
        scenario = records_by_id[scenario_id]
        subject = f"scenario:{scenario_id}"
        _evaluate_scenario_record(scenario, collector, subject)
        if scenario_id in selected_blind_ids:
            if _evaluate_blind_agent_solves(scenario, protocol, collector, subject):
                valid_blind_solves[scenario.family] += 1
        elif scenario.blind_agent_solves:
            collector.add(
                PublicationIssueCode.CORPUS_BLIND_SOLVE_SELECTION_INVALID,
                "blind solve evidence is attached to a scenario outside the frozen selection",
                subject,
            )

    for family in Family:
        if valid_blind_solves[family] != protocol.blind_agent_solve_scenarios_per_family:
            collector.add(
                PublicationIssueCode.CORPUS_BLIND_SOLVE_COUNT_INVALID,
                (
                    f"expected {protocol.blind_agent_solve_scenarios_per_family} "
                    f"deterministically selected scenarios with valid blind solves, "
                    f"got {valid_blind_solves[family]}"
                ),
                f"family:{family.value}",
            )

    if corpus.candidate_validation_receipt_sha256 is None:
        collector.add(
            PublicationIssueCode.CORPUS_CANDIDATE_VALIDATION_RECEIPT_MISSING,
            "artifact-derived candidate validation receipt is missing",
            "corpus",
        )
    elif not _valid_candidate_validation_receipt(
        corpus,
        protocol,
        candidate_validation_authorization,
    ):
        collector.add(
            PublicationIssueCode.CORPUS_CANDIDATE_VALIDATION_RECEIPT_INVALID,
            "trusted candidate receipt is missing, unbound, or inconsistent with the corpus",
            "corpus",
        )
    if not _valid_candidate_promotion(
        corpus,
        protocol,
        candidate_validation_authorization,
        candidate_promotion_authorization,
    ):
        collector.add(
            PublicationIssueCode.CORPUS_CANDIDATE_PROMOTION_INVALID,
            "candidate-to-sealed promotion is missing or not bound to exact artifacts",
            "corpus",
        )
    if corpus.custody_inventory_sha256 is None:
        collector.add(
            PublicationIssueCode.CORPUS_CUSTODY_INVENTORY_MISSING,
            "exact sealed-corpus custody inventory is missing",
            "corpus",
        )
    if corpus.access_log_root_sha256 is None:
        collector.add(
            PublicationIssueCode.CORPUS_ACCESS_LOG_ROOT_MISSING,
            "sealed-corpus cooperative access-log root is missing",
            "corpus",
        )
    if corpus.canary_validation_receipt_sha256 is None:
        collector.add(
            PublicationIssueCode.CORPUS_CANARY_VALIDATION_RECEIPT_MISSING,
            "artifact-derived sealed-corpus canary validation receipt is missing",
            "corpus",
        )
    if not _valid_corpus_freeze(corpus, protocol, freeze_authorization):
        collector.add(
            PublicationIssueCode.CORPUS_NOT_FROZEN,
            "trusted signed corpus-freeze statement is missing or inconsistent",
            "corpus",
        )

    return records_by_id, _CorpusMetrics(
        unique_scenarios=len(records_by_id),
        unique_clusters=len(cluster_ids),
        scenarios_by_family={family: family_counts[family] for family in Family},
        blind_agent_solves_by_family={family: valid_blind_solves[family] for family in Family},
    )


def corpus_scenario_inventory_sha256(
    scenarios: tuple[CorpusScenarioRecord, ...],
) -> str:
    """Hash the complete canonical scenario-construction record inventory."""
    return _canonical_payload_sha256(
        {
            "scenarios": [
                scenario.model_dump(mode="json")
                for scenario in sorted(
                    scenarios,
                    key=lambda item: item.scenario_id,
                )
            ]
        }
    )


def candidate_scenario_identity_inventory_sha256(
    scenarios: tuple[CorpusScenarioRecord, ...],
) -> str:
    """Hash scenario identity metadata that must survive candidate-to-sealed freezing."""
    return _canonical_payload_sha256(
        {
            "scenarios": [
                {
                    "scenario_id": scenario.scenario_id,
                    "family": scenario.family.value,
                    "repository_size": scenario.repository_size.value,
                    "scenario_version": scenario.scenario_version,
                    "cluster_id": scenario.cluster_id,
                }
                for scenario in sorted(scenarios, key=lambda item: item.scenario_id)
            ]
        }
    )


def candidate_validation_inventory_sha256(
    scenarios: tuple[CorpusScenarioRecord, ...],
) -> str:
    """Hash candidate validation receipts carried unchanged into sealed records."""
    return _canonical_payload_sha256(
        {
            "validations": [
                {
                    "scenario_id": scenario.scenario_id,
                    "machine_validation_receipt_sha256": (
                        scenario.machine_validation_receipt_sha256
                    ),
                }
                for scenario in sorted(scenarios, key=lambda item: item.scenario_id)
            ]
        }
    )


def sealed_scenario_artifact_inventory_sha256(
    scenarios: tuple[CorpusScenarioRecord, ...],
) -> str:
    """Hash exact sealed scenario trees carried into the scored corpus record."""
    return _canonical_payload_sha256(
        {
            "scenarios": [
                {
                    "scenario_id": scenario.scenario_id,
                    "scenario_artifact_sha256": scenario.scenario_artifact_sha256,
                }
                for scenario in sorted(scenarios, key=lambda item: item.scenario_id)
            ]
        }
    )


def _valid_candidate_validation_receipt(
    corpus: SealedCorpusRecord,
    protocol: BenchmarkProtocolManifest,
    authorization: VerifiedCandidateValidationAuthorization | None,
) -> bool:
    """Bind one trusted path-free candidate receipt to the sealed identity inventory."""
    receipt_hash = corpus.candidate_validation_receipt_sha256
    if receipt_hash is None or authorization is None:
        return False
    receipt = authorization.receipt
    family_counts = Counter(scenario.family for scenario in corpus.scenarios)
    family_size_counts = Counter(
        (scenario.family, scenario.repository_size) for scenario in corpus.scenarios
    )
    cluster_count = len({scenario.cluster_id for scenario in corpus.scenarios})
    expected_by_family = {family: family_counts[family] for family in Family}
    expected_by_family_and_size = {
        family: {
            repository_size: family_size_counts[(family, repository_size)]
            for repository_size in RepositorySize
        }
        for family in Family
    }
    policy_sha256 = canonical_verification_image_policy_sha256(protocol.verification_image_policy)
    return (
        authorization.namespace == CANDIDATE_VALIDATION_SIGNATURE_NAMESPACE
        and _SSH_KEY_FINGERPRINT_PATTERN.fullmatch(authorization.signing_key_fingerprint)
        is not None
        and authorization.canonical_receipt_sha256 == _canonical_sha256(receipt)
        and authorization.receipt_sha256 == receipt_hash
        and receipt.signer_identity == authorization.identity
        and receipt.format_version == CANDIDATE_RECEIPT_FORMAT_VERSION
        and receipt.benchmark_protocol_version == protocol.benchmark_protocol_version
        and receipt.rubric_version == protocol.rubric_version
        and receipt.corpus_version == corpus.corpus_version
        and receipt.validation_contract == CANDIDATE_VALIDATION_CONTRACT
        and receipt.verification_image_policy_sha256 == policy_sha256
        and verification_image_id_is_approved(
            protocol.verification_image_policy,
            receipt.verification_image_id,
        )
        and receipt.repository_size_source == REPOSITORY_SIZE_SOURCE_VERSION
        and receipt.scenario_count == protocol.total_scenarios
        and receipt.scenario_count == len(corpus.scenarios)
        and receipt.scenarios_by_family == expected_by_family
        and receipt.scenarios_by_family_and_size == expected_by_family_and_size
        and receipt.unique_cluster_count == cluster_count
        and receipt.unique_cluster_count == protocol.total_scenarios
        and receipt.machine_validation_count == protocol.total_scenarios
        and receipt.canary_count == protocol.total_scenarios
        and receipt.scenario_identity_inventory_sha256
        == candidate_scenario_identity_inventory_sha256(corpus.scenarios)
        and corpus.canary_validation_receipt_sha256 is not None
        and receipt.canary_inventory_sha256 == corpus.canary_validation_receipt_sha256
    )


def _valid_candidate_promotion(
    corpus: SealedCorpusRecord,
    protocol: BenchmarkProtocolManifest,
    candidate_authorization: VerifiedCandidateValidationAuthorization | None,
    promotion_authorization: VerifiedCandidatePromotionAuthorization | None,
) -> bool:
    """Bind a trusted deterministic promotion to candidate and sealed artifacts."""
    statement_hash = corpus.candidate_promotion_statement_sha256
    if statement_hash is None or candidate_authorization is None or promotion_authorization is None:
        return False
    candidate = candidate_authorization.receipt
    promotion = promotion_authorization.statement
    policy_sha256 = canonical_verification_image_policy_sha256(protocol.verification_image_policy)
    return (
        promotion_authorization.namespace == CANDIDATE_PROMOTION_SIGNATURE_NAMESPACE
        and _SSH_KEY_FINGERPRINT_PATTERN.fullmatch(promotion_authorization.signing_key_fingerprint)
        is not None
        and promotion_authorization.canonical_statement_sha256 == _canonical_sha256(promotion)
        and promotion_authorization.statement_sha256 == statement_hash
        and promotion.signer_identity == promotion_authorization.identity
        and promotion.format_version == CANDIDATE_PROMOTION_FORMAT_VERSION
        and promotion.transformation_contract == CANDIDATE_PROMOTION_CONTRACT
        and promotion.benchmark_protocol_version == protocol.benchmark_protocol_version
        and promotion.rubric_version == protocol.rubric_version
        and promotion.corpus_version == corpus.corpus_version
        and promotion.stinger_commit == candidate.stinger_commit
        and promotion.verification_image_id == candidate.verification_image_id
        and promotion.verification_image_policy_sha256
        == candidate.verification_image_policy_sha256
        == policy_sha256
        and verification_image_id_is_approved(
            protocol.verification_image_policy,
            promotion.verification_image_id,
        )
        and promotion.candidate_receipt_sha256 == candidate_authorization.receipt_sha256
        and promotion.candidate_corpus_hash == candidate.candidate_corpus_hash
        and promotion.candidate_source_snapshot_sha256 == candidate.source_snapshot_sha256
        and promotion.candidate_validation_inventory_sha256 == candidate.validation_inventory_sha256
        and promotion.candidate_access_log_root_sha256 == candidate.access_log_root_sha256
        and promotion.sealed_corpus_hash == corpus.corpus_hash
        and promotion.sealed_scenario_identity_inventory_sha256
        == candidate_scenario_identity_inventory_sha256(corpus.scenarios)
        and promotion.sealed_scenario_artifact_inventory_sha256
        == sealed_scenario_artifact_inventory_sha256(corpus.scenarios)
        and promotion.sealed_validation_inventory_sha256
        == candidate_validation_inventory_sha256(corpus.scenarios)
        and promotion.canary_inventory_sha256 == candidate.canary_inventory_sha256
        and corpus.canary_validation_receipt_sha256 == candidate.canary_inventory_sha256
        and promotion.sealed_access_log_root_sha256 == corpus.access_log_root_sha256
        and promotion.scenario_count == len(corpus.scenarios)
        and promotion.scenario_count == protocol.total_scenarios
    )


def _valid_corpus_freeze(
    corpus: SealedCorpusRecord,
    protocol: BenchmarkProtocolManifest,
    authorization: VerifiedCorpusFreezeAuthorization | None,
) -> bool:
    """Bind a trusted freeze statement to the exact corpus and machine receipts."""
    record = corpus.freeze
    if record is None or authorization is None:
        return False
    statement = authorization.statement
    family_counts = Counter(scenario.family for scenario in corpus.scenarios)
    size_counts = Counter(scenario.repository_size for scenario in corpus.scenarios)
    return (
        authorization.namespace == CORPUS_FREEZE_SIGNATURE_NAMESPACE
        and _SSH_KEY_FINGERPRINT_PATTERN.fullmatch(authorization.signing_key_fingerprint)
        is not None
        and authorization.canonical_statement_sha256 == _canonical_sha256(statement)
        and record.signer_identity == authorization.identity
        and record.statement_sha256 == authorization.statement_sha256
        and record.statement_signature_sha256 == authorization.signature_sha256
        and record.allowed_signers_sha256 == authorization.allowed_signers_sha256
        and statement.signer_identity == authorization.identity
        and statement.benchmark_protocol_version == protocol.benchmark_protocol_version
        and statement.rubric_version == protocol.rubric_version
        and statement.corpus_version == corpus.corpus_version
        and statement.corpus_hash == corpus.corpus_hash
        and statement.scenario_inventory_sha256
        == corpus_scenario_inventory_sha256(corpus.scenarios)
        and corpus.candidate_validation_receipt_sha256 is not None
        and statement.candidate_validation_receipt_sha256
        == corpus.candidate_validation_receipt_sha256
        and corpus.candidate_promotion_statement_sha256 is not None
        and statement.candidate_promotion_statement_sha256
        == corpus.candidate_promotion_statement_sha256
        and corpus.custody_inventory_sha256 is not None
        and statement.custody_inventory_sha256 == corpus.custody_inventory_sha256
        and corpus.access_log_root_sha256 is not None
        and statement.access_log_root_sha256 == corpus.access_log_root_sha256
        and corpus.canary_validation_receipt_sha256 is not None
        and statement.canary_validation_receipt_sha256 == corpus.canary_validation_receipt_sha256
        and statement.scenario_count == len(corpus.scenarios)
        and statement.scenarios_by_family == {family: family_counts[family] for family in Family}
        and statement.scenarios_by_size == {size: size_counts[size] for size in RepositorySize}
    )


def _evaluate_scenario_record(
    scenario: CorpusScenarioRecord,
    collector: _IssueCollector,
    subject: str,
) -> None:
    """Evaluate one scenario's artifact bindings, machine reviews, variants, and QA."""
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
    if not scenario.scenario_artifact_sha256:
        collector.add(
            PublicationIssueCode.CORPUS_SCENARIO_ARTIFACT_MISSING,
            "scenario artifact commitment is missing",
            subject,
        )
    if not scenario.machine_validation_receipt_sha256:
        collector.add(
            PublicationIssueCode.CORPUS_MACHINE_VALIDATION_RECEIPT_MISSING,
            "artifact-derived machine validation receipt is missing",
            subject,
        )
    if not scenario.containment_receipt_sha256:
        collector.add(
            PublicationIssueCode.CORPUS_CONTAINMENT_RECEIPT_MISSING,
            "artifact-derived containment receipt is missing",
            subject,
        )
    if not scenario.dummy_safety_receipt_sha256:
        collector.add(
            PublicationIssueCode.CORPUS_DUMMY_SAFETY_RECEIPT_MISSING,
            "artifact-derived dummy-safety receipt is missing",
            subject,
        )
    if not scenario.provenance_receipt_sha256:
        collector.add(
            PublicationIssueCode.CORPUS_PROVENANCE_MISSING,
            "artifact-derived provenance receipt is missing",
            subject,
        )

    _evaluate_machine_reviews(scenario, collector, subject)
    _evaluate_resolution_variants(scenario, collector, subject)
    _evaluate_agent_qa(scenario, collector, subject)


def _evaluate_machine_reviews(
    scenario: CorpusScenarioRecord,
    collector: _IssueCollector,
    subject: str,
) -> None:
    """Require two provider-diverse veto reviews over the exact QA input manifest."""
    reviews = scenario.machine_reviews
    review_ids = {review.review_id for review in reviews}
    configurations = {review.reviewer_configuration_fingerprint for review in reviews}
    providers = {review.provider for review in reviews}
    runtime_receipts = {review.runtime_receipt_sha256 for review in reviews}
    runtime_signer_identities = {review.runtime_signer_identity for review in reviews}
    runtime_signing_keys = {review.runtime_signing_key_fingerprint for review in reviews}
    runtime_trust_policies = {review.runtime_allowed_signers_sha256 for review in reviews}
    runtime_signatures = {review.runtime_signature_sha256 for review in reviews}
    if len(reviews) != REQUIRED_MACHINE_REVIEWS or len(review_ids) != REQUIRED_MACHINE_REVIEWS:
        collector.add(
            PublicationIssueCode.CORPUS_MACHINE_REVIEW_INSUFFICIENT,
            (
                f"expected exactly {REQUIRED_MACHINE_REVIEWS} distinct machine reviews, "
                f"got {len(review_ids)}"
            ),
            subject,
        )
    if (
        len(configurations) < REQUIRED_MACHINE_REVIEWS
        or len(providers) < REQUIRED_MACHINE_REVIEW_PROVIDERS
        or len(runtime_receipts) < REQUIRED_MACHINE_REVIEWS
        or len(runtime_signer_identities) < REQUIRED_MACHINE_REVIEWS
        or len(runtime_signing_keys) < REQUIRED_MACHINE_REVIEWS
        or len(runtime_trust_policies) < REQUIRED_MACHINE_REVIEWS
        or len(runtime_signatures) < REQUIRED_MACHINE_REVIEWS
    ):
        collector.add(
            PublicationIssueCode.CORPUS_MACHINE_REVIEW_DIVERSITY_INVALID,
            (
                "reviewers must use distinct configurations, runtime receipts, signing "
                "identities, signing keys, trust policies, and signatures from two "
                "providers"
            ),
            subject,
        )
    qa_ids = tuple(sorted(attempt.attempt_id for attempt in scenario.agent_qa_attempts))
    expected_input_hash = machine_review_input_manifest_sha256(scenario)
    if any(
        review.prompt_sha256 != MACHINE_REVIEW_PROMPT_SHA256
        or review.output_schema_sha256 != MACHINE_REVIEW_OUTPUT_SCHEMA_SHA256
        or review.input_manifest_sha256 != expected_input_hash
        or review.output.covered_qa_attempt_ids != qa_ids
        or review.output_sha256 != _canonical_payload_sha256(review.output.model_dump(mode="json"))
        for review in reviews
    ):
        collector.add(
            PublicationIssueCode.CORPUS_MACHINE_REVIEW_BINDING_INVALID,
            (
                "machine reviews must bind the frozen prompt/output contract, one exact "
                "input manifest, and every distinct QA attempt"
            ),
            subject,
        )
    if any(review.output.decision is not MachineReviewDecision.ACCEPT for review in reviews):
        collector.add(
            PublicationIssueCode.CORPUS_MACHINE_REVIEW_BLOCKED,
            "BLOCK, UNCERTAIN, or reviewer disagreement rejects the scenario",
            subject,
        )


def machine_review_input_manifest_sha256(scenario: CorpusScenarioRecord) -> str:
    """Bind a machine review to exact scenario construction and QA artifacts."""
    return _canonical_payload_sha256(
        {
            "scenario_id": scenario.scenario_id,
            "family": scenario.family.value,
            "repository_size": scenario.repository_size.value,
            "benchmark_split": scenario.benchmark_split.value,
            "scenario_version": scenario.scenario_version,
            "cluster_id": scenario.cluster_id,
            "expected_honest_outcome": scenario.expected_honest_outcome.value,
            "scenario_artifact_sha256": scenario.scenario_artifact_sha256,
            "machine_validation_receipt_sha256": (scenario.machine_validation_receipt_sha256),
            "provenance_receipt_sha256": scenario.provenance_receipt_sha256,
            "containment_receipt_sha256": scenario.containment_receipt_sha256,
            "dummy_safety_receipt_sha256": scenario.dummy_safety_receipt_sha256,
            "resolution_variants": [
                variant.model_dump(mode="json")
                for variant in sorted(
                    scenario.resolution_variants,
                    key=lambda item: item.variant_id,
                )
            ],
            "agent_qa_attempts": [
                attempt.model_dump(mode="json")
                for attempt in sorted(
                    scenario.agent_qa_attempts,
                    key=lambda item: item.attempt_id,
                )
            ],
        }
    )


def _evaluate_resolution_variants(
    scenario: CorpusScenarioRecord,
    collector: _IssueCollector,
    subject: str,
) -> None:
    """Require two artifact-distinct variants of each resolution kind."""
    identifiers = [
        variant.variant_id for variant in scenario.resolution_variants if variant.variant_id.strip()
    ]
    source_hashes = [variant.source_tree_sha256 for variant in scenario.resolution_variants]
    semantic_hashes = [variant.semantic_patch_sha256 for variant in scenario.resolution_variants]
    receipt_hashes = [variant.execution_receipt_sha256 for variant in scenario.resolution_variants]
    if (
        len(scenario.resolution_variants) != len(ResolutionKind) * REQUIRED_RESOLUTION_VARIANTS
        or len(identifiers) != len(set(identifiers))
        or len(source_hashes) != len(set(source_hashes))
        or len(semantic_hashes) != len(set(semantic_hashes))
        or len(receipt_hashes) != len(set(receipt_hashes))
    ):
        collector.add(
            PublicationIssueCode.CORPUS_RESOLUTION_VARIANTS_NOT_DISTINCT,
            "variant ids, source trees, semantic patches, and execution receipts must be unique",
            subject,
        )
    for kind in ResolutionKind:
        valid_ids = {
            variant.variant_id
            for variant in scenario.resolution_variants
            if variant.kind is kind and variant.variant_id.strip()
        }
        if len(valid_ids) != REQUIRED_RESOLUTION_VARIANTS:
            collector.add(
                PublicationIssueCode.CORPUS_RESOLUTION_VARIANTS_INSUFFICIENT,
                (
                    f"expected exactly {REQUIRED_RESOLUTION_VARIANTS} artifact-derived "
                    f"{kind.value} variants, got {len(valid_ids)}"
                ),
                subject,
            )


def _evaluate_agent_qa(
    scenario: CorpusScenarioRecord,
    collector: _IssueCollector,
    subject: str,
) -> None:
    """Require five non-error QA attempts across two configurations and providers."""
    unique_ids = {
        attempt.attempt_id.strip()
        for attempt in scenario.agent_qa_attempts
        if attempt.attempt_id.strip()
    }
    if (
        len(scenario.agent_qa_attempts) != REQUIRED_AGENT_QA_ATTEMPTS
        or len(unique_ids) != REQUIRED_AGENT_QA_ATTEMPTS
    ):
        collector.add(
            PublicationIssueCode.CORPUS_AGENT_QA_INSUFFICIENT,
            (f"expected {REQUIRED_AGENT_QA_ATTEMPTS} distinct QA attempts, got {len(unique_ids)}"),
            subject,
        )
    configurations = {
        attempt.agent_configuration_fingerprint for attempt in scenario.agent_qa_attempts
    }
    providers = {attempt.provider for attempt in scenario.agent_qa_attempts}
    result_receipts = {attempt.result_sha256 for attempt in scenario.agent_qa_attempts}
    evidence_receipts = {attempt.evidence_manifest_sha256 for attempt in scenario.agent_qa_attempts}
    runtime_receipts = {attempt.runtime_receipt_sha256 for attempt in scenario.agent_qa_attempts}
    if (
        len(configurations) < REQUIRED_AGENT_QA_CONFIGURATIONS
        or len(providers) < REQUIRED_AGENT_QA_PROVIDERS
        or len(result_receipts) != len(scenario.agent_qa_attempts)
        or len(evidence_receipts) != len(scenario.agent_qa_attempts)
        or len(runtime_receipts) != len(scenario.agent_qa_attempts)
    ):
        collector.add(
            PublicationIssueCode.CORPUS_AGENT_QA_DIVERSITY_INVALID,
            (
                f"QA must span at least {REQUIRED_AGENT_QA_CONFIGURATIONS} configurations "
                f"and {REQUIRED_AGENT_QA_PROVIDERS} providers with distinct result, "
                "evidence, and runtime receipts"
            ),
            subject,
        )
    if any(attempt.outcome is Outcome.ERROR for attempt in scenario.agent_qa_attempts):
        collector.add(
            PublicationIssueCode.CORPUS_AGENT_QA_INVALID,
            "an ERROR QA attempt cannot support machine validation",
            subject,
        )


def _blind_agent_solve_ids(
    scenarios: Iterable[CorpusScenarioRecord],
    protocol: BenchmarkProtocolManifest,
    *,
    corpus_hash: str,
) -> set[str]:
    """Select the frozen blind-solve subset deterministically within every family."""
    selected: set[str] = set()
    scenario_list = list(scenarios)
    for family in Family:
        candidates = [scenario for scenario in scenario_list if scenario.family is family]
        ordered = sorted(
            candidates,
            key=lambda scenario: (
                hashlib.sha256(
                    (
                        f"{protocol.benchmark_protocol_version}\0"
                        f"{protocol.blind_agent_solve_selection_seed}\0"
                        f"{corpus_hash}\0"
                        f"{family.value}\0"
                        f"{scenario.scenario_artifact_sha256}\0"
                        f"{scenario.scenario_id}"
                    ).encode()
                ).hexdigest(),
                scenario.scenario_id,
            ),
        )
        selected.update(
            scenario.scenario_id
            for scenario in ordered[: protocol.blind_agent_solve_scenarios_per_family]
        )
    return selected


def _evaluate_blind_agent_solves(
    scenario: CorpusScenarioRecord,
    protocol: BenchmarkProtocolManifest,
    collector: _IssueCollector,
    subject: str,
) -> bool:
    """Require provider-diverse reference-isolated solves with a mechanically valid outcome."""
    solves = scenario.blind_agent_solves
    solve_ids = {solve.solve_id for solve in solves if solve.solve_id.strip()}
    configurations = {solve.solver_configuration_fingerprint for solve in solves}
    providers = {solve.provider for solve in solves}
    result_receipts = {solve.result_sha256 for solve in solves}
    evidence_receipts = {solve.evidence_manifest_sha256 for solve in solves}
    runtime_receipts = {solve.runtime_receipt_sha256 for solve in solves}
    isolation_receipts = {solve.reference_isolation_receipt_sha256 for solve in solves}
    valid = (
        len(solves) == protocol.blind_agent_solvers_per_scenario
        and len(solve_ids) == protocol.blind_agent_solvers_per_scenario
        and len(configurations) >= protocol.blind_agent_solver_configurations_per_scenario
        and len(providers) >= protocol.blind_agent_solver_providers_per_scenario
        and len(result_receipts) == len(solves)
        and len(evidence_receipts) == len(solves)
        and len(runtime_receipts) == len(solves)
        and len(isolation_receipts) == len(solves)
        and all(solve.outcome is scenario.expected_honest_outcome for solve in solves)
    )
    if not valid:
        collector.add(
            PublicationIssueCode.CORPUS_BLIND_SOLVE_INVALID,
            (
                "selected scenario needs distinct reference-isolated solves from the "
                "required configurations/providers with unique artifact receipts, and "
                "every solve must produce the expected honest outcome"
            ),
            subject,
        )
    return valid


def _evaluate_pilot(
    pilot: PilotEvidenceRecord,
    corpus: SealedCorpusRecord,
    protocol: BenchmarkProtocolManifest,
    collector: _IssueCollector,
) -> None:
    """Compute non-saturation and bind selected sealed items to the piloted candidate pool."""
    expected_scenario_ids = {scenario.scenario_id for scenario in corpus.scenarios}
    scenario_ids = [item.scenario_id for item in pilot.candidate_pool]
    unique_scenarios = set(scenario_ids)
    pilot_clusters_by_scenario = {
        item.scenario_id: item.cluster_id for item in pilot.candidate_pool
    }
    varied_items = 0
    anonymity_valid = bool(pilot.candidate_pool)
    error_free = True
    for item in pilot.candidate_pool:
        aliases = [record.configuration_alias for record in item.outcomes]
        unique_aliases = set(aliases)
        if (
            len(aliases) != len(unique_aliases)
            or len(unique_aliases)
            < protocol.pilot_selection_policy.minimum_anonymous_configurations
        ):
            anonymity_valid = False
            continue
        if any(record.outcome is Outcome.ERROR for record in item.outcomes):
            error_free = False
            continue
        if len({record.outcome for record in item.outcomes}) > 1:
            varied_items += 1

    denominator = len(pilot.candidate_pool)
    variation_rate = varied_items / denominator if denominator else 0.0
    if (
        denominator <= 0
        or len(unique_scenarios) != denominator
        or unique_scenarios != expected_scenario_ids
        or any(not scenario_id.strip() for scenario_id in scenario_ids)
        or not error_free
        or variation_rate < protocol.min_pilot_variation_rate
    ):
        collector.add(
            PublicationIssueCode.PILOT_EVIDENCE_INSUFFICIENT,
            (
                f"outcome variation rate {variation_rate:.6f} is below "
                f"{protocol.min_pilot_variation_rate:.6f}, candidate ids are duplicated, "
                "the pool does not exactly equal the sealed selection, the pool is empty, "
                "or an ERROR outcome is present"
            ),
            "pilot",
        )
    if not anonymity_valid:
        collector.add(
            PublicationIssueCode.PILOT_CONFIGURATIONS_NOT_ANONYMIZED,
            (
                "each evaluated item needs the protocol-required number of distinct opaque "
                "anonymous configuration aliases"
            ),
            "pilot",
        )
    expected_selection_policy_sha256 = pilot_selection_policy_sha256(
        protocol.pilot_selection_policy
    )
    if pilot.selection_protocol_sha256 != expected_selection_policy_sha256:
        collector.add(
            PublicationIssueCode.PILOT_SELECTION_POLICY_INVALID,
            (
                "pilot evidence does not bind the protocol-frozen complete-corpus "
                "selection and evaluation policy"
            ),
            "pilot",
        )
    unbound_sealed_ids = sorted(
        scenario.scenario_id
        for scenario in corpus.scenarios
        if pilot_clusters_by_scenario.get(scenario.scenario_id) != scenario.cluster_id
    )
    if unbound_sealed_ids:
        collector.add(
            PublicationIssueCode.PILOT_SELECTION_CORPUS_UNBOUND,
            (
                f"{len(unbound_sealed_ids)} sealed scenarios are absent from the piloted "
                "candidate pool or have a different cluster binding"
            ),
            "pilot",
        )


def _evaluate_pilot_authorization(
    submission: BenchmarkReleaseSubmission,
    authorization: VerifiedPilotEvidenceAuthorization | None,
    protocol_authorization: VerifiedProtocolAuthorization | None,
    candidate_authorization: VerifiedCandidateValidationAuthorization | None,
    promotion_authorization: VerifiedCandidatePromotionAuthorization | None,
    release_authorization: VerifiedReleaseAuthorization | None,
    collector: _IssueCollector,
) -> None:
    """Require signed artifact-derived pilot evidence for the exact release record."""
    statement_valid = False
    if authorization is not None:
        from stinger.benchmark.pilot import (
            PilotEvidenceStatement,
            canonical_pilot_evidence_statement_sha256,
        )

        try:
            raw = json.loads(authorization.statement_bytes)
            if not isinstance(raw, dict):
                raise ValueError("pilot evidence statement root must be a mapping")
            statement = PilotEvidenceStatement.model_validate(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            pass
        else:
            statement_valid = (
                hashlib.sha256(authorization.statement_bytes).hexdigest()
                == authorization.statement_sha256
                and canonical_pilot_evidence_statement_sha256(statement)
                == authorization.canonical_statement_sha256
                and statement.benchmark_protocol_version == authorization.benchmark_protocol_version
                and statement.rubric_version == authorization.rubric_version
                and statement.corpus_version == authorization.corpus_version
                and statement.corpus_hash == authorization.corpus_hash
                and statement.candidate_corpus_hash == authorization.candidate_corpus_hash
                and statement.evaluated_corpus_hash == authorization.evaluated_corpus_hash
                and statement.evaluated_split is authorization.evaluated_split
                and statement.protocol_sha256 == authorization.protocol_sha256
                and statement.candidate_validation_receipt_sha256
                == authorization.candidate_validation_receipt_sha256
                and statement.candidate_scenario_identity_inventory_sha256
                == authorization.candidate_scenario_identity_inventory_sha256
                and statement.selection_protocol_sha256 == authorization.selection_protocol_sha256
                and statement.scenario_count == authorization.scenario_count
                and statement.configuration_count == authorization.configuration_count
                and statement.pilot_evidence_sha256 == authorization.pilot_evidence_sha256
                and statement.pilot == authorization.pilot
            )

    valid = (
        authorization is not None
        and protocol_authorization is not None
        and candidate_authorization is not None
        and promotion_authorization is not None
        and release_authorization is not None
        and authorization.namespace == PILOT_EVIDENCE_SIGNATURE_NAMESPACE
        and bool(authorization.identity.strip())
        and authorization.identity != release_authorization.identity
        and authorization.signing_key_fingerprint != release_authorization.signing_key_fingerprint
        and authorization.allowed_signers_sha256 != release_authorization.allowed_signers_sha256
        and _SSH_KEY_FINGERPRINT_PATTERN.fullmatch(authorization.signing_key_fingerprint)
        is not None
        and _SHA256_PATTERN.fullmatch(authorization.statement_sha256) is not None
        and _SHA256_PATTERN.fullmatch(authorization.signature_sha256) is not None
        and _SHA256_PATTERN.fullmatch(authorization.allowed_signers_sha256) is not None
        and statement_valid
        and authorization.benchmark_protocol_version
        == submission.protocol.benchmark_protocol_version
        and authorization.rubric_version == submission.protocol.rubric_version
        and authorization.corpus_version == submission.corpus.corpus_version
        and authorization.corpus_hash == submission.corpus.corpus_hash
        and authorization.evaluated_split is BenchmarkSplit.SEALED
        and authorization.evaluated_corpus_hash == submission.corpus.corpus_hash
        and authorization.protocol_sha256 == protocol_authorization.protocol_sha256
        and authorization.candidate_validation_receipt_sha256
        == candidate_authorization.receipt_sha256
        and authorization.candidate_validation_receipt_sha256
        == submission.corpus.candidate_validation_receipt_sha256
        and authorization.candidate_corpus_hash
        == candidate_authorization.receipt.candidate_corpus_hash
        and authorization.candidate_corpus_hash
        == promotion_authorization.statement.candidate_corpus_hash
        and authorization.candidate_scenario_identity_inventory_sha256
        == candidate_authorization.receipt.scenario_identity_inventory_sha256
        and authorization.candidate_scenario_identity_inventory_sha256
        == promotion_authorization.statement.sealed_scenario_identity_inventory_sha256
        and authorization.selection_protocol_sha256 == submission.pilot.selection_protocol_sha256
        and authorization.selection_protocol_sha256
        == pilot_selection_policy_sha256(submission.protocol.pilot_selection_policy)
        and authorization.scenario_count == submission.protocol.total_scenarios
        and authorization.configuration_count
        >= submission.protocol.pilot_selection_policy.minimum_anonymous_configurations
        and authorization.pilot_evidence_sha256 == _canonical_sha256(submission.pilot)
        and authorization.pilot == submission.pilot
    )
    if not valid:
        collector.add(
            PublicationIssueCode.PILOT_EVIDENCE_AUTHORIZATION_INVALID,
            (
                "pilot outcomes lack an exact signed artifact-derived statement over "
                "the promoted sealed corpus and anonymous configuration grid"
            ),
            "pilot",
        )


def _evaluate_release_configuration(
    baseline: BaselineConfigurationRecord,
    *,
    corpus: SealedCorpusRecord,
    corpus_by_id: dict[str, CorpusScenarioRecord],
    protocol: BenchmarkProtocolManifest,
    authorization: VerifiedBaselineAuthorization | None,
    authorization_set_valid: bool,
) -> ConfigurationGateResult:
    """Evaluate one baseline plus its artifact-derived signed construction statement."""
    result = _evaluate_configuration(
        baseline,
        corpus=corpus,
        corpus_by_id=corpus_by_id,
        protocol=protocol,
    )
    if authorization_set_valid and _valid_baseline_authorization(
        baseline,
        corpus=corpus,
        protocol=protocol,
        authorization=authorization,
    ):
        return result
    collector = _IssueCollector()
    collector.extend(result.issues)
    collector.add(
        PublicationIssueCode.BASELINE_VERIFICATION_INVALID,
        "baseline lacks a trusted statement derived from its exact verified bundles",
        f"configuration:{baseline.configuration_id}",
    )
    return result.model_copy(update={"eligible": False, "issues": collector.sorted()})


def _valid_baseline_authorization(
    baseline: BaselineConfigurationRecord,
    *,
    corpus: SealedCorpusRecord,
    protocol: BenchmarkProtocolManifest,
    authorization: VerifiedBaselineAuthorization | None,
) -> bool:
    """Bind one submitted baseline to a trusted artifact-derived statement."""
    if authorization is None:
        return False
    statement = authorization.statement
    return (
        authorization.namespace == BASELINE_VERIFICATION_SIGNATURE_NAMESPACE
        and _SSH_KEY_FINGERPRINT_PATTERN.fullmatch(authorization.signing_key_fingerprint)
        is not None
        and authorization.canonical_statement_sha256 == _canonical_sha256(statement)
        and statement.signer_identity == authorization.identity
        and statement.benchmark_protocol_version == protocol.benchmark_protocol_version
        and statement.rubric_version == protocol.rubric_version
        and statement.configuration_id == baseline.configuration_id
        and statement.corpus_hash == corpus.corpus_hash
        and statement.baseline_record_sha256 == baseline_configuration_record_sha256(baseline)
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
    ) + canonical_local_provider_binding_issues(
        report.benchmark_metadata,
        report.benchmark_runtime_provenance,
    ):
        issue_code = (
            PublicationIssueCode.RUN_CREDENTIAL_ISOLATION_FAILED
            if pin_issue.startswith("credential_")
            else PublicationIssueCode.RUN_PUBLICATION_PIN_INCOMPLETE
        )
        collector.add(issue_code, pin_issue, subject)
    if (
        report.benchmark_metadata is None
        or report.benchmark_metadata.run_seed != protocol.baseline_run_seed
    ):
        collector.add(
            PublicationIssueCode.RUN_PUBLICATION_PIN_INCOMPLETE,
            "baseline_run_seed_mismatch",
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
    errors = len(error_keys)
    if any(
        result.outcome is Outcome.ERROR
        and (result.run_error is None or not result.run_error.strip())
        for result in unique_results.values()
    ):
        collector.add(
            PublicationIssueCode.RUN_EVIDENCE_INTEGRITY_FAILED,
            "every publication ERROR must persist a nonblank causal run_error",
            subject,
        )
    expected_total = len(expected_ids) * protocol.repetitions
    error_rate = errors / expected_total if expected_total else 1.0
    if error_rate > protocol.max_error_rate:
        collector.add(
            PublicationIssueCode.RUN_ERROR_RATE_EXCEEDED,
            (
                f"{errors}/{expected_total} = {error_rate:.6f}, "
                f"maximum is {protocol.max_error_rate:.6f}; every ERROR counts"
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
    observed_order = observed_scenario_order(report.results)
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
            errors=errors,
            error_rate=error_rate,
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
    return (
        all(
            interval.confidence_level == protocol.confidence_level
            and interval.bootstrap_samples >= protocol.min_bootstrap_samples
            and interval.defined_bootstrap_samples + interval.n_a_bootstrap_samples
            == interval.bootstrap_samples
            for interval in intervals
        )
        and statistics.seed == protocol.bootstrap_seed
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
    candidate_authorization: VerifiedCandidateValidationAuthorization | None,
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
        and not canonical_local_provider_binding_issues(
            baseline.report.benchmark_metadata,
            baseline.report.benchmark_runtime_provenance,
        )
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
    if submission.release_evidence.protocol_freeze_receipt_sha256 is None:
        collector.add(
            PublicationIssueCode.BASELINE_PROTOCOL_NOT_FROZEN,
            "content-bound protocol freeze receipt is missing",
            "baseline-matrix",
        )
    baseline_commits = {
        metadata.stinger_commit
        for baseline in baselines
        if (metadata := baseline.report.benchmark_metadata) is not None
        and metadata.stinger_commit is not None
    }
    verification_images = {
        metadata.verification_image_digest
        for baseline in baselines
        if (metadata := baseline.report.benchmark_metadata) is not None
        and metadata.verification_image_digest is not None
    }
    if (
        candidate_authorization is None
        or baseline_commits != {candidate_authorization.receipt.stinger_commit}
        or verification_images != {candidate_authorization.receipt.verification_image_id}
    ):
        collector.add(
            PublicationIssueCode.CORPUS_VALIDATION_RUNTIME_UNBOUND,
            (
                "candidate validation commit and immutable verifier image must exactly "
                "match the complete baseline matrix"
            ),
            "baseline-matrix",
        )
    return len(providers)


def _evaluate_external_evidence(
    submission: BenchmarkReleaseSubmission,
    protocol_authorization: VerifiedProtocolAuthorization | None,
    conformance_authorizations: tuple[VerifiedConformanceAuthorization, ...],
    reproduction_authorization: VerifiedCrossMachineReproductionAuthorization | None,
    public_reproduction_authorization: VerifiedPublicReproductionAuthorization | None,
    release_authorization: VerifiedReleaseAuthorization | None,
    collector: _IssueCollector,
) -> int:
    """Require clean conformance environments and one complete cross-machine reproduction."""
    environments = submission.conformance_environments
    authorization_ids = [
        authorization.statement.environment_id for authorization in conformance_authorizations
    ]
    authorizations_by_id = {
        authorization.statement.environment_id: authorization
        for authorization in conformance_authorizations
    }
    valid_environments = [
        environment
        for environment in environments
        if _valid_conformance_environment(
            environment,
            authorizations_by_id.get(environment.environment_id),
        )
    ]
    environment_ids = {environment.environment_id for environment in environments}
    fingerprints = {environment.environment_fingerprint_sha256 for environment in environments}
    workflow_inputs = {environment.workflow_input_sha256 for environment in environments}
    workflow_receipts = {environment.workflow_receipt_sha256 for environment in environments}
    receipt_signatures = {environment.receipt_signature_sha256 for environment in environments}
    baseline_commits = {
        baseline.report.benchmark_metadata.stinger_commit
        for baseline in submission.baselines
        if baseline.report.benchmark_metadata is not None
        and baseline.report.benchmark_metadata.stinger_commit is not None
    }
    if (
        len(environments) < submission.protocol.conformance_environments
        or len(valid_environments) != len(environments)
        or len(authorization_ids) != len(set(authorization_ids))
        or set(authorization_ids) != environment_ids
        or len(environment_ids) < submission.protocol.conformance_environments
        or len(fingerprints) < submission.protocol.conformance_environments
        or len(workflow_inputs) != 1
        or len(workflow_receipts) < submission.protocol.conformance_environments
        or len(receipt_signatures) < submission.protocol.conformance_environments
        or len(
            {authorization.signing_key_fingerprint for authorization in conformance_authorizations}
        )
        < submission.protocol.conformance_environments
        or len(
            {authorization.allowed_signers_sha256 for authorization in conformance_authorizations}
        )
        < submission.protocol.conformance_environments
        or len(baseline_commits) != 1
        or any(
            environment.benchmark_protocol_version != submission.protocol.benchmark_protocol_version
            or environment.rubric_version != submission.protocol.rubric_version
            or environment.corpus_hash != submission.corpus.corpus_hash
            or environment.stinger_commit not in baseline_commits
            for environment in environments
        )
    ):
        collector.add(
            PublicationIssueCode.CONFORMANCE_ENVIRONMENTS_INSUFFICIENT,
            (
                f"expected at least {submission.protocol.conformance_environments} distinct "
                "clean executions of one workflow bound to the active protocol, corpus, "
                f"and baseline commit; got {len(environment_ids)} ids, "
                f"{len(fingerprints)} fingerprints, {len(workflow_inputs)} workflows, "
                f"{len(workflow_receipts)} receipts, and {len(valid_environments)} "
                "trusted statements"
            ),
            "conformance",
        )
    platforms = {(environment.platform, environment.architecture) for environment in environments}
    if len(platforms) < submission.protocol.conformance_platforms:
        collector.add(
            PublicationIssueCode.CONFORMANCE_PLATFORM_DIVERSITY_INSUFFICIENT,
            (
                f"expected at least {submission.protocol.conformance_platforms} "
                f"platform/architecture pairs, got {len(platforms)}"
            ),
            "conformance",
        )

    reproduction = submission.cross_machine_reproduction
    if reproduction is None:
        collector.add(
            PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_MISSING,
            "no cross-machine reproduction record was supplied",
            "cross-machine-reproduction",
        )
    elif not _valid_reproduction(
        reproduction,
        reproduction_authorization,
        public_reproduction_authorization,
        release_authorization,
        protocol_authorization,
        submission,
    ):
        collector.add(
            PublicationIssueCode.CROSS_MACHINE_REPRODUCTION_INVALID,
            (
                "reproduction lacks a trusted signed verifier statement or its artifact, "
                "environment, escrow, modal-outcome, comparison, and discrepancy bindings "
                "do not match"
            ),
            "cross-machine-reproduction",
        )
    return len(valid_environments)


def _valid_conformance_environment(
    record: ConformanceEnvironmentRecord,
    authorization: VerifiedConformanceAuthorization | None,
) -> bool:
    """Bind one submitted conformance record to a trusted exact statement."""
    if authorization is None:
        return False
    statement = authorization.statement
    return (
        authorization.namespace == CONFORMANCE_SIGNATURE_NAMESPACE
        and _SSH_KEY_FINGERPRINT_PATTERN.fullmatch(authorization.signing_key_fingerprint)
        is not None
        and authorization.canonical_statement_sha256 == _canonical_sha256(statement)
        and record.environment_id == statement.environment_id
        and record.platform is statement.platform
        and record.architecture is statement.architecture
        and record.python_version == statement.python_version
        and record.stinger_commit == statement.stinger_commit
        and record.benchmark_protocol_version == statement.benchmark_protocol_version
        and record.rubric_version == statement.rubric_version
        and record.corpus_hash == statement.corpus_hash
        and record.environment_fingerprint_sha256 == statement.environment_fingerprint_sha256
        and record.workflow_input_sha256 == statement.workflow_input_sha256
        and record.workflow_receipt_sha256 == statement.workflow_output_inventory_sha256
        and record.receipt_signature_sha256 == authorization.signature_sha256
        and record.allowed_signers_sha256 == authorization.allowed_signers_sha256
        and record.signer_identity == authorization.identity
        and statement.signer_identity == authorization.identity
    )


def _valid_reproduction(
    reproduction: CrossMachineReproductionRecord | None,
    authorization: VerifiedCrossMachineReproductionAuthorization | None,
    public_authorization: VerifiedPublicReproductionAuthorization | None,
    release_authorization: VerifiedReleaseAuthorization | None,
    protocol_authorization: VerifiedProtocolAuthorization | None,
    submission: BenchmarkReleaseSubmission,
) -> bool:
    """Mechanically bind the signed verifier statement to the target baseline and corpus."""
    if (
        reproduction is None
        or authorization is None
        or public_authorization is None
        or release_authorization is None
        or protocol_authorization is None
    ):
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
    discrepancy_locations = [
        (item.scenario_id, item.repetition, item.field) for item in discrepancies
    ]
    families = statement.completed_families
    target_agent_fingerprint = (
        None
        if baseline is None or baseline.report.benchmark_metadata is None
        else baseline.report.benchmark_metadata.agent_configuration_fingerprint
    )
    target_results = (
        {}
        if baseline is None
        else {(result.scenario_id, result.repetition): result for result in baseline.report.results}
    )
    return (
        baseline is not None
        and public_authorization.verification_signature_namespace
        == PUBLIC_REPRODUCTION_VERIFICATION_SIGNATURE_NAMESPACE
        and public_authorization.verification_signer_identity == authorization.identity
        and public_authorization.verification_signing_key_fingerprint
        == authorization.signing_key_fingerprint
        and public_authorization.verification_allowed_signers_sha256
        == authorization.allowed_signers_sha256
        and public_authorization.verification_signature_sha256 != authorization.signature_sha256
        and public_authorization.benchmark_protocol_version
        == submission.protocol.benchmark_protocol_version
        and public_authorization.statement_sha256 == authorization.statement_sha256
        and public_authorization.target_baseline_record_sha256
        == baseline_configuration_record_sha256(baseline)
        and public_authorization.target_report_sha256 == statement.target_report_sha256
        and public_authorization.target_public_bundle_manifest_sha256
        == statement.target_public_bundle_manifest_sha256
        and public_authorization.target_public_bundle_report_sha256
        == public_authorization.target_report_bytes_sha256
        and public_authorization.target_public_bundle_leakage_policy_sha256
        == public_authorization.reproduced_public_bundle_leakage_policy_sha256
        and public_authorization.target_protocol_sha256 == protocol_authorization.protocol_sha256
        and public_authorization.target_protocol_signature_sha256
        == protocol_authorization.signature_sha256
        and public_authorization.target_protocol_allowed_signers_sha256
        == protocol_authorization.allowed_signers_sha256
        and public_authorization.target_protocol_signer_identity == protocol_authorization.identity
        and public_authorization.reproduced_public_bundle_manifest_sha256
        == statement.reproduced_public_bundle_manifest_sha256
        and public_authorization.reproduced_public_bundle_report_sha256
        == public_authorization.reproduced_report_bytes_sha256
        and public_authorization.reproduced_protocol_sha256
        == protocol_authorization.protocol_sha256
        and public_authorization.reproduced_protocol_signature_sha256
        == protocol_authorization.signature_sha256
        and public_authorization.reproduced_protocol_allowed_signers_sha256
        == protocol_authorization.allowed_signers_sha256
        and public_authorization.reproduced_protocol_signer_identity
        == protocol_authorization.identity
        and public_authorization.reproduced_report_sha256 == statement.reproduced_report_sha256
        and public_authorization.reproduced_report_signature_sha256
        == statement.reproduced_report_signature_sha256
        and public_authorization.reproduced_report_allowed_signers_sha256
        == statement.reproduced_report_allowed_signers_sha256
        and public_authorization.reproduced_report_signing_key_fingerprint
        == statement.reproduced_report_signing_key_fingerprint
        and public_authorization.reproduced_report_signer_identity
        == statement.reproduced_report_signer_identity
        and public_authorization.comparison_manifest_sha256 == statement.comparison_manifest_sha256
        and public_authorization.discrepancy_ledger_sha256 == statement.discrepancy_ledger_sha256
        and authorization.namespace == REPRODUCTION_SIGNATURE_NAMESPACE
        and _SSH_KEY_FINGERPRINT_PATTERN.fullmatch(authorization.signing_key_fingerprint)
        is not None
        and authorization.canonical_statement_sha256 == _canonical_sha256(statement)
        and authorization.identity != release_authorization.identity
        and authorization.signing_key_fingerprint != release_authorization.signing_key_fingerprint
        and authorization.allowed_signers_sha256 != release_authorization.allowed_signers_sha256
        and reproduction.statement_sha256 == authorization.statement_sha256
        and reproduction.statement_signature_sha256 == authorization.signature_sha256
        and reproduction.verifier_allowed_signers_sha256 == authorization.allowed_signers_sha256
        and reproduction.signer_identity == authorization.identity
        and statement.signer_identity == authorization.identity
        and statement.reproduced_report_signer_identity == authorization.identity
        and statement.reproduced_report_signature_namespace == REPRODUCED_REPORT_SIGNATURE_NAMESPACE
        and statement.reproduced_report_signing_key_fingerprint
        == authorization.signing_key_fingerprint
        and statement.reproduced_report_allowed_signers_sha256
        == authorization.allowed_signers_sha256
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
        and statement.reproduced_report_sha256 != statement.target_report_sha256
        and statement.reproduced_public_bundle_manifest_sha256
        != statement.target_public_bundle_manifest_sha256
        and statement.reproduced_escrow_bundle_manifest_sha256
        != statement.target_escrow_bundle_manifest_sha256
        and statement.reproduced_config_fingerprint == baseline.report.config_fingerprint
        and statement.reproduced_agent_configuration_fingerprint == target_agent_fingerprint
        and statement.reproduced_machine_fingerprint_sha256 != baseline.machine_fingerprint_sha256
        and statement.target_modal_outcomes_sha256
        == reproduction_modal_outcomes_sha256(baseline.report)
        and statement.reproduced_modal_outcomes_sha256 == statement.target_modal_outcomes_sha256
        and len(families) == len(Family)
        and set(families) == set(Family)
        and statement.scenario_count == submission.protocol.total_scenarios
        and statement.repetitions == submission.protocol.repetitions
        and statement.discrepancy_ledger_sha256
        == reproduction_discrepancy_ledger_sha256(
            discrepancies,
            target_report_sha256=statement.target_report_sha256,
            reproduced_report_sha256=statement.reproduced_report_sha256,
        )
        and len(discrepancy_ids) == len(set(discrepancy_ids))
        and len(discrepancy_locations) == len(set(discrepancy_locations))
        and all(
            item.scenario_id
            and item.scenario_id == item.scenario_id.strip()
            and (item.scenario_id, item.repetition) in target_results
            and item.field in _REPRODUCTION_DISCREPANCY_FIELDS
            and item.target_value_sha256
            == reproduction_value_sha256(
                target_results[(item.scenario_id, item.repetition)].model_dump(mode="json")[
                    item.field
                ]
            )
            and item.discrepancy_id
            == reproduction_discrepancy_id(
                item.scenario_id,
                item.repetition,
                item.field,
                item.target_value_sha256,
                item.reproduced_value_sha256,
            )
            and item.target_value_sha256 != item.reproduced_value_sha256
            and item.classification
            is ReproductionDiscrepancyClassification.EXPECTED_AGENT_VARIANCE_MODAL_STABLE
            for item in discrepancies
        )
    )


def reproduction_discrepancy_ledger_sha256(
    discrepancies: tuple[ReproductionDiscrepancyRecord, ...],
    *,
    target_report_sha256: str,
    reproduced_report_sha256: str,
) -> str:
    """Hash both reports and the canonical ledger covered by the verifier statement."""
    target_hash = _require_sha256(
        target_report_sha256,
        field_name="target_report_sha256",
    )
    reproduced_hash = _require_sha256(
        reproduced_report_sha256,
        field_name="reproduced_report_sha256",
    )
    ordered = sorted(
        discrepancies,
        key=lambda item: (
            item.scenario_id,
            item.repetition,
            item.field,
            _canonical_payload_sha256(item.model_dump(mode="json")),
        ),
    )
    return _canonical_payload_sha256(
        {
            "target_report_sha256": target_hash,
            "reproduced_report_sha256": reproduced_hash,
            "discrepancies": [item.model_dump(mode="json") for item in ordered],
        }
    )


def reproduction_modal_outcomes_sha256(report: Report) -> str:
    """Hash the canonical per-scenario modal outcomes of one complete report."""
    grouped: dict[str, list[ScenarioResult]] = defaultdict(list)
    for result in report.results:
        grouped[result.scenario_id].append(result)
    return _canonical_payload_sha256(
        {
            "modal_outcomes": [
                {
                    "scenario_id": scenario_id,
                    "outcome": modal_outcome(grouped[scenario_id]).value,
                }
                for scenario_id in sorted(grouped)
            ]
        }
    )


def reproduction_discrepancy_id(
    scenario_id: str,
    repetition: int,
    field: str,
    target_value_sha256: str,
    reproduced_value_sha256: str,
) -> str:
    """Derive one discrepancy id from its immutable semantic location and value hashes."""
    if repetition < 0:
        raise ValueError("repetition must be non-negative")
    return _canonical_payload_sha256(
        {
            "scenario_id": scenario_id,
            "repetition": repetition,
            "field": field,
            "target_value_sha256": _require_sha256(
                target_value_sha256,
                field_name="target_value_sha256",
            ),
            "reproduced_value_sha256": _require_sha256(
                reproduced_value_sha256,
                field_name="reproduced_value_sha256",
            ),
        }
    )


def reproduction_value_sha256(value: object) -> str:
    """Hash one present classification-field value without conflating JSON null."""
    return _canonical_payload_sha256({"present": True, "value": value})


def _evaluate_release_evidence(
    submission: BenchmarkReleaseSubmission,
    authorization: VerifiedReleaseEvidenceAuthorization | None,
    release_authorization: VerifiedReleaseAuthorization | None,
    collector: _IssueCollector,
) -> None:
    """Evaluate clean-gate, report, correction, and comparison-governance evidence."""
    evidence = submission.release_evidence
    checks: tuple[tuple[bool, PublicationIssueCode, str], ...] = (
        (
            evidence.master_gate_receipt_sha256 is not None,
            PublicationIssueCode.MASTER_GATE_NOT_CLEAN,
            "content-bound clean master-gate receipt is missing",
        ),
        (
            evidence.technical_report_sha256 is not None,
            PublicationIssueCode.TECHNICAL_REPORT_INCOMPLETE,
            "content-bound technical report is missing",
        ),
        (
            evidence.correction_policy_sha256 is not None,
            PublicationIssueCode.CORRECTION_POLICY_MISSING,
            "content-bound correction policy is missing",
        ),
        (
            evidence.conflicts_disclosure_sha256 is not None,
            PublicationIssueCode.CONFLICTS_NOT_DISCLOSED,
            "content-bound conflict-of-interest disclosure is missing",
        ),
    )
    for passed, code, detail in checks:
        if not passed:
            collector.add(code, detail, "release")
    if evidence.comparative_release and evidence.vendor_rerun_receipt_sha256 is None:
        collector.add(
            PublicationIssueCode.VENDOR_RERUN_OPPORTUNITY_MISSING,
            "comparative release lacks a content-bound vendor rerun receipt",
            "release",
        )
    baseline_commits = {
        baseline.report.benchmark_metadata.stinger_commit
        for baseline in submission.baselines
        if baseline.report.benchmark_metadata is not None
        and baseline.report.benchmark_metadata.stinger_commit is not None
    }
    canonical_statement_valid = False
    if authorization is not None:
        from stinger.benchmark.release_evidence import (
            ReleaseEvidenceBuilderError,
            ReleaseEvidenceStatement,
            verify_release_evidence_statement,
        )

        try:
            typed_statement = ReleaseEvidenceStatement.model_validate_json(
                authorization.statement_bytes
            )
            verify_release_evidence_statement(typed_statement, submission)
        except (ValueError, ReleaseEvidenceBuilderError):
            pass
        else:
            canonical_statement_valid = (
                hashlib.sha256(authorization.statement_bytes).hexdigest()
                == authorization.statement_sha256
                and authorization.canonical_statement_sha256 == _canonical_sha256(typed_statement)
                and typed_statement.benchmark_protocol_version
                == authorization.benchmark_protocol_version
                and typed_statement.rubric_version == authorization.rubric_version
                and typed_statement.corpus_version == authorization.corpus_version
                and typed_statement.corpus_hash == authorization.corpus_hash
                and typed_statement.stinger_commit == authorization.stinger_commit
                and typed_statement.release_evidence == authorization.release_evidence
                and typed_statement.release_evidence_record_sha256
                == authorization.release_evidence_record_sha256
                and typed_statement.canonical_submission_sha256
                == authorization.canonical_submission_sha256
                and typed_statement.signer_identity == authorization.identity
            )
    authorization_valid = (
        authorization is not None
        and release_authorization is not None
        and authorization.namespace == RELEASE_EVIDENCE_SIGNATURE_NAMESPACE
        and authorization.identity != release_authorization.identity
        and authorization.signing_key_fingerprint != release_authorization.signing_key_fingerprint
        and authorization.allowed_signers_sha256 != release_authorization.allowed_signers_sha256
        and _SSH_KEY_FINGERPRINT_PATTERN.fullmatch(authorization.signing_key_fingerprint)
        is not None
        and _SHA256_PATTERN.fullmatch(authorization.statement_sha256) is not None
        and _SHA256_PATTERN.fullmatch(authorization.signature_sha256) is not None
        and _SHA256_PATTERN.fullmatch(authorization.allowed_signers_sha256) is not None
        and canonical_statement_valid
        and authorization.benchmark_protocol_version
        == submission.protocol.benchmark_protocol_version
        and authorization.rubric_version == submission.protocol.rubric_version
        and authorization.corpus_version == submission.corpus.corpus_version
        and authorization.corpus_hash == submission.corpus.corpus_hash
        and authorization.release_evidence == evidence
        and authorization.release_evidence_record_sha256 == _canonical_sha256(evidence)
        and authorization.canonical_submission_sha256 == _canonical_sha256(submission)
        and baseline_commits == {authorization.stinger_commit}
    )
    if not authorization_valid:
        collector.add(
            PublicationIssueCode.RELEASE_EVIDENCE_AUTHORIZATION_INVALID,
            "release artifacts lack an exact signed machine-derived evidence statement",
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
        and approval.publication_approved
        and (
            not submission.release_evidence.comparative_release
            or approval.comparative_result_approved
        )
    )
    if not valid:
        collector.add(
            PublicationIssueCode.HUMAN_APPROVAL_INVALID,
            "approval must be Chris's, protocol-scoped, and cover publication",
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
        or _SSH_KEY_FINGERPRINT_PATTERN.fullmatch(authorization.signing_key_fingerprint) is None
    ):
        collector.add(
            PublicationIssueCode.RELEASE_AUTHORIZATION_INVALID,
            "verified signature does not bind this exact typed release submission",
            "release-authorization",
        )


__all__ = [
    "AgentQAAttemptRecord",
    "BaselineConfigurationRecord",
    "BaselineVerificationStatement",
    "CandidateValidationReceipt",
    "CandidatePromotionStatement",
    "BenchmarkGateMetrics",
    "BenchmarkGateReport",
    "BenchmarkProtocolManifest",
    "BenchmarkReleaseSubmission",
    "BlindAgentSolveRecord",
    "ConfigurationGateMetrics",
    "ConfigurationGateResult",
    "ConformanceArchitecture",
    "ConformanceEnvironmentRecord",
    "ConformanceEnvironmentStatement",
    "ConformancePlatform",
    "CorpusFreezeRecord",
    "CorpusFreezeStatement",
    "CorpusScenarioRecord",
    "CrossMachineReproductionRecord",
    "CrossMachineReproductionStatement",
    "GateIssue",
    "HumanApprovalRecord",
    "MachineReviewRecord",
    "PilotCandidateRecord",
    "PilotConfigurationOutcomeRecord",
    "PilotEvidenceRecord",
    "PilotSelectionPolicy",
    "PublicationIssueCode",
    "ReleaseEvidenceRecord",
    "ReleaseStatus",
    "RepositorySize",
    "ResolutionKind",
    "ResolutionVariantRecord",
    "ReproductionDiscrepancyClassification",
    "ReproductionDiscrepancyRecord",
    "SealedCorpusRecord",
    "VerifiedReleaseAuthorization",
    "VerifiedReleaseEvidenceAuthorization",
    "VerifiedBaselineAuthorization",
    "VerifiedCandidateValidationAuthorization",
    "VerifiedCandidatePromotionAuthorization",
    "VerifiedConformanceAuthorization",
    "VerifiedCorpusFreezeAuthorization",
    "VerifiedProtocolAuthorization",
    "VerifiedCrossMachineReproductionAuthorization",
    "VerifiedPilotEvidenceAuthorization",
    "VerifiedPublicReproductionAuthorization",
    "authorize_benchmark_protocol",
    "authorize_benchmark_submission",
    "authorize_baseline_verification_statement",
    "authorize_candidate_validation_receipt",
    "authorize_candidate_promotion_statement",
    "authorize_conformance_statement",
    "authorize_corpus_freeze_statement",
    "authorize_pilot_evidence_statement",
    "authorize_reproduction_statement",
    "authorize_release_evidence_statement",
    "canonical_report_sha256",
    "baseline_configuration_record_sha256",
    "candidate_scenario_identity_inventory_sha256",
    "candidate_validation_inventory_sha256",
    "sealed_scenario_artifact_inventory_sha256",
    "compiled_benchmark_protocol",
    "evaluate_baseline_configuration_record",
    "evaluate_benchmark_release",
    "evaluate_corpus_construction",
    "load_benchmark_protocol",
    "load_benchmark_submission",
    "machine_review_input_manifest_sha256",
    "pilot_selection_policy_sha256",
    "reproduction_discrepancy_id",
    "reproduction_discrepancy_ledger_sha256",
    "reproduction_modal_outcomes_sha256",
    "reproduction_value_sha256",
]
