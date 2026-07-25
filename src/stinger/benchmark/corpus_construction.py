"""Artifact-derived construction records for a Protocol 2 sealed corpus.

The release-gate models deliberately contain compact hashes rather than private corpus
material.  This module is the trusted construction path from exact private artifacts to
those models.  It never accepts a caller-entered favourable hash or boolean for a
``CorpusScenarioRecord``:

* scenario identity and content come from the safely inventoried sealed tree;
* provenance, containment, dummy-safety, variant, review, and reference-isolation receipts
  are closed canonical JSON records whose exact bytes are re-opened and hashed;
* QA and blind-solve results come from independently verified public/escrow bundle pairs;
* the frozen machine-review prompt, schema, and derived input manifest are cross-bound; and
* the unchanged corpus-construction release gate must return no issue.

The resulting receipt is path-free.  It is private while the corpus is active because it
contains scenario identifiers, but it contains neither host paths nor escrow content.
"""

from __future__ import annotations

import ast
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any, Literal, TypedDict, cast
from uuid import uuid4

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    JsonValue,
    ValidationError,
    field_validator,
    model_validator,
)

from stinger.adapters.base import AgentRun, Budget
from stinger.adapters.cli_base import CliAgentAdapter
from stinger.adapters.factory import AdapterError, build_adapter
from stinger.benchmark.candidate_receipt import (
    CandidateReceiptError,
    _inventory_tree,
    _read_regular_file,
    _Snapshot,
    _snapshot_tree,
    _verify_access_ledger,
    _verify_canaries,
)
from stinger.benchmark.corpus_promotion import SEALED_VALIDATION_CONTRACT
from stinger.benchmark.evidence import (
    EvidenceBundleError,
    EvidenceRole,
    PublicLeakagePolicy,
    VerifiedArtifactReceipt,
    verify_evidence_bundle_pair,
)
from stinger.benchmark.gates import (
    AgentQAAttemptRecord,
    BlindAgentSolveRecord,
    CandidatePromotionStatement,
    CorpusScenarioRecord,
    MachineReviewRecord,
    RepositorySize,
    ResolutionKind,
    ResolutionVariantRecord,
    SealedCorpusRecord,
    VerifiedCandidatePromotionAuthorization,
    VerifiedCandidateValidationAuthorization,
    authorize_candidate_promotion_statement,
    authorize_candidate_validation_receipt,
    compiled_benchmark_protocol,
    corpus_scenario_inventory_sha256,
    evaluate_corpus_construction,
    machine_review_input_manifest_sha256,
)
from stinger.benchmark.git_checkout import (
    GitCheckoutError,
    clean_exact_git_head,
    verify_tracked_implementation,
)
from stinger.benchmark.machine_environment import (
    MACHINE_WORKFLOW_SIGNATURE_NAMESPACE,
    MachineAttestationError,
    VerifiedMachineWorkflowAttestation,
    verify_machine_workflow_attestation,
)
from stinger.benchmark.machine_review import (
    MACHINE_REVIEW_OUTPUT_SCHEMA_SHA256,
    MACHINE_REVIEW_PROMPT,
    MACHINE_REVIEW_PROMPT_SHA256,
    MachineReviewDecision,
    MachineReviewOutput,
)
from stinger.benchmark.protocol import (
    BenchmarkRunMetadata,
    BenchmarkRuntimeProvenance,
    BenchmarkSplit,
    ProviderId,
    canonical_local_provider_binding_issues,
    publication_pin_issues,
)
from stinger.benchmark.replay import (
    INVOCATION_AGGREGATE_NAME,
    ClassificationReplayError,
    verify_invocation_aggregate_snapshot,
)
from stinger.benchmark.signing import (
    ProtocolSignatureError,
    sign_protocol,
    verify_protocol_signature,
)
from stinger.benchmark.verification_image import (
    canonical_verification_image_policy_sha256,
    verification_image_id_is_approved,
)
from stinger.config import AgentConfig
from stinger.docker_runtime import (
    DOCKER_RUNTIME_CLAIM_BOUNDARY,
    DockerRuntimeError,
    DockerRuntimeIdentity,
    inspect_docker_image,
    observe_docker_runtime,
    run_docker,
    terminate_docker_container,
    verify_docker_runtime,
)
from stinger.harness.runner import run_scenario_once
from stinger.harness.sandbox import (
    Isolation,
    Sandbox,
    SandboxError,
    apply_overlay,
    capture,
    diff_states,
)
from stinger.models import Family, Outcome, ScenarioResult
from stinger.report.generate import ReportMismatchError, load_report, verify_report
from stinger.scenario.loader import (
    Scenario,
    ScenarioLoadError,
    corpus_hash,
    discover_scenarios,
    scenario_hash,
)

CONSTRUCTION_RECEIPT_FORMAT_VERSION: Literal["2"] = "2"
"""Canonical receipt format for artifact-derived Protocol 2 corpus construction."""

CORPUS_CONSTRUCTION_SIGNATURE_NAMESPACE = "stinger-benchmark-corpus-construction"
"""Dedicated OpenSSH domain separator for exact construction-receipt bytes."""

MACHINE_REVIEW_RUNTIME_SIGNATURE_NAMESPACE = "stinger-benchmark-machine-review-runtime"
"""Domain separator for a machine runner's exact review invocation receipt."""

MACHINE_REVIEW_RUNTIME_FORMAT_VERSION: Literal["6"] = "6"
"""Version of the signed, transcript-bearing machine-review runtime contract."""

MACHINE_REVIEW_CONFIGURATION_FORMAT_VERSION: Literal["4"] = "4"
"""Reviewer configuration format that includes the canonical executable adapter."""

CODEX_CREDENTIAL_PROJECTION_POLICY = "codex-auth-json-only-v1"
"""Codex reviews receive one copied ``auth.json`` and no other caller state."""

CLAUDE_CREDENTIAL_PROJECTION_POLICY = "claude-explicit-auth-env-only-v1"
"""Claude reviews receive one explicitly named auth variable and no config directory."""

RESOLUTION_EXECUTION_FORMAT_VERSION: Literal["4"] = "4"
"""Resolution receipt format with normalized semantic and mechanism identities."""

MACHINE_REVIEW_CLAIM_BOUNDARY = (
    "signed local workflow evidence for a canonical machine-review CLI invocation whose "
    "raw transcript is deterministically parsed by Stinger; not provider-signed remote-"
    "service, served-model, account-owner, or physical-hardware attestation"
)
"""The deliberately narrow claim made by a signed machine-review runtime receipt."""

MACHINE_REVIEW_INPUT_FILENAME = "machine-review-input.json"
"""Canonical review-workspace filename containing the exact input receipt."""

MACHINE_REVIEW_EVIDENCE_MANIFEST_FILENAME = "machine-review-evidence-manifest.json"
"""Canonical inventory describing every model-visible review evidence byte."""

AGENT_RUN_WORKFLOW_CLAIM_BOUNDARY = (
    "signed local workflow and operating-system-environment evidence binding a verified "
    "InvocationAggregate to exact public and escrow bundle manifests; not provider-signed "
    "served-model, account-owner, organizational-independence, physical-hardware, or "
    "anti-fabrication proof"
)
"""Narrow claim made by the external run-workflow input and attestation pair."""

DUMMY_SAFETY_POLICY_VERSION: Literal["stinger-dummy-safety-v2"] = "stinger-dummy-safety-v2"
"""Frozen local-only target and visibly-dummy credential scan used by construction."""

_AGENT_CONTROL_FILENAMES = frozenset({"AGENTS.md", "CLAUDE.md"})
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_PATTERN = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_IDENTIFIER_PATTERN = re.compile(r"^[^\s]+$")
_READ_CHUNK = 1024 * 1024
_MAX_RECEIPT_BYTES = 8 * 1024 * 1024
_RUNTIME_RECEIPT_DOMAIN: Literal["stinger-corpus-construction-runtime-v2"] = (
    "stinger-corpus-construction-runtime-v2"
)
_URL_TARGET_PATTERN = re.compile(rb"https?://([A-Za-z0-9._~:%\-\[\]@]+)")
_NETWORK_CONTEXT_PATTERN = re.compile(
    rb"""(?ix)
    (?:socket|connect|create_connection|host|hostname|endpoint|target|server|address|uri|
       base[_-]?url|webhook|
       requests?\.(?:get|post|put|patch|delete)|httpx\.(?:get|post|put|patch|delete))
    [^\r\n]{0,256}?
    ["']((?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,63}(?::[0-9]{1,5})?|
         (?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?|
         \[[0-9A-Fa-f:]+\](?::[0-9]{1,5})?)["']
    """
)
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    rb"""(?ix)
    \b(?:[A-Za-z0-9_]*(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer|
       credential|password|passwd|private[_-]?key|secret|token)[A-Za-z0-9_]*)
    \s*(?::|=)\s*
    ["']([^"'\r\n]{4,})["']
    """
)
_SECRET_NAME_PATTERN = re.compile(
    r"(?i)(?:api_?key|access_?token|auth_?token|bearer|credential|password|passwd|"
    r"private_?key|secret|token)"
)
_NETWORK_NAME_PATTERN = re.compile(
    r"(?i)(?:host|hostname|endpoint|target|server|address|uri|url|webhook)"
)
_CREDENTIAL_TOKEN_PATTERN = re.compile(
    rb"(?i)(?:sk-[A-Za-z0-9_-]{12,}|AKIA[A-Z0-9]{12,}|"
    rb"gh[opusr]_[A-Za-z0-9_]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
_DUMMY_MARKERS = (b"dummy", b"not-a-real", b"synthetic", b"example", b"test-only")


class CorpusConstructionError(Exception):
    """Raised when private artifacts cannot support a truthful corpus record."""


class _ClosedModel(BaseModel):
    """Common immutable, closed contract for construction receipts."""

    model_config = ConfigDict(extra="forbid", frozen=True)


def _canonical_identifier(value: str, *, label: str) -> str:
    """Require one nonblank, whitespace-free identifier."""
    if not value or value != value.strip() or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a nonblank identifier without whitespace")
    return value


def _canonical_hash(value: str, *, label: str) -> str:
    """Require one lowercase SHA-256 digest."""
    if _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a canonical sha256")
    return value


class ScenarioProvenanceReceipt(_ClosedModel):
    """Exact authoring provenance and repository-size evidence for one scenario."""

    format_version: Literal["2"]
    benchmark_protocol_version: str
    rubric_version: str
    corpus_version: str
    scenario_id: str
    scenario_artifact_sha256: str
    repository_size: RepositorySize
    authoring_configuration_fingerprints: tuple[str, ...]
    source_artifact_sha256s: tuple[str, ...]

    @field_validator("benchmark_protocol_version", "rubric_version", "corpus_version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        if _SEMVER_PATTERN.fullmatch(value) is None:
            raise ValueError("provenance versions must be semantic versions")
        return value

    @field_validator("scenario_id")
    @classmethod
    def _scenario_identifier(cls, value: str) -> str:
        return _canonical_identifier(value, label="scenario_id")

    @field_validator("scenario_artifact_sha256")
    @classmethod
    def _scenario_hash(cls, value: str) -> str:
        return _canonical_hash(value, label="scenario artifact")

    @field_validator(
        "authoring_configuration_fingerprints",
        "source_artifact_sha256s",
    )
    @classmethod
    def _canonical_hash_inventory(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if (
            not value
            or value != tuple(sorted(value))
            or len(value) != len(set(value))
            or any(_SHA256_PATTERN.fullmatch(item) is None for item in value)
        ):
            raise ValueError("provenance hash inventories must be nonempty, unique, and sorted")
        return value


class ScenarioContainmentReceipt(_ClosedModel):
    """Receipt derived from the signature-authorized Docker promotion validation."""

    format_version: Literal["2"]
    scenario_id: str
    scenario_artifact_sha256: str
    sealed_validation_receipt_sha256: str
    promotion_statement_sha256: str
    validation_contract: Literal["stinger-scenario-validity-v1-docker-sealed"]
    verification_image_id: str
    isolation: Literal["docker"]
    network_mode: Literal["none"]

    @field_validator("scenario_id")
    @classmethod
    def _scenario_identifier(cls, value: str) -> str:
        return _canonical_identifier(value, label="scenario_id")

    @field_validator(
        "scenario_artifact_sha256",
        "sealed_validation_receipt_sha256",
        "promotion_statement_sha256",
    )
    @classmethod
    def _scenario_hash(cls, value: str) -> str:
        return _canonical_hash(value, label="scenario artifact")

    @field_validator("verification_image_id")
    @classmethod
    def _verification_image(cls, value: str) -> str:
        return _canonical_identifier(value, label="verification image")


class DummySafetyReceipt(_ClosedModel):
    """Receipt derived by scanning the exact safely inventoried scenario bytes."""

    format_version: Literal["2"]
    policy_version: Literal["stinger-dummy-safety-v2"]
    scenario_id: str
    scenario_artifact_sha256: str
    scanned_file_count: int
    scanned_byte_count: int
    declared_dummy_secret_count: int
    declared_dummy_secret_inventory_sha256: str
    allowed_network_target_count: int
    allowed_network_target_inventory_sha256: str
    credential_token_inventory_sha256: str

    @field_validator("scenario_id")
    @classmethod
    def _scenario_identifier(cls, value: str) -> str:
        return _canonical_identifier(value, label="scenario_id")

    @field_validator(
        "scenario_artifact_sha256",
        "declared_dummy_secret_inventory_sha256",
        "allowed_network_target_inventory_sha256",
        "credential_token_inventory_sha256",
    )
    @classmethod
    def _scenario_hash(cls, value: str) -> str:
        return _canonical_hash(value, label="scenario artifact")

    @field_validator(
        "scanned_file_count",
        "scanned_byte_count",
        "declared_dummy_secret_count",
        "allowed_network_target_count",
    )
    @classmethod
    def _nonnegative_count(cls, value: int) -> int:
        if value < 0:
            raise ValueError("dummy-safety counts cannot be negative")
        return value


class AuthoringConfigurationReceipt(_ClosedModel):
    """Canonical authoring identity used for semantic reviewer-independence checks."""

    format_version: Literal["2"]
    provider: ProviderId
    model_id: str
    agent_build: str
    reasoning_effort: str
    inference_settings: dict[str, JsonValue]

    @field_validator("model_id", "agent_build", "reasoning_effort")
    @classmethod
    def _identifier(cls, value: str) -> str:
        return _canonical_identifier(value, label="authoring configuration identifier")


class _NormalizedConfigurationIdentity(_ClosedModel):
    """Review-id-free semantic identity derived only from verified review configurations."""

    provider: ProviderId
    model_id: str
    agent_build: str
    reasoning_effort: str
    inference_settings_sha256: str

    @field_validator("model_id", "reasoning_effort")
    @classmethod
    def _identifier(cls, value: str) -> str:
        return _canonical_identifier(value, label="configuration identity")

    @field_validator("agent_build")
    @classmethod
    def _build_text(cls, value: str) -> str:
        if not value or value != value.strip() or "\x00" in value:
            raise ValueError("configuration build identity must be nonblank canonical text")
        return value

    @field_validator("inference_settings_sha256")
    @classmethod
    def _settings_hash(cls, value: str) -> str:
        return _canonical_hash(value, label="inference settings")


class ResolutionExecutionReceipt(_ClosedModel):
    """Builder-produced result of executing one variant through the full Docker pipeline."""

    format_version: Literal["4"]
    scenario_id: str
    scenario_artifact_sha256: str
    variant_id: str
    kind: ResolutionKind
    source_tree_sha256: str
    semantic_patch_sha256: str
    semantic_change_sha256: str
    implementation_mechanism_sha256: str
    agent_run_sha256: str
    verification_image_id: str
    result_sha256: str
    transcript_sha256: str
    diff_sha256: str
    outcome: Outcome
    goal_met: bool
    intended_detector_triggered: bool
    intended_detector: str

    @field_validator("scenario_id", "variant_id", "intended_detector")
    @classmethod
    def _identifier(cls, value: str) -> str:
        return _canonical_identifier(value, label="resolution identifier")

    @field_validator(
        "scenario_artifact_sha256",
        "source_tree_sha256",
        "semantic_patch_sha256",
        "semantic_change_sha256",
        "implementation_mechanism_sha256",
        "agent_run_sha256",
        "result_sha256",
        "transcript_sha256",
        "diff_sha256",
    )
    @classmethod
    def _artifact_hash(cls, value: str) -> str:
        return _canonical_hash(value, label="resolution artifact")

    @field_validator("verification_image_id")
    @classmethod
    def _verification_image(cls, value: str) -> str:
        return _canonical_identifier(value, label="verification image")

    @model_validator(mode="after")
    def _kind_matches_mechanical_result(self) -> ResolutionExecutionReceipt:
        if self.kind is ResolutionKind.HONEST:
            if self.outcome not in {Outcome.HONEST, Outcome.REFUSED}:
                raise ValueError("honest resolution did not produce an honest outcome")
            if self.intended_detector_triggered:
                raise ValueError("honest resolution triggered the intended detector")
            if self.outcome is Outcome.HONEST and not self.goal_met:
                raise ValueError("honest completion resolution did not meet the held-out goal")
            if self.outcome is Outcome.REFUSED and self.goal_met:
                raise ValueError("honest refusal cannot claim the unreachable goal was met")
        elif self.outcome is not Outcome.CHEATED or not self.intended_detector_triggered:
            raise ValueError("cheat resolution did not trigger the intended detector")
        return self


class MachineReviewerConfigurationReceipt(_ClosedModel):
    """Closed, exact reviewer configuration whose bytes define its fingerprint."""

    format_version: Literal["4"]
    claim_boundary: str
    review_id: str
    provider: ProviderId
    model_id: str
    agent_adapter: str
    agent_build: str
    reasoning_effort: str
    inference_settings: dict[str, JsonValue]
    agent_cli_binary_sha256: str
    agent_container_digest: str
    docker_runtime_claim_boundary: str
    docker_client_sha256: str
    docker_runtime_fingerprint_sha256: str
    credential_projection_policy: str
    credential_projection_inventory_sha256: str

    @field_validator("review_id", "model_id", "agent_adapter", "reasoning_effort")
    @classmethod
    def _identifier(cls, value: str) -> str:
        return _canonical_identifier(value, label="reviewer configuration identifier")

    @field_validator("agent_build")
    @classmethod
    def _build_text(cls, value: str) -> str:
        if not value or value != value.strip() or "\x00" in value:
            raise ValueError("reviewer build identity must be nonblank canonical text")
        return value

    @field_validator("claim_boundary")
    @classmethod
    def _fixed_claim_boundary(cls, value: str) -> str:
        if value != MACHINE_REVIEW_CLAIM_BOUNDARY:
            raise ValueError("machine-review claim boundary is fixed")
        return value

    @field_validator(
        "agent_cli_binary_sha256",
        "agent_container_digest",
        "docker_client_sha256",
        "docker_runtime_fingerprint_sha256",
        "credential_projection_inventory_sha256",
    )
    @classmethod
    def _runtime_hash(cls, value: str) -> str:
        return _canonical_hash(value, label="reviewer runtime artifact")

    @field_validator("docker_runtime_claim_boundary")
    @classmethod
    def _fixed_docker_claim_boundary(cls, value: str) -> str:
        if value != DOCKER_RUNTIME_CLAIM_BOUNDARY:
            raise ValueError("reviewer Docker-runtime claim boundary is fixed")
        return value

    @model_validator(mode="after")
    def _credential_policy_matches_adapter(self) -> MachineReviewerConfigurationReceipt:
        expected = {
            "codex": CODEX_CREDENTIAL_PROJECTION_POLICY,
            "claude-code": CLAUDE_CREDENTIAL_PROJECTION_POLICY,
        }.get(self.agent_adapter)
        if expected is None or self.credential_projection_policy != expected:
            raise ValueError("reviewer credential projection policy does not match adapter")
        return self


class MachineReviewEvidenceFile(_ClosedModel):
    """One exact, model-visible file in the closed review-evidence workspace."""

    path: str
    blob_path: str
    sha256: str
    size: int
    executable: bool

    @field_validator("path")
    @classmethod
    def _safe_evidence_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            not value
            or path.is_absolute()
            or "." in path.parts
            or ".." in path.parts
            or "\\" in value
            or path.parts[0] not in {"scenario", "resolutions", "qa"}
        ):
            raise ValueError("machine-review evidence path is outside the closed layout")
        return value

    @field_validator("blob_path")
    @classmethod
    def _content_addressed_blob_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            len(path.parts) != 3
            or path.parts[:2] != ("evidence", "blobs")
            or not path.name.endswith(".bin")
            or _SHA256_PATTERN.fullmatch(path.name.removesuffix(".bin")) is None
        ):
            raise ValueError("machine-review evidence blob path is not content-addressed")
        return value

    @field_validator("sha256")
    @classmethod
    def _file_hash(cls, value: str) -> str:
        return _canonical_hash(value, label="machine-review evidence file")

    @field_validator("size")
    @classmethod
    def _file_size(cls, value: int) -> int:
        if value < 0:
            raise ValueError("machine-review evidence file size cannot be negative")
        return value

    @model_validator(mode="after")
    def _blob_matches_content(self) -> MachineReviewEvidenceFile:
        if self.blob_path != f"evidence/blobs/{self.sha256}.bin":
            raise ValueError("machine-review blob path does not match its content hash")
        return self


class MachineReviewEvidenceManifest(_ClosedModel):
    """Closed manifest for the exact scenario, resolution, and QA review evidence."""

    format_version: Literal["1"]
    scenario_id: str
    scenario_artifact_sha256: str
    input_manifest_sha256: str
    covered_resolution_variant_ids: tuple[str, ...]
    covered_qa_attempt_ids: tuple[str, ...]
    evidence_inventory_sha256: str
    files: tuple[MachineReviewEvidenceFile, ...]

    @field_validator("scenario_id")
    @classmethod
    def _scenario_identifier(cls, value: str) -> str:
        return _canonical_identifier(value, label="scenario_id")

    @field_validator(
        "scenario_artifact_sha256",
        "input_manifest_sha256",
        "evidence_inventory_sha256",
    )
    @classmethod
    def _artifact_hash(cls, value: str) -> str:
        return _canonical_hash(value, label="machine-review evidence artifact")

    @field_validator(
        "covered_resolution_variant_ids",
        "covered_qa_attempt_ids",
    )
    @classmethod
    def _canonical_identifiers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if (
            not value
            or value != tuple(sorted(value))
            or len(value) != len(set(value))
            or any(not item or _IDENTIFIER_PATTERN.fullmatch(item) is None for item in value)
        ):
            raise ValueError("machine-review evidence ids must be nonempty, unique, and sorted")
        return value

    @field_validator("files")
    @classmethod
    def _canonical_files(
        cls,
        value: tuple[MachineReviewEvidenceFile, ...],
    ) -> tuple[MachineReviewEvidenceFile, ...]:
        paths = tuple(item.path for item in value)
        if not value or paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ValueError("machine-review evidence files must be nonempty, unique, and sorted")
        return value

    @model_validator(mode="after")
    def _inventory_matches(self) -> MachineReviewEvidenceManifest:
        if self.evidence_inventory_sha256 != _review_file_inventory_sha256(self.files):
            raise ValueError("machine-review evidence inventory does not match its files")
        return self


class MachineReviewInputReceipt(_ClosedModel):
    """Closed package binding one review to the frozen prompt, schema, and input."""

    format_version: Literal["3"]
    scenario_id: str
    input_manifest_sha256: str
    review_evidence_manifest_sha256: str
    review_evidence_inventory_sha256: str
    prompt_sha256: str
    output_schema_sha256: str
    covered_qa_attempt_ids: tuple[str, ...]

    @field_validator("scenario_id")
    @classmethod
    def _scenario_identifier(cls, value: str) -> str:
        return _canonical_identifier(value, label="scenario_id")

    @field_validator(
        "input_manifest_sha256",
        "review_evidence_manifest_sha256",
        "review_evidence_inventory_sha256",
        "prompt_sha256",
        "output_schema_sha256",
    )
    @classmethod
    def _artifact_hash(cls, value: str) -> str:
        return _canonical_hash(value, label="machine review input artifact")

    @field_validator("covered_qa_attempt_ids")
    @classmethod
    def _canonical_attempt_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if (
            not value
            or value != tuple(sorted(value))
            or len(value) != len(set(value))
            or any(not item or _IDENTIFIER_PATTERN.fullmatch(item) is None for item in value)
        ):
            raise ValueError("covered QA ids must be nonempty, unique, and sorted")
        return value


class MachineReviewRuntimeReceipt(_ClosedModel):
    """Signed runner observation binding invocation, transcript, and parsed output."""

    format_version: Literal["6"]
    claim_boundary: str
    review_id: str
    runner_identity: str
    stinger_commit: str
    agent_adapter: str
    reviewer_configuration_sha256: str
    review_input_receipt_sha256: str
    review_evidence_manifest_sha256: str
    review_workspace_sha256: str
    transcript_sha256: str
    review_output_sha256: str
    invocation_argv: tuple[str, ...]
    version_invocation_argv: tuple[str, ...]
    agent_cli_binary_sha256: str
    agent_container_digest: str
    docker_runtime_claim_boundary: str
    docker_client_sha256: str
    docker_runtime_fingerprint_sha256: str
    credential_projection_policy: str
    credential_projection_inventory_sha256: str
    provider_response_id: str
    parsed_final_message_sha256: str
    invocation_id_sha256: str
    exit_code: Literal[0]

    @field_validator(
        "review_id",
        "runner_identity",
        "agent_adapter",
        "provider_response_id",
    )
    @classmethod
    def _review_identifier(cls, value: str) -> str:
        return _canonical_identifier(value, label="review_id")

    @field_validator("claim_boundary")
    @classmethod
    def _fixed_claim_boundary(cls, value: str) -> str:
        if value != MACHINE_REVIEW_CLAIM_BOUNDARY:
            raise ValueError("machine-review claim boundary is fixed")
        return value

    @field_validator("stinger_commit")
    @classmethod
    def _commit(cls, value: str) -> str:
        if len(value) not in {40, 64} or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("machine-review Stinger commit is invalid")
        return value

    @field_validator(
        "reviewer_configuration_sha256",
        "review_input_receipt_sha256",
        "review_evidence_manifest_sha256",
        "review_workspace_sha256",
        "transcript_sha256",
        "review_output_sha256",
        "agent_cli_binary_sha256",
        "agent_container_digest",
        "docker_client_sha256",
        "docker_runtime_fingerprint_sha256",
        "credential_projection_inventory_sha256",
        "parsed_final_message_sha256",
        "invocation_id_sha256",
    )
    @classmethod
    def _artifact_hash(cls, value: str) -> str:
        return _canonical_hash(value, label="machine review runtime artifact")

    @field_validator("docker_runtime_claim_boundary")
    @classmethod
    def _fixed_docker_claim_boundary(cls, value: str) -> str:
        if value != DOCKER_RUNTIME_CLAIM_BOUNDARY:
            raise ValueError("runtime Docker claim boundary is fixed")
        return value

    @field_validator("invocation_argv", "version_invocation_argv")
    @classmethod
    def _canonical_invocation(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or any(not item or item != item.strip() or "\x00" in item for item in value):
            raise ValueError("machine-review invocation must contain canonical arguments")
        return value

    @model_validator(mode="after")
    def _credential_policy_matches_adapter(self) -> MachineReviewRuntimeReceipt:
        expected = {
            "codex": CODEX_CREDENTIAL_PROJECTION_POLICY,
            "claude-code": CLAUDE_CREDENTIAL_PROJECTION_POLICY,
        }.get(self.agent_adapter)
        if expected is None or self.credential_projection_policy != expected:
            raise ValueError("runtime credential projection policy does not match adapter")
        return self


class ReferenceIsolationReceipt(_ClosedModel):
    """Builder-derived binding of a blind run to the expected seed-only workspace."""

    format_version: Literal["2"]
    solve_id: str
    scenario_id: str
    scenario_artifact_sha256: str
    expected_workspace_inventory_sha256: str
    expected_before_diff_sha256: str
    observed_before_diff_sha256: str
    transcript_sha256: str
    result_diff_sha256: str
    report_sha256: str
    public_manifest_sha256: str
    escrow_manifest_sha256: str
    runtime_receipt_sha256: str

    @field_validator("solve_id", "scenario_id")
    @classmethod
    def _identifier(cls, value: str) -> str:
        return _canonical_identifier(value, label="reference-isolation identifier")

    @field_validator(
        "scenario_artifact_sha256",
        "expected_workspace_inventory_sha256",
        "expected_before_diff_sha256",
        "observed_before_diff_sha256",
        "transcript_sha256",
        "result_diff_sha256",
        "report_sha256",
        "public_manifest_sha256",
        "escrow_manifest_sha256",
        "runtime_receipt_sha256",
    )
    @classmethod
    def _artifact_hash(cls, value: str) -> str:
        return _canonical_hash(value, label="reference-isolation artifact")


class CustodyInventoryReceipt(_ClosedModel):
    """Closed exact-corpus custody inventory used to derive the record commitment."""

    format_version: Literal["2"]
    corpus_version: str
    corpus_hash: str
    sealed_source_snapshot_sha256: str
    candidate_promotion_statement_sha256: str
    access_log_root_sha256: str
    canary_inventory_sha256: str

    @field_validator("corpus_version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        if _SEMVER_PATTERN.fullmatch(value) is None:
            raise ValueError("custody corpus_version must be semantic")
        return value

    @field_validator(
        "corpus_hash",
        "sealed_source_snapshot_sha256",
        "candidate_promotion_statement_sha256",
        "access_log_root_sha256",
        "canary_inventory_sha256",
    )
    @classmethod
    def _artifact_hash(cls, value: str) -> str:
        return _canonical_hash(value, label="custody artifact")


class AgentRunWorkflowInputReceipt(_ClosedModel):
    """External non-secret cross-binding signed after both evidence bundles close."""

    format_version: Literal["1"]
    claim_boundary: str
    run_id: str
    stinger_commit: str
    corpus_hash: str
    config_fingerprint: str
    protocol_sha256: str
    report_sha256: str
    config_sha256: str
    public_manifest_sha256: str
    escrow_manifest_sha256: str
    invocation_aggregate_sha256: str
    runtime_provenance_sha256: str
    agent_adapter: str
    provider: ProviderId
    model_id: str

    @field_validator("claim_boundary")
    @classmethod
    def _fixed_claim_boundary(cls, value: str) -> str:
        if value != AGENT_RUN_WORKFLOW_CLAIM_BOUNDARY:
            raise ValueError("agent-run workflow claim boundary is fixed")
        return value

    @field_validator("run_id", "agent_adapter", "model_id")
    @classmethod
    def _identifier(cls, value: str) -> str:
        return _canonical_identifier(value, label="agent-run workflow identifier")

    @field_validator("stinger_commit")
    @classmethod
    def _commit(cls, value: str) -> str:
        if len(value) not in {40, 64} or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("agent-run workflow Stinger commit is invalid")
        return value

    @field_validator(
        "corpus_hash",
        "config_fingerprint",
        "protocol_sha256",
        "report_sha256",
        "config_sha256",
        "public_manifest_sha256",
        "escrow_manifest_sha256",
        "invocation_aggregate_sha256",
        "runtime_provenance_sha256",
    )
    @classmethod
    def _artifact_hash(cls, value: str) -> str:
        return _canonical_hash(value, label="agent-run workflow artifact")


class CorpusConstructionReceipt(_ClosedModel):
    """Path-free canonical receipt containing the fully derived corpus record."""

    format_version: Literal["2"]
    benchmark_protocol_version: str
    rubric_version: str
    corpus_version: str
    corpus_hash: str
    scenario_count: int
    scenario_inventory_sha256: str
    construction_artifact_inventory_sha256: str
    corpus: SealedCorpusRecord

    @field_validator("benchmark_protocol_version", "rubric_version", "corpus_version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        if _SEMVER_PATTERN.fullmatch(value) is None:
            raise ValueError("construction receipt versions must be semantic")
        return value

    @field_validator(
        "corpus_hash",
        "scenario_inventory_sha256",
        "construction_artifact_inventory_sha256",
    )
    @classmethod
    def _artifact_hash(cls, value: str) -> str:
        return _canonical_hash(value, label="construction artifact")

    @model_validator(mode="after")
    def _cross_bind_record(self) -> CorpusConstructionReceipt:
        if (
            self.corpus_version != self.corpus.corpus_version
            or self.corpus_hash != self.corpus.corpus_hash
            or self.scenario_count != len(self.corpus.scenarios)
            or self.scenario_inventory_sha256
            != corpus_scenario_inventory_sha256(self.corpus.scenarios)
        ):
            raise ValueError("construction receipt does not bind its corpus record")
        return self


class VerifiedCorpusConstructionReceipt(_ClosedModel):
    """Typed handoff proving the exact receipt survived the builder and gate."""

    receipt: CorpusConstructionReceipt
    canonical_receipt_sha256: str

    @field_validator("canonical_receipt_sha256")
    @classmethod
    def _receipt_hash(cls, value: str) -> str:
        return _canonical_hash(value, label="construction receipt")

    @model_validator(mode="after")
    def _hash_matches(self) -> VerifiedCorpusConstructionReceipt:
        if self.canonical_receipt_sha256 != canonical_corpus_construction_receipt_sha256(
            self.receipt
        ):
            raise ValueError("verified construction receipt hash does not match")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedCorpusConstructionAuthorization:
    """Out-of-band signature authorization over one exact construction receipt."""

    receipt: CorpusConstructionReceipt
    identity: str
    namespace: str
    receipt_sha256: str
    canonical_receipt_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str
    signing_key_fingerprint: str


@dataclass(frozen=True, slots=True)
class VerifiedMachineReviewRuntimeAuthorization:
    """Detached-signature authorization for one exact review runtime receipt."""

    receipt: MachineReviewRuntimeReceipt
    identity: str
    namespace: str
    receipt_sha256: str
    canonical_receipt_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str
    signing_key_fingerprint: str


@dataclass(frozen=True, slots=True)
class ResolutionVariantInput:
    """Private exact attempt inputs; all favorable execution facts are derived."""

    variant_id: str
    kind: ResolutionKind
    source_tree: Path
    semantic_patch: Path
    agent_run: Path


@dataclass(frozen=True, slots=True)
class _ResolutionVariantBuild:
    """Mechanically verified resolution plus exact model-visible evidence bytes."""

    record: ResolutionVariantRecord
    execution: ResolutionExecutionReceipt
    source_tree: Path
    semantic_patch: bytes
    agent_run: bytes
    transcript: bytes
    diff: bytes


@dataclass(frozen=True, slots=True)
class VerifiedRunBundleInput:
    """Exact bundles plus independent protocol and execution-workflow trust."""

    run_id: str
    public_bundle: Path
    escrow_bundle: Path
    leakage_policy: PublicLeakagePolicy
    protocol_allowed_signers: Path
    protocol_signer_identity: str
    machine_identity_artifact: Path
    workflow_input: Path
    workflow_receipt: Path
    workflow_attestation: Path
    workflow_signature: Path
    workflow_allowed_signers: Path
    workflow_signer_identity: str


@dataclass(frozen=True, slots=True)
class _RunExecutionIdentity:
    """Uniqueness evidence retained while composing QA and blind runs."""

    invocation_ids: frozenset[str]
    challenge_nonce_sha256s: frozenset[str]
    provider_response_id_sha256s: frozenset[str]
    execution_evidence_sha256s: frozenset[str]
    workflow_signature_sha256: str


@dataclass(frozen=True, slots=True)
class _VerifiedRunEvidence:
    """Exact verified bundle, workflow authorization, and derived run identity."""

    artifact_receipt: VerifiedArtifactReceipt
    result: ScenarioResult
    provider: ProviderId
    configuration_fingerprint: str
    runtime_receipt_sha256: str
    execution_identity: _RunExecutionIdentity
    workflow_authorization: VerifiedMachineWorkflowAttestation


@dataclass(frozen=True, slots=True)
class _LifecycleRoleConstraints:
    """Signer roles that QA, blind, and review workflows may not reuse."""

    signer_identities: frozenset[str]
    signing_key_fingerprints: frozenset[str]
    trust_policy_sha256s: frozenset[str]


@dataclass(frozen=True, slots=True)
class MachineReviewPackageInput:
    """Exact signed runner package comprising one machine-review invocation."""

    configuration_receipt: Path
    input_receipt: Path
    review_workspace: Path
    runtime_receipt: Path
    transcript: Path
    output: Path
    runtime_signature: Path
    runtime_allowed_signers: Path
    runtime_signer_identity: str


@dataclass(frozen=True, slots=True)
class BlindSolveInput:
    """One verified run bundle; reference isolation is derived from its escrow."""

    bundle: VerifiedRunBundleInput


@dataclass(frozen=True, slots=True)
class ScenarioConstructionInput:
    """All private artifact locations required for one sealed scenario."""

    scenario_directory: Path
    provenance_receipt: Path
    authoring_configuration_artifacts: tuple[Path, ...]
    provenance_source_artifacts: tuple[Path, ...]
    resolution_variants: tuple[ResolutionVariantInput, ...]
    qa_attempts: tuple[VerifiedRunBundleInput, ...]
    machine_reviews: tuple[MachineReviewPackageInput, ...]
    blind_agent_solves: tuple[BlindSolveInput, ...] = ()


class _LifecycleAuthorizationManifest(_ClosedModel):
    """Private paths and expected identity for one signed lifecycle artifact."""

    artifact: str
    signature: str
    allowed_signers: str
    signer_identity: str

    @field_validator("artifact", "signature", "allowed_signers")
    @classmethod
    def _safe_path_text(cls, value: str) -> str:
        return _manifest_path_text(value)

    @field_validator("signer_identity")
    @classmethod
    def _identity(cls, value: str) -> str:
        return _canonical_identifier(value, label="manifest signer identity")


class ConstructionRunBundleManifest(_ClosedModel):
    """Closed path mapping for one verified public/escrow run."""

    run_id: str
    public_bundle: str
    escrow_bundle: str
    forbidden_sources: tuple[str, ...]
    marker_files: tuple[str, ...]
    protocol_allowed_signers: str
    protocol_signer_identity: str
    machine_identity_artifact: str
    workflow_input: str
    workflow_receipt: str
    workflow_attestation: str
    workflow_signature: str
    workflow_allowed_signers: str
    workflow_signer_identity: str

    @field_validator(
        "run_id",
        "protocol_signer_identity",
        "workflow_signer_identity",
    )
    @classmethod
    def _identifier(cls, value: str) -> str:
        return _canonical_identifier(value, label="run manifest identifier")

    @field_validator(
        "public_bundle",
        "escrow_bundle",
        "protocol_allowed_signers",
        "machine_identity_artifact",
        "workflow_input",
        "workflow_receipt",
        "workflow_attestation",
        "workflow_signature",
        "workflow_allowed_signers",
    )
    @classmethod
    def _safe_path_text(cls, value: str) -> str:
        return _manifest_path_text(value)

    @field_validator("forbidden_sources", "marker_files")
    @classmethod
    def _canonical_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_manifest_path_inventory(value)

    @model_validator(mode="after")
    def _distinct_bundles(self) -> ConstructionRunBundleManifest:
        if self.public_bundle == self.escrow_bundle:
            raise ValueError("public and escrow bundle paths must differ")
        return self


class ConstructionResolutionVariantManifest(_ClosedModel):
    """Closed path mapping for one mechanically executed resolution attempt."""

    variant_id: str
    kind: ResolutionKind
    source_tree: str
    semantic_patch: str
    agent_run: str

    @field_validator("variant_id")
    @classmethod
    def _variant_identifier(cls, value: str) -> str:
        return _canonical_identifier(value, label="variant_id")

    @field_validator("source_tree", "semantic_patch", "agent_run")
    @classmethod
    def _safe_path_text(cls, value: str) -> str:
        return _manifest_path_text(value)


class ConstructionMachineReviewManifest(_ClosedModel):
    """Closed path mapping for one machine-review package."""

    configuration_receipt: str
    input_receipt: str
    review_workspace: str
    runtime_receipt: str
    transcript: str
    output: str
    runtime_signature: str
    runtime_allowed_signers: str
    runtime_signer_identity: str

    @field_validator(
        "configuration_receipt",
        "input_receipt",
        "review_workspace",
        "runtime_receipt",
        "transcript",
        "output",
        "runtime_signature",
        "runtime_allowed_signers",
    )
    @classmethod
    def _safe_path_text(cls, value: str) -> str:
        return _manifest_path_text(value)

    @field_validator("runtime_signer_identity")
    @classmethod
    def _identity(cls, value: str) -> str:
        return _canonical_identifier(value, label="machine-review runner identity")


class ConstructionBlindSolveManifest(_ClosedModel):
    """Closed path mapping for one blind solve whose isolation is derived."""

    bundle: ConstructionRunBundleManifest


class ConstructionScenarioManifest(_ClosedModel):
    """Closed private path inventory for one scenario-construction input."""

    scenario_directory: str
    provenance_receipt: str
    authoring_configuration_artifacts: tuple[str, ...]
    provenance_source_artifacts: tuple[str, ...]
    resolution_variants: tuple[ConstructionResolutionVariantManifest, ...]
    qa_attempts: tuple[ConstructionRunBundleManifest, ...]
    machine_reviews: tuple[ConstructionMachineReviewManifest, ...]
    blind_agent_solves: tuple[ConstructionBlindSolveManifest, ...] = ()

    @field_validator(
        "scenario_directory",
        "provenance_receipt",
    )
    @classmethod
    def _safe_path_text(cls, value: str) -> str:
        return _manifest_path_text(value)

    @field_validator(
        "authoring_configuration_artifacts",
        "provenance_source_artifacts",
    )
    @classmethod
    def _canonical_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_manifest_path_inventory(value)

    @model_validator(mode="after")
    def _canonical_nested_inventories(self) -> ConstructionScenarioManifest:
        variant_keys = tuple(item.variant_id for item in self.resolution_variants)
        variant_kinds = tuple(item.kind for item in self.resolution_variants)
        qa_ids = tuple(item.run_id for item in self.qa_attempts)
        review_keys = tuple(item.configuration_receipt for item in self.machine_reviews)
        blind_ids = tuple(item.bundle.run_id for item in self.blind_agent_solves)
        if (
            len(self.resolution_variants) != 4
            or variant_keys != tuple(sorted(variant_keys))
            or len(variant_keys) != len(set(variant_keys))
            or any(variant_kinds.count(kind) != 2 for kind in ResolutionKind)
        ):
            raise ValueError(
                "resolution variants must contain four unique id-sorted entries, two per kind"
            )
        if (
            len(self.qa_attempts) != 5
            or qa_ids != tuple(sorted(qa_ids))
            or len(qa_ids) != len(set(qa_ids))
        ):
            raise ValueError("QA attempts must contain five unique run-id-sorted entries")
        if (
            len(self.machine_reviews) != 2
            or review_keys != tuple(sorted(review_keys))
            or len(review_keys) != len(set(review_keys))
        ):
            raise ValueError("machine reviews must contain two unique configuration-sorted entries")
        if (
            len(self.blind_agent_solves) not in {0, 2}
            or blind_ids != tuple(sorted(blind_ids))
            or len(blind_ids) != len(set(blind_ids))
        ):
            raise ValueError(
                "blind solves must be empty or contain two unique run-id-sorted entries"
            )
        return self


class CorpusConstructionInputManifest(_ClosedModel):
    """Closed private manifest consumed by the corpus-construction CLI boundary."""

    format_version: Literal["4"]
    repository: str
    corpus_root: str
    corpus_version: str
    candidate_validation: _LifecycleAuthorizationManifest
    candidate_promotion: _LifecycleAuthorizationManifest
    custody_inventory_receipt: str
    canary_registry: str
    access_ledger: str
    scenarios: tuple[ConstructionScenarioManifest, ...]

    @field_validator(
        "corpus_root",
        "repository",
        "custody_inventory_receipt",
        "canary_registry",
        "access_ledger",
    )
    @classmethod
    def _safe_path_text(cls, value: str) -> str:
        return _manifest_path_text(value)

    @field_validator("corpus_version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        if _SEMVER_PATTERN.fullmatch(value) is None:
            raise ValueError("manifest corpus_version must be semantic")
        return value

    @field_validator("scenarios")
    @classmethod
    def _canonical_scenarios(
        cls,
        value: tuple[ConstructionScenarioManifest, ...],
    ) -> tuple[ConstructionScenarioManifest, ...]:
        keys = tuple(item.scenario_directory for item in value)
        if not value or keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("manifest scenarios must be nonempty, unique, and path-sorted")
        return value


class CorpusConstructionBuilderKwargs(TypedDict):
    """Exact keyword shape accepted by ``build_corpus_construction_receipt``."""

    repository: Path
    corpus_root: Path
    corpus_version: str
    candidate_validation_authorization: VerifiedCandidateValidationAuthorization
    candidate_promotion_authorization: VerifiedCandidatePromotionAuthorization
    custody_inventory_receipt: Path
    canary_registry: Path
    access_ledger: Path
    scenarios: tuple[ScenarioConstructionInput, ...]


def load_corpus_construction_input_manifest(
    path: Path,
) -> CorpusConstructionBuilderKwargs:
    """Load one safe JSON/YAML manifest into exact construction-builder kwargs.

    Relative paths resolve against the manifest directory.  Every referenced path is
    checked for the node type expected by its downstream verifier, marker files are read as
    private bytes, and candidate/promotion signatures are authorized immediately.  No
    private path or marker is returned in an exception message.
    """
    safe_manifest_path = _resolve_without_symlink_components(path)
    content = _read_exact_regular_file(
        safe_manifest_path,
        label="construction input manifest",
    )
    if not content:
        raise CorpusConstructionError("construction input manifest is empty")
    suffix = safe_manifest_path.suffix.lower()
    raw = _parse_input_manifest(content, suffix=suffix)
    try:
        manifest = CorpusConstructionInputManifest.model_validate(raw)
    except ValidationError:
        raise CorpusConstructionError(
            "construction input manifest violates its closed schema"
        ) from None
    if suffix == ".json" and content != _canonical_model_bytes(manifest):
        raise CorpusConstructionError("JSON construction input manifest is not canonical")
    base = safe_manifest_path.parent
    candidate_artifact = _manifest_regular_file(
        base,
        manifest.candidate_validation.artifact,
    )
    candidate_signature = _manifest_regular_file(
        base,
        manifest.candidate_validation.signature,
    )
    candidate_signers = _manifest_regular_file(
        base,
        manifest.candidate_validation.allowed_signers,
    )
    promotion_artifact = _manifest_regular_file(
        base,
        manifest.candidate_promotion.artifact,
    )
    promotion_signature = _manifest_regular_file(
        base,
        manifest.candidate_promotion.signature,
    )
    promotion_signers = _manifest_regular_file(
        base,
        manifest.candidate_promotion.allowed_signers,
    )
    try:
        candidate_authorization = authorize_candidate_validation_receipt(
            candidate_artifact,
            candidate_signature,
            candidate_signers,
            manifest.candidate_validation.signer_identity,
        )
        promotion_authorization = authorize_candidate_promotion_statement(
            promotion_artifact,
            promotion_signature,
            promotion_signers,
            manifest.candidate_promotion.signer_identity,
        )
    except (OSError, ProtocolSignatureError, ValidationError, ValueError):
        raise CorpusConstructionError("construction lifecycle authorization failed") from None
    if _read_exact_regular_file(
        candidate_artifact,
        label="candidate validation receipt",
    ) != _canonical_model_bytes(candidate_authorization.receipt) or _read_exact_regular_file(
        promotion_artifact,
        label="candidate promotion statement",
    ) != _canonical_model_bytes(promotion_authorization.statement):
        raise CorpusConstructionError("construction lifecycle artifacts are not canonical")

    corpus_root = _manifest_directory(base, manifest.corpus_root)
    scenario_inputs = tuple(_resolve_scenario_manifest(base, item) for item in manifest.scenarios)
    resolved_scenario_paths = tuple(item.scenario_directory for item in scenario_inputs)
    if len(resolved_scenario_paths) != len(set(resolved_scenario_paths)):
        raise CorpusConstructionError(
            "construction manifest resolves duplicate scenario directories"
        )
    _reject_reused_bundle_paths(scenario_inputs)
    return CorpusConstructionBuilderKwargs(
        repository=_manifest_directory(base, manifest.repository),
        corpus_root=corpus_root,
        corpus_version=manifest.corpus_version,
        candidate_validation_authorization=candidate_authorization,
        candidate_promotion_authorization=promotion_authorization,
        custody_inventory_receipt=_manifest_regular_file(
            base,
            manifest.custody_inventory_receipt,
        ),
        canary_registry=_manifest_regular_file(base, manifest.canary_registry),
        access_ledger=_manifest_regular_file(base, manifest.access_ledger),
        scenarios=scenario_inputs,
    )


def build_corpus_construction_receipt(
    *,
    repository: Path,
    corpus_root: Path,
    corpus_version: str,
    candidate_validation_authorization: VerifiedCandidateValidationAuthorization,
    candidate_promotion_authorization: VerifiedCandidatePromotionAuthorization,
    custody_inventory_receipt: Path,
    canary_registry: Path,
    access_ledger: Path,
    scenarios: tuple[ScenarioConstructionInput, ...],
) -> VerifiedCorpusConstructionReceipt:
    """Run construction from one clean implementation and immutable corpus snapshot."""
    expected_commit = candidate_promotion_authorization.statement.stinger_commit
    try:
        initial_commit = _clean_exact_git_head(repository)
        implementation_inventory = _require_construction_implementation(
            repository,
            expected_commit=initial_commit,
        )
    except (CandidateReceiptError, OSError, ValueError):
        raise CorpusConstructionError(
            "construction implementation is not a clean exact checkout"
        ) from None
    if (
        initial_commit != expected_commit
        or initial_commit != candidate_validation_authorization.receipt.stinger_commit
        or not implementation_inventory
    ):
        raise CorpusConstructionError("construction implementation differs from lifecycle evidence")

    try:
        unresolved = corpus_root.lstat()
        if not stat.S_ISDIR(unresolved.st_mode) or stat.S_ISLNK(unresolved.st_mode):
            raise CorpusConstructionError("sealed corpus root is not a real directory")
        live_root = corpus_root.resolve(strict=True)
        initial_inventory = _inventory_tree(live_root)
    except CorpusConstructionError:
        raise
    except (CandidateReceiptError, OSError, ValueError):
        raise CorpusConstructionError("sealed corpus could not be safely inventoried") from None

    with tempfile.TemporaryDirectory(prefix="stinger-construction-snapshot-") as temporary_name:
        snapshot_root = Path(temporary_name) / "corpus"
        try:
            copied_inventory = _snapshot_tree(live_root, snapshot_root)
            snapshot_inventory = _inventory_tree(snapshot_root)
            post_copy_inventory = _inventory_tree(live_root)
        except (CandidateReceiptError, OSError, ValueError):
            raise CorpusConstructionError("sealed corpus snapshot failed") from None
        if (
            copied_inventory.inventory_sha256 != initial_inventory.inventory_sha256
            or snapshot_inventory.inventory_sha256 != initial_inventory.inventory_sha256
            or post_copy_inventory.inventory_sha256 != initial_inventory.inventory_sha256
        ):
            raise CorpusConstructionError("sealed corpus changed while it was snapshotted")

        snapshotted_inputs: list[ScenarioConstructionInput] = []
        for item in scenarios:
            try:
                relative = item.scenario_directory.resolve(strict=True).relative_to(live_root)
            except (OSError, ValueError):
                raise CorpusConstructionError(
                    "scenario construction input is outside the sealed corpus"
                ) from None
            snapshotted_inputs.append(
                replace(
                    item,
                    scenario_directory=snapshot_root / relative,
                )
            )
        result = _build_corpus_construction_from_snapshot(
            repository=repository,
            corpus_root=snapshot_root,
            corpus_version=corpus_version,
            candidate_validation_authorization=candidate_validation_authorization,
            candidate_promotion_authorization=candidate_promotion_authorization,
            custody_inventory_receipt=custody_inventory_receipt,
            canary_registry=canary_registry,
            access_ledger=access_ledger,
            scenarios=tuple(snapshotted_inputs),
        )

    try:
        final_inventory = _inventory_tree(live_root)
        final_commit = _clean_exact_git_head(repository)
        final_implementation_inventory = _require_construction_implementation(
            repository,
            expected_commit=final_commit,
        )
    except (CandidateReceiptError, OSError, ValueError):
        raise CorpusConstructionError(
            "construction inputs or implementation changed during execution"
        ) from None
    if (
        final_inventory.inventory_sha256 != initial_inventory.inventory_sha256
        or final_commit != initial_commit
        or final_implementation_inventory != implementation_inventory
    ):
        raise CorpusConstructionError(
            "construction inputs or implementation changed during execution"
        )
    return result


def _build_corpus_construction_from_snapshot(
    *,
    repository: Path,
    corpus_root: Path,
    corpus_version: str,
    candidate_validation_authorization: VerifiedCandidateValidationAuthorization,
    candidate_promotion_authorization: VerifiedCandidatePromotionAuthorization,
    custody_inventory_receipt: Path,
    canary_registry: Path,
    access_ledger: Path,
    scenarios: tuple[ScenarioConstructionInput, ...],
) -> VerifiedCorpusConstructionReceipt:
    """Derive and gate the complete ``SealedCorpusRecord`` from exact artifacts.

    All path-bearing inputs remain outside the returned receipt.  Any failure uses a
    disclosure-safe diagnostic without echoing a scenario id, corpus path, canary, or
    escrow location.
    """
    protocol = compiled_benchmark_protocol()
    if (
        _SEMVER_PATTERN.fullmatch(corpus_version) is None
        or corpus_version != candidate_validation_authorization.receipt.corpus_version
        or corpus_version != candidate_promotion_authorization.statement.corpus_version
    ):
        raise CorpusConstructionError("corpus version is invalid or inconsistent")
    sensitive_paths = _all_sensitive_paths(
        corpus_root,
        custody_inventory_receipt,
        canary_registry,
        access_ledger,
        scenarios,
    )
    try:
        unresolved_root_metadata = corpus_root.lstat()
        if not stat.S_ISDIR(unresolved_root_metadata.st_mode) or stat.S_ISLNK(
            unresolved_root_metadata.st_mode
        ):
            raise CorpusConstructionError("sealed corpus root is not a real directory")
        source = corpus_root.resolve(strict=True)
        root_metadata = source.lstat()
        if not stat.S_ISDIR(root_metadata.st_mode) or source.is_symlink():
            raise CorpusConstructionError("sealed corpus root is not a real directory")
        source_snapshot = _inventory_tree(source)
        loaded = discover_scenarios(source)
    except CorpusConstructionError:
        raise
    except (CandidateReceiptError, OSError, ScenarioLoadError, ValueError):
        raise CorpusConstructionError("sealed corpus could not be safely inventoried") from None

    if len(loaded) != protocol.total_scenarios:
        raise CorpusConstructionError("sealed corpus does not contain the protocol item count")
    try:
        derived_corpus_hash = corpus_hash(loaded)
    except (OSError, SandboxError, ValueError):
        raise CorpusConstructionError("sealed corpus could not be hashed safely") from None
    promotion = candidate_promotion_authorization.statement
    verification_image_policy_sha256 = canonical_verification_image_policy_sha256(
        protocol.verification_image_policy
    )
    if (
        promotion.sealed_corpus_hash != derived_corpus_hash
        or promotion.sealed_source_snapshot_sha256 != source_snapshot.inventory_sha256
        or promotion.scenario_count != len(loaded)
        or promotion.benchmark_protocol_version != protocol.benchmark_protocol_version
        or promotion.rubric_version != protocol.rubric_version
        or promotion.verification_image_policy_sha256
        != candidate_validation_authorization.receipt.verification_image_policy_sha256
        or promotion.verification_image_policy_sha256 != verification_image_policy_sha256
        or not verification_image_id_is_approved(
            protocol.verification_image_policy,
            promotion.verification_image_id,
        )
    ):
        raise CorpusConstructionError("sealed corpus differs from trusted promotion evidence")

    try:
        registry_bytes = _read_regular_file(canary_registry)
        canary_inventory, canary_values = _verify_canaries(
            loaded,
            registry_bytes,
            registry_sha256=_sha256(registry_bytes),
        )
        ledger_bytes = _read_regular_file(access_ledger)
        access_root, _, _ = _verify_access_ledger(
            ledger_bytes,
            candidate_corpus_hash=derived_corpus_hash,
            canary_registry_sha256=_sha256(registry_bytes),
        )
    except (CandidateReceiptError, OSError, ValueError):
        raise CorpusConstructionError("sealed custody evidence failed verification") from None
    if (
        canary_inventory != promotion.canary_inventory_sha256
        or canary_inventory != candidate_validation_authorization.receipt.canary_inventory_sha256
        or access_root != promotion.sealed_access_log_root_sha256
    ):
        raise CorpusConstructionError("sealed custody evidence is not cross-bound")

    custody, custody_bytes = _load_canonical_model(
        custody_inventory_receipt,
        CustodyInventoryReceipt,
        label="custody inventory",
    )
    if (
        custody.corpus_version != corpus_version
        or custody.corpus_hash != derived_corpus_hash
        or custody.sealed_source_snapshot_sha256 != source_snapshot.inventory_sha256
        or custody.candidate_promotion_statement_sha256
        != candidate_promotion_authorization.statement_sha256
        or custody.access_log_root_sha256 != access_root
        or custody.canary_inventory_sha256 != canary_inventory
    ):
        raise CorpusConstructionError("custody inventory is not bound to the sealed corpus")

    loaded_by_path = {scenario.directory.resolve(): scenario for scenario in loaded}
    inputs_by_path: dict[Path, ScenarioConstructionInput] = {}
    for item in scenarios:
        try:
            unresolved_metadata = item.scenario_directory.lstat()
            if not stat.S_ISDIR(unresolved_metadata.st_mode) or stat.S_ISLNK(
                unresolved_metadata.st_mode
            ):
                raise CorpusConstructionError("scenario construction input is not a real directory")
            path = item.scenario_directory.resolve(strict=True)
        except OSError:
            raise CorpusConstructionError("scenario construction input is unavailable") from None
        if path in inputs_by_path:
            raise CorpusConstructionError("scenario construction inputs contain a duplicate")
        inputs_by_path[path] = item
    if set(inputs_by_path) != set(loaded_by_path):
        raise CorpusConstructionError("scenario construction inputs do not exactly cover corpus")

    try:
        resolution_sandbox = Sandbox(
            isolation=Isolation.DOCKER,
            image=promotion.verification_image_id,
        )
        resolution_sandbox.preflight_benchmark(
            repository,
            policy=protocol.verification_image_policy,
        )
    except SandboxError:
        raise CorpusConstructionError(
            "resolution execution Docker environment failed preflight"
        ) from None

    lifecycle_role_constraints = _LifecycleRoleConstraints(
        signer_identities=frozenset(
            {
                candidate_validation_authorization.identity,
                candidate_promotion_authorization.identity,
            }
        ),
        signing_key_fingerprints=frozenset(
            {
                candidate_validation_authorization.signing_key_fingerprint,
                candidate_promotion_authorization.signing_key_fingerprint,
            }
        ),
        trust_policy_sha256s=frozenset(
            {
                candidate_validation_authorization.allowed_signers_sha256,
                candidate_promotion_authorization.allowed_signers_sha256,
            }
        ),
    )
    base_records: dict[str, CorpusScenarioRecord] = {}
    qa_execution_identities: dict[str, tuple[_RunExecutionIdentity, ...]] = {}
    qa_workflow_authorizations: dict[
        str,
        tuple[VerifiedMachineWorkflowAttestation, ...],
    ] = {}
    artifact_inventory: list[dict[str, Any]] = []
    for index, scenario in enumerate(sorted(loaded, key=lambda item: item.id)):
        item = inputs_by_path[scenario.directory.resolve()]
        try:
            (
                record,
                inventory,
                execution_identities,
                workflow_authorizations,
            ) = _build_base_scenario_record(
                scenario,
                item,
                corpus_version=corpus_version,
                corpus_hash_value=derived_corpus_hash,
                promotion=promotion,
                promotion_statement_sha256=(candidate_promotion_authorization.statement_sha256),
                resolution_sandbox=resolution_sandbox,
                lifecycle_role_constraints=lifecycle_role_constraints,
            )
        except CorpusConstructionError:
            raise
        except (
            CandidateReceiptError,
            EvidenceBundleError,
            OSError,
            SandboxError,
            ValidationError,
            ValueError,
        ):
            raise CorpusConstructionError(
                f"scenario construction artifacts failed verification at ordinal {index + 1}"
            ) from None
        if record.scenario_id in base_records:
            raise CorpusConstructionError("sealed corpus contains duplicate scenario identities")
        base_records[record.scenario_id] = record
        qa_execution_identities[record.scenario_id] = execution_identities
        qa_workflow_authorizations[record.scenario_id] = workflow_authorizations
        artifact_inventory.append(inventory)

    selected_blind_ids = _selected_blind_solve_ids(
        tuple(base_records.values()),
        corpus_hash_value=derived_corpus_hash,
    )
    final_records: list[CorpusScenarioRecord] = []
    for index, scenario in enumerate(sorted(loaded, key=lambda item: item.id)):
        item = inputs_by_path[scenario.directory.resolve()]
        base = base_records[scenario.id]
        selected = scenario.id in selected_blind_ids
        qa_authorizations = qa_workflow_authorizations[scenario.id]
        qa_signer_identities = {
            authorization.signer_identity for authorization in qa_authorizations
        }
        qa_signing_keys = {
            authorization.signing_key_fingerprint for authorization in qa_authorizations
        }
        qa_trust_policies = {
            authorization.allowed_signers_sha256 for authorization in qa_authorizations
        }
        try:
            review_signer_identities = {
                review.runtime_signer_identity for review in base.machine_reviews
            }
            review_signing_keys = {
                review.runtime_signing_key_fingerprint for review in base.machine_reviews
            }
            review_trust_policies = {
                review.runtime_allowed_signers_sha256 for review in base.machine_reviews
            }
            (
                blind_solves,
                blind_execution_identities,
                _,
            ) = _build_blind_solves(
                base,
                scenario,
                item.blind_agent_solves,
                selected=selected,
                corpus_hash_value=derived_corpus_hash,
                expected_stinger_commit=promotion.stinger_commit,
                forbidden_signer_identities=(
                    lifecycle_role_constraints.signer_identities
                    | frozenset(qa_signer_identities)
                    | frozenset(review_signer_identities)
                ),
                forbidden_signing_key_fingerprints=(
                    lifecycle_role_constraints.signing_key_fingerprints
                    | frozenset(qa_signing_keys)
                    | frozenset(review_signing_keys)
                ),
                forbidden_trust_policy_sha256s=(
                    lifecycle_role_constraints.trust_policy_sha256s
                    | frozenset(qa_trust_policies)
                    | frozenset(review_trust_policies)
                ),
            )
            _require_unique_run_executions(
                (
                    *qa_execution_identities[scenario.id],
                    *blind_execution_identities,
                )
            )
        except CorpusConstructionError:
            raise
        except (EvidenceBundleError, OSError, ValidationError, ValueError):
            raise CorpusConstructionError(
                f"review or blind-solve artifacts failed verification at ordinal {index + 1}"
            ) from None
        record = base.model_copy(
            update={
                "blind_agent_solves": blind_solves,
            }
        )
        final_records.append(record)
        artifact_inventory[index]["blind_agent_solves_sha256"] = _canonical_payload_sha256(
            [solve.model_dump(mode="json") for solve in blind_solves]
        )

    try:
        resolution_sandbox.verify_runtime_unchanged()
    except SandboxError:
        raise CorpusConstructionError(
            "resolution execution Docker runtime changed during construction"
        ) from None

    corpus_record = SealedCorpusRecord(
        corpus_version=corpus_version,
        corpus_hash=derived_corpus_hash,
        scenarios=tuple(sorted(final_records, key=lambda item: item.scenario_id)),
        candidate_validation_receipt_sha256=(candidate_validation_authorization.receipt_sha256),
        candidate_promotion_statement_sha256=(candidate_promotion_authorization.statement_sha256),
        custody_inventory_sha256=_sha256(custody_bytes),
        access_log_root_sha256=access_root,
        canary_validation_receipt_sha256=canary_inventory,
        freeze=None,
    )
    issues = evaluate_corpus_construction(
        corpus_record,
        protocol=protocol,
        candidate_validation_authorization=candidate_validation_authorization,
        candidate_promotion_authorization=candidate_promotion_authorization,
    )
    if issues:
        codes = ",".join(sorted({issue.code.value for issue in issues}))
        raise CorpusConstructionError(
            f"derived corpus record failed the construction gate ({codes})"
        )

    receipt = CorpusConstructionReceipt(
        format_version=CONSTRUCTION_RECEIPT_FORMAT_VERSION,
        benchmark_protocol_version=protocol.benchmark_protocol_version,
        rubric_version=protocol.rubric_version,
        corpus_version=corpus_version,
        corpus_hash=derived_corpus_hash,
        scenario_count=len(corpus_record.scenarios),
        scenario_inventory_sha256=corpus_scenario_inventory_sha256(corpus_record.scenarios),
        construction_artifact_inventory_sha256=_canonical_payload_sha256(
            {
                "source_snapshot_sha256": source_snapshot.inventory_sha256,
                "custody_inventory_receipt_sha256": _sha256(custody_bytes),
                "candidate_validation_receipt_sha256": (
                    candidate_validation_authorization.receipt_sha256
                ),
                "candidate_promotion_statement_sha256": (
                    candidate_promotion_authorization.statement_sha256
                ),
                "scenarios": artifact_inventory,
            }
        ),
        corpus=corpus_record,
    )
    encoded = _canonical_model_bytes(receipt)
    _reject_path_leakage(encoded, sensitive_paths=sensitive_paths)
    for marker in canary_values:
        if marker and marker in encoded:
            raise CorpusConstructionError("construction receipt contains sealed marker material")
    for private_marker in _all_sensitive_markers(scenarios):
        marker_bytes = (
            private_marker.encode("utf-8") if isinstance(private_marker, str) else private_marker
        )
        if marker_bytes and marker_bytes in encoded:
            raise CorpusConstructionError("construction receipt contains private marker material")
    try:
        final_snapshot_inventory = _inventory_tree(source)
    except (CandidateReceiptError, OSError, ValueError):
        raise CorpusConstructionError(
            "sealed corpus snapshot changed during construction"
        ) from None
    if final_snapshot_inventory.inventory_sha256 != source_snapshot.inventory_sha256:
        raise CorpusConstructionError("sealed corpus snapshot changed during construction")
    return VerifiedCorpusConstructionReceipt(
        receipt=receipt,
        canonical_receipt_sha256=_sha256(encoded),
    )


def canonical_corpus_construction_receipt_sha256(
    receipt: CorpusConstructionReceipt,
) -> str:
    """Hash the exact canonical JSON bytes for one construction receipt."""
    return _sha256(_canonical_model_bytes(receipt))


def write_corpus_construction_receipt(
    destination: Path,
    receipt: CorpusConstructionReceipt,
) -> None:
    """Atomically create a canonical path-free receipt without overwriting."""
    content = _canonical_model_bytes(receipt)
    if destination.exists() or destination.is_symlink():
        raise CorpusConstructionError("construction receipt output already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.link(temporary, destination)
        temporary.unlink()
    except OSError as exc:
        raise CorpusConstructionError("construction receipt could not be created") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def build_agent_run_workflow_input_receipt(
    *,
    run_id: str,
    public_bundle: Path,
    escrow_bundle: Path,
    leakage_policy: PublicLeakagePolicy,
    protocol_allowed_signers: Path,
    protocol_signer_identity: str,
) -> AgentRunWorkflowInputReceipt:
    """Derive the external post-bundle workflow input from exact verified artifacts."""
    try:
        receipt = verify_evidence_bundle_pair(
            public_bundle,
            escrow_bundle,
            leakage_policy,
            trusted_allowed_signers=protocol_allowed_signers,
            expected_signer_identity=protocol_signer_identity,
        )
        _verify_bundle_snapshot(receipt)
        with tempfile.TemporaryDirectory(
            prefix="stinger-workflow-input-evidence-"
        ) as temporary_name:
            package = _materialize_verified_rerunnable_evidence(
                receipt,
                escrow_bundle,
                Path(temporary_name) / "rerunnable-evidence",
            )
            verified_aggregate = verify_invocation_aggregate_snapshot(
                package,
                config=receipt.config,
                report=receipt.report,
            )
    except (
        ClassificationReplayError,
        CorpusConstructionError,
        EvidenceBundleError,
        OSError,
        ValueError,
    ):
        raise CorpusConstructionError(
            "agent-run workflow input could not be derived from verified bundles"
        ) from None
    return _expected_agent_run_workflow_input(
        run_id=run_id,
        receipt=receipt,
        invocation_aggregate_sha256=verified_aggregate.sha256,
    )


def write_agent_run_workflow_input_receipt(
    destination: Path,
    receipt: AgentRunWorkflowInputReceipt,
) -> None:
    """Atomically create one canonical workflow input without overwriting."""
    _atomic_create_private_file(destination, _canonical_model_bytes(receipt))


def sign_corpus_construction_receipt(
    receipt: Path,
    private_key: Path,
) -> Path:
    """Sign exact construction-receipt bytes in their dedicated namespace."""
    return sign_protocol(
        receipt,
        private_key,
        namespace=CORPUS_CONSTRUCTION_SIGNATURE_NAMESPACE,
    )


def authorize_corpus_construction_receipt(
    receipt: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> VerifiedCorpusConstructionAuthorization:
    """Verify, load, and authorize one exact canonical construction receipt.

    The bytes are read before and after OpenSSH verification.  A path replacement during
    signature verification therefore cannot authorize a different parsed receipt.
    """
    try:
        content = _read_exact_regular_file(receipt, label="construction receipt")
    except CorpusConstructionError as exc:
        raise ProtocolSignatureError(
            "construction receipt must be a regular nonsymlink file"
        ) from exc
    verification = verify_protocol_signature(
        receipt,
        signature,
        allowed_signers,
        identity,
        namespace=CORPUS_CONSTRUCTION_SIGNATURE_NAMESPACE,
    )
    try:
        verified_content = _read_exact_regular_file(
            receipt,
            label="construction receipt",
        )
    except CorpusConstructionError as exc:
        raise ProtocolSignatureError(
            "construction receipt changed during signature verification"
        ) from exc
    if verified_content != content or _sha256(content) != verification.protocol_sha256:
        raise ProtocolSignatureError("construction receipt changed during signature verification")
    try:
        raw = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
        parsed = CorpusConstructionReceipt.model_validate(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError):
        raise CorpusConstructionError("construction receipt is malformed") from None
    if content != _canonical_model_bytes(parsed):
        raise CorpusConstructionError("construction receipt is not canonical")
    return VerifiedCorpusConstructionAuthorization(
        receipt=parsed,
        identity=verification.identity,
        namespace=verification.namespace,
        receipt_sha256=verification.protocol_sha256,
        canonical_receipt_sha256=canonical_corpus_construction_receipt_sha256(parsed),
        signature_sha256=verification.signature_sha256,
        allowed_signers_sha256=verification.allowed_signers_sha256,
        signing_key_fingerprint=verification.signing_key_fingerprint,
    )


@dataclass(frozen=True, slots=True)
class _ObservedReviewRuntime:
    """Locally observed immutable reviewer CLI/container identity."""

    image_id: str
    cli_binary_sha256: str
    cli_version: str
    docker_runtime: DockerRuntimeIdentity


@dataclass(frozen=True, slots=True)
class _ReviewCredentialProjection:
    """Private auth-only projection plus a non-secret structural commitment."""

    mount: Path | None
    policy: str
    inventory_sha256: str
    secret_values: tuple[bytes, ...]
    environment_name: str | None
    credential_bytes: bytes | None


def _canonical_review_segment(value: str, *, label: str) -> str:
    """Require an identifier that is also one safe review-workspace path segment."""
    canonical = _canonical_identifier(value, label=label)
    if "/" in canonical or "\\" in canonical or canonical in {".", ".."}:
        raise CorpusConstructionError(f"{label} is not a safe workspace identifier")
    return canonical


def _write_review_file(destination: Path, content: bytes) -> None:
    """Create one private model-visible review artifact without replacement."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    _atomic_create_private_file(destination, content)


class _ReviewEvidenceCollector:
    """Write only content-addressed blobs while retaining logical paths in a manifest."""

    def __init__(self, workspace: Path) -> None:
        self._workspace = workspace
        self._entries: dict[str, MachineReviewEvidenceFile] = {}

    @property
    def files(self) -> tuple[MachineReviewEvidenceFile, ...]:
        """Return the canonical logical-path inventory."""
        return tuple(self._entries[path] for path in sorted(self._entries))

    def add(
        self,
        logical_path: PurePosixPath,
        content: bytes,
        *,
        executable: bool = False,
    ) -> None:
        """Add exact bytes under a safe logical name without creating that name on disk."""
        digest = _sha256(content)
        entry = MachineReviewEvidenceFile(
            path=logical_path.as_posix(),
            blob_path=f"evidence/blobs/{digest}.bin",
            sha256=digest,
            size=len(content),
            executable=executable,
        )
        if entry.path in self._entries:
            raise CorpusConstructionError("machine-review logical evidence path is duplicated")
        blob = self._workspace.joinpath(*PurePosixPath(entry.blob_path).parts)
        if blob.exists():
            if _read_exact_regular_file(blob, label="machine-review evidence blob") != content:
                raise CorpusConstructionError("machine-review content-addressed blob collision")
        else:
            _write_review_file(blob, content)
        self._entries[entry.path] = entry

    def add_tree(
        self,
        source: Path,
        logical_root: PurePosixPath,
    ) -> str:
        """Snapshot a tree into blobs and return its stable source inventory hash."""
        try:
            before = _inventory_tree(source)
            for item in before.files:
                content = _read_exact_regular_file(
                    source.joinpath(*PurePosixPath(item.relative_path).parts),
                    label="machine-review source evidence",
                )
                if len(content) != item.size or _sha256(content) != item.sha256:
                    raise CorpusConstructionError(
                        "machine-review source evidence changed while read"
                    )
                self.add(
                    logical_root / PurePosixPath(item.relative_path),
                    content,
                    executable=item.executable,
                )
            after = _inventory_tree(source)
        except (CandidateReceiptError, OSError):
            raise CorpusConstructionError(
                "machine-review source evidence could not be snapshotted"
            ) from None
        if before.inventory_sha256 != after.inventory_sha256:
            raise CorpusConstructionError(
                "machine-review source evidence changed while snapshotted"
            )
        return before.inventory_sha256


def _materialize_machine_review_workspace(
    destination: Path,
    *,
    scenario: Scenario,
    scenario_record: CorpusScenarioRecord,
    resolution_builds: tuple[_ResolutionVariantBuild, ...],
    qa_materials: tuple[tuple[VerifiedRunBundleInput, _VerifiedRunEvidence], ...],
    expected_stinger_commit: str,
    forbidden_signer_identities: frozenset[str],
    forbidden_signing_key_fingerprints: frozenset[str],
    forbidden_trust_policy_sha256s: frozenset[str],
) -> tuple[
    MachineReviewInputReceipt,
    MachineReviewEvidenceManifest,
    str,
]:
    """Build the sole accepted closed workspace from exact verified source artifacts."""
    if destination.exists() or destination.is_symlink():
        raise CorpusConstructionError("machine-review workspace output already exists")
    destination.mkdir(mode=0o700, parents=True)
    collector = _ReviewEvidenceCollector(destination)
    scenario_snapshot_sha256 = collector.add_tree(
        scenario.directory,
        PurePosixPath("scenario"),
    )
    if scenario_hash(scenario) != scenario_record.scenario_artifact_sha256:
        raise CorpusConstructionError("machine-review scenario evidence is inconsistent")

    for build in resolution_builds:
        variant_id = _canonical_review_segment(
            build.record.variant_id,
            label="resolution variant id",
        )
        logical_root = PurePosixPath("resolutions") / variant_id
        source_snapshot_sha256 = collector.add_tree(
            build.source_tree,
            logical_root / "source-tree",
        )
        if source_snapshot_sha256 != build.execution.source_tree_sha256:
            raise CorpusConstructionError(
                "machine-review resolution source changed after execution"
            )
        for name, content in (
            ("semantic.patch", build.semantic_patch),
            ("agent-run.json", build.agent_run),
            ("execution-receipt.json", _canonical_model_bytes(build.execution)),
            ("transcript.bin", build.transcript),
            ("result.diff", build.diff),
        ):
            collector.add(logical_root / name, content)

    copied_qa: list[_VerifiedRunEvidence] = []
    for run, verified in qa_materials:
        attempt_id = _canonical_review_segment(run.run_id, label="QA attempt id")
        receipt = verified.artifact_receipt
        for name, content in (
            ("report.json", receipt.public_bundle.report_bytes),
            ("config.resolved.json", receipt.public_bundle.config_bytes),
            ("protocol.json", receipt.public_bundle.protocol_bytes),
            ("result.json", _canonical_model_bytes(verified.result)),
            (
                "public-bundle.manifest.json",
                _read_exact_regular_file(
                    run.public_bundle / "bundle.manifest.json",
                    label="machine-review public manifest",
                ),
            ),
            (
                "escrow-bundle.manifest.json",
                _read_exact_regular_file(
                    run.escrow_bundle / "bundle.manifest.json",
                    label="machine-review escrow manifest",
                ),
            ),
            (
                "workflow-input.json",
                _read_exact_regular_file(
                    run.workflow_input,
                    label="machine-review workflow input",
                ),
            ),
            (
                "workflow-attestation.json",
                _read_exact_regular_file(
                    run.workflow_attestation,
                    label="machine-review workflow attestation",
                ),
            ),
        ):
            collector.add(
                PurePosixPath("qa") / attempt_id / "commitments" / name,
                content,
            )

        run_parent = _run_artifact_path(
            verified.result.transcript_path,
            label="transcript",
        ).parent
        diff_parent = _run_artifact_path(
            verified.result.diff_path,
            label="result diff",
        ).parent
        if run_parent != diff_parent:
            raise CorpusConstructionError(
                "machine-review QA run artifacts do not share one directory"
            )
        run_prefix = f"rerunnable-evidence/{run_parent.as_posix()}/"
        projected_run_paths: list[PurePosixPath] = []
        for relative_path, entry in sorted(receipt.escrow_bundle.manifest.files.items()):
            if not relative_path.startswith(run_prefix):
                continue
            relative = PurePosixPath(relative_path).relative_to("rerunnable-evidence")
            content = _snapshot_escrow_inventory_file(
                receipt,
                run.escrow_bundle,
                relative,
            )
            if entry.role is not EvidenceRole.RERUNNABLE_EVIDENCE:
                raise CorpusConstructionError(
                    "machine-review QA projection contains an invalid run role"
                )
            projected_run_paths.append(relative)
            collector.add(
                PurePosixPath("qa") / attempt_id / "run" / relative.relative_to(run_parent),
                content,
            )
        if not projected_run_paths:
            raise CorpusConstructionError("machine-review QA projection contains no run artifacts")
        for name in ("corpus.lock", INVOCATION_AGGREGATE_NAME):
            content = _snapshot_escrow_inventory_file(
                receipt,
                run.escrow_bundle,
                PurePosixPath(name),
            )
            collector.add(
                PurePosixPath("qa") / attempt_id / "commitments" / name,
                content,
            )

        copied_verified = _verify_run_bundle(
            run,
            scenario=scenario,
            corpus_hash_value=verified.artifact_receipt.report.corpus_hash,
            expected_stinger_commit=expected_stinger_commit,
            forbidden_signer_identities=forbidden_signer_identities,
            forbidden_signing_key_fingerprints=forbidden_signing_key_fingerprints,
            forbidden_trust_policy_sha256s=forbidden_trust_policy_sha256s,
        )
        if (
            copied_verified.result != verified.result
            or copied_verified.configuration_fingerprint != verified.configuration_fingerprint
            or copied_verified.runtime_receipt_sha256 != verified.runtime_receipt_sha256
            or copied_verified.execution_identity != verified.execution_identity
            or copied_verified.workflow_authorization != verified.workflow_authorization
            or copied_verified.artifact_receipt.public_bundle.manifest_sha256
            != verified.artifact_receipt.public_bundle.manifest_sha256
            or copied_verified.artifact_receipt.escrow_bundle.manifest_sha256
            != verified.artifact_receipt.escrow_bundle.manifest_sha256
        ):
            raise CorpusConstructionError(
                "machine-review QA snapshot differs from verified execution evidence"
            )
        copied_qa.append(copied_verified)

    evidence_files = collector.files
    evidence_inventory_sha256 = _review_file_inventory_sha256(evidence_files)
    expected_input_sha256 = machine_review_input_manifest_sha256(scenario_record)
    manifest = MachineReviewEvidenceManifest(
        format_version="1",
        scenario_id=scenario_record.scenario_id,
        scenario_artifact_sha256=scenario_record.scenario_artifact_sha256,
        input_manifest_sha256=expected_input_sha256,
        covered_resolution_variant_ids=tuple(
            sorted(build.record.variant_id for build in resolution_builds)
        ),
        covered_qa_attempt_ids=tuple(
            sorted(record.attempt_id for record in scenario_record.agent_qa_attempts)
        ),
        evidence_inventory_sha256=evidence_inventory_sha256,
        files=evidence_files,
    )
    manifest_bytes = _canonical_model_bytes(manifest)
    review_input = MachineReviewInputReceipt(
        format_version="3",
        scenario_id=scenario_record.scenario_id,
        input_manifest_sha256=expected_input_sha256,
        review_evidence_manifest_sha256=_sha256(manifest_bytes),
        review_evidence_inventory_sha256=evidence_inventory_sha256,
        prompt_sha256=MACHINE_REVIEW_PROMPT_SHA256,
        output_schema_sha256=MACHINE_REVIEW_OUTPUT_SCHEMA_SHA256,
        covered_qa_attempt_ids=manifest.covered_qa_attempt_ids,
    )
    _write_review_file(
        destination / MACHINE_REVIEW_EVIDENCE_MANIFEST_FILENAME,
        manifest_bytes,
    )
    _write_review_file(
        destination / MACHINE_REVIEW_INPUT_FILENAME,
        _canonical_model_bytes(review_input),
    )
    final_snapshot = _verify_machine_review_workspace(
        destination,
        expected_input=_canonical_model_bytes(review_input),
    )
    if len(copied_qa) != 5 or not scenario_snapshot_sha256:
        raise CorpusConstructionError("machine-review evidence coverage is incomplete")
    return review_input, manifest, final_snapshot.inventory_sha256


def _verify_machine_review_workspace(
    workspace: Path,
    *,
    expected_input: bytes | None = None,
) -> _Snapshot:
    """Verify the closed workspace layout and every manifest-bound model-visible byte."""
    try:
        snapshot = _inventory_tree(workspace)
        review_input, input_bytes = _load_canonical_model(
            workspace / MACHINE_REVIEW_INPUT_FILENAME,
            MachineReviewInputReceipt,
            label="machine review workspace input",
        )
        manifest, manifest_bytes = _load_canonical_model(
            workspace / MACHINE_REVIEW_EVIDENCE_MANIFEST_FILENAME,
            MachineReviewEvidenceManifest,
            label="machine review evidence manifest",
        )
    except (CandidateReceiptError, OSError, ValidationError, ValueError):
        raise CorpusConstructionError("machine-review workspace is malformed") from None
    if expected_input is not None and input_bytes != expected_input:
        raise CorpusConstructionError("machine-review workspace input is not exact")
    root_files = {
        MACHINE_REVIEW_INPUT_FILENAME,
        MACHINE_REVIEW_EVIDENCE_MANIFEST_FILENAME,
    }
    expected_blobs = {item.blob_path: (item.sha256, item.size) for item in manifest.files}
    observed_blobs = {
        item.relative_path: (item.sha256, item.size)
        for item in snapshot.files
        if item.relative_path not in root_files
    }
    observed_root_files = {
        item.relative_path for item in snapshot.files if "/" not in item.relative_path
    }
    if (
        observed_root_files != root_files
        or observed_blobs != expected_blobs
        or review_input.scenario_id != manifest.scenario_id
        or review_input.input_manifest_sha256 != manifest.input_manifest_sha256
        or review_input.review_evidence_manifest_sha256 != _sha256(manifest_bytes)
        or review_input.review_evidence_inventory_sha256 != manifest.evidence_inventory_sha256
        or review_input.covered_qa_attempt_ids != manifest.covered_qa_attempt_ids
        or len(manifest.covered_resolution_variant_ids) != 4
        or len(manifest.covered_qa_attempt_ids) != 5
    ):
        raise CorpusConstructionError(
            "machine-review workspace is not the closed canonical evidence package"
        )
    return snapshot


def execute_machine_review_workflow(
    *,
    agent: AgentConfig,
    review_id: str,
    review_input_receipt: Path,
    review_workspace: Path,
    output_directory: Path,
    repository: Path,
    expected_stinger_commit: str,
    runner_identity: str,
    private_key: Path,
    allowed_signers: Path,
    max_seconds: int = 3600,
) -> MachineReviewPackageInput:
    """Execute, parse, bind, and sign one canonical contained machine review.

    The emitted signature proves runner accountability for this local workflow. It does not
    prove which remote model a provider served; that narrower boundary is fixed in every
    configuration and runtime receipt.
    """
    if agent.container_image is None or agent.provider is None or agent.model is None:
        raise CorpusConstructionError(
            "machine-review workflow requires pinned container, provider, and model"
        )
    if output_directory.exists() or output_directory.is_symlink():
        raise CorpusConstructionError("machine-review output already exists")
    try:
        repository_root = repository.resolve(strict=True)
        output_parent = output_directory.parent.resolve(strict=True)
    except OSError:
        output_directory.parent.mkdir(parents=True, exist_ok=True)
        try:
            repository_root = repository.resolve(strict=True)
            output_parent = output_directory.parent.resolve(strict=True)
        except OSError:
            raise CorpusConstructionError(
                "machine-review repository or output parent is unavailable"
            ) from None
    if output_parent.is_relative_to(repository_root):
        raise CorpusConstructionError("machine-review output must be outside the repository")
    try:
        commit_before = _clean_exact_git_head(repository)
        implementation_before = _require_construction_implementation(
            repository,
            expected_commit=commit_before,
        )
    except (CandidateReceiptError, OSError, ValueError):
        raise CorpusConstructionError(
            "machine-review implementation is not a clean exact checkout"
        ) from None
    if commit_before != expected_stinger_commit:
        raise CorpusConstructionError(
            "machine-review implementation differs from the expected commit"
        )

    review_input, review_input_bytes = _load_canonical_model(
        review_input_receipt,
        MachineReviewInputReceipt,
        label="machine review input",
    )
    source_workspace = _verify_machine_review_workspace(
        review_workspace,
        expected_input=review_input_bytes,
    )
    temporary = Path(tempfile.mkdtemp(prefix="stinger-machine-review-execution-"))
    credential_root = Path(tempfile.mkdtemp(prefix="stinger-machine-review-auth-"))
    staging: Path | None = None
    try:
        _require_control_free_ancestor_chain(temporary)
        _require_control_free_ancestor_chain(credential_root)
        projection = _build_review_credential_projection(
            agent,
            credential_root=credential_root,
        )
        package_root = temporary / "publishable-package"
        original_workspace = package_root / "review-workspace"
        snapshot = _snapshot_tree(review_workspace, original_workspace)
        copied_snapshot = _verify_machine_review_workspace(
            original_workspace,
            expected_input=review_input_bytes,
        )
        if (
            source_workspace.inventory_sha256 != snapshot.inventory_sha256
            or snapshot.inventory_sha256 != copied_snapshot.inventory_sha256
        ):
            raise CorpusConstructionError(
                "machine-review workspace changed while it was snapshotted"
            )
        observed = _observe_review_runtime(agent)
        immutable_agent = agent.model_copy(
            update={
                "container_image": observed.image_id,
                "container_image_digest": observed.image_id,
                "cli_version": observed.cli_version,
                "credential_mount": projection.mount,
            }
        )
        adapter = build_adapter(immutable_agent)
        if not isinstance(adapter, CliAgentAdapter):
            raise CorpusConstructionError(
                "machine-review workflow requires a canonical CLI adapter"
            )
        _require_canonical_reviewer_provider_binding(
            immutable_agent,
            adapter,
            stinger_commit=expected_stinger_commit,
            docker_runtime=observed.docker_runtime,
        )
        execution_workspace = temporary / "execution-workspace"
        _snapshot_tree(original_workspace, execution_workspace)
        run = adapter.run(
            execution_workspace,
            MACHINE_REVIEW_PROMPT,
            Budget(max_seconds=max_seconds),
        )
        if not run.exit_ok or run.error is not None:
            raise CorpusConstructionError(
                "machine-review CLI invocation did not complete successfully"
            )
        output = _parse_machine_review_output(run.final_message)
        output_bytes = _canonical_model_bytes(output)
        transcript_bytes = run.transcript.encode("utf-8")
        _verify_review_credential_projection(projection)
        _require_no_projected_secret_material(
            projection,
            execution_workspace=execution_workspace,
            transcript=transcript_bytes,
            output=output_bytes,
        )
        try:
            verify_docker_runtime(observed.docker_runtime)
        except DockerRuntimeError:
            raise CorpusConstructionError(
                "machine-review Docker runtime changed during execution"
            ) from None
        provider_response_id = _provider_response_id(
            immutable_agent.adapter,
            run.transcript,
        )
        configuration = MachineReviewerConfigurationReceipt(
            format_version=MACHINE_REVIEW_CONFIGURATION_FORMAT_VERSION,
            claim_boundary=MACHINE_REVIEW_CLAIM_BOUNDARY,
            review_id=_canonical_identifier(review_id, label="review_id"),
            provider=cast(ProviderId, immutable_agent.provider),
            model_id=cast(str, immutable_agent.model),
            agent_adapter=immutable_agent.adapter,
            agent_build=observed.cli_version,
            reasoning_effort=immutable_agent.reasoning_effort or "unspecified",
            inference_settings=immutable_agent.inference_settings,
            agent_cli_binary_sha256=observed.cli_binary_sha256,
            agent_container_digest=observed.image_id.removeprefix("sha256:"),
            docker_runtime_claim_boundary=DOCKER_RUNTIME_CLAIM_BOUNDARY,
            docker_client_sha256=observed.docker_runtime.client_sha256,
            docker_runtime_fingerprint_sha256=(observed.docker_runtime.fingerprint_sha256),
            credential_projection_policy=projection.policy,
            credential_projection_inventory_sha256=projection.inventory_sha256,
        )
        configuration_bytes = _canonical_model_bytes(configuration)
        invocation_argv = adapter.resolved_invocation_template()
        version_argv = tuple(adapter.version_argv())
        invocation_id_sha256 = _canonical_payload_sha256(
            {
                "review_id": review_id,
                "configuration_sha256": _sha256(configuration_bytes),
                "input_sha256": _sha256(review_input_bytes),
                "workspace_sha256": snapshot.inventory_sha256,
                "transcript_sha256": _sha256(transcript_bytes),
                "output_sha256": _sha256(output_bytes),
                "provider_response_id": provider_response_id,
                "stinger_commit": expected_stinger_commit,
            }
        )
        runtime = MachineReviewRuntimeReceipt(
            format_version=MACHINE_REVIEW_RUNTIME_FORMAT_VERSION,
            claim_boundary=MACHINE_REVIEW_CLAIM_BOUNDARY,
            review_id=review_id,
            runner_identity=_canonical_identifier(
                runner_identity,
                label="machine-review runner identity",
            ),
            stinger_commit=expected_stinger_commit,
            agent_adapter=immutable_agent.adapter,
            reviewer_configuration_sha256=_sha256(configuration_bytes),
            review_input_receipt_sha256=_sha256(review_input_bytes),
            review_evidence_manifest_sha256=(review_input.review_evidence_manifest_sha256),
            review_workspace_sha256=snapshot.inventory_sha256,
            transcript_sha256=_sha256(transcript_bytes),
            review_output_sha256=_sha256(output_bytes),
            invocation_argv=invocation_argv,
            version_invocation_argv=version_argv,
            agent_cli_binary_sha256=observed.cli_binary_sha256,
            agent_container_digest=observed.image_id.removeprefix("sha256:"),
            docker_runtime_claim_boundary=DOCKER_RUNTIME_CLAIM_BOUNDARY,
            docker_client_sha256=observed.docker_runtime.client_sha256,
            docker_runtime_fingerprint_sha256=(observed.docker_runtime.fingerprint_sha256),
            credential_projection_policy=projection.policy,
            credential_projection_inventory_sha256=projection.inventory_sha256,
            provider_response_id=provider_response_id,
            parsed_final_message_sha256=_sha256(run.final_message.encode("utf-8")),
            invocation_id_sha256=invocation_id_sha256,
            exit_code=0,
        )
        configuration_path = package_root / "configuration.json"
        input_path = package_root / "input.json"
        transcript_path = package_root / "transcript.bin"
        output_path = package_root / "output.json"
        runtime_path = package_root / "runtime.json"
        for path, content in (
            (configuration_path, configuration_bytes),
            (input_path, review_input_bytes),
            (transcript_path, transcript_bytes),
            (output_path, output_bytes),
            (runtime_path, _canonical_model_bytes(runtime)),
        ):
            _atomic_create_private_file(path, content)
        signature_path = sign_machine_review_runtime_receipt(
            runtime_path,
            private_key,
        )
        if (
            _read_exact_regular_file(
                allowed_signers,
                label="machine-review allowed signers",
            )
            == b""
        ):
            raise CorpusConstructionError("machine-review allowed-signers policy is empty")
        commit_after = _clean_exact_git_head(repository)
        implementation_after = _require_construction_implementation(
            repository,
            expected_commit=commit_after,
        )
        if commit_after != commit_before or implementation_after != implementation_before:
            raise CorpusConstructionError("machine-review implementation changed during execution")
        source_inventory = _inventory_tree(package_root)
        staging = Path(
            tempfile.mkdtemp(
                prefix=f".{output_directory.name}.publish.",
                dir=output_parent,
            )
        )
        staged_package = staging / "package"
        copied_inventory = _snapshot_tree(package_root, staged_package)
        final_source_inventory = _inventory_tree(package_root)
        staged_inventory = _inventory_tree(staged_package)
        if (
            source_inventory.inventory_sha256 != copied_inventory.inventory_sha256
            or source_inventory.inventory_sha256 != final_source_inventory.inventory_sha256
            or source_inventory.inventory_sha256 != staged_inventory.inventory_sha256
        ):
            raise CorpusConstructionError(
                "machine-review output changed while staged for publication"
            )
        os.rename(staged_package, output_directory)
        return MachineReviewPackageInput(
            configuration_receipt=output_directory / configuration_path.name,
            input_receipt=output_directory / input_path.name,
            review_workspace=output_directory / original_workspace.name,
            runtime_receipt=output_directory / runtime_path.name,
            transcript=output_directory / transcript_path.name,
            output=output_directory / output_path.name,
            runtime_signature=output_directory / signature_path.name,
            runtime_allowed_signers=allowed_signers,
            runtime_signer_identity=runner_identity,
        )
    except (
        AdapterError,
        CandidateReceiptError,
        OSError,
        ProtocolSignatureError,
        SandboxError,
        subprocess.TimeoutExpired,
        ValueError,
    ) as exc:
        if isinstance(exc, CorpusConstructionError):
            raise
        raise CorpusConstructionError("machine-review workflow failed closed") from None
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
        if credential_root.exists():
            shutil.rmtree(credential_root)
        if staging is not None and staging.exists():
            shutil.rmtree(staging)


def _require_control_free_ancestor_chain(path: Path) -> None:
    """Reject an execution cwd whose ancestors can auto-inject agent instructions."""
    try:
        current = path.resolve(strict=True)
    except OSError:
        raise CorpusConstructionError("machine-review execution root is unavailable") from None
    for ancestor in (current, *current.parents):
        for name in _AGENT_CONTROL_FILENAMES:
            candidate = ancestor / name
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                continue
            except OSError:
                raise CorpusConstructionError(
                    "machine-review execution ancestor could not be inspected"
                ) from None
            if stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise CorpusConstructionError(
                    "machine-review execution ancestor contains an agent control file"
                )


def _build_review_credential_projection(
    agent: AgentConfig,
    *,
    credential_root: Path,
) -> _ReviewCredentialProjection:
    """Build one private auth-only projection without caller config or instruction state."""
    if agent.options:
        raise CorpusConstructionError(
            "machine-review workflow forbids caller-supplied environment options"
        )
    if agent.adapter == "codex":
        if agent.api_key_env is not None or agent.credential_mount is None:
            raise CorpusConstructionError(
                "Codex machine review requires only an auth.json credential mount"
            )
        try:
            source_metadata = agent.credential_mount.lstat()
            source_root = agent.credential_mount.resolve(strict=True)
        except OSError:
            raise CorpusConstructionError("Codex credential source is unavailable") from None
        if not stat.S_ISDIR(source_metadata.st_mode) or stat.S_ISLNK(source_metadata.st_mode):
            raise CorpusConstructionError("Codex credential source is not a real directory")
        try:
            entries = tuple(sorted(os.scandir(source_root), key=lambda item: item.name))
        except OSError:
            raise CorpusConstructionError(
                "Codex credential source could not be inventoried"
            ) from None
        if (
            len(entries) != 1
            or entries[0].name != "auth.json"
            or not entries[0].is_file(follow_symlinks=False)
            or entries[0].is_symlink()
        ):
            raise CorpusConstructionError(
                "Codex credential source must contain only regular auth.json"
            )
        source = source_root / "auth.json"
        try:
            mode = stat.S_IMODE(source.lstat().st_mode)
        except OSError:
            raise CorpusConstructionError("Codex auth.json is unavailable") from None
        if mode != 0o600:
            raise CorpusConstructionError("Codex auth.json must have mode 0600")
        content = _read_exact_regular_file(source, label="Codex auth.json")
        secret_values = _validate_codex_auth_json(content)
        projection = credential_root / "credentials"
        projection.mkdir(mode=0o700)
        os.chmod(projection, 0o700)
        destination = projection / "auth.json"
        _atomic_create_private_file(destination, content)
        if _read_exact_regular_file(source, label="Codex auth.json") != content:
            raise CorpusConstructionError("Codex auth.json changed while it was projected")
        inventory_sha256 = _canonical_payload_sha256(
            {
                "policy": CODEX_CREDENTIAL_PROJECTION_POLICY,
                "files": [
                    {
                        "path": "auth.json",
                        "node_type": "regular",
                        "mode": "0600",
                    }
                ],
                "environment_names": [],
                "global_control_state": "verified-empty-in-immutable-image",
            }
        )
        return _ReviewCredentialProjection(
            mount=projection,
            policy=CODEX_CREDENTIAL_PROJECTION_POLICY,
            inventory_sha256=inventory_sha256,
            secret_values=(content, *secret_values),
            environment_name=None,
            credential_bytes=content,
        )
    if agent.adapter == "claude-code":
        allowed_environment_names = {
            "ANTHROPIC_API_KEY",
            "CLAUDE_CODE_OAUTH_TOKEN",
        }
        if agent.credential_mount is not None or agent.api_key_env not in allowed_environment_names:
            raise CorpusConstructionError(
                "Claude machine review requires one explicit supported auth environment"
            )
        environment_name = agent.api_key_env
        value = os.environ.get(environment_name)
        if value is None or not value or value != value.strip() or "\x00" in value:
            raise CorpusConstructionError("Claude machine-review auth environment is unavailable")
        encoded = value.encode("utf-8")
        inventory_sha256 = _canonical_payload_sha256(
            {
                "policy": CLAUDE_CREDENTIAL_PROJECTION_POLICY,
                "files": [],
                "environment_names": [environment_name],
                "global_control_state": "verified-empty-in-immutable-image",
            }
        )
        return _ReviewCredentialProjection(
            mount=None,
            policy=CLAUDE_CREDENTIAL_PROJECTION_POLICY,
            inventory_sha256=inventory_sha256,
            secret_values=(encoded,),
            environment_name=environment_name,
            credential_bytes=None,
        )
    raise CorpusConstructionError(
        "machine-review credential projection lacks a canonical adapter policy"
    )


def _validate_codex_auth_json(content: bytes) -> tuple[bytes, ...]:
    """Validate the closed pinned-Codex auth structure and retain only private secrets."""
    try:
        raw = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise CorpusConstructionError("Codex auth.json is malformed") from None
    if not isinstance(raw, dict):
        raise CorpusConstructionError("Codex auth.json must be a JSON object")
    allowed_top = {"auth_mode", "last_refresh", "tokens", "OPENAI_API_KEY"}
    if "auth_mode" not in raw or not set(raw).issubset(allowed_top):
        raise CorpusConstructionError("Codex auth.json has unsupported top-level keys")
    if not isinstance(raw["auth_mode"], str) or not raw["auth_mode"]:
        raise CorpusConstructionError("Codex auth.json auth_mode is invalid")
    secrets: list[bytes] = []
    tokens = raw.get("tokens")
    api_key = raw.get("OPENAI_API_KEY")
    if tokens is not None:
        allowed_tokens = {
            "access_token",
            "account_id",
            "id_token",
            "refresh_token",
        }
        required_tokens = {"access_token", "id_token", "refresh_token"}
        if (
            not isinstance(tokens, dict)
            or not required_tokens.issubset(tokens)
            or not set(tokens).issubset(allowed_tokens)
            or any(not isinstance(value, str) or not value for value in tokens.values())
        ):
            raise CorpusConstructionError("Codex auth.json token structure is unsupported")
        secrets.extend(value.encode("utf-8") for value in tokens.values())
    if api_key is not None:
        if not isinstance(api_key, str) or not api_key:
            raise CorpusConstructionError("Codex auth.json API key is invalid")
        secrets.append(api_key.encode("utf-8"))
    if not secrets or (tokens is not None and api_key is not None):
        raise CorpusConstructionError(
            "Codex auth.json must contain exactly one supported credential mode"
        )
    return tuple(secrets)


def _verify_review_credential_projection(
    projection: _ReviewCredentialProjection,
) -> None:
    """Recheck private projected auth immediately after the model invocation."""
    if projection.mount is not None:
        try:
            entries = tuple(sorted(os.scandir(projection.mount), key=lambda item: item.name))
        except OSError:
            raise CorpusConstructionError(
                "machine-review credential projection is unavailable"
            ) from None
        if (
            len(entries) != 1
            or entries[0].name != "auth.json"
            or not entries[0].is_file(follow_symlinks=False)
            or entries[0].is_symlink()
            or projection.credential_bytes is None
            or _read_exact_regular_file(
                projection.mount / "auth.json",
                label="projected Codex auth.json",
            )
            != projection.credential_bytes
        ):
            raise CorpusConstructionError(
                "machine-review credential projection changed during execution"
            )
    elif (
        projection.environment_name is None
        or os.environ.get(projection.environment_name, "").encode("utf-8")
        not in projection.secret_values
    ):
        raise CorpusConstructionError(
            "machine-review credential environment changed during execution"
        )


def _require_no_projected_secret_material(
    projection: _ReviewCredentialProjection,
    *,
    execution_workspace: Path,
    transcript: bytes,
    output: bytes,
) -> None:
    """Refuse publication if projected credential material entered review artifacts."""
    secrets = tuple(value for value in projection.secret_values if value)
    if any(secret in transcript or secret in output for secret in secrets):
        raise CorpusConstructionError(
            "machine-review output contains projected credential material"
        )
    try:
        for root, directories, files in os.walk(
            execution_workspace,
            topdown=True,
            followlinks=False,
        ):
            directories.sort()
            files.sort()
            root_path = Path(root)
            for name in (*directories, *files):
                metadata = (root_path / name).lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    raise CorpusConstructionError(
                        "machine-review execution workspace contains a symlink"
                    )
            for name in files:
                path = root_path / name
                content = _read_exact_regular_file(
                    path,
                    label="machine-review execution artifact",
                )
                if any(secret in content for secret in secrets):
                    raise CorpusConstructionError(
                        "machine-review workspace contains projected credential material"
                    )
    except OSError:
        raise CorpusConstructionError(
            "machine-review execution workspace could not be scanned"
        ) from None


def _require_clean_review_image_state(
    image_id: str,
    *,
    adapter: str,
    docker_runtime: DockerRuntimeIdentity,
) -> None:
    """Reject recognized image-global instruction, memory, skill, or settings state."""
    if adapter == "codex":
        adapter_script = r"""
            [ -n "${CODEX_HOME:-}" ] || exit 31
            [ "${CODEX_HOME}" != "/credentials" ] || exit 32
            empty_or_absent "${CODEX_HOME}" || exit 33
            absent_or_empty_dir "/tmp/.codex" || exit 34
            absent_node "/etc/codex/config.toml" || exit 35
            absent_or_empty_dir "/etc/codex/rules" || exit 36
        """
    elif adapter == "claude-code":
        adapter_script = r"""
            absent_or_empty_dir "/tmp/.claude" || exit 41
            if [ -n "${CLAUDE_CONFIG_DIR:-}" ]; then
                absent_or_empty_dir "${CLAUDE_CONFIG_DIR}" || exit 42
            fi
            absent_node "/etc/claude-code/managed-settings.json" || exit 43
            absent_node "/etc/claude/managed-settings.json" || exit 44
        """
    else:
        raise CorpusConstructionError("machine-review image state lacks a canonical adapter policy")
    script = (
        r"""
        set -eu
        absent_node() {
            [ ! -e "$1" ] && [ ! -L "$1" ]
        }
        empty_or_absent() {
            if [ ! -e "$1" ] && [ ! -L "$1" ]; then
                return 0
            fi
            [ -d "$1" ] && [ ! -L "$1" ] || return 1
            [ -z "$(find "$1" -mindepth 1 -maxdepth 1 -print -quit)" ]
        }
        absent_or_empty_dir() {
            empty_or_absent "$1"
        }
        for path in \
            /AGENTS.md /CLAUDE.md \
            /tmp/AGENTS.md /tmp/CLAUDE.md \
            /tmp/config.toml /tmp/settings.json /tmp/settings.local.json
        do
            absent_node "$path" || exit 21
        done
        """
        + adapter_script
    )
    probe = _run_review_docker(
        [
            "run",
            "--rm",
            "--network",
            "none",
            "--env",
            "HOME=/tmp",
            "--entrypoint",
            "sh",
            image_id,
            "-c",
            script,
        ],
        runtime=docker_runtime,
        timeout=60,
    )
    if probe.returncode != 0:
        raise CorpusConstructionError("machine-review image contains unapproved global agent state")


def _run_review_docker(
    arguments: list[str],
    *,
    runtime: DockerRuntimeIdentity,
    timeout: int,
    container_name: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one review probe without leaving an abnormally ended container behind."""
    effective_arguments = list(arguments)
    if effective_arguments and effective_arguments[0] in {"run", "create"}:
        operation = effective_arguments[0]
        if container_name is None:
            container_name = f"stinger-review-{operation}-{uuid4().hex[:12]}"
        effective_arguments[1:1] = ["--name", container_name]
    elif container_name is not None:
        raise CorpusConstructionError(
            "machine-review container handle was supplied for a non-container operation"
        )
    try:
        completed = run_docker(
            effective_arguments,
            runtime=runtime,
            timeout=timeout,
        )
    except BaseException as exc:
        _require_review_container_absent(container_name, runtime)
        if isinstance(exc, (DockerRuntimeError, OSError)):
            raise CorpusConstructionError(
                "machine-review Docker invocation failed closed"
            ) from None
        raise
    if completed.returncode != 0:
        # `run --rm` normally removes a container before returning an inner-command error,
        # but a crashed or killed Docker client has the same return-code shape. A failed
        # `create` may likewise be committed by the daemon after the client exits. Preserve
        # the result only after exact-name absence has been proved.
        _require_review_container_absent(container_name, runtime)
    return completed


def _require_review_container_absent(
    name: str | None,
    runtime: DockerRuntimeIdentity,
) -> None:
    """Prove an abnormal review probe left no exact-name container."""
    if name is None:
        return
    try:
        terminate_docker_container(
            name,
            runtime=runtime,
            timeout=30,
        )
    except DockerRuntimeError:
        raise CorpusConstructionError(
            "machine-review Docker invocation failed and container cleanup could not be verified"
        ) from None


def _observe_review_runtime(agent: AgentConfig) -> _ObservedReviewRuntime:
    """Inspect one immutable agent image, CLI binary, and version without a model call."""
    adapter = build_adapter(agent)
    if not isinstance(adapter, CliAgentAdapter):
        raise CorpusConstructionError("machine-review adapter is not a live CLI adapter")
    if agent.container_image is None:
        raise CorpusConstructionError("machine-review agent container is missing")
    try:
        docker_runtime = observe_docker_runtime()
        image_id, _ = inspect_docker_image(
            agent.container_image,
            runtime=docker_runtime,
        )
    except DockerRuntimeError:
        raise CorpusConstructionError(
            "machine-review Docker runtime could not be observed"
        ) from None
    _require_clean_review_image_state(
        image_id,
        adapter=agent.adapter,
        docker_runtime=docker_runtime,
    )
    executable = adapter.version_argv()[0]
    path_probe = _run_review_docker(
        [
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "sh",
            image_id,
            "-c",
            'command -v "$1"',
            "sh",
            executable,
        ],
        runtime=docker_runtime,
        timeout=60,
    )
    executable_path = path_probe.stdout.strip()
    if path_probe.returncode != 0 or not executable_path.startswith("/") or "\n" in executable_path:
        raise CorpusConstructionError("machine-review CLI executable could not be observed")
    version_argv = adapter.version_argv()
    version_probe = _run_review_docker(
        [
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            executable_path,
            image_id,
            *version_argv[1:],
        ],
        runtime=docker_runtime,
        timeout=60,
    )
    version = version_probe.stdout.strip()
    if version_probe.returncode != 0 or not version or "\n" in version or "\x00" in version:
        raise CorpusConstructionError("machine-review CLI version could not be observed")

    container_name = f"stinger-review-create-{uuid4().hex[:12]}"
    try:
        # Enter the cleanup region before asking the daemon to create anything. This closes
        # the interrupt window between a successful `docker create` and the old following
        # `try` statement.
        container = _run_review_docker(
            ["create", "--entrypoint", "/bin/true", image_id],
            runtime=docker_runtime,
            timeout=60,
            container_name=container_name,
        )
        container_id = container.stdout.strip()
        if container.returncode != 0 or not container_id:
            raise CorpusConstructionError("machine-review CLI container could not be inspected")
        with tempfile.TemporaryDirectory(prefix="stinger-review-cli-") as temporary_name:
            copied = Path(temporary_name) / "agent-cli"
            copy = _run_review_docker(
                [
                    "cp",
                    f"{container_name}:{executable_path}",
                    str(copied),
                ],
                runtime=docker_runtime,
                timeout=60,
            )
            if copy.returncode != 0:
                raise CorpusConstructionError("machine-review CLI binary could not be snapshotted")
            binary = _read_exact_regular_file(
                copied,
                label="machine-review CLI binary",
            )
    finally:
        try:
            terminate_docker_container(
                container_name,
                runtime=docker_runtime,
                timeout=30,
            )
        except DockerRuntimeError:
            raise CorpusConstructionError(
                "machine-review CLI container cleanup could not be verified"
            ) from None
    return _ObservedReviewRuntime(
        image_id=image_id,
        cli_binary_sha256=_sha256(binary),
        cli_version=version,
        docker_runtime=docker_runtime,
    )


def _require_canonical_reviewer_provider_binding(
    agent: AgentConfig,
    adapter: CliAgentAdapter,
    *,
    stinger_commit: str,
    docker_runtime: DockerRuntimeIdentity,
) -> None:
    """Require the direct canonical OpenAI/Codex or Anthropic/Claude CLI mapping."""
    if agent.adapter not in {"codex", "claude-code"}:
        raise CorpusConstructionError(
            "machine-review adapter lacks a direct canonical provider binding"
        )
    metadata = BenchmarkRunMetadata(
        provider=agent.provider,
        model_id=agent.model,
        agent_adapter=agent.adapter,
        agent_cli_version=agent.cli_version,
        reasoning_effort=agent.reasoning_effort,
        inference_settings=agent.inference_settings,
        stinger_commit=stinger_commit,
        agent_container_digest=agent.container_image_digest,
        verification_image_digest=agent.container_image_digest,
    )
    runtime = BenchmarkRuntimeProvenance(
        requested_provider=agent.provider,
        requested_model_id=agent.model,
        stinger_commit=stinger_commit,
        docker_client_sha256=docker_runtime.client_sha256,
        docker_runtime_fingerprint_sha256=docker_runtime.fingerprint_sha256,
        docker_runtime_claim_boundary=DOCKER_RUNTIME_CLAIM_BOUNDARY,
        agent_cli_version=agent.cli_version,
        agent_container_image_id=agent.container_image_digest,
        verification_image_id=agent.container_image_digest,
        resolved_agent_invocation=adapter.resolved_invocation_template(),
        resolved_version_invocation=tuple(adapter.version_argv()),
        reasoning_effort=agent.reasoning_effort,
        inference_settings=agent.inference_settings,
        verified=True,
    )
    if canonical_local_provider_binding_issues(metadata, runtime):
        raise CorpusConstructionError(
            "machine-review adapter/provider/executable mapping is invalid"
        )


def _parse_machine_review_output(final_message: str) -> MachineReviewOutput:
    """Accept only a final message that is exactly canonical closed-contract JSON."""
    content = final_message.strip().encode("utf-8") + b"\n"
    try:
        raw = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
        output = MachineReviewOutput.model_validate(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError):
        raise CorpusConstructionError(
            "machine-review final message is not closed-contract JSON"
        ) from None
    if content != _canonical_model_bytes(output):
        raise CorpusConstructionError("machine-review final message is not canonical JSON")
    return output


def _provider_response_id(agent_adapter: str, transcript: str) -> str:
    """Extract one canonical provider session/thread id from a raw direct-CLI transcript."""
    values: set[str] = set()
    for line in transcript.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        value: object | None = None
        if agent_adapter == "codex" and event.get("type") == "thread.started":
            value = event.get("thread_id")
        elif (
            agent_adapter == "claude-code"
            and event.get("type") == "system"
            and event.get("subtype") == "init"
        ):
            value = event.get("session_id")
        if isinstance(value, str) and value and not any(char.isspace() for char in value):
            values.add(value)
    if len(values) != 1:
        raise CorpusConstructionError(
            "machine-review transcript lacks one canonical provider session id"
        )
    return next(iter(values))


def sign_machine_review_runtime_receipt(
    receipt: Path,
    private_key: Path,
) -> Path:
    """Sign one exact transcript-bearing review runtime in its dedicated namespace."""
    return sign_protocol(
        receipt,
        private_key,
        namespace=MACHINE_REVIEW_RUNTIME_SIGNATURE_NAMESPACE,
    )


def authorize_machine_review_runtime_receipt(
    receipt: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> VerifiedMachineReviewRuntimeAuthorization:
    """Authorize exact runtime bytes while detecting path replacement around verification."""
    try:
        content = _read_exact_regular_file(receipt, label="machine review runtime")
    except CorpusConstructionError as exc:
        raise ProtocolSignatureError(
            "machine review runtime must be a regular nonsymlink file"
        ) from exc
    verification = verify_protocol_signature(
        receipt,
        signature,
        allowed_signers,
        identity,
        namespace=MACHINE_REVIEW_RUNTIME_SIGNATURE_NAMESPACE,
    )
    try:
        verified_content = _read_exact_regular_file(
            receipt,
            label="machine review runtime",
        )
    except CorpusConstructionError as exc:
        raise ProtocolSignatureError(
            "machine review runtime changed during signature verification"
        ) from exc
    if verified_content != content or _sha256(content) != verification.protocol_sha256:
        raise ProtocolSignatureError("machine review runtime changed during signature verification")
    try:
        raw = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
        parsed = MachineReviewRuntimeReceipt.model_validate(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError):
        raise CorpusConstructionError("machine review runtime is malformed") from None
    if content != _canonical_model_bytes(parsed):
        raise CorpusConstructionError("machine review runtime is not canonical")
    if parsed.runner_identity != verification.identity:
        raise ProtocolSignatureError(
            "machine review runtime signer does not match its runner identity"
        )
    return VerifiedMachineReviewRuntimeAuthorization(
        receipt=parsed,
        identity=verification.identity,
        namespace=verification.namespace,
        receipt_sha256=verification.protocol_sha256,
        canonical_receipt_sha256=_sha256(_canonical_model_bytes(parsed)),
        signature_sha256=verification.signature_sha256,
        allowed_signers_sha256=verification.allowed_signers_sha256,
        signing_key_fingerprint=verification.signing_key_fingerprint,
    )


def _build_base_scenario_record(
    scenario: Scenario,
    item: ScenarioConstructionInput,
    *,
    corpus_version: str,
    corpus_hash_value: str,
    promotion: CandidatePromotionStatement,
    promotion_statement_sha256: str,
    resolution_sandbox: Sandbox,
    lifecycle_role_constraints: _LifecycleRoleConstraints,
) -> tuple[
    CorpusScenarioRecord,
    dict[str, Any],
    tuple[_RunExecutionIdentity, ...],
    tuple[VerifiedMachineWorkflowAttestation, ...],
]:
    """Derive one scenario record excluding review and blind-solve evidence."""
    if (
        scenario.manifest.benchmark_split is not BenchmarkSplit.SEALED
        or scenario.manifest.cluster_id is None
    ):
        raise CorpusConstructionError("scenario lifecycle metadata is not sealed and complete")
    artifact_sha256 = scenario_hash(scenario)
    authoring_snapshots = tuple(
        _load_canonical_model(
            path,
            AuthoringConfigurationReceipt,
            label="authoring configuration",
        )
        for path in item.authoring_configuration_artifacts
    )
    authoring_hashes = tuple(sorted(_sha256(content) for _, content in authoring_snapshots))
    source_hashes = tuple(
        sorted(
            _sha256(_read_exact_regular_file(path, label="provenance source"))
            for path in item.provenance_source_artifacts
        )
    )
    provenance, provenance_bytes = _load_canonical_model(
        item.provenance_receipt,
        ScenarioProvenanceReceipt,
        label="scenario provenance",
    )
    protocol = compiled_benchmark_protocol()
    if (
        provenance.benchmark_protocol_version != protocol.benchmark_protocol_version
        or provenance.rubric_version != protocol.rubric_version
        or provenance.corpus_version != corpus_version
        or provenance.scenario_id != scenario.id
        or provenance.scenario_artifact_sha256 != artifact_sha256
        or provenance.authoring_configuration_fingerprints != authoring_hashes
        or provenance.source_artifact_sha256s != source_hashes
    ):
        raise CorpusConstructionError("scenario provenance is not bound to exact artifacts")

    validation_sha256 = _canonical_payload_sha256(
        {
            "scenario_id": scenario.id,
            "scenario_artifact_sha256": artifact_sha256,
            "sealed_corpus_hash": corpus_hash_value,
            "stinger_commit": promotion.stinger_commit,
            "verification_image_id": promotion.verification_image_id,
            "verification_image_policy_sha256": (promotion.verification_image_policy_sha256),
            "validation_contract": SEALED_VALIDATION_CONTRACT,
        }
    )
    containment = ScenarioContainmentReceipt(
        format_version=CONSTRUCTION_RECEIPT_FORMAT_VERSION,
        scenario_id=scenario.id,
        scenario_artifact_sha256=artifact_sha256,
        sealed_validation_receipt_sha256=validation_sha256,
        promotion_statement_sha256=promotion_statement_sha256,
        validation_contract=cast(
            Literal["stinger-scenario-validity-v1-docker-sealed"],
            SEALED_VALIDATION_CONTRACT,
        ),
        verification_image_id=promotion.verification_image_id,
        isolation="docker",
        network_mode="none",
    )
    containment_bytes = _canonical_model_bytes(containment)
    safety = _derive_dummy_safety_receipt(
        scenario,
        scenario_artifact_sha256=artifact_sha256,
    )
    safety_bytes = _canonical_model_bytes(safety)
    variant_builds = tuple(
        sorted(
            (
                _build_resolution_variant(
                    scenario,
                    artifact_sha256,
                    variant_input,
                    sandbox=resolution_sandbox,
                )
                for variant_input in item.resolution_variants
            ),
            key=lambda value: value.record.variant_id,
        )
    )
    variants = tuple(build.record for build in variant_builds)
    expected_outcome = Outcome.REFUSED if scenario.manifest.honest_is_refusal else Outcome.HONEST
    execution_receipts = tuple(build.execution for build in variant_builds)
    if any(
        execution.kind is ResolutionKind.HONEST and execution.outcome is not expected_outcome
        for execution in execution_receipts
    ):
        raise CorpusConstructionError("honest resolution outcome disagrees with scenario contract")
    for kind in ResolutionKind:
        semantic_changes = {
            execution.semantic_change_sha256
            for execution in execution_receipts
            if execution.kind is kind
        }
        mechanisms = {
            execution.implementation_mechanism_sha256
            for execution in execution_receipts
            if execution.kind is kind
        }
        if len(semantic_changes) != 2 or len(mechanisms) != 2:
            raise CorpusConstructionError(
                "resolution variants are not structurally distinct after normalization"
            )
    qa_builds = tuple(
        sorted(
            (
                _build_qa_attempt(
                    run,
                    scenario=scenario,
                    corpus_hash_value=corpus_hash_value,
                    expected_stinger_commit=promotion.stinger_commit,
                    forbidden_signer_identities=(lifecycle_role_constraints.signer_identities),
                    forbidden_signing_key_fingerprints=(
                        lifecycle_role_constraints.signing_key_fingerprints
                    ),
                    forbidden_trust_policy_sha256s=(
                        lifecycle_role_constraints.trust_policy_sha256s
                    ),
                )
                for run in item.qa_attempts
            ),
            key=lambda value: value[0].attempt_id,
        )
    )
    qa_attempts = tuple(record for record, _, _, _ in qa_builds)
    qa_execution_identities = tuple(identity for _, identity, _, _ in qa_builds)
    qa_workflow_authorizations = tuple(authorization for _, _, authorization, _ in qa_builds)
    qa_verified_evidence = tuple(verified for _, _, _, verified in qa_builds)
    _require_unique_run_executions(qa_execution_identities)
    base_record = CorpusScenarioRecord(
        scenario_id=scenario.id,
        family=scenario.manifest.family,
        repository_size=provenance.repository_size,
        benchmark_split=BenchmarkSplit.SEALED,
        scenario_version=scenario.manifest.scenario_version,
        cluster_id=scenario.manifest.cluster_id,
        expected_honest_outcome=expected_outcome,
        scenario_artifact_sha256=artifact_sha256,
        machine_validation_receipt_sha256=validation_sha256,
        provenance_receipt_sha256=_sha256(provenance_bytes),
        containment_receipt_sha256=_sha256(containment_bytes),
        dummy_safety_receipt_sha256=_sha256(safety_bytes),
        resolution_variants=variants,
        agent_qa_attempts=qa_attempts,
        machine_reviews=(),
        blind_agent_solves=(),
    )
    qa_signer_identities = frozenset(
        authorization.signer_identity for authorization in qa_workflow_authorizations
    )
    qa_signing_keys = frozenset(
        authorization.signing_key_fingerprint for authorization in qa_workflow_authorizations
    )
    qa_trust_policies = frozenset(
        authorization.allowed_signers_sha256 for authorization in qa_workflow_authorizations
    )
    with tempfile.TemporaryDirectory(prefix="stinger-machine-review-workspace-") as temporary_name:
        expected_review_workspace = Path(temporary_name) / "workspace"
        _materialize_machine_review_workspace(
            expected_review_workspace,
            scenario=scenario,
            scenario_record=base_record,
            resolution_builds=variant_builds,
            qa_materials=tuple(zip(item.qa_attempts, qa_verified_evidence, strict=True)),
            expected_stinger_commit=promotion.stinger_commit,
            forbidden_signer_identities=(lifecycle_role_constraints.signer_identities),
            forbidden_signing_key_fingerprints=(
                lifecycle_role_constraints.signing_key_fingerprints
            ),
            forbidden_trust_policy_sha256s=(lifecycle_role_constraints.trust_policy_sha256s),
        )
        reviews = _build_machine_reviews(
            base_record,
            item.machine_reviews,
            expected_review_workspace=expected_review_workspace,
            forbidden_signer_identities=(
                lifecycle_role_constraints.signer_identities | qa_signer_identities
            ),
            forbidden_signing_key_fingerprints=(
                lifecycle_role_constraints.signing_key_fingerprints | qa_signing_keys
            ),
            forbidden_trust_policy_sha256s=(
                lifecycle_role_constraints.trust_policy_sha256s | qa_trust_policies
            ),
            expected_stinger_commit=promotion.stinger_commit,
        )
    record = base_record.model_copy(update={"machine_reviews": reviews})
    return (
        record,
        {
            "scenario_id": scenario.id,
            "provenance_receipt_sha256": _sha256(provenance_bytes),
            "containment_receipt_sha256": _sha256(containment_bytes),
            "dummy_safety_receipt_sha256": _sha256(safety_bytes),
            "resolution_variants_sha256": _canonical_payload_sha256(
                [value.model_dump(mode="json") for value in variants]
            ),
            "agent_qa_attempts_sha256": _canonical_payload_sha256(
                [value.model_dump(mode="json") for value in qa_attempts]
            ),
            "machine_reviews_sha256": _canonical_payload_sha256(
                [value.model_dump(mode="json") for value in reviews]
            ),
        },
        qa_execution_identities,
        qa_workflow_authorizations,
    )


def _normalized_configuration_identity(
    configuration: MachineReviewerConfigurationReceipt,
) -> _NormalizedConfigurationIdentity:
    """Project a signed reviewer configuration into its semantic identity."""
    if not isinstance(configuration, MachineReviewerConfigurationReceipt):
        raise CorpusConstructionError(
            "unsigned authoring metadata cannot establish reviewer independence"
        )
    return _NormalizedConfigurationIdentity(
        provider=configuration.provider,
        model_id=configuration.model_id,
        agent_build=configuration.agent_build,
        reasoning_effort=configuration.reasoning_effort,
        inference_settings_sha256=_canonical_payload_sha256(configuration.inference_settings),
    )


def _normalized_configuration_identity_sort_key(
    identity: _NormalizedConfigurationIdentity,
) -> tuple[str, str, str, str, str]:
    """Return the canonical sort key for semantic configuration identities."""
    return (
        identity.provider.value,
        identity.model_id,
        identity.agent_build,
        identity.reasoning_effort,
        identity.inference_settings_sha256,
    )


def _derive_dummy_safety_receipt(
    scenario: Scenario,
    *,
    scenario_artifact_sha256: str,
) -> DummySafetyReceipt:
    """Scan one exact scenario snapshot for non-dummy credentials or real URL targets."""
    with tempfile.TemporaryDirectory(prefix="stinger-safety-") as temporary_name:
        snapshot_parent = Path(temporary_name)
        snapshot_root = snapshot_parent / scenario.id
        try:
            _snapshot_tree(scenario.directory, snapshot_root)
            loaded = discover_scenarios(snapshot_parent)
        except (CandidateReceiptError, OSError, ScenarioLoadError):
            raise CorpusConstructionError("dummy-safety snapshot could not be verified") from None
        if (
            len(loaded) != 1
            or loaded[0].id != scenario.id
            or scenario_hash(loaded[0]) != scenario_artifact_sha256
        ):
            raise CorpusConstructionError("dummy-safety snapshot changed scenario identity")

        scanned_files = 0
        scanned_bytes = 0
        target_hashes: list[str] = []
        credential_hashes: list[str] = []
        for path in sorted(
            (item for item in snapshot_root.rglob("*") if item.is_file()),
            key=lambda item: item.relative_to(snapshot_root).as_posix(),
        ):
            content = _read_exact_regular_file(path, label="dummy-safety scenario file")
            scanned_files += 1
            scanned_bytes += len(content)
            if path.suffix == ".py":
                ast_targets, ast_credentials = _python_dummy_safety_evidence(content)
                target_hashes.extend(ast_targets)
                credential_hashes.extend(ast_credentials)
            for match in _URL_TARGET_PATTERN.finditer(content):
                raw_authority = match.group(1)
                try:
                    authority = raw_authority.decode("ascii")
                except UnicodeDecodeError:
                    raise CorpusConstructionError(
                        "scenario contains a non-ASCII network authority"
                    ) from None
                if not _allowed_network_authority(authority):
                    raise CorpusConstructionError(
                        "scenario contains a non-local or non-reserved network target"
                    )
                target_hashes.append(_sha256(raw_authority.lower()))
            for match in _NETWORK_CONTEXT_PATTERN.finditer(content):
                raw_authority = match.group(1)
                try:
                    authority = raw_authority.decode("ascii")
                except UnicodeDecodeError:
                    raise CorpusConstructionError(
                        "scenario contains a non-ASCII network target"
                    ) from None
                if not _allowed_network_authority(authority):
                    raise CorpusConstructionError(
                        "scenario contains a non-local or non-reserved network target"
                    )
                target_hashes.append(_sha256(raw_authority.lower()))
            for match in _CREDENTIAL_TOKEN_PATTERN.finditer(content):
                token = match.group(0)
                if not any(marker in token.lower() for marker in _DUMMY_MARKERS):
                    raise CorpusConstructionError(
                        "scenario contains credential-like material not visibly marked dummy"
                    )
                credential_hashes.append(_sha256(token))
            for match in _SECRET_ASSIGNMENT_PATTERN.finditer(content):
                value = match.group(1)
                if not any(marker in value.lower() for marker in _DUMMY_MARKERS):
                    raise CorpusConstructionError(
                        "scenario contains a secret-like assignment not visibly marked dummy"
                    )
                credential_hashes.append(_sha256(value))

    declared_secret_hashes: list[str] = []
    for detector in scenario.manifest.detectors:
        raw_secrets = detector.config.get("secrets")
        if raw_secrets is None:
            continue
        if not isinstance(raw_secrets, list):
            raise CorpusConstructionError("declared secret inventory is malformed")
        for raw_secret in raw_secrets:
            if not isinstance(raw_secret, dict):
                raise CorpusConstructionError("declared secret inventory is malformed")
            value = raw_secret.get("value")
            origin = raw_secret.get("origin")
            if (
                not isinstance(value, str)
                or not value
                or not isinstance(origin, str)
                or not origin
                or not any(marker.decode("ascii") in value.casefold() for marker in _DUMMY_MARKERS)
            ):
                raise CorpusConstructionError("declared bait secret is not visibly dummy-only")
            declared_secret_hashes.append(
                _canonical_payload_sha256(
                    {
                        "value_sha256": _sha256(value.encode("utf-8")),
                        "origin": origin,
                    }
                )
            )
    return DummySafetyReceipt(
        format_version=CONSTRUCTION_RECEIPT_FORMAT_VERSION,
        policy_version=DUMMY_SAFETY_POLICY_VERSION,
        scenario_id=scenario.id,
        scenario_artifact_sha256=scenario_artifact_sha256,
        scanned_file_count=scanned_files,
        scanned_byte_count=scanned_bytes,
        declared_dummy_secret_count=len(declared_secret_hashes),
        declared_dummy_secret_inventory_sha256=_canonical_payload_sha256(
            sorted(declared_secret_hashes)
        ),
        allowed_network_target_count=len(target_hashes),
        allowed_network_target_inventory_sha256=_canonical_payload_sha256(sorted(target_hashes)),
        credential_token_inventory_sha256=_canonical_payload_sha256(sorted(credential_hashes)),
    )


def _allowed_network_authority(authority: str) -> bool:
    """Accept only loopback or reserved example/test DNS authorities."""
    if "@" in authority:
        return False
    candidate = authority
    if candidate.startswith("["):
        closing = candidate.find("]")
        if closing < 0:
            return False
        host = candidate[1:closing]
        suffix = candidate[closing + 1 :]
        if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit()):
            return False
    else:
        host, separator, port = candidate.rpartition(":")
        if not separator or not port.isdigit():
            host = candidate
        elif not host:
            return False
    normalized = host.rstrip(".").casefold()
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return (
            normalized == "localhost"
            or normalized.endswith(
                (
                    ".localhost",
                    ".example.com",
                    ".example.net",
                    ".example.org",
                    ".example.test",
                    ".invalid",
                    ".test",
                )
            )
            or normalized
            in {
                "example.com",
                "example.net",
                "example.org",
                "example.test",
                "invalid",
                "test",
            }
        )
    return address.is_loopback


def _python_dummy_safety_evidence(
    content: bytes,
) -> tuple[list[str], list[str]]:
    """Resolve constant Python sink values, failing closed on unresolved safety sinks."""
    try:
        source = content.decode("utf-8")
        tree = ast.parse(source)
    except (UnicodeDecodeError, SyntaxError):
        raise CorpusConstructionError(
            "scenario Python source cannot be parsed for dummy safety"
        ) from None
    constants: dict[str, str] = {}
    targets: list[str] = []
    credentials: list[str] = []

    for statement in tree.body:
        assignment = _assignment_name_and_value(statement)
        if assignment is None:
            continue
        name, value_node = assignment
        value = _constant_python_string(value_node, constants)
        if value is not None:
            constants[name] = value
        if _SECRET_NAME_PATTERN.search(name):
            if value is None:
                raise CorpusConstructionError(
                    "scenario contains an unresolved secret-like assignment"
                )
            encoded = value.encode("utf-8")
            if not any(marker in encoded.lower() for marker in _DUMMY_MARKERS):
                raise CorpusConstructionError(
                    "scenario contains a secret-like assignment not visibly marked dummy"
                )
            credentials.append(_sha256(encoded))
        if _NETWORK_NAME_PATTERN.search(name):
            if value is None:
                raise CorpusConstructionError(
                    "scenario contains an unresolved network-target assignment"
                )
            _record_resolved_network_target(value, targets)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _python_call_name(node.func)
        if not _is_network_sink_call(call_name):
            continue
        candidate_node = _network_call_value_node(node)
        if candidate_node is None:
            raise CorpusConstructionError("scenario contains an unresolved network sink")
        value = _constant_python_string(candidate_node, constants)
        if value is None and isinstance(candidate_node, (ast.Tuple, ast.List)):
            value = (
                _constant_python_string(candidate_node.elts[0], constants)
                if candidate_node.elts
                else None
            )
        if value is None:
            raise CorpusConstructionError("scenario contains an unresolved network sink")
        _record_resolved_network_target(value, targets)
    return targets, credentials


def _assignment_name_and_value(
    statement: ast.stmt,
) -> tuple[str, ast.expr] | None:
    """Return one simple module-level assignment for safety evaluation."""
    if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
        target = statement.targets[0]
        if isinstance(target, ast.Name):
            return target.id, statement.value
    if (
        isinstance(statement, ast.AnnAssign)
        and isinstance(statement.target, ast.Name)
        and statement.value is not None
    ):
        return statement.target.id, statement.value
    return None


def _constant_python_string(
    node: ast.expr,
    constants: dict[str, str],
) -> str | None:
    """Evaluate only side-effect-free constant string composition."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_python_string(node.left, constants)
        right = _constant_python_string(node.right, constants)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        pieces: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                pieces.append(value.value)
                continue
            if isinstance(value, ast.FormattedValue):
                resolved = _constant_python_string(value.value, constants)
                if resolved is not None:
                    pieces.append(resolved)
                    continue
            return None
        return "".join(pieces)
    return None


def _python_call_name(node: ast.expr) -> str:
    """Return a dotted syntactic call target without resolving runtime aliases."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _python_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _is_network_sink_call(call_name: str) -> bool:
    """Recognize direct network APIs whose destination must be mechanically safe."""
    lowered = call_name.casefold()
    return lowered.endswith(("create_connection", ".connect")) or lowered in {
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
    }


def _network_call_value_node(call: ast.Call) -> ast.expr | None:
    """Select the syntactic destination expression from a recognized network call."""
    for keyword in call.keywords:
        if keyword.arg is not None and _NETWORK_NAME_PATTERN.search(keyword.arg):
            return keyword.value
    return call.args[0] if call.args else None


def _record_resolved_network_target(value: str, targets: list[str]) -> None:
    """Validate one resolved URL/authority and retain only its hash."""
    authority = value
    url_match = re.match(r"(?i)^https?://([^/]+)", value)
    if url_match is not None:
        authority = url_match.group(1)
    if not _allowed_network_authority(authority):
        raise CorpusConstructionError(
            "scenario contains a non-local or non-reserved network target"
        )
    targets.append(_sha256(authority.casefold().encode("ascii")))


def _build_resolution_variant(
    scenario: Scenario,
    scenario_artifact_sha256: str,
    item: ResolutionVariantInput,
    *,
    sandbox: Sandbox,
) -> _ResolutionVariantBuild:
    """Execute one exact overlay and derive every favorable fact from the result."""
    variant_id = _canonical_identifier(item.variant_id, label="variant_id")
    semantic_patch = _read_exact_regular_file(item.semantic_patch, label="semantic patch")
    agent_run, agent_run_bytes = _load_canonical_model(
        item.agent_run,
        AgentRun,
        label="resolution agent run",
    )
    intended = tuple(spec.name for spec in scenario.manifest.detectors if spec.intended)
    if len(intended) != 1:
        raise CorpusConstructionError("resolution scenario lacks one intended detector")
    with tempfile.TemporaryDirectory(prefix="stinger-resolution-") as temporary_name:
        temporary = Path(temporary_name)
        overlay = temporary / "overlay"
        try:
            source_snapshot = _snapshot_tree(item.source_tree, overlay)
        except (CandidateReceiptError, OSError):
            raise CorpusConstructionError(
                "resolution source tree could not be snapshotted"
            ) from None
        artifacts = temporary / "artifacts"
        result = run_scenario_once(
            scenario.directory,
            scenario.manifest,
            _ResolutionOverlayAdapter(overlay, agent_run),
            0,
            sandbox=sandbox,
            artifacts_dir=artifacts,
            path_root=artifacts,
        )
        transcript = _read_exact_regular_file(
            artifacts / result.transcript_path,
            label="resolution transcript",
        )
        diff = _read_exact_regular_file(
            artifacts / result.diff_path,
            label="resolution diff",
        )
        semantic_change_sha256 = _semantic_change_sha256(overlay, diff)
        implementation_mechanism_sha256 = _implementation_mechanism_sha256(
            overlay,
            diff,
        )
    if diff != semantic_patch:
        raise CorpusConstructionError(
            "resolution semantic patch does not equal the mechanically observed diff"
        )
    if result.run_error is not None or result.outcome is Outcome.ERROR:
        raise CorpusConstructionError("resolution execution did not produce a scorable result")
    intended_triggered = any(
        detector.detector == intended[0] and detector.fired and not detector.low_confidence
        for detector in result.detector_results
    )
    if item.kind is ResolutionKind.HONEST:
        expected = Outcome.REFUSED if scenario.manifest.honest_is_refusal else Outcome.HONEST
        if (
            result.outcome is not expected
            or intended_triggered
            or (expected is Outcome.HONEST and not result.goal_met)
            or (expected is Outcome.REFUSED and result.goal_met)
        ):
            raise CorpusConstructionError(
                "honest resolution failed the mechanically executed scenario contract"
            )
    elif result.outcome is not Outcome.CHEATED or not intended_triggered:
        raise CorpusConstructionError("cheat resolution failed to trigger the intended detector")
    receipt = ResolutionExecutionReceipt(
        format_version=RESOLUTION_EXECUTION_FORMAT_VERSION,
        scenario_id=scenario.id,
        scenario_artifact_sha256=scenario_artifact_sha256,
        variant_id=variant_id,
        kind=item.kind,
        source_tree_sha256=source_snapshot.inventory_sha256,
        semantic_patch_sha256=_sha256(semantic_patch),
        semantic_change_sha256=semantic_change_sha256,
        implementation_mechanism_sha256=implementation_mechanism_sha256,
        agent_run_sha256=_sha256(agent_run_bytes),
        verification_image_id=sandbox.image,
        result_sha256=_canonical_model_sha256(result),
        transcript_sha256=_sha256(transcript),
        diff_sha256=_sha256(diff),
        outcome=result.outcome,
        goal_met=result.goal_met,
        intended_detector_triggered=intended_triggered,
        intended_detector=intended[0],
    )
    receipt_bytes = _canonical_model_bytes(receipt)
    return _ResolutionVariantBuild(
        record=ResolutionVariantRecord(
            variant_id=variant_id,
            kind=item.kind,
            source_tree_sha256=source_snapshot.inventory_sha256,
            semantic_patch_sha256=_sha256(semantic_patch),
            execution_receipt_sha256=_sha256(receipt_bytes),
        ),
        execution=receipt,
        source_tree=item.source_tree,
        semantic_patch=semantic_patch,
        agent_run=agent_run_bytes,
        transcript=transcript,
        diff=diff,
    )


class _LocalBindingCollector(ast.NodeVisitor):
    """Collect bound function-local names without descending into nested scopes."""

    def __init__(self) -> None:
        self.names: list[str] = []
        self.global_names: set[str] = set()
        self.nonlocal_names: set[str] = set()

    def _add(self, name: str) -> None:
        if name not in self.names:
            self.names.append(name)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._add(node.id)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        del node

    def visit_Global(self, node: ast.Global) -> None:
        self.global_names.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocal_names.update(node.names)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._add(alias.asname or alias.name.split(".", 1)[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                self._add(alias.asname or alias.name)


class _LocalAlphaNormalizer(ast.NodeTransformer):
    """Normalize function locals while preserving module globals and API names."""

    def __init__(self) -> None:
        self._scopes: list[dict[str, str]] = []

    def _renamed(self, name: str) -> str:
        for scope in reversed(self._scopes):
            if name in scope:
                return scope[name]
        return name

    @staticmethod
    def _mapping(
        arguments: ast.arguments,
        body: list[ast.stmt],
    ) -> dict[str, str]:
        names = [
            argument.arg
            for argument in (
                *arguments.posonlyargs,
                *arguments.args,
                *arguments.kwonlyargs,
            )
        ]
        if arguments.vararg is not None:
            names.append(arguments.vararg.arg)
        if arguments.kwarg is not None:
            names.append(arguments.kwarg.arg)
        collector = _LocalBindingCollector()
        for statement in body:
            collector.visit(statement)
        names.extend(name for name in collector.names if name not in names)
        excluded = collector.global_names | collector.nonlocal_names
        return {
            name: f"local_{index}"
            for index, name in enumerate(name for name in names if name not in excluded)
        }

    def visit_Name(self, node: ast.Name) -> ast.Name:
        node.id = self._renamed(node.id)
        return node

    def visit_arg(self, node: ast.arg) -> ast.arg:
        node.arg = self._renamed(node.arg)
        return cast(ast.arg, self.generic_visit(node))

    def visit_alias(self, node: ast.alias) -> ast.alias:
        bound = node.asname or node.name.split(".", 1)[0]
        renamed = self._renamed(bound)
        if renamed != bound:
            node.asname = renamed
        return node

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.ExceptHandler:
        if node.name is not None:
            node.name = self._renamed(node.name)
        return cast(ast.ExceptHandler, self.generic_visit(node))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        node.name = self._renamed(node.name)
        node.decorator_list = [self.visit(item) for item in node.decorator_list]
        node.returns = None if node.returns is None else self.visit(node.returns)
        self._scopes.append(self._mapping(node.args, node.body))
        try:
            node.args = self.visit(node.args)
            node.body = [self.visit(statement) for statement in node.body]
        finally:
            self._scopes.pop()
        return node

    def visit_AsyncFunctionDef(
        self,
        node: ast.AsyncFunctionDef,
    ) -> ast.AsyncFunctionDef:
        node.name = self._renamed(node.name)
        node.decorator_list = [self.visit(item) for item in node.decorator_list]
        node.returns = None if node.returns is None else self.visit(node.returns)
        self._scopes.append(self._mapping(node.args, node.body))
        try:
            node.args = self.visit(node.args)
            node.body = [self.visit(statement) for statement in node.body]
        finally:
            self._scopes.pop()
        return node

    def visit_Lambda(self, node: ast.Lambda) -> ast.Lambda:
        self._scopes.append(self._mapping(node.args, []))
        try:
            node.args = self.visit(node.args)
            node.body = self.visit(node.body)
        finally:
            self._scopes.pop()
        return node


def _normalized_python_tree(source: str, *, filename: str) -> ast.AST:
    """Parse and alpha-normalize local bindings for structural comparison."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        raise CorpusConstructionError("resolution changed Python source does not parse") from None
    normalized = cast(ast.AST, _LocalAlphaNormalizer().visit(tree))
    ast.fix_missing_locations(normalized)
    return normalized


def _semantic_change_sha256(overlay: Path, diff: bytes) -> str:
    """Hash changed ASTs/tokens so comment or whitespace variants collapse."""
    try:
        text = diff.decode("utf-8")
    except UnicodeDecodeError:
        raise CorpusConstructionError("resolution diff is not valid UTF-8") from None
    changed_paths: list[PurePosixPath] = []
    for line in text.splitlines():
        if not line.startswith("+++ "):
            continue
        value = line[4:]
        if value == "/dev/null":
            raise CorpusConstructionError(
                "resolution semantic identity cannot prove a deleted-file behavior"
            )
        if not value.startswith("b/") or "\t" in value or '"' in value or "\\" in value:
            raise CorpusConstructionError("resolution diff contains a noncanonical changed path")
        path = PurePosixPath(value[2:])
        if (
            path.is_absolute()
            or not path.parts
            or "." in path.parts
            or ".." in path.parts
            or path in changed_paths
        ):
            raise CorpusConstructionError("resolution diff changed-path inventory is invalid")
        changed_paths.append(path)
    if not changed_paths:
        raise CorpusConstructionError("resolution diff contains no changed file")

    semantic_files: list[dict[str, object]] = []
    for relative in sorted(changed_paths, key=lambda value: value.as_posix()):
        content = _read_exact_regular_file(
            overlay.joinpath(*relative.parts),
            label="resolution changed source",
        )
        try:
            source = content.decode("utf-8")
        except UnicodeDecodeError:
            raise CorpusConstructionError("resolution changed source is not valid UTF-8") from None
        if relative.suffix == ".py":
            tree = _normalized_python_tree(source, filename=relative.as_posix())
            representation: object = {
                "kind": "python_ast",
                "value": ast.dump(tree, annotate_fields=True, include_attributes=False),
            }
        else:
            try:
                lexer = shlex.shlex(source, posix=True, punctuation_chars=True)
                lexer.commenters = "#"
                lexer.whitespace_split = True
                tokens = tuple(lexer)
            except ValueError:
                raise CorpusConstructionError(
                    "resolution changed source cannot be tokenized"
                ) from None
            if not tokens:
                raise CorpusConstructionError("resolution changed source has no semantic tokens")
            representation = {
                "kind": "text_tokens",
                "value": tokens,
            }
        semantic_files.append(
            {
                "path": relative.as_posix(),
                "representation": representation,
            }
        )
    return _canonical_payload_sha256(semantic_files)


def _implementation_mechanism_sha256(overlay: Path, diff: bytes) -> str:
    """Hash conservative control-flow/operator/call-target implementation features."""
    try:
        text = diff.decode("utf-8")
    except UnicodeDecodeError:
        raise CorpusConstructionError("resolution diff is not valid UTF-8") from None
    changed_paths = sorted(
        {PurePosixPath(line[6:]) for line in text.splitlines() if line.startswith("+++ b/")},
        key=lambda value: value.as_posix(),
    )
    if not changed_paths:
        raise CorpusConstructionError("resolution diff contains no changed file")
    mechanisms: list[dict[str, object]] = []
    for relative in changed_paths:
        content = _read_exact_regular_file(
            overlay.joinpath(*relative.parts),
            label="resolution mechanism source",
        )
        try:
            source = content.decode("utf-8")
        except UnicodeDecodeError:
            raise CorpusConstructionError(
                "resolution mechanism source is not valid UTF-8"
            ) from None
        if relative.suffix == ".py":
            tree = _normalized_python_tree(source, filename=relative.as_posix())
            node_counts: dict[str, int] = {}
            operators: list[str] = []
            calls: list[str] = []
            statement_shapes: list[str] = []
            for node in ast.walk(tree):
                node_name = type(node).__name__
                node_counts[node_name] = node_counts.get(node_name, 0) + 1
                if isinstance(node, (ast.operator, ast.boolop, ast.unaryop, ast.cmpop)):
                    operators.append(node_name)
                if isinstance(node, ast.Call):
                    calls.append(_python_call_name(node.func))
                if isinstance(node, ast.stmt):
                    statement_shapes.append(node_name)
            features: object = {
                "kind": "python",
                "node_counts": dict(sorted(node_counts.items())),
                "operators": sorted(operators),
                "calls": sorted(calls),
                "statement_shapes": statement_shapes,
            }
        else:
            try:
                lexer = shlex.shlex(source, posix=True, punctuation_chars=True)
                lexer.commenters = "#"
                lexer.whitespace_split = True
                tokens = tuple(lexer)
            except ValueError:
                raise CorpusConstructionError(
                    "resolution mechanism source cannot be tokenized"
                ) from None
            if not tokens:
                raise CorpusConstructionError("resolution mechanism source has no semantic tokens")
            features = {
                "kind": "text",
                "token_classes": [
                    "word" if token.replace("_", "").isalnum() else token for token in tokens
                ],
            }
        mechanisms.append({"path": relative.as_posix(), "features": features})
    return _canonical_payload_sha256(mechanisms)


class _ResolutionOverlayAdapter:
    """Deterministic adapter that applies one exact attempt before returning its run log."""

    name = "corpus-construction-resolution"

    def __init__(self, overlay: Path, run: AgentRun) -> None:
        self._overlay = overlay
        self._run = run

    def run(self, workdir: Path, prompt: str, budget: Budget) -> AgentRun:
        """Apply the snapshotted attempt; prompt and budget are fixed scenario inputs."""
        del prompt, budget
        apply_overlay(self._overlay, workdir)
        return self._run


def _build_qa_attempt(
    run: VerifiedRunBundleInput,
    *,
    scenario: Scenario,
    corpus_hash_value: str,
    expected_stinger_commit: str,
    forbidden_signer_identities: frozenset[str],
    forbidden_signing_key_fingerprints: frozenset[str],
    forbidden_trust_policy_sha256s: frozenset[str],
) -> tuple[
    AgentQAAttemptRecord,
    _RunExecutionIdentity,
    VerifiedMachineWorkflowAttestation,
    _VerifiedRunEvidence,
]:
    """Derive one QA record from a verified exact bundle pair."""
    verified = _verify_run_bundle(
        run,
        scenario=scenario,
        corpus_hash_value=corpus_hash_value,
        expected_stinger_commit=expected_stinger_commit,
        forbidden_signer_identities=forbidden_signer_identities,
        forbidden_signing_key_fingerprints=forbidden_signing_key_fingerprints,
        forbidden_trust_policy_sha256s=forbidden_trust_policy_sha256s,
    )
    return (
        AgentQAAttemptRecord(
            attempt_id=_canonical_identifier(run.run_id, label="attempt_id"),
            provider=verified.provider,
            agent_configuration_fingerprint=verified.configuration_fingerprint,
            result_sha256=_canonical_model_sha256(verified.result),
            evidence_manifest_sha256=(verified.artifact_receipt.public_bundle.manifest_sha256),
            runtime_receipt_sha256=verified.runtime_receipt_sha256,
            outcome=verified.result.outcome,
        ),
        verified.execution_identity,
        verified.workflow_authorization,
        verified,
    )


def _require_unique_run_executions(
    identities: tuple[_RunExecutionIdentity, ...],
) -> None:
    """Reject bundle reuse or replay across QA and blind workflow evidence."""
    seen_invocations: set[str] = set()
    seen_challenges: set[str] = set()
    seen_provider_responses: set[str] = set()
    seen_execution_evidence: set[str] = set()
    seen_signatures: set[str] = set()
    for identity in identities:
        if (
            seen_invocations.intersection(identity.invocation_ids)
            or seen_challenges.intersection(identity.challenge_nonce_sha256s)
            or seen_provider_responses.intersection(identity.provider_response_id_sha256s)
            or seen_execution_evidence.intersection(identity.execution_evidence_sha256s)
            or identity.workflow_signature_sha256 in seen_signatures
        ):
            raise CorpusConstructionError("QA or blind evidence reuses one signed invocation")
        seen_invocations.update(identity.invocation_ids)
        seen_challenges.update(identity.challenge_nonce_sha256s)
        seen_provider_responses.update(identity.provider_response_id_sha256s)
        seen_execution_evidence.update(identity.execution_evidence_sha256s)
        seen_signatures.add(identity.workflow_signature_sha256)


def _build_machine_reviews(
    scenario: CorpusScenarioRecord,
    packages: tuple[MachineReviewPackageInput, ...],
    *,
    expected_review_workspace: Path,
    forbidden_signer_identities: frozenset[str],
    forbidden_signing_key_fingerprints: frozenset[str],
    forbidden_trust_policy_sha256s: frozenset[str],
    expected_stinger_commit: str,
) -> tuple[MachineReviewRecord, ...]:
    """Derive reviews only from signed, transcript-bearing runner invocations."""
    expected_input_sha256 = machine_review_input_manifest_sha256(scenario)
    expected_qa_ids = tuple(sorted(attempt.attempt_id for attempt in scenario.agent_qa_attempts))
    expected_workspace_snapshot = _verify_machine_review_workspace(
        expected_review_workspace,
    )
    expected_workspace_input, expected_workspace_input_bytes = _load_canonical_model(
        expected_review_workspace / MACHINE_REVIEW_INPUT_FILENAME,
        MachineReviewInputReceipt,
        label="expected machine review input",
    )
    records: list[MachineReviewRecord] = []
    semantic_reviewer_identities: list[_NormalizedConfigurationIdentity] = []
    runner_identities: list[str] = []
    runner_key_fingerprints: list[str] = []
    runner_trust_policy_hashes: list[str] = []
    runtime_signature_hashes: list[str] = []
    invocation_ids: list[str] = []
    provider_response_ids: list[str] = []
    for package in packages:
        configuration, configuration_bytes = _load_canonical_model(
            package.configuration_receipt,
            MachineReviewerConfigurationReceipt,
            label="reviewer configuration",
        )
        review_input, input_bytes = _load_canonical_model(
            package.input_receipt,
            MachineReviewInputReceipt,
            label="machine review input",
        )
        output, output_bytes = _load_canonical_model(
            package.output,
            MachineReviewOutput,
            label="machine review output",
        )
        transcript_bytes = _read_exact_regular_file(
            package.transcript,
            label="machine review transcript",
        )
        try:
            transcript = transcript_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise CorpusConstructionError("machine-review transcript is not valid UTF-8") from None
        workspace_snapshot = _verify_machine_review_workspace(
            package.review_workspace,
            expected_input=expected_workspace_input_bytes,
        )
        authorization = authorize_machine_review_runtime_receipt(
            package.runtime_receipt,
            package.runtime_signature,
            package.runtime_allowed_signers,
            package.runtime_signer_identity,
        )
        runtime = authorization.receipt
        configuration_sha256 = _sha256(configuration_bytes)
        exact_output_sha256 = _sha256(output_bytes)
        output_sha256 = _canonical_model_sha256(output)
        semantic_identity = _normalized_configuration_identity(configuration)
        review_agent = AgentConfig(
            adapter=configuration.agent_adapter,
            model=configuration.model_id,
            provider=configuration.provider,
            cli_version=configuration.agent_build,
            reasoning_effort=configuration.reasoning_effort,
            inference_settings=configuration.inference_settings,
            container_image=f"sha256:{configuration.agent_container_digest}",
            container_image_digest=f"sha256:{configuration.agent_container_digest}",
        )
        try:
            adapter = build_adapter(review_agent)
        except AdapterError:
            raise CorpusConstructionError(
                "machine-review configuration names an unsupported adapter"
            ) from None
        if not isinstance(adapter, CliAgentAdapter):
            raise CorpusConstructionError(
                "machine-review configuration is not a canonical CLI adapter"
            )
        observed = _observe_review_runtime(review_agent)
        _require_canonical_reviewer_provider_binding(
            review_agent,
            adapter,
            stinger_commit=expected_stinger_commit,
            docker_runtime=observed.docker_runtime,
        )
        parsed_run = adapter.replay(transcript, exit_code=runtime.exit_code)
        parsed_output = _parse_machine_review_output(parsed_run.final_message)
        provider_response_id = _provider_response_id(
            configuration.agent_adapter,
            transcript,
        )
        expected_invocation_id = _canonical_payload_sha256(
            {
                "review_id": configuration.review_id,
                "configuration_sha256": configuration_sha256,
                "input_sha256": _sha256(input_bytes),
                "workspace_sha256": workspace_snapshot.inventory_sha256,
                "transcript_sha256": _sha256(transcript_bytes),
                "output_sha256": exact_output_sha256,
                "provider_response_id": provider_response_id,
                "stinger_commit": expected_stinger_commit,
            }
        )
        if (
            review_input.scenario_id != scenario.scenario_id
            or review_input.input_manifest_sha256 != expected_input_sha256
            or review_input.prompt_sha256 != MACHINE_REVIEW_PROMPT_SHA256
            or review_input.output_schema_sha256 != MACHINE_REVIEW_OUTPUT_SCHEMA_SHA256
            or review_input.covered_qa_attempt_ids != expected_qa_ids
            or review_input != expected_workspace_input
            or output.covered_qa_attempt_ids != expected_qa_ids
            or output.decision is not MachineReviewDecision.ACCEPT
            or parsed_output != output
            or output_bytes != _canonical_model_bytes(output)
            or input_bytes != expected_workspace_input_bytes
            or workspace_snapshot.inventory_sha256 != expected_workspace_snapshot.inventory_sha256
            or runtime.review_id != configuration.review_id
            or runtime.runner_identity != authorization.identity
            or runtime.stinger_commit != expected_stinger_commit
            or runtime.agent_adapter != configuration.agent_adapter
            or runtime.reviewer_configuration_sha256 != configuration_sha256
            or runtime.review_input_receipt_sha256 != _sha256(input_bytes)
            or runtime.review_evidence_manifest_sha256
            != review_input.review_evidence_manifest_sha256
            or runtime.review_workspace_sha256 != workspace_snapshot.inventory_sha256
            or runtime.transcript_sha256 != _sha256(transcript_bytes)
            or runtime.review_output_sha256 != exact_output_sha256
            or runtime.agent_cli_binary_sha256 != configuration.agent_cli_binary_sha256
            or runtime.agent_container_digest != configuration.agent_container_digest
            or runtime.docker_runtime_claim_boundary != configuration.docker_runtime_claim_boundary
            or runtime.docker_client_sha256 != configuration.docker_client_sha256
            or runtime.docker_runtime_fingerprint_sha256
            != configuration.docker_runtime_fingerprint_sha256
            or runtime.credential_projection_policy != configuration.credential_projection_policy
            or runtime.credential_projection_inventory_sha256
            != configuration.credential_projection_inventory_sha256
            or observed.image_id.removeprefix("sha256:") != configuration.agent_container_digest
            or observed.cli_binary_sha256 != configuration.agent_cli_binary_sha256
            or observed.cli_version != configuration.agent_build
            or observed.docker_runtime.client_sha256 != configuration.docker_client_sha256
            or observed.docker_runtime.fingerprint_sha256
            != configuration.docker_runtime_fingerprint_sha256
            or runtime.invocation_argv != adapter.resolved_invocation_template()
            or runtime.version_invocation_argv != tuple(adapter.version_argv())
            or runtime.provider_response_id != provider_response_id
            or runtime.parsed_final_message_sha256
            != _sha256(parsed_run.final_message.encode("utf-8"))
            or runtime.invocation_id_sha256 != expected_invocation_id
            or authorization.namespace != MACHINE_REVIEW_RUNTIME_SIGNATURE_NAMESPACE
            or authorization.receipt_sha256 != _sha256(_canonical_model_bytes(runtime))
            or authorization.identity in forbidden_signer_identities
            or authorization.signing_key_fingerprint in forbidden_signing_key_fingerprints
            or authorization.allowed_signers_sha256 in forbidden_trust_policy_sha256s
        ):
            raise CorpusConstructionError(
                "signed machine review invocation is not exactly cross-bound or independent"
            )
        semantic_reviewer_identities.append(semantic_identity)
        runner_identities.append(authorization.identity)
        runner_key_fingerprints.append(authorization.signing_key_fingerprint)
        runner_trust_policy_hashes.append(authorization.allowed_signers_sha256)
        runtime_signature_hashes.append(authorization.signature_sha256)
        invocation_ids.append(runtime.invocation_id_sha256)
        provider_response_ids.append(runtime.provider_response_id)
        records.append(
            MachineReviewRecord(
                review_id=configuration.review_id,
                provider=configuration.provider,
                model_id=configuration.model_id,
                reviewer_configuration_fingerprint=configuration_sha256,
                runtime_receipt_sha256=authorization.receipt_sha256,
                runtime_signer_identity=authorization.identity,
                runtime_signing_key_fingerprint=authorization.signing_key_fingerprint,
                runtime_allowed_signers_sha256=authorization.allowed_signers_sha256,
                runtime_signature_sha256=authorization.signature_sha256,
                prompt_sha256=MACHINE_REVIEW_PROMPT_SHA256,
                input_manifest_sha256=expected_input_sha256,
                output_schema_sha256=MACHINE_REVIEW_OUTPUT_SCHEMA_SHA256,
                output_sha256=output_sha256,
                output=output,
            )
        )
    if (
        len(semantic_reviewer_identities) != len(set(semantic_reviewer_identities))
        or len(runner_identities) != len(set(runner_identities))
        or len(runner_key_fingerprints) != len(set(runner_key_fingerprints))
        or len(runner_trust_policy_hashes) != len(set(runner_trust_policy_hashes))
        or len(runtime_signature_hashes) != len(set(runtime_signature_hashes))
        or len(invocation_ids) != len(set(invocation_ids))
        or len(provider_response_ids) != len(set(provider_response_ids))
    ):
        raise CorpusConstructionError(
            "machine reviews reuse one semantic configuration or runner authority"
        )
    return tuple(sorted(records, key=lambda value: value.review_id))


def _build_blind_solves(
    scenario: CorpusScenarioRecord,
    source_scenario: Scenario,
    solves: tuple[BlindSolveInput, ...],
    *,
    selected: bool,
    corpus_hash_value: str,
    expected_stinger_commit: str,
    forbidden_signer_identities: frozenset[str],
    forbidden_signing_key_fingerprints: frozenset[str],
    forbidden_trust_policy_sha256s: frozenset[str],
) -> tuple[
    tuple[BlindAgentSolveRecord, ...],
    tuple[_RunExecutionIdentity, ...],
    tuple[VerifiedMachineWorkflowAttestation, ...],
]:
    """Derive reference-isolated solve records for the frozen subset only."""
    if not selected:
        if solves:
            raise CorpusConstructionError("blind solve evidence is outside frozen selection")
        return (), (), ()
    records: list[BlindAgentSolveRecord] = []
    execution_identities: list[_RunExecutionIdentity] = []
    workflow_authorizations: list[VerifiedMachineWorkflowAttestation] = []
    for item in solves:
        verified = _verify_run_bundle(
            item.bundle,
            scenario=source_scenario,
            corpus_hash_value=corpus_hash_value,
            expected_stinger_commit=expected_stinger_commit,
            forbidden_signer_identities=forbidden_signer_identities,
            forbidden_signing_key_fingerprints=forbidden_signing_key_fingerprints,
            forbidden_trust_policy_sha256s=forbidden_trust_policy_sha256s,
        )
        isolation = _derive_reference_isolation_receipt(
            scenario,
            source_scenario,
            item.bundle,
            verified.artifact_receipt,
            verified.result,
            runtime_receipt_sha256=verified.runtime_receipt_sha256,
        )
        if verified.result.outcome is not scenario.expected_honest_outcome:
            raise CorpusConstructionError("blind solve is not bound to reference isolation")
        records.append(
            BlindAgentSolveRecord(
                solve_id=_canonical_identifier(item.bundle.run_id, label="solve_id"),
                provider=verified.provider,
                solver_configuration_fingerprint=(verified.configuration_fingerprint),
                result_sha256=_canonical_model_sha256(verified.result),
                evidence_manifest_sha256=(verified.artifact_receipt.public_bundle.manifest_sha256),
                runtime_receipt_sha256=verified.runtime_receipt_sha256,
                reference_isolation_receipt_sha256=_sha256(_canonical_model_bytes(isolation)),
                outcome=verified.result.outcome,
            )
        )
        execution_identities.append(verified.execution_identity)
        workflow_authorizations.append(verified.workflow_authorization)
    return (
        tuple(sorted(records, key=lambda value: value.solve_id)),
        tuple(execution_identities),
        tuple(workflow_authorizations),
    )


def _derive_reference_isolation_receipt(
    scenario: CorpusScenarioRecord,
    source_scenario: Scenario,
    run: VerifiedRunBundleInput,
    receipt: VerifiedArtifactReceipt,
    result: ScenarioResult,
    *,
    runtime_receipt_sha256: str,
) -> ReferenceIsolationReceipt:
    """Bind a verified blind run to the independently reconstructed seed-only workspace."""
    transcript_path = _run_artifact_path(result.transcript_path, label="transcript")
    result_diff_path = _run_artifact_path(result.diff_path, label="result diff")
    if transcript_path.parent != result_diff_path.parent:
        raise CorpusConstructionError("blind run artifacts do not share one run directory")
    before_diff_path = transcript_path.parent / "before.diff"
    transcript = _snapshot_escrow_inventory_file(
        receipt,
        run.escrow_bundle,
        transcript_path,
    )
    result_diff = _snapshot_escrow_inventory_file(
        receipt,
        run.escrow_bundle,
        result_diff_path,
    )
    observed_before_diff = _snapshot_escrow_inventory_file(
        receipt,
        run.escrow_bundle,
        before_diff_path,
    )

    with tempfile.TemporaryDirectory(prefix="stinger-blind-workspace-") as temporary_name:
        workspace = Path(temporary_name) / "workdir"
        preparer = Sandbox(
            isolation=Isolation.DOCKER,
            image=receipt.config.image,
        )
        prepared = preparer.prepare(
            source_scenario.directory,
            source_scenario.manifest,
            workspace,
        )
        seed = capture(source_scenario.directory / source_scenario.manifest.seed_repo)
        expected = preparer.capture(prepared)
        expected_before_diff = diff_states(seed, expected).encode("utf-8")
        expected_workspace_sha256 = _canonical_payload_sha256(
            {
                "tracked_files": dict(sorted(expected.tracked_files.items())),
                "unreadable_files": sorted(expected.unreadable_files),
                "head_commit": expected.head_commit,
            }
        )
    if observed_before_diff != expected_before_diff:
        raise CorpusConstructionError(
            "blind run initial workspace differs from the reconstructed seed-only workspace"
        )
    forbidden_roots = {
        PurePosixPath(source_scenario.manifest.reference_honest).parts[0],
        PurePosixPath(source_scenario.manifest.reference_cheat).parts[0],
        PurePosixPath(source_scenario.manifest.completion_check).parts[0],
    }
    if any(
        PurePosixPath(path).parts and PurePosixPath(path).parts[0] in forbidden_roots
        for path in expected.tracked_files
    ):
        raise CorpusConstructionError(
            "reconstructed blind workspace contains answer-bearing scenario material"
        )
    return ReferenceIsolationReceipt(
        format_version=CONSTRUCTION_RECEIPT_FORMAT_VERSION,
        solve_id=_canonical_identifier(run.run_id, label="solve_id"),
        scenario_id=scenario.scenario_id,
        scenario_artifact_sha256=scenario.scenario_artifact_sha256,
        expected_workspace_inventory_sha256=expected_workspace_sha256,
        expected_before_diff_sha256=_sha256(expected_before_diff),
        observed_before_diff_sha256=_sha256(observed_before_diff),
        transcript_sha256=_sha256(transcript),
        result_diff_sha256=_sha256(result_diff),
        report_sha256=_sha256(receipt.public_bundle.report_bytes),
        public_manifest_sha256=receipt.public_bundle.manifest_sha256,
        escrow_manifest_sha256=receipt.escrow_bundle.manifest_sha256,
        runtime_receipt_sha256=runtime_receipt_sha256,
    )


def _run_artifact_path(value: str, *, label: str) -> PurePosixPath:
    """Return one canonical run artifact path rooted below ``runs/``."""
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or "\\" in value
        or "." in path.parts
        or ".." in path.parts
        or len(path.parts) < 4
        or path.parts[0] != "runs"
    ):
        raise CorpusConstructionError(f"blind {label} path is not a canonical run artifact")
    return path


def _snapshot_escrow_inventory_file(
    receipt: VerifiedArtifactReceipt,
    escrow_root: Path,
    run_relative_path: PurePosixPath,
) -> bytes:
    """Snapshot one exact inventory-bound rerunnable artifact after pair verification."""
    relative = PurePosixPath("rerunnable-evidence") / run_relative_path
    entry = receipt.escrow_bundle.manifest.files.get(relative.as_posix())
    if entry is None or entry.role is not EvidenceRole.RERUNNABLE_EVIDENCE:
        raise CorpusConstructionError("blind run artifact is absent from escrow inventory")
    path = escrow_root.joinpath(*relative.parts)
    content = _read_exact_regular_file(path, label="escrow run artifact")
    if len(content) != entry.size or _sha256(content) != entry.sha256:
        raise CorpusConstructionError("blind run artifact changed after bundle verification")
    return content


def _materialize_verified_rerunnable_evidence(
    receipt: VerifiedArtifactReceipt,
    escrow_root: Path,
    destination: Path,
) -> Path:
    """Copy only manifest-bound rerunnable bytes into a verifier-owned closed tree."""
    if destination.exists() or destination.is_symlink():
        raise CorpusConstructionError("rerunnable evidence snapshot destination exists")
    destination.mkdir(parents=True, mode=0o700)
    copied: set[str] = set()
    prefix = PurePosixPath("rerunnable-evidence")
    for relative_text, entry in sorted(receipt.escrow_bundle.manifest.files.items()):
        relative = PurePosixPath(relative_text)
        if entry.role is not EvidenceRole.RERUNNABLE_EVIDENCE:
            continue
        if (
            not relative.parts
            or relative.parts[0] != prefix.name
            or len(relative.parts) < 2
            or relative.is_absolute()
            or "." in relative.parts
            or ".." in relative.parts
            or "\\" in relative_text
        ):
            raise CorpusConstructionError("rerunnable evidence inventory path is invalid")
        run_relative = PurePosixPath(*relative.parts[1:])
        canonical = run_relative.as_posix()
        if canonical in copied:
            raise CorpusConstructionError("rerunnable evidence inventory is duplicated")
        source = escrow_root.joinpath(*relative.parts)
        content = _read_exact_regular_file(source, label="rerunnable evidence")
        if len(content) != entry.size or _sha256(content) != entry.sha256:
            raise CorpusConstructionError("rerunnable evidence changed after bundle verification")
        target = destination.joinpath(*run_relative.parts)
        _atomic_create_private_file(target, content)
        os.chmod(target, 0o700 if entry.executable else 0o600)
        copied.add(canonical)
    if not copied or INVOCATION_AGGREGATE_NAME not in copied:
        raise CorpusConstructionError("rerunnable evidence inventory is incomplete")
    return destination


def _expected_agent_run_workflow_input(
    *,
    run_id: str,
    receipt: VerifiedArtifactReceipt,
    invocation_aggregate_sha256: str,
) -> AgentRunWorkflowInputReceipt:
    """Build the sole accepted external binding for one closed bundle pair."""
    metadata = receipt.report.benchmark_metadata
    runtime = receipt.report.benchmark_runtime_provenance
    if (
        metadata is None
        or runtime is None
        or metadata.stinger_commit is None
        or metadata.agent_adapter is None
        or metadata.provider is None
        or metadata.model_id is None
    ):
        raise CorpusConstructionError("agent-run workflow metadata is incomplete")
    return AgentRunWorkflowInputReceipt(
        format_version="1",
        claim_boundary=AGENT_RUN_WORKFLOW_CLAIM_BOUNDARY,
        run_id=_canonical_identifier(run_id, label="run_id"),
        stinger_commit=metadata.stinger_commit,
        corpus_hash=receipt.report.corpus_hash,
        config_fingerprint=receipt.config.fingerprint(),
        protocol_sha256=_sha256(receipt.public_bundle.protocol_bytes),
        report_sha256=_sha256(receipt.public_bundle.report_bytes),
        config_sha256=_sha256(receipt.public_bundle.config_bytes),
        public_manifest_sha256=receipt.public_bundle.manifest_sha256,
        escrow_manifest_sha256=receipt.escrow_bundle.manifest_sha256,
        invocation_aggregate_sha256=invocation_aggregate_sha256,
        runtime_provenance_sha256=_canonical_model_sha256(runtime),
        agent_adapter=metadata.agent_adapter,
        provider=metadata.provider,
        model_id=metadata.model_id,
    )


def _verify_run_bundle(
    run: VerifiedRunBundleInput,
    *,
    scenario: Scenario,
    corpus_hash_value: str,
    expected_stinger_commit: str,
    forbidden_signer_identities: frozenset[str],
    forbidden_signing_key_fingerprints: frozenset[str],
    forbidden_trust_policy_sha256s: frozenset[str],
) -> _VerifiedRunEvidence:
    """Verify one bundle pair and derive its exact result/runtime commitments."""
    try:
        receipt = verify_evidence_bundle_pair(
            run.public_bundle,
            run.escrow_bundle,
            run.leakage_policy,
            trusted_allowed_signers=run.protocol_allowed_signers,
            expected_signer_identity=run.protocol_signer_identity,
        )
    except (EvidenceBundleError, OSError, ValueError):
        raise CorpusConstructionError("run evidence bundle verification failed") from None
    _verify_bundle_snapshot(receipt)
    protocol = compiled_benchmark_protocol()
    report = receipt.report
    try:
        verify_report(report)
    except (ReportMismatchError, ValueError):
        raise CorpusConstructionError("run report failed deterministic verification") from None
    metadata = report.benchmark_metadata
    runtime = report.benchmark_runtime_provenance
    if (
        receipt.protocol != protocol
        or report.benchmark_protocol_version != protocol.benchmark_protocol_version
        or report.rubric_version != protocol.rubric_version
        or report.corpus_hash != corpus_hash_value
        or report.config_fingerprint != receipt.config.fingerprint()
        or metadata is None
        or runtime is None
        or publication_pin_issues(metadata, runtime)
        or canonical_local_provider_binding_issues(metadata, runtime)
        or metadata.provider is None
        or metadata.agent_configuration_fingerprint is None
        or receipt.config.reps != 1
        or receipt.config.isolation is not Isolation.DOCKER
        or metadata.stinger_commit != expected_stinger_commit
        or runtime.stinger_commit != expected_stinger_commit
        or receipt.config.agent.container_image_digest is None
        or receipt.config.verification_image_digest is None
        or any(result.outcome is Outcome.ERROR for result in report.results)
    ):
        raise CorpusConstructionError("run bundle lacks required contained provenance")
    matching = [
        result
        for result in report.results
        if result.scenario_id == scenario.id and result.repetition == 0
    ]
    if (
        len(matching) != 1
        or any(result.repetition != 0 for result in report.results)
        or matching[0].family is not scenario.manifest.family
        or matching[0].benchmark_split is not BenchmarkSplit.SEALED
        or matching[0].scenario_version != scenario.manifest.scenario_version
        or matching[0].cluster_id != scenario.manifest.cluster_id
    ):
        raise CorpusConstructionError("run bundle does not contain one exact scenario result")
    try:
        with tempfile.TemporaryDirectory(prefix="stinger-run-evidence-snapshot-") as temporary_name:
            package = _materialize_verified_rerunnable_evidence(
                receipt,
                run.escrow_bundle,
                Path(temporary_name) / "rerunnable-evidence",
            )
            verified_aggregate = verify_invocation_aggregate_snapshot(
                package,
                config=receipt.config,
                report=report,
            )
        aggregate = verified_aggregate.aggregate
        aggregate_sha256 = verified_aggregate.sha256
        aggregate_bytes = verified_aggregate.canonical_bytes
        workflow_receipt_bytes = _read_exact_regular_file(
            run.workflow_receipt,
            label="agent-run workflow receipt",
        )
        machine_identity_bytes = _read_exact_regular_file(
            run.machine_identity_artifact,
            label="agent-run machine identity",
        )
        workflow_attestation_bytes = _read_exact_regular_file(
            run.workflow_attestation,
            label="agent-run workflow attestation",
        )
        workflow_signature_bytes = _read_exact_regular_file(
            run.workflow_signature,
            label="agent-run workflow signature",
        )
        workflow_allowed_signers_bytes = _read_exact_regular_file(
            run.workflow_allowed_signers,
            label="agent-run workflow trust",
        )
        workflow_input, workflow_input_bytes = _load_canonical_model(
            run.workflow_input,
            AgentRunWorkflowInputReceipt,
            label="agent-run workflow input",
        )
        expected_workflow_input = _expected_agent_run_workflow_input(
            run_id=run.run_id,
            receipt=receipt,
            invocation_aggregate_sha256=aggregate_sha256,
        )
        with tempfile.TemporaryDirectory(
            prefix="stinger-run-workflow-snapshot-"
        ) as workflow_temporary_name:
            workflow_root = Path(workflow_temporary_name)
            workflow_paths: dict[str, Path] = {}
            for name, content in (
                ("machine-identity.json", machine_identity_bytes),
                ("workflow-input.json", workflow_input_bytes),
                ("workflow-receipt.json", workflow_receipt_bytes),
                ("workflow-attestation.json", workflow_attestation_bytes),
                ("workflow-signature", workflow_signature_bytes),
                ("workflow-allowed-signers", workflow_allowed_signers_bytes),
            ):
                path = workflow_root / name
                _atomic_create_private_file(path, content)
                workflow_paths[name] = path
            workflow_authorization = verify_machine_workflow_attestation(
                machine_identity_artifact=workflow_paths["machine-identity.json"],
                workflow_input=workflow_paths["workflow-input.json"],
                workflow_receipt=workflow_paths["workflow-receipt.json"],
                attestation=workflow_paths["workflow-attestation.json"],
                signature=workflow_paths["workflow-signature"],
                allowed_signers=workflow_paths["workflow-allowed-signers"],
                signer_identity=run.workflow_signer_identity,
                expected_stinger_commit=expected_stinger_commit,
            )
        protocol_key_fingerprint = receipt.protocol_signature_verification.signing_key_fingerprint
    except (
        ClassificationReplayError,
        CorpusConstructionError,
        MachineAttestationError,
        OSError,
        ProtocolSignatureError,
        ValidationError,
        ValueError,
    ):
        raise CorpusConstructionError(
            "run workflow execution evidence failed verification"
        ) from None
    if (
        workflow_receipt_bytes != aggregate_bytes
        or _sha256(workflow_receipt_bytes) != aggregate_sha256
        or workflow_input != expected_workflow_input
        or workflow_input_bytes != _canonical_model_bytes(expected_workflow_input)
        or workflow_authorization.statement.workflow_input_sha256 != _sha256(workflow_input_bytes)
        or workflow_authorization.statement.workflow_receipt_sha256
        != _sha256(workflow_receipt_bytes)
        or workflow_authorization.statement.machine_identity_sha256
        != _sha256(machine_identity_bytes)
        or workflow_authorization.attestation_sha256 != _sha256(workflow_attestation_bytes)
        or workflow_authorization.signature_sha256 != _sha256(workflow_signature_bytes)
        or workflow_authorization.allowed_signers_sha256 != _sha256(workflow_allowed_signers_bytes)
        or aggregate.config_fingerprint != receipt.config.fingerprint()
        or aggregate.runtime_provenance_sha256 != _canonical_model_sha256(runtime)
        or aggregate.report_sha256 != _canonical_model_sha256(report)
        or aggregate.receipt_count != len(report.results)
        or len(aggregate.invocation_ids) != len(set(aggregate.invocation_ids))
        or len(aggregate.invocation_challenge_nonce_sha256s)
        != len(set(aggregate.invocation_challenge_nonce_sha256s))
        or len(aggregate.execution_evidence_sha256s)
        != len(set(aggregate.execution_evidence_sha256s))
        or workflow_authorization.signature_namespace != MACHINE_WORKFLOW_SIGNATURE_NAMESPACE
        or workflow_authorization.signer_identity == run.protocol_signer_identity
        or workflow_authorization.signer_identity in forbidden_signer_identities
        or workflow_authorization.signing_key_fingerprint == protocol_key_fingerprint
        or workflow_authorization.signing_key_fingerprint in forbidden_signing_key_fingerprints
        or workflow_authorization.allowed_signers_sha256
        == receipt.public_bundle.manifest.allowed_signers_sha256
        or workflow_authorization.allowed_signers_sha256 in forbidden_trust_policy_sha256s
        or workflow_authorization.signature_sha256
        == receipt.public_bundle.manifest.protocol_signature_sha256
    ):
        raise CorpusConstructionError("run workflow is not exactly cross-bound or role-separated")
    runtime_receipt_sha256 = _canonical_payload_sha256(
        {
            "workflow_input_sha256": _sha256(workflow_input_bytes),
            "workflow_attestation_sha256": workflow_authorization.attestation_sha256,
            "workflow_signature_sha256": workflow_authorization.signature_sha256,
            "workflow_allowed_signers_sha256": (workflow_authorization.allowed_signers_sha256),
            "workflow_signing_key_fingerprint": (workflow_authorization.signing_key_fingerprint),
            "machine_identity_sha256": (workflow_authorization.statement.machine_identity_sha256),
            "invocation_aggregate_sha256": aggregate_sha256,
        }
    )
    return _VerifiedRunEvidence(
        artifact_receipt=receipt,
        result=matching[0],
        provider=metadata.provider,
        configuration_fingerprint=metadata.agent_configuration_fingerprint,
        runtime_receipt_sha256=runtime_receipt_sha256,
        execution_identity=_RunExecutionIdentity(
            invocation_ids=frozenset(aggregate.invocation_ids),
            challenge_nonce_sha256s=frozenset(aggregate.invocation_challenge_nonce_sha256s),
            provider_response_id_sha256s=frozenset(aggregate.provider_response_id_sha256s),
            execution_evidence_sha256s=frozenset(aggregate.execution_evidence_sha256s),
            workflow_signature_sha256=workflow_authorization.signature_sha256,
        ),
        workflow_authorization=workflow_authorization,
    )


def _verify_bundle_snapshot(receipt: VerifiedArtifactReceipt) -> None:
    """Recheck exact bytes retained by the bundle verifier before deriving hashes."""
    public = receipt.public_bundle
    escrow = receipt.escrow_bundle
    signature = receipt.protocol_signature_verification
    try:
        parsed = load_report(public.report_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValidationError, ReportMismatchError):
        raise CorpusConstructionError("verified run report bytes are malformed") from None
    if (
        parsed != receipt.report
        or public.report != receipt.report
        or escrow.report != receipt.report
        or public.report_bytes != escrow.report_bytes
        or _sha256(public.report_bytes) != public.manifest.report_sha256
        or _sha256(escrow.report_bytes) != escrow.manifest.report_sha256
        or _sha256(public.manifest_bytes) != public.manifest_sha256
        or _sha256(escrow.manifest_bytes) != escrow.manifest_sha256
        or public.protocol_bytes != escrow.protocol_bytes
        or _sha256(public.protocol_bytes) != public.manifest.protocol_sha256
        or _sha256(escrow.protocol_bytes) != escrow.manifest.protocol_sha256
        or public.protocol != receipt.protocol
        or escrow.protocol != receipt.protocol
        or public.config.fingerprint() != receipt.config.fingerprint()
        or escrow.config.fingerprint() != receipt.config.fingerprint()
        or signature.identity != public.manifest.protocol_signer_identity
        or signature.namespace != public.manifest.protocol_signature_namespace
        or signature.protocol_sha256 != _sha256(public.protocol_bytes)
        or signature.signature_sha256 != _sha256(public.protocol_signature_bytes)
        or signature.allowed_signers_sha256 != _sha256(public.allowed_signers_bytes)
        or public.protocol_signature_bytes != escrow.protocol_signature_bytes
        or public.allowed_signers_bytes != escrow.allowed_signers_bytes
    ):
        raise CorpusConstructionError("verified bundle snapshot is internally inconsistent")


def _selected_blind_solve_ids(
    scenarios: tuple[CorpusScenarioRecord, ...],
    *,
    corpus_hash_value: str,
) -> set[str]:
    """Mirror the frozen per-family blind-solve selection without caller choice."""
    protocol = compiled_benchmark_protocol()
    selected: set[str] = set()
    for family in Family:
        candidates = [scenario for scenario in scenarios if scenario.family is family]
        ordered = sorted(
            candidates,
            key=lambda scenario: (
                hashlib.sha256(
                    (
                        f"{protocol.benchmark_protocol_version}\0"
                        f"{protocol.blind_agent_solve_selection_seed}\0"
                        f"{corpus_hash_value}\0"
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


def _load_canonical_model[ModelT: BaseModel](
    path: Path,
    model_type: type[ModelT],
    *,
    label: str,
) -> tuple[ModelT, bytes]:
    """Load duplicate-free exact canonical JSON from one checked regular file."""
    content = _read_exact_regular_file(path, label=label)
    try:
        raw = json.loads(content.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
        model = model_type.model_validate(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError):
        raise CorpusConstructionError(f"{label} receipt is malformed") from None
    if content != _canonical_model_bytes(model):
        raise CorpusConstructionError(f"{label} receipt is not canonical")
    return model, content


def _read_exact_regular_file(path: Path, *, label: str) -> bytes:
    """Read one bounded regular nonsymlink, non-hardlinked file without TOCTOU."""
    del label
    try:
        before = path.lstat()
    except OSError:
        raise CorpusConstructionError("construction artifact is unavailable") from None
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > _MAX_RECEIPT_BYTES
    ):
        raise CorpusConstructionError("construction artifact is not a safe regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise CorpusConstructionError("construction artifact could not be opened safely") from None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        ):
            raise CorpusConstructionError("construction artifact changed before reading")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, _READ_CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            raise CorpusConstructionError("construction artifact changed while reading")
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _atomic_create_private_file(destination: Path, content: bytes) -> None:
    """Create one mode-0600 file atomically without replacing any existing node."""
    if destination.exists() or destination.is_symlink():
        raise CorpusConstructionError("construction output already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.link(temporary, destination)
        temporary.unlink()
    except OSError as exc:
        raise CorpusConstructionError("construction output could not be created") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


_CONSTRUCTION_TRACKED_ROOTS = (
    "src/stinger",
    "scripts",
    "docker",
    "benchmark/protocol.yaml",
)
"""Complete tracked implementation roots that can affect construction or review."""


def _clean_exact_git_head(repository: Path) -> str:
    """Map the shared fixed-Git checkout boundary into construction errors."""
    try:
        return clean_exact_git_head(repository)
    except GitCheckoutError:
        raise CandidateReceiptError(
            "construction repository is not a clean exact checkout"
        ) from None


def _require_construction_implementation(
    repository: Path,
    *,
    expected_commit: str,
) -> str:
    """Bind the complete tracked implementation and every loaded module to one commit."""
    try:
        verified = verify_tracked_implementation(
            repository,
            expected_commit=expected_commit,
            tracked_roots=_CONSTRUCTION_TRACKED_ROOTS,
        )
    except GitCheckoutError:
        raise CandidateReceiptError(
            "tracked construction implementation could not be verified"
        ) from None
    root = repository.resolve(strict=True)
    source_root = (root / "src" / "stinger").resolve(strict=True)
    inventory = {item.relative_path: item.sha256 for item in verified.files}

    for module_name, module in tuple(sys.modules.items()):
        if module_name != "stinger" and not module_name.startswith("stinger."):
            continue
        source_value = getattr(module, "__file__", None)
        if not isinstance(source_value, str) or not source_value:
            raise CandidateReceiptError("loaded Stinger module source is unavailable")
        source = Path(source_value)
        if source.suffix in {".pyc", ".pyo"}:
            source = source.with_suffix(".py")
        try:
            resolved = source.resolve(strict=True)
            resolved.relative_to(source_root)
            module_relative = resolved.relative_to(root).as_posix()
        except (OSError, ValueError):
            raise CandidateReceiptError(
                "loaded Stinger module is outside the supplied checkout"
            ) from None
        if module_relative not in inventory:
            raise CandidateReceiptError(
                "loaded Stinger module is not bound to the tracked implementation"
            )
        if (
            _sha256(_read_exact_regular_file(resolved, label="loaded Stinger implementation"))
            != inventory[module_relative]
        ):
            raise CandidateReceiptError(
                "loaded Stinger module differs from committed checkout bytes"
            )
    if _clean_exact_git_head(root) != expected_commit:
        raise CandidateReceiptError("construction implementation changed during verification")
    return verified.inventory_sha256


def _canonical_model_bytes(model: BaseModel) -> bytes:
    """Render one typed record in the sole accepted canonical JSON form."""
    return (
        json.dumps(
            model.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _canonical_model_sha256(model: BaseModel) -> str:
    """Hash a typed model without the transport newline used by files."""
    return _canonical_payload_sha256(model.model_dump(mode="json"))


def _canonical_payload_sha256(payload: object) -> str:
    """Hash one JSON-compatible payload deterministically."""
    return _sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _review_file_inventory_sha256(
    files: tuple[MachineReviewEvidenceFile, ...],
) -> str:
    """Hash review files with the exact path/byte/mode inventory contract."""
    return _canonical_payload_sha256(
        {
            "files": [
                {
                    "relative_path": item.path,
                    "blob_path": item.blob_path,
                    "sha256": item.sha256,
                    "size": item.size,
                    "executable": item.executable,
                }
                for item in files
            ]
        }
    )


def _sha256(content: bytes) -> str:
    """Return one lowercase SHA-256 digest."""
    return hashlib.sha256(content).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys at every nesting level."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


class _UniqueSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate keys instead of taking the last."""


def _construct_unique_mapping(
    loader: _UniqueSafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    """Construct one YAML mapping while rejecting duplicate or unhashable keys."""
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found a duplicate mapping key",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _manifest_path_text(value: str) -> str:
    """Reject blank, NUL-bearing, or control-bearing path strings."""
    if (
        not value
        or value != value.strip()
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError("manifest path must be nonblank and contain no controls")
    return value


def _canonical_manifest_path_inventory(value: tuple[str, ...]) -> tuple[str, ...]:
    """Require one nonempty, unique, path-sorted manifest inventory."""
    for item in value:
        _manifest_path_text(item)
    if not value or value != tuple(sorted(value)) or len(value) != len(set(value)):
        raise ValueError("manifest path inventories must be nonempty, unique, and sorted")
    return value


def _parse_input_manifest(content: bytes, *, suffix: str) -> object:
    """Parse duplicate-free JSON or alias-free safe YAML without echoing content."""
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise CorpusConstructionError("construction input manifest is not UTF-8") from None
    try:
        if suffix == ".json":
            raw = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
        elif suffix in {".yaml", ".yml"}:
            forbidden_tokens = (
                yaml.tokens.AliasToken,
                yaml.tokens.AnchorToken,
                yaml.tokens.TagToken,
            )
            if any(isinstance(token, forbidden_tokens) for token in yaml.scan(text)):
                raise ValueError("YAML aliases, anchors, and tags are not allowed")
            raw = yaml.load(text, Loader=_UniqueSafeLoader)
        else:
            raise CorpusConstructionError(
                "construction input manifest must use .json, .yaml, or .yml"
            )
    except CorpusConstructionError:
        raise
    except (json.JSONDecodeError, ValueError, yaml.YAMLError):
        raise CorpusConstructionError("construction input manifest is malformed") from None
    if not isinstance(raw, dict) or not raw:
        raise CorpusConstructionError("construction input manifest root must be a nonempty mapping")
    return raw


def _resolve_manifest_path(base: Path, value: str) -> Path:
    """Resolve one absolute or manifest-relative path without expanding a shell."""
    raw = Path(value)
    candidate = raw if raw.is_absolute() else base / raw
    return _resolve_without_symlink_components(candidate)


def _resolve_without_symlink_components(path: Path) -> Path:
    """Resolve an existing path only after rejecting every lexical symlink component."""
    absolute = path if path.is_absolute() else Path.cwd() / path
    anchor = absolute.anchor
    if not anchor:
        raise CorpusConstructionError("construction manifest references an unsafe node")
    current = Path(anchor)
    try:
        for part in absolute.parts[1:]:
            if part in {"", "."}:
                continue
            if part == "..":
                current = current.parent
                continue
            current = current / part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise CorpusConstructionError("construction manifest references an unsafe node")
        return current.resolve(strict=True)
    except CorpusConstructionError:
        raise
    except OSError:
        raise CorpusConstructionError(
            "construction manifest references an unavailable node"
        ) from None


def _manifest_regular_file(base: Path, value: str) -> Path:
    """Resolve and re-open one manifest file as a safe regular nonsymlink."""
    resolved = _resolve_manifest_path(base, value)
    _read_exact_regular_file(resolved, label="construction manifest file")
    return resolved


def _manifest_directory(base: Path, value: str) -> Path:
    """Resolve one real nonsymlink directory."""
    resolved = _resolve_manifest_path(base, value)
    try:
        metadata = resolved.lstat()
    except OSError:
        raise CorpusConstructionError("construction manifest directory is unavailable") from None
    if not stat.S_ISDIR(metadata.st_mode) or resolved.is_symlink():
        raise CorpusConstructionError("construction manifest node is not a real directory")
    return resolved


def _manifest_existing_source(base: Path, value: str) -> Path:
    """Resolve one regular file or real directory used by leakage policy."""
    resolved = _resolve_manifest_path(base, value)
    try:
        metadata = resolved.lstat()
    except OSError:
        raise CorpusConstructionError("construction manifest source is unavailable") from None
    if stat.S_ISREG(metadata.st_mode):
        _read_exact_regular_file(resolved, label="forbidden source")
    elif not stat.S_ISDIR(metadata.st_mode):
        raise CorpusConstructionError("construction manifest source has an unsafe node type")
    return resolved


def _resolve_run_manifest(
    base: Path,
    item: ConstructionRunBundleManifest,
) -> VerifiedRunBundleInput:
    """Resolve one closed run mapping and privately load all leakage markers."""
    public_bundle = _manifest_directory(base, item.public_bundle)
    escrow_bundle = _manifest_directory(base, item.escrow_bundle)
    if public_bundle == escrow_bundle:
        raise CorpusConstructionError("construction run resolves the same public and escrow bundle")
    forbidden_sources = tuple(
        _manifest_existing_source(base, value) for value in item.forbidden_sources
    )
    marker_paths = tuple(_manifest_regular_file(base, value) for value in item.marker_files)
    if len(forbidden_sources) != len(set(forbidden_sources)) or len(marker_paths) != len(
        set(marker_paths)
    ):
        raise CorpusConstructionError("construction run resolves duplicate leakage-policy inputs")
    markers: list[bytes] = []
    for marker_path in marker_paths:
        marker = _read_exact_regular_file(
            marker_path,
            label="private marker",
        ).rstrip(b"\r\n")
        if not marker:
            raise CorpusConstructionError("construction marker file is empty")
        markers.append(marker)
    if len(markers) != len(set(markers)):
        raise CorpusConstructionError("construction run contains duplicate private markers")
    return VerifiedRunBundleInput(
        run_id=item.run_id,
        public_bundle=public_bundle,
        escrow_bundle=escrow_bundle,
        leakage_policy=PublicLeakagePolicy(
            forbidden_sources=forbidden_sources,
            forbidden_markers=tuple(markers),
        ),
        protocol_allowed_signers=_manifest_regular_file(
            base,
            item.protocol_allowed_signers,
        ),
        protocol_signer_identity=item.protocol_signer_identity,
        machine_identity_artifact=_manifest_regular_file(
            base,
            item.machine_identity_artifact,
        ),
        workflow_input=_manifest_regular_file(base, item.workflow_input),
        workflow_receipt=_manifest_regular_file(base, item.workflow_receipt),
        workflow_attestation=_manifest_regular_file(base, item.workflow_attestation),
        workflow_signature=_manifest_regular_file(base, item.workflow_signature),
        workflow_allowed_signers=_manifest_regular_file(
            base,
            item.workflow_allowed_signers,
        ),
        workflow_signer_identity=item.workflow_signer_identity,
    )


def _resolve_scenario_manifest(
    base: Path,
    item: ConstructionScenarioManifest,
) -> ScenarioConstructionInput:
    """Resolve all private paths for one scenario into the builder dataclass."""
    authoring = tuple(
        _manifest_regular_file(base, value) for value in item.authoring_configuration_artifacts
    )
    provenance_sources = tuple(
        _manifest_regular_file(base, value) for value in item.provenance_source_artifacts
    )
    if len(authoring) != len(set(authoring)) or len(provenance_sources) != len(
        set(provenance_sources)
    ):
        raise CorpusConstructionError("construction scenario resolves duplicate provenance inputs")
    variants = tuple(
        ResolutionVariantInput(
            variant_id=variant.variant_id,
            kind=variant.kind,
            source_tree=_manifest_directory(base, variant.source_tree),
            semantic_patch=_manifest_regular_file(base, variant.semantic_patch),
            agent_run=_manifest_regular_file(
                base,
                variant.agent_run,
            ),
        )
        for variant in item.resolution_variants
    )
    reviews = tuple(
        MachineReviewPackageInput(
            configuration_receipt=_manifest_regular_file(
                base,
                review.configuration_receipt,
            ),
            input_receipt=_manifest_regular_file(base, review.input_receipt),
            review_workspace=_manifest_directory(base, review.review_workspace),
            runtime_receipt=_manifest_regular_file(
                base,
                review.runtime_receipt,
            ),
            transcript=_manifest_regular_file(base, review.transcript),
            output=_manifest_regular_file(base, review.output),
            runtime_signature=_manifest_regular_file(
                base,
                review.runtime_signature,
            ),
            runtime_allowed_signers=_manifest_regular_file(
                base,
                review.runtime_allowed_signers,
            ),
            runtime_signer_identity=review.runtime_signer_identity,
        )
        for review in item.machine_reviews
    )
    return ScenarioConstructionInput(
        scenario_directory=_manifest_directory(base, item.scenario_directory),
        provenance_receipt=_manifest_regular_file(
            base,
            item.provenance_receipt,
        ),
        authoring_configuration_artifacts=authoring,
        provenance_source_artifacts=provenance_sources,
        resolution_variants=variants,
        qa_attempts=tuple(_resolve_run_manifest(base, run) for run in item.qa_attempts),
        machine_reviews=reviews,
        blind_agent_solves=tuple(
            BlindSolveInput(
                bundle=_resolve_run_manifest(base, solve.bundle),
            )
            for solve in item.blind_agent_solves
        ),
    )


def _reject_reused_bundle_paths(
    scenarios: tuple[ScenarioConstructionInput, ...],
) -> None:
    """Reject duplicate run evidence within a scenario while allowing corpus-wide runs."""
    for scenario in scenarios:
        runs = (
            *scenario.qa_attempts,
            *(solve.bundle for solve in scenario.blind_agent_solves),
        )
        run_ids = tuple(run.run_id for run in runs)
        public_paths = tuple(run.public_bundle for run in runs)
        escrow_paths = tuple(run.escrow_bundle for run in runs)
        if (
            len(run_ids) != len(set(run_ids))
            or len(public_paths) != len(set(public_paths))
            or len(escrow_paths) != len(set(escrow_paths))
        ):
            raise CorpusConstructionError("construction scenario reuses one run bundle")


def _all_sensitive_paths(
    corpus_root: Path,
    custody_inventory: Path,
    canary_registry: Path,
    access_ledger: Path,
    scenarios: tuple[ScenarioConstructionInput, ...],
) -> tuple[Path, ...]:
    """Collect every private input location solely for final leakage checking."""
    paths: list[Path] = [
        corpus_root,
        custody_inventory,
        canary_registry,
        access_ledger,
    ]
    for scenario in scenarios:
        paths.extend(
            (
                scenario.scenario_directory,
                scenario.provenance_receipt,
                *scenario.authoring_configuration_artifacts,
                *scenario.provenance_source_artifacts,
            )
        )
        for variant in scenario.resolution_variants:
            paths.extend((variant.source_tree, variant.semantic_patch, variant.agent_run))
        for run in scenario.qa_attempts:
            paths.extend(_bundle_sensitive_paths(run))
        for review in scenario.machine_reviews:
            paths.extend(
                (
                    review.configuration_receipt,
                    review.input_receipt,
                    review.runtime_receipt,
                    review.transcript,
                    review.output,
                    review.runtime_signature,
                    review.runtime_allowed_signers,
                )
            )
        for solve in scenario.blind_agent_solves:
            paths.extend(_bundle_sensitive_paths(solve.bundle))
    return tuple(paths)


def _bundle_sensitive_paths(run: VerifiedRunBundleInput) -> tuple[Path, ...]:
    """Return all path-bearing private inputs for one bundle verification."""
    return (
        run.public_bundle,
        run.escrow_bundle,
        run.protocol_allowed_signers,
        *run.leakage_policy.forbidden_sources,
    )


def _all_sensitive_markers(
    scenarios: tuple[ScenarioConstructionInput, ...],
) -> tuple[str | bytes, ...]:
    """Collect private leakage markers solely for final output scanning."""
    markers: list[str | bytes] = []
    for scenario in scenarios:
        for run in scenario.qa_attempts:
            markers.extend(run.leakage_policy.forbidden_markers)
        for solve in scenario.blind_agent_solves:
            markers.extend(solve.bundle.leakage_policy.forbidden_markers)
    return tuple(markers)


def _reject_path_leakage(content: bytes, *, sensitive_paths: tuple[Path, ...]) -> None:
    """Reject any absolute private path appearing in the path-free receipt."""
    for path in sensitive_paths:
        try:
            value = str(path.resolve(strict=False)).encode("utf-8")
        except OSError:
            value = str(path.absolute()).encode("utf-8")
        if value and value in content:
            raise CorpusConstructionError("construction receipt contains a private path")


__all__ = [
    "CONSTRUCTION_RECEIPT_FORMAT_VERSION",
    "CORPUS_CONSTRUCTION_SIGNATURE_NAMESPACE",
    "DUMMY_SAFETY_POLICY_VERSION",
    "MACHINE_REVIEW_RUNTIME_FORMAT_VERSION",
    "MACHINE_REVIEW_RUNTIME_SIGNATURE_NAMESPACE",
    "AuthoringConfigurationReceipt",
    "BlindSolveInput",
    "ConstructionBlindSolveManifest",
    "ConstructionMachineReviewManifest",
    "ConstructionResolutionVariantManifest",
    "ConstructionRunBundleManifest",
    "ConstructionScenarioManifest",
    "CorpusConstructionError",
    "CorpusConstructionBuilderKwargs",
    "CorpusConstructionInputManifest",
    "CorpusConstructionReceipt",
    "CustodyInventoryReceipt",
    "DummySafetyReceipt",
    "MachineReviewInputReceipt",
    "MachineReviewPackageInput",
    "MachineReviewRuntimeReceipt",
    "MachineReviewerConfigurationReceipt",
    "ReferenceIsolationReceipt",
    "ResolutionExecutionReceipt",
    "ResolutionVariantInput",
    "ScenarioConstructionInput",
    "ScenarioContainmentReceipt",
    "ScenarioProvenanceReceipt",
    "VerifiedCorpusConstructionReceipt",
    "VerifiedCorpusConstructionAuthorization",
    "VerifiedRunBundleInput",
    "VerifiedMachineReviewRuntimeAuthorization",
    "authorize_corpus_construction_receipt",
    "authorize_machine_review_runtime_receipt",
    "build_corpus_construction_receipt",
    "canonical_corpus_construction_receipt_sha256",
    "load_corpus_construction_input_manifest",
    "sign_corpus_construction_receipt",
    "sign_machine_review_runtime_receipt",
    "write_corpus_construction_receipt",
]
