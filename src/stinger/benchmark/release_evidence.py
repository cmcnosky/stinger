"""Artifact-derived release-evidence records and signed-statement payloads.

Construction is deliberately two-stage.  The first stage runs the repository master gate,
derives a :class:`ReleaseEvidenceRecord` from exact artifact bytes, and persists a private
preparation package containing a canonical path-free receipt plus the exact gate output.
The caller can then place that record into a finalized
:class:`BenchmarkReleaseSubmission`; the second stage reloads that package, re-verifies the
same clean commit and artifacts without rerunning the gate, and binds the finalized
submission without introducing a circular hash.

Master-gate output is hashed but never copied into the public statement or interpolated into
diagnostics.  It remains private inside the preparation package so the public record remains
reachable even when otherwise equivalent gate executions produce different output bytes.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from stinger.benchmark.gates import (
    BenchmarkReleaseSubmission,
    ReleaseEvidenceRecord,
    compiled_benchmark_protocol,
)
from stinger.benchmark.git_checkout import (
    DirtyGitCheckoutError,
    GitCheckoutError,
    clean_exact_git_head,
)

__all__ = [
    "MasterGateExecution",
    "MasterGateWorkflowReceipt",
    "PreparedReleaseEvidence",
    "ProtocolFreezeArtifact",
    "ReleaseArtifactManifest",
    "ReleaseEvidenceBuilderError",
    "ReleaseEvidencePreparationReceipt",
    "ReleaseEvidenceStatement",
    "TechnicalReportArtifact",
    "TechnicalReportSection",
    "ConflictDisclosureEntry",
    "ConflictsDisclosureArtifact",
    "CorrectionPolicyArtifact",
    "build_conflicts_disclosure_artifact",
    "build_correction_policy_artifact",
    "build_protocol_freeze_artifact",
    "build_release_artifact_manifest",
    "build_release_evidence_statement",
    "build_technical_report_artifact",
    "canonical_benchmark_submission_sha256",
    "canonical_release_evidence_record_sha256",
    "load_release_evidence_preparation_package",
    "prepare_release_evidence",
    "release_evidence_record_from_artifacts",
    "run_tracked_master_gate_workflow",
    "verify_release_evidence_statement",
    "verify_release_artifact_semantics",
    "write_release_artifact",
    "write_release_artifact_package",
    "write_release_evidence_preparation_package",
    "write_release_evidence_record",
    "write_release_evidence_statement",
]

_COMMIT_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_SEMVER_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
_READ_CHUNK = 1024 * 1024
_GIT_TIMEOUT_SECONDS = 120
_MASTER_GATE_TIMEOUT_SECONDS = 3600
_MASTER_GATE_REAP_TIMEOUT_SECONDS = 10
_PREPARATION_RECEIPT_FILE = "preparation-receipt.json"
_MASTER_GATE_RECEIPT_FILE = "master-gate-receipt.json"
_MASTER_GATE_OUTPUT_FILE = "master-gate-output.bin"
_PREPARATION_PACKAGE_FILES = frozenset(
    {
        _PREPARATION_RECEIPT_FILE,
        _MASTER_GATE_RECEIPT_FILE,
        _MASTER_GATE_OUTPUT_FILE,
    }
)
_MASTER_GATE_CLAIM_BOUNDARY = (
    "local signed toolchain and tracked-source evidence; not a hermetic build, remote "
    "service attestation, or independently trusted CI result"
)
_TECHNICAL_REPORT_SECTION_NAMES = (
    "claim-and-construct",
    "corpus-sampling-and-construction",
    "baseline-configurations",
    "results-and-uncertainty",
    "detector-boundaries-and-machine-veto-findings",
    "evidence-conformance-and-reproduction",
    "release-vendor-opportunity-and-corrections",
)
_CORRECTION_TRIGGERS = (
    "task-defect",
    "detector-defect",
    "leakage-event",
    "protocol-ambiguity",
)
_CORRECTION_ACTIONS = (
    "record-affected-version-evidence-and-impact",
    "quarantine-and-stop-affected-comparative-publication",
    "assign-new-scenario-corpus-protocol-or-tool-version",
    "recompute-or-mark-affected-results-superseded",
    "publish-correction-impact-and-conclusion-changes",
    "notify-affected-vendors-and-offer-rerun",
)
_TECHNICAL_REPORT_PLACEHOLDER_PATTERN = re.compile(
    r"(?i)(?:\b(?:todo|tbd|placeholder|fill[ -]?in)\b|template only|"
    r"delete this notice|what stinger (?:does|measures)|exact release artifact)"
)
_TOOL_DISTRIBUTIONS = ("coverage", "mypy", "pytest", "pytest-cov", "ruff")
_TOOLCHAIN_PROBE_LIMIT_BYTES = 16 * 1024 * 1024
_RELEASE_ARTIFACT_LIMIT_BYTES = 16 * 1024 * 1024
_FIXED_SYSTEM_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"
_TOOLCHAIN_PROBE = r"""
import hashlib
import importlib.metadata
import json
import os
import stat

names = json.loads(os.environ["STINGER_TOOL_DISTRIBUTIONS_JSON"])
records = []
for name in names:
    distribution = importlib.metadata.distribution(name)
    files = []
    for item in sorted(distribution.files or (), key=str):
        path = distribution.locate_file(item)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError("tool distribution contains a non-regular file")
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
        finally:
            os.close(descriptor)
        files.append({"path": str(item), "sha256": digest.hexdigest(), "size": size})
    if not files:
        raise RuntimeError("tool distribution contains no files")
    inventory = json.dumps(
        {"files": files},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    records.append(
        {
            "name": name,
            "version": distribution.version,
            "file_inventory_sha256": hashlib.sha256(inventory).hexdigest(),
            "file_count": len(files),
        }
    )
print(json.dumps(records, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
"""


class ReleaseEvidenceBuilderError(Exception):
    """Raised when exact machine evidence cannot support a release statement."""


@dataclass(frozen=True, slots=True)
class MasterGateExecution:
    """Exact exit status and merged output bytes from one master-gate execution."""

    returncode: int
    output: bytes


@dataclass(frozen=True, slots=True)
class _MasterGateWorkflowRun:
    """Private exact receipt and output returned by the fixed workflow runner."""

    receipt: MasterGateWorkflowReceipt
    output: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class _ArtifactBinding:
    """Private path-to-content binding retained only between the two build stages."""

    path: Path = field(repr=False)
    sha256: str


@dataclass(frozen=True, slots=True)
class PreparedReleaseEvidence:
    """Private first-stage result used to construct a finalized release statement."""

    receipt: ReleaseEvidencePreparationReceipt
    master_gate_receipt: MasterGateWorkflowReceipt
    master_gate_output: bytes = field(repr=False)
    repository: Path = field(repr=False)
    artifacts: tuple[_ArtifactBinding, ...] = field(repr=False)

    @property
    def record(self) -> ReleaseEvidenceRecord:
        """Return the public record embedded in the private preparation receipt."""
        return self.receipt.release_evidence

    @property
    def benchmark_protocol_version(self) -> str:
        """Return the protocol version bound by the preparation receipt."""
        return self.receipt.benchmark_protocol_version

    @property
    def rubric_version(self) -> str:
        """Return the rubric version bound by the preparation receipt."""
        return self.receipt.rubric_version

    @property
    def corpus_version(self) -> str:
        """Return the corpus version bound by the preparation receipt."""
        return self.receipt.corpus_version

    @property
    def corpus_hash(self) -> str:
        """Return the corpus hash bound by the preparation receipt."""
        return self.receipt.corpus_hash

    @property
    def stinger_commit(self) -> str:
        """Return the exact clean commit that passed the master gate."""
        return self.receipt.stinger_commit

    @property
    def release_artifacts(self) -> ReleaseArtifactManifest:
        """Return the parsed semantic artifacts embedded in the private receipt."""
        return self.receipt.release_artifacts


class _ClosedModel(BaseModel):
    """Immutable closed schema for a separately signed release statement."""

    model_config = ConfigDict(extra="forbid", frozen=True)


def _model_semver(value: str, *, field_name: str) -> str:
    """Validate semantic versions inside Pydantic models with a normal ValueError."""
    if _SEMVER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must use semantic versioning")
    return value


def _model_sha256(value: str, *, field_name: str) -> str:
    """Validate canonical hashes inside Pydantic models with a normal ValueError."""
    if _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be canonical sha256")
    return value


def _model_identifier(value: str, *, field_name: str) -> str:
    """Validate canonical identifiers inside Pydantic models with a normal ValueError."""
    if not value or value != value.strip() or any(character.isspace() for character in value):
        raise ValueError(f"{field_name} must be nonblank and whitespace-free")
    return value


class ProtocolFreezeArtifact(_ClosedModel):
    """Typed binding from the active protocol to the signed corpus-freeze record."""

    format_version: Literal["1"] = "1"
    artifact_type: Literal["stinger-benchmark-protocol-freeze"] = (
        "stinger-benchmark-protocol-freeze"
    )
    benchmark_protocol_version: str
    rubric_version: str
    corpus_version: str
    corpus_hash: str
    protocol_manifest_sha256: str
    corpus_freeze_signer_identity: str
    corpus_freeze_statement_sha256: str
    corpus_freeze_signature_sha256: str
    corpus_freeze_allowed_signers_sha256: str

    @field_validator("benchmark_protocol_version", "rubric_version", "corpus_version")
    @classmethod
    def _valid_version(cls, value: str) -> str:
        """Require semantic identities for the exact frozen protocol and corpus."""
        return _model_semver(value, field_name="protocol freeze version")

    @field_validator(
        "protocol_manifest_sha256",
        "corpus_hash",
        "corpus_freeze_statement_sha256",
        "corpus_freeze_signature_sha256",
        "corpus_freeze_allowed_signers_sha256",
    )
    @classmethod
    def _valid_hash(cls, value: str) -> str:
        """Require exact canonical protocol and freeze authorization bindings."""
        return _model_sha256(value, field_name="protocol freeze artifact hash")

    @field_validator("corpus_freeze_signer_identity")
    @classmethod
    def _valid_freeze_identity(cls, value: str) -> str:
        """Require the signer identity represented by the submission freeze record."""
        return _model_identifier(value, field_name="corpus freeze signer identity")


class TechnicalReportSection(_ClosedModel):
    """One deterministic technical-report section tied to exact machine evidence."""

    name: Literal[
        "claim-and-construct",
        "corpus-sampling-and-construction",
        "baseline-configurations",
        "results-and-uncertainty",
        "detector-boundaries-and-machine-veto-findings",
        "evidence-conformance-and-reproduction",
        "release-vendor-opportunity-and-corrections",
    ]
    evidence_sha256: str

    @field_validator("evidence_sha256")
    @classmethod
    def _valid_evidence_hash(cls, value: str) -> str:
        """Require every narrative section to name an exact evidence inventory."""
        return _model_sha256(value, field_name="technical report section evidence")


class TechnicalReportArtifact(_ClosedModel):
    """Closed, evidence-indexed technical report for a non-comparative release."""

    format_version: Literal["1"] = "1"
    artifact_type: Literal["stinger-benchmark-technical-report"] = (
        "stinger-benchmark-technical-report"
    )
    benchmark_protocol_version: str
    rubric_version: str
    corpus_version: str
    corpus_hash: str
    release_claim: Literal["Stinger Benchmark v1, machine-reproduced"] = (
        "Stinger Benchmark v1, machine-reproduced"
    )
    publication_mode: Literal["non-comparative"] = "non-comparative"
    protocol_freeze_artifact_sha256: str
    correction_policy_artifact_sha256: str
    conflicts_disclosure_artifact_sha256: str
    baseline_inventory_sha256: str
    conformance_inventory_sha256: str
    reproduction_record_sha256: str | None
    sections: tuple[TechnicalReportSection, ...]

    @field_validator("benchmark_protocol_version", "rubric_version", "corpus_version")
    @classmethod
    def _valid_version(cls, value: str) -> str:
        """Require the exact semantic identities represented by the report."""
        return _model_semver(value, field_name="technical report version")

    @field_validator(
        "corpus_hash",
        "protocol_freeze_artifact_sha256",
        "correction_policy_artifact_sha256",
        "conflicts_disclosure_artifact_sha256",
        "baseline_inventory_sha256",
        "conformance_inventory_sha256",
    )
    @classmethod
    def _valid_required_hash(cls, value: str) -> str:
        """Require exact evidence inventories for every report-wide claim."""
        return _model_sha256(value, field_name="technical report artifact hash")

    @field_validator("reproduction_record_sha256")
    @classmethod
    def _valid_reproduction_hash(cls, value: str | None) -> str | None:
        """Permit truthful pre-release drafts while validating any reproduction binding."""
        if value is not None:
            _model_sha256(value, field_name="technical report reproduction hash")
        return value

    @model_validator(mode="after")
    def _complete_section_inventory(self) -> TechnicalReportArtifact:
        """Require every normative report section exactly once in frozen order."""
        if tuple(section.name for section in self.sections) != _TECHNICAL_REPORT_SECTION_NAMES:
            raise ValueError("technical report section inventory is incomplete or reordered")
        return self


class CorrectionPolicyArtifact(_ClosedModel):
    """Closed correction and corpus-retirement policy required for publication."""

    format_version: Literal["1"] = "1"
    artifact_type: Literal["stinger-benchmark-correction-policy"] = (
        "stinger-benchmark-correction-policy"
    )
    benchmark_protocol_version: str
    rubric_version: str
    corpus_version: str
    corpus_hash: str
    claim_boundary: Literal["append-only-no-silent-in-place-edits"] = (
        "append-only-no-silent-in-place-edits"
    )
    triggers: tuple[str, ...] = _CORRECTION_TRIGGERS
    required_actions: tuple[str, ...] = _CORRECTION_ACTIONS
    retirement_release_contract: Literal[
        "release-retired-corpus-after-dummy-local-safety-check"
    ] = "release-retired-corpus-after-dummy-local-safety-check"
    established_benchmark_minimum_correction_cycles: Literal[1] = 1
    established_benchmark_minimum_distinct_environment_runs: Literal[3] = 3

    @field_validator("benchmark_protocol_version", "rubric_version", "corpus_version")
    @classmethod
    def _valid_version(cls, value: str) -> str:
        """Require the policy to be scoped to one exact release identity."""
        return _model_semver(value, field_name="correction policy version")

    @field_validator("corpus_hash")
    @classmethod
    def _valid_corpus_hash(cls, value: str) -> str:
        """Bind the policy to the corpus covered by this release."""
        return _model_sha256(value, field_name="correction policy corpus hash")

    @model_validator(mode="after")
    def _fixed_policy_contract(self) -> CorrectionPolicyArtifact:
        """Prevent omission, reordering, or caller weakening of correction obligations."""
        if self.triggers != _CORRECTION_TRIGGERS or self.required_actions != _CORRECTION_ACTIONS:
            raise ValueError("correction policy differs from the fixed Protocol 2 contract")
        return self


class ConflictDisclosureEntry(_ClosedModel):
    """One material relationship disclosed by the release-evidence signer."""

    category: Literal["financial", "employment", "advisory", "investment", "family", "other"]
    entity: str
    description: str

    @field_validator("entity")
    @classmethod
    def _valid_entity(cls, value: str) -> str:
        """Require a final, canonical entity label."""
        if value != value.strip() or not value or len(value) > 256:
            raise ValueError("conflict entity must be nonblank, trimmed, and bounded")
        return value

    @field_validator("description")
    @classmethod
    def _valid_description(cls, value: str) -> str:
        """Require a substantive disclosure rather than a favorable empty label."""
        if (
            value != value.strip()
            or len(value) < 32
            or len(value) > 4_000
            or _TECHNICAL_REPORT_PLACEHOLDER_PATTERN.search(value) is not None
        ):
            raise ValueError("conflict descriptions must be substantive and final")
        return value


class ConflictsDisclosureArtifact(_ClosedModel):
    """Signed-scope conflict attestation covering every released configuration/provider."""

    format_version: Literal["1"] = "1"
    artifact_type: Literal["stinger-benchmark-conflicts-disclosure"] = (
        "stinger-benchmark-conflicts-disclosure"
    )
    benchmark_protocol_version: str
    rubric_version: str
    corpus_version: str
    corpus_hash: str
    scope: Literal["project-providers-configurations-and-publication"] = (
        "project-providers-configurations-and-publication"
    )
    covered_configuration_ids: tuple[str, ...]
    covered_providers: tuple[str, ...]
    declaration: Literal["no-known-material-conflicts", "material-conflicts-disclosed"]
    relationships: tuple[ConflictDisclosureEntry, ...] = ()

    @field_validator("benchmark_protocol_version", "rubric_version", "corpus_version")
    @classmethod
    def _valid_version(cls, value: str) -> str:
        """Scope the attestation to one exact benchmark release identity."""
        return _model_semver(value, field_name="conflicts disclosure version")

    @field_validator("corpus_hash")
    @classmethod
    def _valid_corpus_hash(cls, value: str) -> str:
        """Bind the disclosure to one exact corpus."""
        return _model_sha256(value, field_name="conflicts disclosure corpus hash")

    @field_validator("covered_configuration_ids", "covered_providers")
    @classmethod
    def _canonical_coverage(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require a unique sorted scope inventory, including the truthful empty case."""
        if value != tuple(sorted(set(value))) or any(not item.strip() for item in value):
            raise ValueError("conflict disclosure coverage must be unique, sorted, and nonblank")
        return value

    @model_validator(mode="after")
    def _declaration_matches_relationships(self) -> ConflictsDisclosureArtifact:
        """Prevent a no-conflicts declaration from carrying contradictory relationships."""
        if (self.declaration == "no-known-material-conflicts") != (not self.relationships):
            raise ValueError("conflict declaration is inconsistent with disclosed relationships")
        if self.relationships != tuple(
            sorted(
                self.relationships,
                key=lambda item: (item.category, item.entity, item.description),
            )
        ):
            raise ValueError("conflict relationships must use canonical sorted order")
        return self


class ReleaseArtifactManifest(_ClosedModel):
    """Complete typed semantic layer embedded in the signed release-evidence statement."""

    format_version: Literal["1"] = "1"
    protocol_freeze: ProtocolFreezeArtifact
    technical_report: TechnicalReportArtifact
    correction_policy: CorrectionPolicyArtifact
    conflicts_disclosure: ConflictsDisclosureArtifact
    vendor_opportunity: None = None

    @model_validator(mode="after")
    def _cross_bound_artifacts(self) -> ReleaseArtifactManifest:
        """Require one identity and exact internal hashes across every release artifact."""
        identity = (
            self.protocol_freeze.benchmark_protocol_version,
            self.protocol_freeze.rubric_version,
            self.protocol_freeze.corpus_version,
            self.protocol_freeze.corpus_hash,
        )
        for artifact in (
            self.technical_report,
            self.correction_policy,
            self.conflicts_disclosure,
        ):
            if (
                artifact.benchmark_protocol_version,
                artifact.rubric_version,
                artifact.corpus_version,
                artifact.corpus_hash,
            ) != identity:
                raise ValueError("release artifacts do not share one exact release identity")
        if (
            self.technical_report.protocol_freeze_artifact_sha256
            != _canonical_artifact_sha256(self.protocol_freeze)
            or self.technical_report.correction_policy_artifact_sha256
            != _canonical_artifact_sha256(self.correction_policy)
            or self.technical_report.conflicts_disclosure_artifact_sha256
            != _canonical_artifact_sha256(self.conflicts_disclosure)
        ):
            raise ValueError("technical report does not bind the exact release artifacts")
        return self


class MasterGateExecutableReceipt(_ClosedModel):
    """Path-free binding to one exact executable used by the local workflow."""

    name: str
    sha256: str
    version: str

    @field_validator("name", "version")
    @classmethod
    def _nonblank_text(cls, value: str) -> str:
        """Require unambiguous executable labels and observed versions."""
        if not value or value != value.strip():
            raise ValueError("master-gate executable fields must be nonblank and trimmed")
        return value

    @field_validator("sha256")
    @classmethod
    def _canonical_sha256(cls, value: str) -> str:
        """Require an exact executable-content hash."""
        if _SHA256_PATTERN.fullmatch(value) is None:
            raise ValueError("master-gate executable hash must be canonical sha256")
        return value


class MasterGateDistributionReceipt(_ClosedModel):
    """Path-free version and file-inventory binding for one Python tool distribution."""

    name: str
    version: str
    file_inventory_sha256: str
    file_count: int

    @field_validator("name", "version")
    @classmethod
    def _nonblank_text(cls, value: str) -> str:
        """Require canonical package identity values."""
        if not value or value != value.strip():
            raise ValueError("master-gate package fields must be nonblank and trimmed")
        return value

    @field_validator("file_inventory_sha256")
    @classmethod
    def _canonical_sha256(cls, value: str) -> str:
        """Require an exact package-file inventory hash."""
        if _SHA256_PATTERN.fullmatch(value) is None:
            raise ValueError("master-gate package inventory must be canonical sha256")
        return value

    @field_validator("file_count")
    @classmethod
    def _positive_file_count(cls, value: int) -> int:
        """A package with no exact files cannot be treated as a bound tool."""
        if value <= 0:
            raise ValueError("master-gate package inventory must contain files")
        return value


class MasterGateWorkflowReceipt(_ClosedModel):
    """Typed receipt for the exact local, explicitly non-hermetic master-gate run."""

    format_version: Literal["2"] = "2"
    claim_boundary: str = _MASTER_GATE_CLAIM_BOUNDARY
    stinger_commit: str
    source_archive_sha256: str
    check_script_sha256: str
    command: tuple[str, ...]
    environment_projection: tuple[str, ...]
    executables: tuple[MasterGateExecutableReceipt, ...]
    distributions: tuple[MasterGateDistributionReceipt, ...]
    returncode: Literal[0]
    output_sha256: str
    output_size_bytes: int

    @field_validator("claim_boundary")
    @classmethod
    def _fixed_claim_boundary(cls, value: str) -> str:
        """Prevent a local receipt from being relabeled as hermetic or remote evidence."""
        if value != _MASTER_GATE_CLAIM_BOUNDARY:
            raise ValueError("master-gate claim boundary is fixed")
        return value

    @field_validator("stinger_commit")
    @classmethod
    def _valid_commit(cls, value: str) -> str:
        """Require one full Git object id."""
        if _COMMIT_PATTERN.fullmatch(value) is None:
            raise ValueError("master-gate commit must be a full lowercase Git object id")
        return value

    @field_validator("source_archive_sha256", "check_script_sha256", "output_sha256")
    @classmethod
    def _canonical_sha256(cls, value: str) -> str:
        """Require exact canonical artifact hashes."""
        if _SHA256_PATTERN.fullmatch(value) is None:
            raise ValueError("master-gate artifact hash must be canonical sha256")
        return value

    @model_validator(mode="after")
    def _closed_workflow_contract(self) -> MasterGateWorkflowReceipt:
        """Require the fixed command, environment projection, and complete tool inventory."""
        if self.command != ("bash", "scripts/check.sh"):
            raise ValueError("master-gate command differs from the fixed workflow")
        if self.environment_projection != (
            "COVERAGE_FILE=external-artifact",
            "HOME=ephemeral-empty",
            "LANG=C",
            "LC_ALL=C",
            "MYPY_CACHE_DIR=external-artifact",
            "PATH=fixed-system-search-v1",
            "PYTEST_ADDOPTS=-p no:cacheprovider",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONPATH=tracked-snapshot/src",
            "RUFF_CACHE_DIR=external-artifact",
            "STINGER_CHECK_ARTIFACT_DIR=external-artifact",
            "STINGER_CHECK_PYTHON=external-toolchain-python",
            "STINGER_COVERAGE_JSON=external-artifact/coverage.json",
            "TMPDIR=external-artifact",
        ):
            raise ValueError("master-gate environment differs from the fixed projection")
        if tuple(item.name for item in self.executables) != ("bash", "git", "grep", "python"):
            raise ValueError("master-gate executable inventory is incomplete or unordered")
        if tuple(item.name for item in self.distributions) != _TOOL_DISTRIBUTIONS:
            raise ValueError("master-gate package inventory is incomplete or unordered")
        if self.output_size_bytes <= 0:
            raise ValueError("master-gate output must be nonempty")
        return self


class ReleaseEvidencePreparationReceipt(_ClosedModel):
    """Canonical path-free receipt for one preserved master-gate execution."""

    format_version: Literal["3"] = "3"
    benchmark_protocol_version: str
    rubric_version: str
    corpus_version: str
    corpus_hash: str
    stinger_commit: str
    release_evidence: ReleaseEvidenceRecord
    release_artifacts: ReleaseArtifactManifest
    release_evidence_record_sha256: str
    master_gate_workflow_receipt_sha256: str
    master_gate_output_size_bytes: int

    @field_validator(
        "benchmark_protocol_version",
        "rubric_version",
        "corpus_version",
    )
    @classmethod
    def _valid_version(cls, value: str) -> str:
        """Require a complete semantic version in every preparation binding."""
        if _SEMVER_PATTERN.fullmatch(value) is None:
            raise ValueError("release evidence version must use semantic versioning")
        return value

    @field_validator(
        "corpus_hash",
        "release_evidence_record_sha256",
        "master_gate_workflow_receipt_sha256",
    )
    @classmethod
    def _valid_sha256(cls, value: str) -> str:
        """Require exact canonical lowercase SHA-256 values."""
        if _SHA256_PATTERN.fullmatch(value) is None:
            raise ValueError("release evidence hash must be canonical sha256")
        return value

    @field_validator("stinger_commit")
    @classmethod
    def _valid_commit(cls, value: str) -> str:
        """Require a full lowercase Git object id."""
        if _COMMIT_PATTERN.fullmatch(value) is None:
            raise ValueError("stinger_commit must be a full lowercase Git object id")
        return value

    @field_validator("master_gate_output_size_bytes")
    @classmethod
    def _valid_output_size(cls, value: int) -> int:
        """Require preserved nonempty gate output."""
        if value <= 0:
            raise ValueError("master gate output must be nonempty")
        return value

    @model_validator(mode="after")
    def _record_is_complete(self) -> ReleaseEvidencePreparationReceipt:
        """Reject incomplete, contradictory, or incorrectly hashed preparation evidence."""
        required_hashes = (
            self.release_evidence.protocol_freeze_receipt_sha256,
            self.release_evidence.master_gate_receipt_sha256,
            self.release_evidence.technical_report_sha256,
            self.release_evidence.correction_policy_sha256,
            self.release_evidence.conflicts_disclosure_sha256,
        )
        if any(value is None for value in required_hashes):
            raise ValueError("preparation receipt requires every release artifact")
        if self.release_evidence.comparative_release != (
            self.release_evidence.vendor_rerun_receipt_sha256 is not None
        ):
            raise ValueError("preparation receipt has inconsistent vendor evidence")
        if self.release_evidence.comparative_release:
            raise ValueError(
                "comparative publication is on HOLD until signed vendor opportunity evidence exists"
            )
        _require_release_record_artifact_hashes(
            self.release_evidence,
            self.release_artifacts,
        )
        if (
            canonical_release_evidence_record_sha256(self.release_evidence)
            != self.release_evidence_record_sha256
        ):
            raise ValueError("preparation receipt record hash does not match embedded record")
        if (
            self.release_evidence.master_gate_receipt_sha256
            != self.master_gate_workflow_receipt_sha256
        ):
            raise ValueError("preparation receipt does not bind its master-gate workflow receipt")
        return self


class ReleaseEvidenceStatement(_ClosedModel):
    """Canonical binding from exact artifacts to one finalized release submission."""

    format_version: Literal["2"] = "2"
    benchmark_protocol_version: str
    rubric_version: str
    corpus_version: str
    corpus_hash: str
    stinger_commit: str
    release_evidence: ReleaseEvidenceRecord
    release_artifacts: ReleaseArtifactManifest
    release_evidence_record_sha256: str
    canonical_submission_sha256: str
    signer_identity: str

    @field_validator(
        "benchmark_protocol_version",
        "rubric_version",
        "corpus_version",
    )
    @classmethod
    def _valid_version(cls, value: str) -> str:
        """Require a complete semantic version in every release binding."""
        if _SEMVER_PATTERN.fullmatch(value) is None:
            raise ValueError("release evidence version must use semantic versioning")
        return value

    @field_validator(
        "corpus_hash",
        "release_evidence_record_sha256",
        "canonical_submission_sha256",
    )
    @classmethod
    def _valid_sha256(cls, value: str) -> str:
        """Require exact canonical lowercase SHA-256 values."""
        if _SHA256_PATTERN.fullmatch(value) is None:
            raise ValueError("release evidence hash must be canonical sha256")
        return value

    @field_validator("stinger_commit")
    @classmethod
    def _valid_commit(cls, value: str) -> str:
        """Require a full lowercase Git object id."""
        if _COMMIT_PATTERN.fullmatch(value) is None:
            raise ValueError("stinger_commit must be a full lowercase Git object id")
        return value

    @field_validator("signer_identity")
    @classmethod
    def _valid_signer_identity(cls, value: str) -> str:
        """Require a canonical whitespace-free signing identity."""
        if not value or value != value.strip() or any(character.isspace() for character in value):
            raise ValueError("signer identity must be nonblank and whitespace-free")
        return value

    @model_validator(mode="after")
    def _record_hash_matches(self) -> ReleaseEvidenceStatement:
        """Reject incomplete, contradictory, or incorrectly hashed embedded evidence."""
        required_hashes = (
            self.release_evidence.protocol_freeze_receipt_sha256,
            self.release_evidence.master_gate_receipt_sha256,
            self.release_evidence.technical_report_sha256,
            self.release_evidence.correction_policy_sha256,
            self.release_evidence.conflicts_disclosure_sha256,
        )
        if any(value is None for value in required_hashes):
            raise ValueError("release evidence statement requires every release artifact")
        if self.release_evidence.comparative_release != (
            self.release_evidence.vendor_rerun_receipt_sha256 is not None
        ):
            raise ValueError("release evidence statement has inconsistent vendor evidence")
        if self.release_evidence.comparative_release:
            raise ValueError(
                "comparative publication is on HOLD until signed vendor opportunity evidence exists"
            )
        _require_release_record_artifact_hashes(
            self.release_evidence,
            self.release_artifacts,
        )
        if (
            canonical_release_evidence_record_sha256(self.release_evidence)
            != self.release_evidence_record_sha256
        ):
            raise ValueError("release evidence record hash does not match embedded record")
        return self


def build_protocol_freeze_artifact(
    submission: BenchmarkReleaseSubmission,
) -> ProtocolFreezeArtifact:
    """Derive the release-side protocol/freeze binding from typed submission evidence."""
    freeze = submission.corpus.freeze
    if freeze is None:
        raise ReleaseEvidenceBuilderError("release corpus lacks a signed freeze record")
    return ProtocolFreezeArtifact(
        benchmark_protocol_version=submission.protocol.benchmark_protocol_version,
        rubric_version=submission.protocol.rubric_version,
        corpus_version=submission.corpus.corpus_version,
        corpus_hash=submission.corpus.corpus_hash,
        protocol_manifest_sha256=_canonical_model_sha256(submission.protocol),
        corpus_freeze_signer_identity=freeze.signer_identity,
        corpus_freeze_statement_sha256=freeze.statement_sha256,
        corpus_freeze_signature_sha256=freeze.statement_signature_sha256,
        corpus_freeze_allowed_signers_sha256=freeze.allowed_signers_sha256,
    )


def build_correction_policy_artifact(
    submission: BenchmarkReleaseSubmission,
) -> CorrectionPolicyArtifact:
    """Derive the fixed Protocol 2 correction policy for one exact release identity."""
    return CorrectionPolicyArtifact(
        benchmark_protocol_version=submission.protocol.benchmark_protocol_version,
        rubric_version=submission.protocol.rubric_version,
        corpus_version=submission.corpus.corpus_version,
        corpus_hash=submission.corpus.corpus_hash,
    )


def build_conflicts_disclosure_artifact(
    submission: BenchmarkReleaseSubmission,
    *,
    declaration: Literal[
        "no-known-material-conflicts",
        "material-conflicts-disclosed",
    ],
    relationships: tuple[ConflictDisclosureEntry, ...] = (),
) -> ConflictsDisclosureArtifact:
    """Build a closed signed declaration covering every released provider/configuration.

    The declaration is an attestation by the release-evidence signer. Stinger mechanically
    verifies its exact scope and internal consistency; it does not claim that software can
    discover undisclosed real-world relationships.
    """
    configuration_ids = tuple(
        sorted(baseline.configuration_id for baseline in submission.baselines)
    )
    if len(configuration_ids) != len(set(configuration_ids)):
        raise ReleaseEvidenceBuilderError("baseline configuration identities are not unique")
    providers: list[str] = []
    for baseline in submission.baselines:
        metadata = baseline.report.benchmark_metadata
        if metadata is None or metadata.provider is None or not metadata.provider.strip():
            raise ReleaseEvidenceBuilderError(
                "baseline provider scope is incomplete for conflict disclosure"
            )
        providers.append(metadata.provider)
    return ConflictsDisclosureArtifact(
        benchmark_protocol_version=submission.protocol.benchmark_protocol_version,
        rubric_version=submission.protocol.rubric_version,
        corpus_version=submission.corpus.corpus_version,
        corpus_hash=submission.corpus.corpus_hash,
        covered_configuration_ids=configuration_ids,
        covered_providers=tuple(sorted(set(providers))),
        declaration=declaration,
        relationships=relationships,
    )


def build_technical_report_artifact(
    submission: BenchmarkReleaseSubmission,
    *,
    protocol_freeze: ProtocolFreezeArtifact,
    correction_policy: CorrectionPolicyArtifact,
    conflicts_disclosure: ConflictsDisclosureArtifact,
) -> TechnicalReportArtifact:
    """Derive a deterministic, non-comparative technical-report evidence index.

    There is intentionally no caller-authored prose in the gate artifact. A reader-facing
    renderer may turn this closed evidence index into fixed prose, but cannot insert vendor
    comparisons or unsupported conclusions into publication evidence.
    """
    section_hashes = _technical_report_section_hashes(
        submission,
        protocol_freeze=protocol_freeze,
        correction_policy=correction_policy,
        conflicts_disclosure=conflicts_disclosure,
    )
    sections = tuple(
        TechnicalReportSection.model_validate(
            {
                "name": name,
                "evidence_sha256": section_hashes[name],
            }
        )
        for name in _TECHNICAL_REPORT_SECTION_NAMES
    )
    return TechnicalReportArtifact(
        benchmark_protocol_version=submission.protocol.benchmark_protocol_version,
        rubric_version=submission.protocol.rubric_version,
        corpus_version=submission.corpus.corpus_version,
        corpus_hash=submission.corpus.corpus_hash,
        protocol_freeze_artifact_sha256=_canonical_artifact_sha256(protocol_freeze),
        correction_policy_artifact_sha256=_canonical_artifact_sha256(correction_policy),
        conflicts_disclosure_artifact_sha256=_canonical_artifact_sha256(conflicts_disclosure),
        baseline_inventory_sha256=_baseline_inventory_sha256(submission),
        conformance_inventory_sha256=_conformance_inventory_sha256(submission),
        reproduction_record_sha256=_optional_model_sha256(submission.cross_machine_reproduction),
        sections=sections,
    )


def build_release_artifact_manifest(
    submission: BenchmarkReleaseSubmission,
    *,
    conflicts_declaration: Literal[
        "no-known-material-conflicts",
        "material-conflicts-disclosed",
    ],
    conflict_relationships: tuple[ConflictDisclosureEntry, ...] = (),
) -> ReleaseArtifactManifest:
    """Build every non-comparative release artifact from one typed submission."""
    if submission.release_evidence.comparative_release:
        raise ReleaseEvidenceBuilderError(
            "comparative publication is on HOLD until signed vendor opportunity evidence exists"
        )
    protocol_freeze = build_protocol_freeze_artifact(submission)
    correction_policy = build_correction_policy_artifact(submission)
    conflicts_disclosure = build_conflicts_disclosure_artifact(
        submission,
        declaration=conflicts_declaration,
        relationships=conflict_relationships,
    )
    technical_report = build_technical_report_artifact(
        submission,
        protocol_freeze=protocol_freeze,
        correction_policy=correction_policy,
        conflicts_disclosure=conflicts_disclosure,
    )
    return ReleaseArtifactManifest(
        protocol_freeze=protocol_freeze,
        technical_report=technical_report,
        correction_policy=correction_policy,
        conflicts_disclosure=conflicts_disclosure,
    )


def release_evidence_record_from_artifacts(
    artifacts: ReleaseArtifactManifest,
    *,
    master_gate_receipt_sha256: str,
) -> ReleaseEvidenceRecord:
    """Derive the public release record; callers cannot enter favorable artifact hashes."""
    _require_sha256(master_gate_receipt_sha256)
    return ReleaseEvidenceRecord(
        protocol_freeze_receipt_sha256=_canonical_artifact_sha256(artifacts.protocol_freeze),
        master_gate_receipt_sha256=master_gate_receipt_sha256,
        technical_report_sha256=_canonical_artifact_sha256(artifacts.technical_report),
        correction_policy_sha256=_canonical_artifact_sha256(artifacts.correction_policy),
        conflicts_disclosure_sha256=_canonical_artifact_sha256(artifacts.conflicts_disclosure),
        comparative_release=False,
        vendor_rerun_receipt_sha256=None,
    )


def verify_release_artifact_semantics(
    artifacts: ReleaseArtifactManifest,
    submission: BenchmarkReleaseSubmission,
) -> None:
    """Recompute every semantic artifact from the signed submission and fail closed."""
    if (
        submission.release_evidence.comparative_release
        or submission.release_evidence.vendor_rerun_receipt_sha256 is not None
    ):
        raise ReleaseEvidenceBuilderError(
            "comparative publication is on HOLD until signed vendor opportunity evidence exists"
        )
    expected = build_release_artifact_manifest(
        submission,
        conflicts_declaration=artifacts.conflicts_disclosure.declaration,
        conflict_relationships=artifacts.conflicts_disclosure.relationships,
    )
    if artifacts != expected:
        raise ReleaseEvidenceBuilderError(
            "release artifacts do not match the exact typed submission"
        )
    _require_release_record_artifact_hashes(submission.release_evidence, artifacts)


def write_release_artifact(destination: Path, artifact: BaseModel) -> None:
    """Atomically create one canonical typed release artifact without overwriting."""
    if not isinstance(
        artifact,
        (
            ProtocolFreezeArtifact,
            TechnicalReportArtifact,
            CorrectionPolicyArtifact,
            ConflictsDisclosureArtifact,
        ),
    ):
        raise ReleaseEvidenceBuilderError("unsupported release artifact type")
    _atomic_create(destination, _canonical_model_bytes(artifact))


def write_release_artifact_package(
    destination: Path,
    artifacts: ReleaseArtifactManifest,
) -> None:
    """Atomically create the four canonical typed release artifacts in a new directory."""
    _atomic_create_private_directory(
        destination,
        {
            "protocol-freeze.json": _canonical_model_bytes(artifacts.protocol_freeze),
            "technical-report.json": _canonical_model_bytes(artifacts.technical_report),
            "correction-policy.json": _canonical_model_bytes(artifacts.correction_policy),
            "conflicts-disclosure.json": _canonical_model_bytes(artifacts.conflicts_disclosure),
        },
    )


def _require_release_record_artifact_hashes(
    record: ReleaseEvidenceRecord,
    artifacts: ReleaseArtifactManifest,
) -> None:
    """Require every favorable release hash to come from exact typed artifact bytes."""
    master_gate_hash = record.master_gate_receipt_sha256
    if master_gate_hash is None or _SHA256_PATTERN.fullmatch(master_gate_hash) is None:
        raise ValueError("release evidence record lacks a canonical master-gate receipt hash")
    expected = ReleaseEvidenceRecord(
        protocol_freeze_receipt_sha256=_canonical_artifact_sha256(artifacts.protocol_freeze),
        master_gate_receipt_sha256=master_gate_hash,
        technical_report_sha256=_canonical_artifact_sha256(artifacts.technical_report),
        correction_policy_sha256=_canonical_artifact_sha256(artifacts.correction_policy),
        conflicts_disclosure_sha256=_canonical_artifact_sha256(artifacts.conflicts_disclosure),
        comparative_release=False,
        vendor_rerun_receipt_sha256=None,
    )
    if record != expected:
        raise ValueError("release evidence record does not match typed release artifacts")


def _baseline_inventory_sha256(submission: BenchmarkReleaseSubmission) -> str:
    """Hash the exact sorted baseline record inventory used by the technical report."""
    return _canonical_payload_sha256(
        [
            baseline.model_dump(mode="json")
            for baseline in sorted(
                submission.baselines,
                key=lambda item: item.configuration_id,
            )
        ]
    )


def _conformance_inventory_sha256(submission: BenchmarkReleaseSubmission) -> str:
    """Hash the exact sorted conformance record inventory used by the technical report."""
    return _canonical_payload_sha256(
        [
            record.model_dump(mode="json")
            for record in sorted(
                submission.conformance_environments,
                key=lambda item: item.environment_id,
            )
        ]
    )


def _optional_model_sha256(model: BaseModel | None) -> str | None:
    """Hash one present typed record while preserving a truthful absent value."""
    return None if model is None else _canonical_model_sha256(model)


def _technical_report_section_hashes(
    submission: BenchmarkReleaseSubmission,
    *,
    protocol_freeze: ProtocolFreezeArtifact,
    correction_policy: CorrectionPolicyArtifact,
    conflicts_disclosure: ConflictsDisclosureArtifact,
) -> dict[str, str]:
    """Derive the fixed evidence inventory for every technical-report section."""
    baseline_hash = _baseline_inventory_sha256(submission)
    external_hash = _canonical_payload_sha256(
        {
            "conformance_inventory_sha256": _conformance_inventory_sha256(submission),
            "reproduction_record_sha256": _optional_model_sha256(
                submission.cross_machine_reproduction
            ),
        }
    )
    release_hash = _canonical_payload_sha256(
        {
            "protocol_freeze_sha256": _canonical_artifact_sha256(protocol_freeze),
            "correction_policy_sha256": _canonical_artifact_sha256(correction_policy),
            "conflicts_disclosure_sha256": _canonical_artifact_sha256(conflicts_disclosure),
        }
    )
    return {
        "claim-and-construct": _canonical_model_sha256(submission.protocol),
        "corpus-sampling-and-construction": _canonical_model_sha256(submission.corpus),
        "baseline-configurations": baseline_hash,
        "results-and-uncertainty": baseline_hash,
        "detector-boundaries-and-machine-veto-findings": baseline_hash,
        "evidence-conformance-and-reproduction": external_hash,
        "release-vendor-opportunity-and-corrections": release_hash,
    }


def _canonical_payload_sha256(value: object) -> str:
    """Hash one plain JSON value in the same canonical transport form as models."""
    return _sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def prepare_release_evidence(
    *,
    repository: Path,
    toolchain_python: Path,
    expected_stinger_commit: str,
    corpus_version: str,
    corpus_hash: str,
    protocol_freeze_receipt: Path,
    technical_report: Path,
    correction_policy: Path,
    conflicts_disclosure: Path,
    comparative_release: bool = False,
    vendor_rerun_receipt: Path | None = None,
) -> PreparedReleaseEvidence:
    """Run the clean master gate and derive exact content-bound release evidence.

    This production API always executes the checkout's fixed ``./scripts/check.sh`` entry
    point in a Git-tracked-only temporary snapshot, using the explicitly supplied external
    Python toolchain and a fixed sanitized environment. Tests isolate the private subprocess
    boundary rather than accepting a caller-supplied executor that could manufacture a
    successful release receipt.
    """
    _require_commit(expected_stinger_commit)
    _require_semver(corpus_version)
    _require_sha256(corpus_hash)
    if comparative_release or vendor_rerun_receipt is not None:
        raise ReleaseEvidenceBuilderError(
            "comparative publication is on HOLD until signed vendor opportunity evidence exists"
        )

    repository_root = _require_real_directory(repository)
    initial_commit = _clean_git_head(repository_root)
    if initial_commit != expected_stinger_commit:
        raise ReleaseEvidenceBuilderError("release checkout does not match the expected commit")

    release_artifacts, artifact_bindings = _load_release_artifact_files(
        protocol_freeze_receipt=protocol_freeze_receipt,
        technical_report=technical_report,
        correction_policy=correction_policy,
        conflicts_disclosure=conflicts_disclosure,
        corpus_version=corpus_version,
        corpus_hash=corpus_hash,
    )

    try:
        workflow_run = _execute_master_gate(
            repository_root,
            toolchain_python=toolchain_python,
            expected_stinger_commit=initial_commit,
        )
    except ReleaseEvidenceBuilderError:
        raise
    except Exception:
        raise ReleaseEvidenceBuilderError("master gate execution failed") from None
    if not isinstance(workflow_run, _MasterGateWorkflowRun):
        raise ReleaseEvidenceBuilderError("master gate executor returned an invalid result")
    execution = workflow_run.receipt
    if execution.returncode != 0:
        raise ReleaseEvidenceBuilderError("master gate did not pass")
    if not isinstance(workflow_run.output, bytes) or not workflow_run.output:
        raise ReleaseEvidenceBuilderError("master gate produced no receipt output")

    try:
        final_commit = _clean_git_head(repository_root)
    except ReleaseEvidenceBuilderError:
        raise ReleaseEvidenceBuilderError(
            "release checkout changed during master-gate execution"
        ) from None
    if final_commit != initial_commit:
        raise ReleaseEvidenceBuilderError("release checkout changed during master-gate execution")
    _verify_artifact_bindings(artifact_bindings)

    protocol = compiled_benchmark_protocol()
    record = release_evidence_record_from_artifacts(
        release_artifacts,
        master_gate_receipt_sha256=_sha256(_canonical_model_bytes(execution)),
    )
    receipt = ReleaseEvidencePreparationReceipt(
        benchmark_protocol_version=protocol.benchmark_protocol_version,
        rubric_version=protocol.rubric_version,
        corpus_version=corpus_version,
        corpus_hash=corpus_hash,
        stinger_commit=initial_commit,
        release_evidence=record,
        release_artifacts=release_artifacts,
        release_evidence_record_sha256=canonical_release_evidence_record_sha256(record),
        master_gate_workflow_receipt_sha256=_sha256(_canonical_model_bytes(execution)),
        master_gate_output_size_bytes=len(workflow_run.output),
    )
    return PreparedReleaseEvidence(
        receipt=receipt,
        master_gate_receipt=execution,
        master_gate_output=workflow_run.output,
        repository=repository_root,
        artifacts=artifact_bindings,
    )


def run_tracked_master_gate_workflow(
    repository: Path,
    *,
    toolchain_python: Path,
    expected_stinger_commit: str,
) -> tuple[MasterGateWorkflowReceipt, bytes]:
    """Execute the fixed tracked-source gate and return its typed receipt and exact output.

    This is the non-injectable workflow primitive reused by conformance construction.
    Callers still have to bind the receipt to their role-specific input and machine
    attestation; this function only establishes the local gate facts described by the
    receipt's explicit non-hermetic claim boundary.
    """
    root = _require_real_directory(repository)
    initial_commit = _clean_git_head(root)
    if initial_commit != expected_stinger_commit:
        raise ReleaseEvidenceBuilderError("release checkout does not match the expected commit")
    run = _execute_master_gate(
        root,
        toolchain_python=toolchain_python,
        expected_stinger_commit=expected_stinger_commit,
    )
    if _clean_git_head(root) != initial_commit:
        raise ReleaseEvidenceBuilderError("release checkout changed during master-gate execution")
    return run.receipt, run.output


def write_release_evidence_preparation_package(
    destination: Path,
    prepared: PreparedReleaseEvidence,
) -> None:
    """Atomically persist one private, complete, create-only preparation package.

    The directory contains exactly three private files: a canonical preparation receipt,
    the typed path-free workflow receipt, and preserved merged stdout/stderr bytes.
    """
    _verify_prepared_release_evidence(prepared)
    _atomic_create_private_directory(
        destination,
        {
            _PREPARATION_RECEIPT_FILE: _canonical_model_bytes(prepared.receipt),
            _MASTER_GATE_RECEIPT_FILE: _canonical_model_bytes(prepared.master_gate_receipt),
            _MASTER_GATE_OUTPUT_FILE: prepared.master_gate_output,
        },
    )


def load_release_evidence_preparation_package(
    package: Path,
    *,
    repository: Path,
    expected_stinger_commit: str,
    corpus_version: str,
    corpus_hash: str,
    protocol_freeze_receipt: Path,
    technical_report: Path,
    correction_policy: Path,
    conflicts_disclosure: Path,
    comparative_release: bool = False,
    vendor_rerun_receipt: Path | None = None,
) -> PreparedReleaseEvidence:
    """Reload and reverify a private preparation package without rerunning the gate.

    Every caller-supplied artifact is reopened and hashed, the checkout must still be clean
    at the exact receipt commit, and the package is read twice around those checks.  No path
    or gate-output content is included in any diagnostic.
    """
    _require_commit(expected_stinger_commit)
    _require_semver(corpus_version)
    _require_sha256(corpus_hash)
    if comparative_release or vendor_rerun_receipt is not None:
        raise ReleaseEvidenceBuilderError(
            "comparative publication is on HOLD until signed vendor opportunity evidence exists"
        )

    receipt_bytes, workflow_receipt_bytes, output = _read_preparation_package(package)
    receipt = _parse_preparation_receipt(receipt_bytes)
    workflow_receipt = _parse_master_gate_workflow_receipt(workflow_receipt_bytes)
    protocol = compiled_benchmark_protocol()
    if (
        receipt.benchmark_protocol_version != protocol.benchmark_protocol_version
        or receipt.rubric_version != protocol.rubric_version
    ):
        raise ReleaseEvidenceBuilderError("preparation package does not use the compiled protocol")
    if (
        receipt.stinger_commit != expected_stinger_commit
        or receipt.corpus_version != corpus_version
        or receipt.corpus_hash != corpus_hash
    ):
        raise ReleaseEvidenceBuilderError(
            "preparation package does not match the expected release identity"
        )
    _verify_preserved_gate_output(receipt, workflow_receipt, output)

    repository_root = _require_real_directory(repository)
    initial_commit = _clean_git_head(repository_root)
    if initial_commit != receipt.stinger_commit:
        raise ReleaseEvidenceBuilderError("release checkout does not match the prepared commit")

    release_artifacts, artifact_bindings = _load_release_artifact_files(
        protocol_freeze_receipt=protocol_freeze_receipt,
        technical_report=technical_report,
        correction_policy=correction_policy,
        conflicts_disclosure=conflicts_disclosure,
        corpus_version=corpus_version,
        corpus_hash=corpus_hash,
    )
    expected_record = release_evidence_record_from_artifacts(
        release_artifacts,
        master_gate_receipt_sha256=_sha256(workflow_receipt_bytes),
    )
    if (
        expected_record != receipt.release_evidence
        or release_artifacts != receipt.release_artifacts
    ):
        raise ReleaseEvidenceBuilderError(
            "preparation package does not bind the exact release artifacts"
        )

    try:
        final_commit = _clean_git_head(repository_root)
    except ReleaseEvidenceBuilderError:
        raise ReleaseEvidenceBuilderError(
            "release checkout changed during preparation verification"
        ) from None
    if final_commit != initial_commit:
        raise ReleaseEvidenceBuilderError(
            "release checkout changed during preparation verification"
        )
    _verify_artifact_bindings(artifact_bindings)
    final_receipt_bytes, final_workflow_receipt_bytes, final_output = _read_preparation_package(
        package
    )
    if (
        final_receipt_bytes != receipt_bytes
        or final_workflow_receipt_bytes != workflow_receipt_bytes
        or final_output != output
    ):
        raise ReleaseEvidenceBuilderError(
            "release evidence preparation package changed during verification"
        )

    return PreparedReleaseEvidence(
        receipt=receipt,
        master_gate_receipt=workflow_receipt,
        master_gate_output=output,
        repository=repository_root,
        artifacts=artifact_bindings,
    )


def build_release_evidence_statement(
    submission: BenchmarkReleaseSubmission,
    prepared: PreparedReleaseEvidence,
    *,
    signer_identity: str,
) -> ReleaseEvidenceStatement:
    """Bind a finalized submission after re-verifying the first-stage artifacts.

    The submission can contain the already-derived record before its canonical hash exists,
    so no field depends on its own statement or signature hash.
    """
    _require_identifier(signer_identity)
    protocol = compiled_benchmark_protocol()
    if submission.protocol != protocol:
        raise ReleaseEvidenceBuilderError("release submission does not use the compiled protocol")
    if (
        submission.protocol.benchmark_protocol_version != prepared.benchmark_protocol_version
        or submission.protocol.rubric_version != prepared.rubric_version
        or submission.corpus.corpus_version != prepared.corpus_version
        or submission.corpus.corpus_hash != prepared.corpus_hash
    ):
        raise ReleaseEvidenceBuilderError("release submission does not match prepared evidence")
    if submission.release_evidence != prepared.record:
        raise ReleaseEvidenceBuilderError("release submission evidence record was altered")
    verify_release_artifact_semantics(prepared.release_artifacts, submission)
    _verify_prepared_release_evidence(
        prepared,
        checkout_error="release checkout changed before statement binding",
    )

    statement = ReleaseEvidenceStatement(
        benchmark_protocol_version=prepared.benchmark_protocol_version,
        rubric_version=prepared.rubric_version,
        corpus_version=prepared.corpus_version,
        corpus_hash=prepared.corpus_hash,
        stinger_commit=prepared.stinger_commit,
        release_evidence=prepared.record,
        release_artifacts=prepared.release_artifacts,
        release_evidence_record_sha256=canonical_release_evidence_record_sha256(prepared.record),
        canonical_submission_sha256=canonical_benchmark_submission_sha256(submission),
        signer_identity=signer_identity,
    )
    verify_release_evidence_statement(statement, submission)
    return statement


def verify_release_evidence_statement(
    statement: ReleaseEvidenceStatement,
    submission: BenchmarkReleaseSubmission,
) -> None:
    """Fail closed unless a statement binds one exact typed release submission."""
    if (
        statement.benchmark_protocol_version != submission.protocol.benchmark_protocol_version
        or statement.rubric_version != submission.protocol.rubric_version
        or statement.corpus_version != submission.corpus.corpus_version
        or statement.corpus_hash != submission.corpus.corpus_hash
        or statement.release_evidence != submission.release_evidence
        or statement.release_evidence_record_sha256
        != canonical_release_evidence_record_sha256(submission.release_evidence)
        or statement.canonical_submission_sha256
        != canonical_benchmark_submission_sha256(submission)
    ):
        raise ReleaseEvidenceBuilderError(
            "release evidence statement does not bind the exact submission"
        )
    verify_release_artifact_semantics(statement.release_artifacts, submission)


def canonical_release_evidence_record_sha256(record: ReleaseEvidenceRecord) -> str:
    """Return the canonical digest of one typed release-evidence record."""
    return _canonical_model_sha256(record)


def canonical_benchmark_submission_sha256(submission: BenchmarkReleaseSubmission) -> str:
    """Return the canonical digest of one typed finalized release submission."""
    return _canonical_model_sha256(submission)


def write_release_evidence_record(
    destination: Path,
    record: ReleaseEvidenceRecord,
) -> None:
    """Atomically create canonical record JSON without overwriting."""
    _atomic_create(destination, _canonical_model_bytes(record))


def write_release_evidence_statement(
    destination: Path,
    statement: ReleaseEvidenceStatement,
) -> None:
    """Atomically create canonical statement JSON without overwriting."""
    _atomic_create(destination, _canonical_model_bytes(statement))


def _verify_prepared_release_evidence(
    prepared: PreparedReleaseEvidence,
    *,
    checkout_error: str = "release checkout changed before preparation persistence",
) -> None:
    """Reverify one in-memory preparation without exposing private content."""
    protocol = compiled_benchmark_protocol()
    if (
        prepared.receipt.benchmark_protocol_version != protocol.benchmark_protocol_version
        or prepared.receipt.rubric_version != protocol.rubric_version
    ):
        raise ReleaseEvidenceBuilderError("prepared evidence does not use the compiled protocol")
    _verify_preserved_gate_output(
        prepared.receipt,
        prepared.master_gate_receipt,
        prepared.master_gate_output,
    )
    try:
        binding_commit = _clean_git_head(prepared.repository)
    except ReleaseEvidenceBuilderError:
        raise ReleaseEvidenceBuilderError(checkout_error) from None
    if binding_commit != prepared.stinger_commit:
        raise ReleaseEvidenceBuilderError(checkout_error)
    _verify_artifact_bindings(prepared.artifacts)


def _verify_preserved_gate_output(
    receipt: ReleaseEvidencePreparationReceipt,
    workflow_receipt: MasterGateWorkflowReceipt,
    output: bytes,
) -> None:
    """Require exact typed workflow and output bytes matching every retained digest."""
    if not isinstance(output, bytes) or not output:
        raise ReleaseEvidenceBuilderError("prepared master-gate output is unavailable")
    workflow_bytes = _canonical_model_bytes(workflow_receipt)
    if (
        len(output) != receipt.master_gate_output_size_bytes
        or len(output) != workflow_receipt.output_size_bytes
        or _sha256(output) != workflow_receipt.output_sha256
        or _sha256(workflow_bytes) != receipt.master_gate_workflow_receipt_sha256
        or _sha256(workflow_bytes) != receipt.release_evidence.master_gate_receipt_sha256
    ):
        raise ReleaseEvidenceBuilderError("prepared master-gate output does not match its receipt")


def _read_preparation_package(package: Path) -> tuple[bytes, bytes, bytes]:
    """Read exactly one complete private package through a stable directory handle."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_descriptor = os.open(package, flags)
    except OSError:
        raise ReleaseEvidenceBuilderError(
            "release evidence preparation package is unavailable"
        ) from None
    try:
        before = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(before.st_mode):
            raise ReleaseEvidenceBuilderError(
                "release evidence preparation package is not a real directory"
            )
        try:
            names = frozenset(os.listdir(directory_descriptor))
        except OSError:
            raise ReleaseEvidenceBuilderError(
                "release evidence preparation package could not be scanned"
            ) from None
        if names != _PREPARATION_PACKAGE_FILES:
            raise ReleaseEvidenceBuilderError(
                "release evidence preparation package is incomplete or has extra files"
            )
        receipt_bytes = _read_regular_file_at(
            directory_descriptor,
            _PREPARATION_RECEIPT_FILE,
            label="preparation receipt",
        )
        workflow_receipt_bytes = _read_regular_file_at(
            directory_descriptor,
            _MASTER_GATE_RECEIPT_FILE,
            label="master-gate workflow receipt",
        )
        output = _read_regular_file_at(
            directory_descriptor,
            _MASTER_GATE_OUTPUT_FILE,
            label="prepared master-gate output",
        )
        try:
            final_names = frozenset(os.listdir(directory_descriptor))
            after = os.fstat(directory_descriptor)
        except OSError:
            raise ReleaseEvidenceBuilderError(
                "release evidence preparation package changed while reading"
            ) from None
        if final_names != names or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ReleaseEvidenceBuilderError(
                "release evidence preparation package changed while reading"
            )
        return receipt_bytes, workflow_receipt_bytes, output
    finally:
        os.close(directory_descriptor)


def _read_regular_file_at(directory_descriptor: int, name: str, *, label: str) -> bytes:
    """Read stable nonempty bytes for one expected package member."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except OSError:
        raise ReleaseEvidenceBuilderError(f"{label} is unavailable") from None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ReleaseEvidenceBuilderError(f"{label} is not a regular file")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, _READ_CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
    except OSError:
        raise ReleaseEvidenceBuilderError(f"{label} could not be read") from None
    finally:
        os.close(descriptor)
    if size == 0:
        raise ReleaseEvidenceBuilderError(f"{label} is empty")
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise ReleaseEvidenceBuilderError(f"{label} changed while reading")
    return b"".join(chunks)


def _parse_preparation_receipt(content: bytes) -> ReleaseEvidencePreparationReceipt:
    """Parse duplicate-free canonical preparation JSON without accepting ambiguity."""
    try:
        raw = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_pairs,
        )
        receipt = ReleaseEvidencePreparationReceipt.model_validate(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ReleaseEvidenceBuilderError(
            "release evidence preparation receipt is invalid"
        ) from None
    if _canonical_model_bytes(receipt) != content:
        raise ReleaseEvidenceBuilderError("release evidence preparation receipt is not canonical")
    return receipt


def _parse_master_gate_workflow_receipt(content: bytes) -> MasterGateWorkflowReceipt:
    """Parse duplicate-free canonical typed workflow evidence."""
    try:
        raw = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_pairs,
        )
        receipt = MasterGateWorkflowReceipt.model_validate(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ReleaseEvidenceBuilderError("master-gate workflow receipt is invalid") from None
    if _canonical_model_bytes(receipt) != content:
        raise ReleaseEvidenceBuilderError("master-gate workflow receipt is not canonical")
    return receipt


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys rather than accepting last-key-wins input."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _execute_master_gate(
    repository: Path,
    *,
    toolchain_python: Path,
    expected_stinger_commit: str,
) -> _MasterGateWorkflowRun:
    """Run the fixed gate from a tracked-only snapshot with an explicit local toolchain."""
    python = _external_toolchain_python(toolchain_python, repository=repository)
    bash = _fixed_system_executable("bash")
    git = _fixed_system_executable("git")
    grep = _fixed_system_executable("grep")
    executable_receipts_before = (
        _executable_receipt("bash", bash, ("--version",)),
        _executable_receipt("git", git, ("--version",)),
        _executable_receipt("grep", grep, ("--version",)),
        _executable_receipt("python", python, ("--version",)),
    )
    distribution_receipts_before = _tool_distribution_receipts(python)

    archive = _git_archive(
        repository,
        git=git,
        expected_stinger_commit=expected_stinger_commit,
    )
    source_archive_sha256 = _sha256(archive)
    with tempfile.TemporaryDirectory(prefix="stinger-release-gate-") as temporary_name:
        temporary = Path(temporary_name)
        snapshot = temporary / "tracked-source"
        artifacts = temporary / "gate-artifacts"
        empty_home = temporary / "empty-home"
        snapshot.mkdir(mode=0o700)
        artifacts.mkdir(mode=0o700)
        empty_home.mkdir(mode=0o700)
        tracked_inventory = _extract_git_archive(archive, snapshot)
        script = snapshot / "scripts" / "check.sh"
        check_script_sha256 = _hash_regular_file(script)
        environment = {
            "COVERAGE_FILE": str(artifacts / ".coverage"),
            "HOME": str(empty_home),
            "LANG": "C",
            "LC_ALL": "C",
            "MYPY_CACHE_DIR": str(artifacts / "mypy-cache"),
            "PATH": _FIXED_SYSTEM_PATH,
            "PYTEST_ADDOPTS": "-p no:cacheprovider",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(snapshot / "src"),
            "RUFF_CACHE_DIR": str(artifacts / "ruff-cache"),
            "STINGER_CHECK_ARTIFACT_DIR": str(artifacts),
            "STINGER_CHECK_PYTHON": str(python),
            "STINGER_COVERAGE_JSON": str(artifacts / "coverage.json"),
            "TMPDIR": str(artifacts),
        }
        execution = _run_master_gate_subprocess(
            (str(bash), str(script)),
            cwd=snapshot,
            environment=environment,
        )
        if execution.returncode != 0:
            raise ReleaseEvidenceBuilderError("master gate did not pass")
        if not isinstance(execution.output, bytes) or not execution.output:
            raise ReleaseEvidenceBuilderError("master gate produced no receipt output")
        _verify_tracked_snapshot(snapshot, tracked_inventory)

    executable_receipts_after = (
        _executable_receipt("bash", bash, ("--version",)),
        _executable_receipt("git", git, ("--version",)),
        _executable_receipt("grep", grep, ("--version",)),
        _executable_receipt("python", python, ("--version",)),
    )
    distribution_receipts_after = _tool_distribution_receipts(python)
    if (
        executable_receipts_after != executable_receipts_before
        or distribution_receipts_after != distribution_receipts_before
    ):
        raise ReleaseEvidenceBuilderError("master-gate toolchain changed during execution")

    receipt = MasterGateWorkflowReceipt(
        stinger_commit=expected_stinger_commit,
        source_archive_sha256=source_archive_sha256,
        check_script_sha256=check_script_sha256,
        command=("bash", "scripts/check.sh"),
        environment_projection=(
            "COVERAGE_FILE=external-artifact",
            "HOME=ephemeral-empty",
            "LANG=C",
            "LC_ALL=C",
            "MYPY_CACHE_DIR=external-artifact",
            "PATH=fixed-system-search-v1",
            "PYTEST_ADDOPTS=-p no:cacheprovider",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONPATH=tracked-snapshot/src",
            "RUFF_CACHE_DIR=external-artifact",
            "STINGER_CHECK_ARTIFACT_DIR=external-artifact",
            "STINGER_CHECK_PYTHON=external-toolchain-python",
            "STINGER_COVERAGE_JSON=external-artifact/coverage.json",
            "TMPDIR=external-artifact",
        ),
        executables=executable_receipts_before,
        distributions=distribution_receipts_before,
        returncode=0,
        output_sha256=_sha256(execution.output),
        output_size_bytes=len(execution.output),
    )
    return _MasterGateWorkflowRun(receipt=receipt, output=execution.output)


def _run_master_gate_subprocess(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> MasterGateExecution:
    """Run the tracked gate in a private process group and leave no live descendants."""
    try:
        process: subprocess.Popen[bytes] = subprocess.Popen(
            argv,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError:
        raise ReleaseEvidenceBuilderError("master gate execution failed") from None
    try:
        output, _ = process.communicate(timeout=_MASTER_GATE_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        raise ReleaseEvidenceBuilderError("master gate execution failed") from None
    finally:
        _terminate_and_reap_master_gate_process_group(process)
    if process.returncode is None:  # pragma: no cover - communicate plus cleanup sets it
        raise ReleaseEvidenceBuilderError("master gate execution failed")
    return MasterGateExecution(returncode=process.returncode, output=output)


def _terminate_and_reap_master_gate_process_group(
    process: subprocess.Popen[bytes],
) -> None:
    """Kill the gate's private session and reap its leader with bounded waits."""
    _kill_master_gate_process_group(process)
    if process.poll() is not None:
        return
    try:
        process.communicate(timeout=_MASTER_GATE_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        _kill_master_gate_process_group(process)
        try:
            process.communicate(timeout=_MASTER_GATE_REAP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as exc:  # pragma: no cover - unkillable OS child
            raise ReleaseEvidenceBuilderError(
                "master gate process group could not be reaped"
            ) from exc
    except OSError as exc:
        raise ReleaseEvidenceBuilderError("master gate process group could not be reaped") from exc


def _kill_master_gate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Send SIGKILL to the session created exclusively for one master-gate run."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        # Darwin can report EPERM after the session leader has exited but before Popen has
        # reaped it. A still-live leader means cleanup is genuinely unverified.
        if process.poll() is None:
            raise ReleaseEvidenceBuilderError(
                "master gate process group could not be terminated"
            ) from None


def _external_toolchain_python(path: Path, *, repository: Path) -> Path:
    """Require an explicit Python executable outside the release checkout."""
    if not path.is_absolute():
        raise ReleaseEvidenceBuilderError("toolchain Python must be an absolute path")
    absolute = path.absolute()
    try:
        resolved = absolute.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        raise ReleaseEvidenceBuilderError("toolchain Python is unavailable") from None
    repository_resolved = repository.resolve()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not os.access(absolute, os.X_OK)
        or absolute.is_relative_to(repository_resolved)
        or resolved.is_relative_to(repository_resolved)
    ):
        raise ReleaseEvidenceBuilderError(
            "toolchain Python must be an executable outside the release checkout"
        )
    return absolute


def _fixed_system_executable(name: str) -> Path:
    """Resolve one OS tool from a closed path set, never ambient ``PATH``."""
    candidates = {
        "bash": (Path("/bin/bash"), Path("/usr/bin/bash")),
        "git": (Path("/usr/bin/git"), Path("/bin/git")),
        "grep": (Path("/usr/bin/grep"), Path("/bin/grep")),
    }
    for candidate in candidates[name]:
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode) and os.access(candidate, os.X_OK):
            return candidate
    raise ReleaseEvidenceBuilderError(f"fixed master-gate {name} executable is unavailable")


def _executable_receipt(
    name: str,
    executable: Path,
    version_arguments: tuple[str, ...],
) -> MasterGateExecutableReceipt:
    """Hash an exact executable and capture its bounded version output."""
    try:
        resolved = executable.resolve(strict=True)
        completed = subprocess.run(
            (str(executable), *version_arguments),
            env={"PATH": _FIXED_SYSTEM_PATH, "LANG": "C", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ReleaseEvidenceBuilderError("master-gate toolchain could not be observed") from None
    output = completed.stdout[:4096].decode("utf-8", errors="replace").strip()
    if completed.returncode != 0 or not output:
        raise ReleaseEvidenceBuilderError("master-gate toolchain version is unavailable")
    return MasterGateExecutableReceipt(
        name=name,
        sha256=_hash_regular_file(resolved),
        version=" ".join(output.split()),
    )


def _tool_distribution_receipts(
    python: Path,
) -> tuple[MasterGateDistributionReceipt, ...]:
    """Derive exact top-level gate-tool package inventories from the selected Python."""
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": _FIXED_SYSTEM_PATH,
        "PYTHONDONTWRITEBYTECODE": "1",
        "STINGER_TOOL_DISTRIBUTIONS_JSON": json.dumps(_TOOL_DISTRIBUTIONS),
    }
    try:
        completed = subprocess.run(
            (str(python), "-I", "-c", _TOOLCHAIN_PROBE),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ReleaseEvidenceBuilderError("master-gate Python toolchain probe failed") from None
    if (
        completed.returncode != 0
        or not completed.stdout
        or len(completed.stdout) > _TOOLCHAIN_PROBE_LIMIT_BYTES
    ):
        raise ReleaseEvidenceBuilderError("master-gate Python toolchain is incomplete")
    try:
        raw = json.loads(completed.stdout)
        receipts = tuple(MasterGateDistributionReceipt.model_validate(item) for item in raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        raise ReleaseEvidenceBuilderError(
            "master-gate Python toolchain receipt is invalid"
        ) from None
    if tuple(item.name for item in receipts) != _TOOL_DISTRIBUTIONS:
        raise ReleaseEvidenceBuilderError("master-gate Python toolchain is incomplete")
    return receipts


def _git_archive(repository: Path, *, git: Path, expected_stinger_commit: str) -> bytes:
    """Read the exact committed tree as a deterministic tar archive."""
    try:
        completed = subprocess.run(
            (
                str(git),
                "-C",
                str(repository),
                "archive",
                "--format=tar",
                expected_stinger_commit,
            ),
            env={"PATH": _FIXED_SYSTEM_PATH, "LANG": "C", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ReleaseEvidenceBuilderError("tracked release snapshot could not be created") from None
    if completed.returncode != 0 or not completed.stdout:
        raise ReleaseEvidenceBuilderError("tracked release snapshot could not be created")
    return completed.stdout


def _extract_git_archive(
    archive: bytes,
    destination: Path,
) -> tuple[tuple[str, str, bool], ...]:
    """Extract only regular tracked files/directories and return their exact inventory."""
    inventory: list[tuple[str, str, bool]] = []
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
            members = bundle.getmembers()
            for member in members:
                relative = PurePosixPath(member.name)
                if (
                    not member.name
                    or relative.is_absolute()
                    or "." in relative.parts
                    or ".." in relative.parts
                    or "\\" in member.name
                    or member.name in seen
                    or not (member.isdir() or member.isfile())
                ):
                    raise ReleaseEvidenceBuilderError(
                        "tracked release snapshot contains an unsafe entry"
                    )
                seen.add(member.name)
                target = destination.joinpath(*relative.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                source = bundle.extractfile(member)
                if source is None:
                    raise ReleaseEvidenceBuilderError(
                        "tracked release snapshot contains an unreadable file"
                    )
                content = source.read()
                target.parent.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o700 if member.mode & 0o111 else 0o600,
                )
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(content)
                inventory.append((relative.as_posix(), _sha256(content), bool(member.mode & 0o111)))
    except (OSError, tarfile.TarError):
        raise ReleaseEvidenceBuilderError("tracked release snapshot is invalid") from None
    return tuple(sorted(inventory))


def _verify_tracked_snapshot(
    snapshot: Path,
    expected: tuple[tuple[str, str, bool], ...],
) -> None:
    """Fail if the master gate changed any tracked source file in its snapshot."""
    observed: list[tuple[str, str, bool]] = []
    for relative, _, _ in expected:
        path = snapshot.joinpath(*PurePosixPath(relative).parts)
        try:
            metadata = path.lstat()
        except OSError:
            raise ReleaseEvidenceBuilderError("master gate changed tracked source") from None
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ReleaseEvidenceBuilderError("master gate changed tracked source")
        observed.append(
            (
                relative,
                _hash_regular_file(path),
                bool(metadata.st_mode & 0o111),
            )
        )
    if tuple(observed) != expected:
        raise ReleaseEvidenceBuilderError("master gate changed tracked source")


def _require_real_directory(path: Path) -> Path:
    """Require a real nonsymlink directory and return its absolute spelling."""
    absolute = path.absolute()
    try:
        metadata = absolute.lstat()
    except OSError:
        raise ReleaseEvidenceBuilderError("release checkout is unavailable") from None
    if absolute.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseEvidenceBuilderError("release checkout must be a real directory")
    return absolute


def _clean_git_head(repository: Path) -> str:
    """Return HEAD only when the checkout is clean at a full object id."""
    try:
        return clean_exact_git_head(repository, timeout=_GIT_TIMEOUT_SECONDS)
    except DirtyGitCheckoutError:
        raise ReleaseEvidenceBuilderError(
            "release checkout must be clean at an exact commit"
        ) from None
    except GitCheckoutError:
        raise ReleaseEvidenceBuilderError("release Git identity could not be established") from None


def _sha256(content: bytes) -> str:
    """Return the canonical SHA-256 of exact in-memory bytes."""
    return hashlib.sha256(content).hexdigest()


def _load_release_artifact_files(
    *,
    protocol_freeze_receipt: Path,
    technical_report: Path,
    correction_policy: Path,
    conflicts_disclosure: Path,
    corpus_version: str,
    corpus_hash: str,
) -> tuple[ReleaseArtifactManifest, tuple[_ArtifactBinding, ...]]:
    """Parse four canonical typed artifacts and require one exact release identity."""
    protocol_freeze, protocol_binding = _parse_canonical_release_artifact(
        protocol_freeze_receipt,
        ProtocolFreezeArtifact,
    )
    technical, technical_binding = _parse_canonical_release_artifact(
        technical_report,
        TechnicalReportArtifact,
    )
    correction, correction_binding = _parse_canonical_release_artifact(
        correction_policy,
        CorrectionPolicyArtifact,
    )
    conflicts, conflicts_binding = _parse_canonical_release_artifact(
        conflicts_disclosure,
        ConflictsDisclosureArtifact,
    )
    try:
        manifest = ReleaseArtifactManifest(
            protocol_freeze=protocol_freeze,
            technical_report=technical,
            correction_policy=correction,
            conflicts_disclosure=conflicts,
        )
    except ValueError:
        raise ReleaseEvidenceBuilderError("release artifact manifest is inconsistent") from None
    protocol = compiled_benchmark_protocol()
    if (
        manifest.protocol_freeze.benchmark_protocol_version != protocol.benchmark_protocol_version
        or manifest.protocol_freeze.rubric_version != protocol.rubric_version
        or manifest.protocol_freeze.corpus_version != corpus_version
        or manifest.protocol_freeze.corpus_hash != corpus_hash
    ):
        raise ReleaseEvidenceBuilderError(
            "release artifacts do not match the compiled release identity"
        )
    return manifest, (
        protocol_binding,
        technical_binding,
        correction_binding,
        conflicts_binding,
    )


def _parse_canonical_release_artifact[ReleaseArtifactT: BaseModel](
    path: Path,
    model: type[ReleaseArtifactT],
) -> tuple[ReleaseArtifactT, _ArtifactBinding]:
    """Read one stable file, parse its closed schema, and require canonical exact bytes."""
    content = _read_release_artifact_bytes(path)
    try:
        raw = json.loads(content)
        if not isinstance(raw, dict):
            raise ValueError
        artifact = model.model_validate(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ReleaseEvidenceBuilderError(
            "release evidence artifact does not match its closed schema"
        ) from None
    if content != _canonical_model_bytes(artifact):
        raise ReleaseEvidenceBuilderError("release evidence artifact is not canonical typed JSON")
    return artifact, _ArtifactBinding(path=path.absolute(), sha256=_sha256(content))


def _read_release_artifact_bytes(path: Path) -> bytes:
    """Read bounded stable bytes from one regular nonsymlink artifact without path leakage."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ReleaseEvidenceBuilderError("release evidence artifact is unavailable") from None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ReleaseEvidenceBuilderError("release evidence artifact is not a regular file")
        content = bytearray()
        while True:
            chunk = os.read(descriptor, _READ_CHUNK)
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > _RELEASE_ARTIFACT_LIMIT_BYTES:
                raise ReleaseEvidenceBuilderError("release evidence artifact exceeds size limit")
        after = os.fstat(descriptor)
    except OSError:
        raise ReleaseEvidenceBuilderError("release evidence artifact could not be read") from None
    finally:
        os.close(descriptor)
    if not content:
        raise ReleaseEvidenceBuilderError("release evidence artifact is empty")
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise ReleaseEvidenceBuilderError("release evidence artifact changed while reading")
    return bytes(content)


def _bind_artifact(path: Path) -> _ArtifactBinding:
    """Capture the exact digest of one nonempty regular nonsymlink artifact."""
    return _ArtifactBinding(path=path.absolute(), sha256=_hash_regular_file(path))


def _verify_artifact_bindings(bindings: tuple[_ArtifactBinding, ...]) -> None:
    """Re-read every artifact and reject any content or file-type change."""
    for binding in bindings:
        if _hash_regular_file(binding.path) != binding.sha256:
            raise ReleaseEvidenceBuilderError("release evidence artifact changed")


def _hash_regular_file(path: Path) -> str:
    """Hash exact nonempty bytes from one regular nonsymlink file."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ReleaseEvidenceBuilderError("release evidence artifact is unavailable") from None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ReleaseEvidenceBuilderError("release evidence artifact is not a regular file")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, _READ_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
    except OSError:
        raise ReleaseEvidenceBuilderError("release evidence artifact could not be read") from None
    finally:
        os.close(descriptor)
    if size == 0:
        raise ReleaseEvidenceBuilderError("release evidence artifact is empty")
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise ReleaseEvidenceBuilderError("release evidence artifact changed while reading")
    return digest.hexdigest()


def _require_commit(value: str) -> None:
    """Require a full lowercase Git object id."""
    if _COMMIT_PATTERN.fullmatch(value) is None:
        raise ReleaseEvidenceBuilderError("expected commit must be a full Git object id")


def _require_semver(value: str) -> None:
    """Require a complete semantic version."""
    if _SEMVER_PATTERN.fullmatch(value) is None:
        raise ReleaseEvidenceBuilderError("corpus version must use semantic versioning")


def _require_sha256(value: str) -> None:
    """Require a canonical lowercase SHA-256."""
    if _SHA256_PATTERN.fullmatch(value) is None:
        raise ReleaseEvidenceBuilderError("corpus hash must be canonical sha256")


def _require_identifier(value: str) -> None:
    """Require one nonblank whitespace-free identifier."""
    if not value or value != value.strip() or any(character.isspace() for character in value):
        raise ReleaseEvidenceBuilderError(
            "release evidence signer identity must be nonblank and whitespace-free"
        )


def _canonical_model_sha256(model: BaseModel) -> str:
    """Hash one typed model using Stinger's canonical JSON convention."""
    payload = json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical_model_bytes(model: BaseModel) -> bytes:
    """Serialize one typed model deterministically with one terminal newline."""
    return (
        json.dumps(
            model.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _canonical_artifact_sha256(model: BaseModel) -> str:
    """Hash the exact canonical newline-terminated bytes written as an artifact."""
    return _sha256(_canonical_model_bytes(model))


def _atomic_create_private_directory(
    destination: Path,
    files: dict[str, bytes],
) -> None:
    """Atomically publish a complete private directory without overwriting."""
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ReleaseEvidenceBuilderError(
            "release evidence package parent must be an existing real directory"
        )
    if destination.is_symlink() or destination.exists():
        raise ReleaseEvidenceBuilderError("release evidence preparation package already exists")
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
                raise ReleaseEvidenceBuilderError("release evidence package member name is unsafe")
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
    except ReleaseEvidenceBuilderError:
        raise
    except OSError:
        raise ReleaseEvidenceBuilderError(
            "release evidence preparation package could not be created"
        ) from None
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
        except AttributeError:
            raise ReleaseEvidenceBuilderError(
                "atomic create-only package publication is unavailable"
            ) from None
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
        raise ReleaseEvidenceBuilderError("atomic create-only package publication is unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ReleaseEvidenceBuilderError("release evidence preparation package already exists")
    raise ReleaseEvidenceBuilderError(
        "release evidence preparation package could not be created"
    ) from None


def _fsync_directory(path: Path) -> None:
    """Persist directory entries before returning a completed package."""
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        raise ReleaseEvidenceBuilderError(
            "release evidence preparation package could not be persisted"
        ) from None
    try:
        os.fsync(descriptor)
    except OSError:
        raise ReleaseEvidenceBuilderError(
            "release evidence preparation package could not be persisted"
        ) from None
    finally:
        os.close(descriptor)


def _atomic_create(destination: Path, content: bytes) -> None:
    """Create one canonical file atomically and refuse existing destinations."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None = None
    temporary: Path | None = None
    try:
        descriptor, raw_temporary = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary = Path(raw_temporary)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        try:
            os.link(temporary, destination)
        except FileExistsError:
            raise ReleaseEvidenceBuilderError("release evidence output already exists") from None
        os.unlink(temporary)
        temporary = None
    except ReleaseEvidenceBuilderError:
        raise
    except OSError:
        raise ReleaseEvidenceBuilderError("release evidence output could not be created") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
