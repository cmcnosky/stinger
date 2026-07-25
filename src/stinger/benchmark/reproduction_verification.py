"""Full verification and public-gate handoff for reproduction evidence.

The private reproduction builder opens escrow in order to prove corpus and rerunnable
evidence integrity. A separate full-public verification step reopens both public bundles and
uses private leakage comparison material to recompute every claim that can be proved without
escrow:

* the target baseline and exact target report bytes;
* the reproduced public-bundle manifest and exact reproduced report bytes;
* the evaluator's detached reproduced-report signature;
* structural identity, modal outcomes, and classification-field discrepancies; and
* the bound discrepancy ledger and paired statistical comparison.

That step emits a canonical non-secret statement for a dedicated detached signature. The
release checker authorizes only that statement, its signature, and external verifier trust;
it never accepts bundle, report, escrow, corpus, marker, or leakage-policy paths.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from stinger.benchmark.comparison import (
    BenchmarkComparisonError,
    PairedBenchmarkComparison,
    verify_paired_comparison,
)
from stinger.benchmark.evidence import (
    BUNDLE_FORMAT_VERSION,
    BundleKind,
    EvidenceBundleError,
    EvidenceBundleManifest,
    EvidenceBundleReceipt,
    EvidenceRole,
    InventoryFile,
    PublicLeakagePolicy,
    verify_public_evidence_bundle_receipt,
)
from stinger.benchmark.gates import (
    BaselineConfigurationRecord,
    CrossMachineReproductionStatement,
    ReproductionDiscrepancyRecord,
    VerifiedCrossMachineReproductionAuthorization,
    VerifiedPublicReproductionAuthorization,
    baseline_configuration_record_sha256,
    canonical_report_sha256,
    reproduction_discrepancy_ledger_sha256,
    reproduction_modal_outcomes_sha256,
)
from stinger.benchmark.reproduction import (
    CLASSIFICATION_FIELDS,
    EXCLUDED_RUN_FIELDS,
    ReproductionBuilderError,
    ReproductionComparisonManifest,
    ReproductionDiffTemplate,
    build_reproduction_diff,
)
from stinger.benchmark.signing import (
    PROTOCOL_SIGNATURE_NAMESPACE,
    REPRODUCED_REPORT_SIGNATURE_NAMESPACE,
    REPRODUCTION_SIGNATURE_NAMESPACE,
    ArtifactSignatureVerification,
    ProtocolSignatureError,
    verify_public_reproduction_verification_statement_signature,
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

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SSH_KEY_FINGERPRINT_PATTERN = re.compile(r"^SHA256:[A-Za-z0-9+/]+={0,2}$")
_REQUIRED_COMPARISON_SAMPLES = 10_000
_REQUIRED_COMPARISON_SEED = 0
_REQUIRED_CONFIDENCE_LEVEL = 0.95
PUBLIC_REPRODUCTION_VERIFICATION_FORMAT_VERSION: Literal["1"] = "1"
PUBLIC_REPRODUCTION_VERIFICATION_DOMAIN: Literal["stinger-public-reproduction-verification-v1"] = (
    "stinger-public-reproduction-verification-v1"
)
_CORE_ROLES = frozenset(
    {
        EvidenceRole.PROTOCOL,
        EvidenceRole.PROTOCOL_SIGNATURE,
        EvidenceRole.SIGNER_POLICY,
        EvidenceRole.CONFIG,
        EvidenceRole.REPORT,
    }
)

__all__ = [
    "PublicReproductionVerificationError",
    "PublicReproductionVerificationStatement",
    "ReproductionDiscrepancyLedger",
    "VerifiedPublicReproductionReceipt",
    "authorize_public_reproduction_verification_statement",
    "build_public_reproduction_verification_statement",
    "verify_public_reproduction",
    "write_public_reproduction_verification_statement",
]


class PublicReproductionVerificationError(Exception):
    """Raised when public artifacts do not prove the signed reproduction statement."""


class ReproductionDiscrepancyLedger(BaseModel):
    """Closed public schema for the exact bound discrepancy-ledger payload."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    target_report_sha256: str
    reproduced_report_sha256: str
    discrepancies: tuple[ReproductionDiscrepancyRecord, ...] = ()


class PublicReproductionVerificationStatement(BaseModel):
    """Signed, non-secret handoff from full verification to the public release gate."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    format_version: Literal["1"] = PUBLIC_REPRODUCTION_VERIFICATION_FORMAT_VERSION
    domain: Literal["stinger-public-reproduction-verification-v1"] = (
        PUBLIC_REPRODUCTION_VERIFICATION_DOMAIN
    )
    signature_namespace: Literal["stinger-benchmark-public-reproduction-verification"] = (
        "stinger-benchmark-public-reproduction-verification"
    )
    benchmark_protocol_version: str
    authorized_reproduction_statement_sha256: str
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
    verifier_identity: str
    verifier_signing_key_fingerprint: str
    verifier_allowed_signers_sha256: str

    @field_validator(
        "authorized_reproduction_statement_sha256",
        "target_baseline_record_sha256",
        "target_report_sha256",
        "target_report_bytes_sha256",
        "target_public_bundle_manifest_sha256",
        "target_public_bundle_inventory_sha256",
        "target_public_bundle_leakage_policy_sha256",
        "target_public_bundle_report_sha256",
        "target_protocol_sha256",
        "target_protocol_signature_sha256",
        "target_protocol_allowed_signers_sha256",
        "reproduced_public_bundle_manifest_sha256",
        "reproduced_public_bundle_inventory_sha256",
        "reproduced_public_bundle_leakage_policy_sha256",
        "reproduced_public_bundle_report_sha256",
        "reproduced_protocol_sha256",
        "reproduced_protocol_signature_sha256",
        "reproduced_protocol_allowed_signers_sha256",
        "reproduced_report_sha256",
        "reproduced_report_bytes_sha256",
        "reproduced_report_signature_sha256",
        "reproduced_report_allowed_signers_sha256",
        "comparison_manifest_sha256",
        "discrepancy_ledger_sha256",
        "verifier_allowed_signers_sha256",
    )
    @classmethod
    def _valid_sha256(cls, value: str) -> str:
        """Require exact lowercase SHA-256 bindings."""
        if _SHA256_PATTERN.fullmatch(value) is None:
            raise ValueError("hash must be 64 lowercase hexadecimal characters")
        return value

    @field_validator(
        "reproduced_report_signing_key_fingerprint",
        "verifier_signing_key_fingerprint",
    )
    @classmethod
    def _valid_key_fingerprint(cls, value: str) -> str:
        """Require the canonical OpenSSH key-fingerprint form."""
        if _SSH_KEY_FINGERPRINT_PATTERN.fullmatch(value) is None:
            raise ValueError("signing key fingerprint is invalid")
        return value

    @field_validator(
        "reproduced_protocol_signer_identity",
        "target_protocol_signer_identity",
        "reproduced_report_signer_identity",
        "verifier_identity",
    )
    @classmethod
    def _valid_identity(cls, value: str) -> str:
        """Reject ambiguous or whitespace-bearing signer identities."""
        if not value or value != value.strip() or any(character.isspace() for character in value):
            raise ValueError("signer identity must be nonblank and whitespace-free")
        return value


@dataclass(frozen=True, slots=True)
class VerifiedPublicReproductionReceipt:
    """Non-secret typed receipt safe to hand to the public release gate."""

    statement: CrossMachineReproductionStatement
    statement_sha256: str
    statement_signature_sha256: str
    statement_allowed_signers_sha256: str
    statement_signing_key_fingerprint: str
    target_baseline: BaselineConfigurationRecord
    target_report: Report
    target_report_bytes_sha256: str
    target_public_bundle: EvidenceBundleReceipt
    target_public_bundle_manifest: EvidenceBundleManifest
    target_public_bundle_manifest_sha256: str
    reproduced_public_bundle: EvidenceBundleReceipt
    reproduced_public_bundle_manifest: EvidenceBundleManifest
    reproduced_public_bundle_manifest_sha256: str
    reproduced_report: Report
    reproduced_report_bytes_sha256: str
    reproduced_report_signature: ArtifactSignatureVerification
    comparison_manifest: ReproductionComparisonManifest
    comparison_manifest_sha256: str
    discrepancy_ledger: ReproductionDiscrepancyLedger
    discrepancy_ledger_sha256: str
    paired_comparison: PairedBenchmarkComparison


def build_public_reproduction_verification_statement(
    receipt: VerifiedPublicReproductionReceipt,
) -> PublicReproductionVerificationStatement:
    """Derive the signed public-gate handoff without caller-entered claims."""
    public_manifest = receipt.reproduced_public_bundle_manifest
    target_public_manifest = receipt.target_public_bundle_manifest
    if public_manifest.leakage_policy_sha256 is None:
        raise PublicReproductionVerificationError(
            "verified public bundle lacks a leakage-policy binding"
        )
    if target_public_manifest.leakage_policy_sha256 is None:
        raise PublicReproductionVerificationError(
            "verified target public bundle lacks a leakage-policy binding"
        )
    return PublicReproductionVerificationStatement(
        benchmark_protocol_version=receipt.statement.benchmark_protocol_version,
        authorized_reproduction_statement_sha256=receipt.statement_sha256,
        target_baseline_record_sha256=baseline_configuration_record_sha256(receipt.target_baseline),
        target_report_sha256=canonical_report_sha256(receipt.target_report),
        target_report_bytes_sha256=receipt.target_report_bytes_sha256,
        target_public_bundle_manifest_sha256=(receipt.target_public_bundle_manifest_sha256),
        target_public_bundle_inventory_sha256=target_public_manifest.inventory_sha256,
        target_public_bundle_leakage_policy_sha256=(target_public_manifest.leakage_policy_sha256),
        target_public_bundle_report_sha256=target_public_manifest.report_sha256,
        target_protocol_sha256=target_public_manifest.protocol_sha256,
        target_protocol_signature_sha256=target_public_manifest.protocol_signature_sha256,
        target_protocol_allowed_signers_sha256=target_public_manifest.allowed_signers_sha256,
        target_protocol_signer_identity=target_public_manifest.protocol_signer_identity,
        reproduced_public_bundle_manifest_sha256=(receipt.reproduced_public_bundle_manifest_sha256),
        reproduced_public_bundle_inventory_sha256=public_manifest.inventory_sha256,
        reproduced_public_bundle_leakage_policy_sha256=(public_manifest.leakage_policy_sha256),
        reproduced_public_bundle_report_sha256=public_manifest.report_sha256,
        reproduced_protocol_sha256=public_manifest.protocol_sha256,
        reproduced_protocol_signature_sha256=public_manifest.protocol_signature_sha256,
        reproduced_protocol_allowed_signers_sha256=public_manifest.allowed_signers_sha256,
        reproduced_protocol_signer_identity=public_manifest.protocol_signer_identity,
        reproduced_report_sha256=canonical_report_sha256(receipt.reproduced_report),
        reproduced_report_bytes_sha256=receipt.reproduced_report_bytes_sha256,
        reproduced_report_signature_sha256=(receipt.reproduced_report_signature.signature_sha256),
        reproduced_report_allowed_signers_sha256=(
            receipt.reproduced_report_signature.allowed_signers_sha256
        ),
        reproduced_report_signing_key_fingerprint=(
            receipt.reproduced_report_signature.signing_key_fingerprint
        ),
        reproduced_report_signer_identity=receipt.reproduced_report_signature.identity,
        comparison_manifest_sha256=receipt.comparison_manifest_sha256,
        discrepancy_ledger_sha256=receipt.discrepancy_ledger_sha256,
        verifier_identity=receipt.statement.signer_identity,
        verifier_signing_key_fingerprint=receipt.statement_signing_key_fingerprint,
        verifier_allowed_signers_sha256=receipt.statement_allowed_signers_sha256,
    )


def write_public_reproduction_verification_statement(
    statement: PublicReproductionVerificationStatement,
    destination: Path,
) -> None:
    """Atomically create one canonical verification statement."""
    _atomic_create(destination, _canonical_model_bytes(statement))


def authorize_public_reproduction_verification_statement(
    statement: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> VerifiedPublicReproductionAuthorization:
    """Authorize an exact canonical statement without reopening private verification inputs."""
    statement_bytes = _read_regular_bytes(
        statement,
        label="public reproduction verification statement",
    )
    model = _load_public_reproduction_verification_statement(statement_bytes)
    if statement_bytes != _canonical_model_bytes(model):
        raise PublicReproductionVerificationError(
            "public reproduction verification statement must use canonical JSON bytes"
        )
    with tempfile.TemporaryDirectory(
        prefix="stinger-public-reproduction-authorization-"
    ) as temporary:
        snapshot = Path(temporary) / "verification-statement.json"
        snapshot.write_bytes(statement_bytes)
        snapshot.chmod(0o600)
        try:
            verification = verify_public_reproduction_verification_statement_signature(
                snapshot,
                signature,
                allowed_signers,
                identity,
            )
        except ProtocolSignatureError as exc:
            raise PublicReproductionVerificationError(
                "public reproduction verification statement signature is invalid"
            ) from exc
    statement_hash = _sha256(statement_bytes)
    if (
        verification.artifact_sha256 != statement_hash
        or verification.namespace != model.signature_namespace
        or verification.identity != model.verifier_identity
        or verification.signing_key_fingerprint != model.verifier_signing_key_fingerprint
        or verification.allowed_signers_sha256 != model.verifier_allowed_signers_sha256
    ):
        raise PublicReproductionVerificationError(
            "public reproduction verification signature disagrees with its statement"
        )
    return VerifiedPublicReproductionAuthorization(
        verification_statement_sha256=statement_hash,
        verification_signature_sha256=verification.signature_sha256,
        verification_allowed_signers_sha256=verification.allowed_signers_sha256,
        verification_signing_key_fingerprint=verification.signing_key_fingerprint,
        verification_signer_identity=verification.identity,
        verification_signature_namespace=verification.namespace,
        benchmark_protocol_version=model.benchmark_protocol_version,
        statement_sha256=model.authorized_reproduction_statement_sha256,
        target_baseline_record_sha256=model.target_baseline_record_sha256,
        target_report_sha256=model.target_report_sha256,
        target_report_bytes_sha256=model.target_report_bytes_sha256,
        target_public_bundle_manifest_sha256=model.target_public_bundle_manifest_sha256,
        target_public_bundle_inventory_sha256=model.target_public_bundle_inventory_sha256,
        target_public_bundle_leakage_policy_sha256=(
            model.target_public_bundle_leakage_policy_sha256
        ),
        target_public_bundle_report_sha256=model.target_public_bundle_report_sha256,
        target_protocol_sha256=model.target_protocol_sha256,
        target_protocol_signature_sha256=model.target_protocol_signature_sha256,
        target_protocol_allowed_signers_sha256=(model.target_protocol_allowed_signers_sha256),
        target_protocol_signer_identity=model.target_protocol_signer_identity,
        reproduced_public_bundle_manifest_sha256=(model.reproduced_public_bundle_manifest_sha256),
        reproduced_public_bundle_inventory_sha256=(model.reproduced_public_bundle_inventory_sha256),
        reproduced_public_bundle_leakage_policy_sha256=(
            model.reproduced_public_bundle_leakage_policy_sha256
        ),
        reproduced_public_bundle_report_sha256=(model.reproduced_public_bundle_report_sha256),
        reproduced_protocol_sha256=model.reproduced_protocol_sha256,
        reproduced_protocol_signature_sha256=model.reproduced_protocol_signature_sha256,
        reproduced_protocol_allowed_signers_sha256=(
            model.reproduced_protocol_allowed_signers_sha256
        ),
        reproduced_protocol_signer_identity=model.reproduced_protocol_signer_identity,
        reproduced_report_sha256=model.reproduced_report_sha256,
        reproduced_report_bytes_sha256=model.reproduced_report_bytes_sha256,
        reproduced_report_signature_sha256=model.reproduced_report_signature_sha256,
        reproduced_report_allowed_signers_sha256=(model.reproduced_report_allowed_signers_sha256),
        reproduced_report_signing_key_fingerprint=(model.reproduced_report_signing_key_fingerprint),
        reproduced_report_signer_identity=model.reproduced_report_signer_identity,
        comparison_manifest_sha256=model.comparison_manifest_sha256,
        discrepancy_ledger_sha256=model.discrepancy_ledger_sha256,
    )


def verify_public_reproduction(
    authorization: VerifiedCrossMachineReproductionAuthorization,
    *,
    target_baseline: BaselineConfigurationRecord,
    target_public_bundle: Path,
    reproduced_public_bundle: Path,
    reproduced_public_leakage_policy: PublicLeakagePolicy,
    reproduced_protocol_allowed_signers: Path,
    reproduced_protocol_signer_identity: str,
    reproduced_report_signature: Path,
    reproduced_report_allowed_signers: Path,
    reproduced_report_signer_identity: str,
    comparison_manifest: Path,
    discrepancy_ledger: Path,
) -> VerifiedPublicReproductionReceipt:
    """Verify an authorized reproduction before constructing its public-gate handoff.

    Every file is snapshotted through a regular-nonsymlink descriptor before parsing or
    hashing.  Signature verification uses a temporary copy of the already-read report
    bytes, closing report-path substitution between parsing and OpenSSH verification. The
    active leakage policy is used here and is never handed to ``release-check``.

    Args:
        authorization: Previously verified evaluator signature and parsed statement.
        target_baseline: Artifact-derived baseline record already present in the release.
        target_public_bundle: Complete target public evidence bundle.
        reproduced_public_bundle: Complete reproduced public evidence bundle.
        reproduced_public_leakage_policy: Active sealed-source and marker comparison set.
        reproduced_protocol_allowed_signers: Independently supplied protocol trust policy.
        reproduced_protocol_signer_identity: Independently expected protocol signer.
        reproduced_report_signature: Detached evaluator signature over the reproduced report.
        reproduced_report_allowed_signers: Independently obtained evaluator trust policy.
        reproduced_report_signer_identity: Expected evaluator principal.
        comparison_manifest: Exact public ``comparison.manifest.json``.
        discrepancy_ledger: Exact public ``discrepancy-ledger.json``.

    Returns:
        A frozen receipt containing only public typed artifacts and cryptographic hashes.

    Raises:
        PublicReproductionVerificationError: If any public claim is missing, ambiguous,
            inconsistent, noncanonical, unsigned, or not mechanically reproducible.
    """
    statement = authorization.statement
    _verify_statement_authorization(authorization)

    try:
        target_public_bundle_receipt = verify_public_evidence_bundle_receipt(
            target_public_bundle,
            reproduced_public_leakage_policy,
            trusted_allowed_signers=reproduced_protocol_allowed_signers,
            expected_signer_identity=reproduced_protocol_signer_identity,
        )
    except EvidenceBundleError as exc:
        raise PublicReproductionVerificationError(
            "target public evidence bundle failed complete verification"
        ) from exc
    try:
        public_bundle_receipt = verify_public_evidence_bundle_receipt(
            reproduced_public_bundle,
            reproduced_public_leakage_policy,
            trusted_allowed_signers=reproduced_protocol_allowed_signers,
            expected_signer_identity=reproduced_protocol_signer_identity,
        )
    except EvidenceBundleError as exc:
        raise PublicReproductionVerificationError(
            "reproduced public evidence bundle failed complete verification"
        ) from exc
    target_report_bytes = target_public_bundle_receipt.report_bytes
    reproduced_report_bytes = public_bundle_receipt.report_bytes
    target_public_manifest_bytes = target_public_bundle_receipt.manifest_bytes
    public_manifest_bytes = public_bundle_receipt.manifest_bytes
    comparison_bytes = _read_regular_bytes(
        comparison_manifest,
        label="reproduction comparison manifest",
    )
    ledger_bytes = _read_regular_bytes(
        discrepancy_ledger,
        label="reproduction discrepancy ledger",
    )

    target_report_model = target_public_bundle_receipt.report
    reproduced_report_model = public_bundle_receipt.report
    target_public_manifest_model = target_public_bundle_receipt.manifest
    public_manifest_model = public_bundle_receipt.manifest
    comparison_model = _load_comparison_manifest(comparison_bytes)
    ledger_model = _load_discrepancy_ledger(ledger_bytes)

    signature_verification = _verify_report_signature(
        reproduced_report_bytes,
        signature=reproduced_report_signature,
        allowed_signers=reproduced_report_allowed_signers,
        identity=reproduced_report_signer_identity,
    )

    target_report_bytes_hash = _sha256(target_report_bytes)
    reproduced_report_bytes_hash = _sha256(reproduced_report_bytes)
    target_public_manifest_hash = _sha256(target_public_manifest_bytes)
    public_manifest_hash = _sha256(public_manifest_bytes)
    comparison_hash = _sha256(comparison_bytes)
    ledger_hash = _sha256(ledger_bytes)

    _verify_target(
        statement,
        target_baseline=target_baseline,
        target_report=target_report_model,
        target_public_bundle_manifest_sha256=target_public_manifest_hash,
    )
    _verify_reproduced_identity(
        statement,
        reproduced_report=reproduced_report_model,
        public_manifest_sha256=public_manifest_hash,
        signature=signature_verification,
    )
    expected_diff = _recompute_diff(target_report_model, reproduced_report_model)
    _verify_statement_shape(
        statement,
        reproduced_report=reproduced_report_model,
        expected_discrepancies=expected_diff.discrepancies,
    )
    _verify_ledger(
        statement,
        ledger_model=ledger_model,
        ledger_bytes=ledger_bytes,
        expected_discrepancies=expected_diff.discrepancies,
    )
    _verify_comparison(
        statement,
        comparison_model=comparison_model,
        target_baseline=target_baseline,
        target_report=target_report_model,
        reproduced_report=reproduced_report_model,
        target_report_bytes_sha256=target_report_bytes_hash,
        reproduced_report_bytes_sha256=reproduced_report_bytes_hash,
        target_public_bundle_manifest_sha256=target_public_manifest_hash,
        reproduced_public_bundle_manifest_sha256=public_manifest_hash,
        report_signature=signature_verification,
    )

    if statement.comparison_manifest_sha256 != comparison_hash:
        raise PublicReproductionVerificationError(
            "comparison manifest hash disagrees with the signed statement"
        )
    if statement.discrepancy_ledger_sha256 != ledger_hash:
        raise PublicReproductionVerificationError(
            "discrepancy ledger hash disagrees with the signed statement"
        )

    return VerifiedPublicReproductionReceipt(
        statement=statement,
        statement_sha256=authorization.statement_sha256,
        statement_signature_sha256=authorization.signature_sha256,
        statement_allowed_signers_sha256=authorization.allowed_signers_sha256,
        statement_signing_key_fingerprint=authorization.signing_key_fingerprint,
        target_baseline=target_baseline,
        target_report=target_report_model,
        target_report_bytes_sha256=target_report_bytes_hash,
        target_public_bundle=target_public_bundle_receipt,
        target_public_bundle_manifest=target_public_manifest_model,
        target_public_bundle_manifest_sha256=target_public_manifest_hash,
        reproduced_public_bundle=public_bundle_receipt,
        reproduced_public_bundle_manifest=public_manifest_model,
        reproduced_public_bundle_manifest_sha256=public_manifest_hash,
        reproduced_report=reproduced_report_model,
        reproduced_report_bytes_sha256=reproduced_report_bytes_hash,
        reproduced_report_signature=signature_verification,
        comparison_manifest=comparison_model,
        comparison_manifest_sha256=comparison_hash,
        discrepancy_ledger=ledger_model,
        discrepancy_ledger_sha256=ledger_hash,
        paired_comparison=comparison_model.paired_comparison,
    )


def _verify_statement_authorization(
    authorization: VerifiedCrossMachineReproductionAuthorization,
) -> None:
    """Reject fabricated or internally inconsistent authorization dataclasses."""
    statement = authorization.statement
    if (
        authorization.namespace != REPRODUCTION_SIGNATURE_NAMESPACE
        or not authorization.identity
        or authorization.identity != authorization.identity.strip()
        or statement.signer_identity != authorization.identity
        or statement.reproduced_report_signer_identity != authorization.identity
        or statement.reproduced_report_signature_namespace != REPRODUCED_REPORT_SIGNATURE_NAMESPACE
        or statement.reproduced_report_signing_key_fingerprint
        != authorization.signing_key_fingerprint
        or statement.reproduced_report_allowed_signers_sha256
        != authorization.allowed_signers_sha256
        or _SSH_KEY_FINGERPRINT_PATTERN.fullmatch(authorization.signing_key_fingerprint) is None
        or authorization.canonical_statement_sha256 != _canonical_model_sha256(statement)
    ):
        raise PublicReproductionVerificationError(
            "reproduction statement authorization is internally inconsistent"
        )
    for digest in (
        authorization.statement_sha256,
        authorization.signature_sha256,
        authorization.allowed_signers_sha256,
    ):
        _require_sha256(digest, label="reproduction authorization hash")


def _verify_target(
    statement: CrossMachineReproductionStatement,
    *,
    target_baseline: BaselineConfigurationRecord,
    target_report: Report,
    target_public_bundle_manifest_sha256: str,
) -> None:
    """Bind the statement to the exact target baseline and parsed target report."""
    target_metadata = target_report.benchmark_metadata
    if (
        target_baseline.report != target_report
        or target_baseline.report_sha256 != canonical_report_sha256(target_report)
        or statement.configuration_id != target_baseline.configuration_id
        or statement.target_report_sha256 != target_baseline.report_sha256
        or statement.target_public_bundle_manifest_sha256
        != target_baseline.public_bundle_manifest_sha256
        or statement.target_public_bundle_manifest_sha256 != target_public_bundle_manifest_sha256
        or statement.target_escrow_bundle_manifest_sha256
        != target_baseline.escrow_bundle_manifest_sha256
        or statement.target_machine_fingerprint_sha256 != target_baseline.machine_fingerprint_sha256
        or statement.target_config_fingerprint != target_report.config_fingerprint
        or target_metadata is None
        or target_metadata.agent_configuration_fingerprint is None
        or statement.target_agent_configuration_fingerprint
        != target_metadata.agent_configuration_fingerprint
        or statement.benchmark_protocol_version != target_report.benchmark_protocol_version
        or statement.corpus_hash != target_report.corpus_hash
    ):
        raise PublicReproductionVerificationError(
            "signed statement does not bind the supplied target baseline"
        )
    try:
        verify_report(target_report)
    except ReportMismatchError as exc:
        raise PublicReproductionVerificationError(
            "target report failed deterministic verification"
        ) from exc


def _verify_reproduced_identity(
    statement: CrossMachineReproductionStatement,
    *,
    reproduced_report: Report,
    public_manifest_sha256: str,
    signature: ArtifactSignatureVerification,
) -> None:
    """Bind reproduced report bytes, public inventory, and evaluator trust."""
    metadata = reproduced_report.benchmark_metadata
    if (
        statement.reproduced_public_bundle_manifest_sha256 != public_manifest_sha256
        or statement.reproduced_report_sha256 != canonical_report_sha256(reproduced_report)
        or statement.reproduced_config_fingerprint != reproduced_report.config_fingerprint
        or metadata is None
        or metadata.agent_configuration_fingerprint is None
        or statement.reproduced_agent_configuration_fingerprint
        != metadata.agent_configuration_fingerprint
        or statement.reproduced_report_signature_sha256 != signature.signature_sha256
        or statement.reproduced_report_signature_namespace != signature.namespace
        or statement.reproduced_report_signer_identity != signature.identity
        or statement.reproduced_report_signing_key_fingerprint != signature.signing_key_fingerprint
        or statement.reproduced_report_allowed_signers_sha256 != signature.allowed_signers_sha256
        or statement.reproduced_machine_fingerprint_sha256
        == statement.target_machine_fingerprint_sha256
        or statement.reproduced_report_sha256 == statement.target_report_sha256
        or statement.reproduced_public_bundle_manifest_sha256
        == statement.target_public_bundle_manifest_sha256
        or statement.reproduced_escrow_bundle_manifest_sha256
        == statement.target_escrow_bundle_manifest_sha256
    ):
        raise PublicReproductionVerificationError(
            "reproduced public evidence does not match the signed statement"
        )


def _verify_statement_shape(
    statement: CrossMachineReproductionStatement,
    *,
    reproduced_report: Report,
    expected_discrepancies: tuple[ReproductionDiscrepancyRecord, ...],
) -> None:
    """Recompute result coverage, modal outcomes, and every discrepancy."""
    scenario_ids = {result.scenario_id for result in reproduced_report.results}
    completed_families = tuple(
        family
        for family in Family
        if any(result.family is family for result in reproduced_report.results)
    )
    repetitions_by_scenario: dict[str, set[int]] = {
        scenario_id: set() for scenario_id in scenario_ids
    }
    for result in reproduced_report.results:
        repetitions_by_scenario[result.scenario_id].add(result.repetition)
    required_repetitions = set(range(statement.repetitions))
    if (
        not statement.evaluator_id
        or statement.evaluator_id != statement.evaluator_id.strip()
        or statement.scenario_count != len(scenario_ids)
        or statement.completed_families != completed_families
        or statement.repetitions <= 0
        or any(
            repetitions != required_repetitions for repetitions in repetitions_by_scenario.values()
        )
        or statement.target_modal_outcomes_sha256 != statement.reproduced_modal_outcomes_sha256
        or statement.reproduced_modal_outcomes_sha256
        != reproduction_modal_outcomes_sha256(reproduced_report)
        or statement.discrepancies != expected_discrepancies
    ):
        raise PublicReproductionVerificationError(
            "reproduction shape or classification evidence disagrees with public reports"
        )


def _verify_ledger(
    statement: CrossMachineReproductionStatement,
    *,
    ledger_model: ReproductionDiscrepancyLedger,
    ledger_bytes: bytes,
    expected_discrepancies: tuple[ReproductionDiscrepancyRecord, ...],
) -> None:
    """Recompute the report-bound canonical discrepancy ledger."""
    ordered_discrepancies = _ordered_discrepancies(expected_discrepancies)
    expected_hash = reproduction_discrepancy_ledger_sha256(
        expected_discrepancies,
        target_report_sha256=statement.target_report_sha256,
        reproduced_report_sha256=statement.reproduced_report_sha256,
    )
    if (
        ledger_model.target_report_sha256 != statement.target_report_sha256
        or ledger_model.reproduced_report_sha256 != statement.reproduced_report_sha256
        or ledger_model.discrepancies != ordered_discrepancies
        or statement.discrepancy_ledger_sha256 != expected_hash
        or _sha256(ledger_bytes) != expected_hash
    ):
        raise PublicReproductionVerificationError(
            "discrepancy ledger does not recompute from the public reports"
        )


def _ordered_discrepancies(
    discrepancies: tuple[ReproductionDiscrepancyRecord, ...],
) -> tuple[ReproductionDiscrepancyRecord, ...]:
    """Match the canonical ledger ordering used by the private builder."""
    return tuple(
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


def _verify_comparison(
    statement: CrossMachineReproductionStatement,
    *,
    comparison_model: ReproductionComparisonManifest,
    target_baseline: BaselineConfigurationRecord,
    target_report: Report,
    reproduced_report: Report,
    target_report_bytes_sha256: str,
    reproduced_report_bytes_sha256: str,
    target_public_bundle_manifest_sha256: str,
    reproduced_public_bundle_manifest_sha256: str,
    report_signature: ArtifactSignatureVerification,
) -> None:
    """Cross-bind every public comparison field and recompute paired intervals."""
    target_metadata = target_report.benchmark_metadata
    reproduced_metadata = reproduced_report.benchmark_metadata
    paired = comparison_model.paired_comparison
    if (
        target_metadata is None
        or reproduced_metadata is None
        or target_metadata.agent_configuration_fingerprint is None
        or reproduced_metadata.agent_configuration_fingerprint is None
        or comparison_model.benchmark_protocol_version != statement.benchmark_protocol_version
        or comparison_model.rubric_version != target_report.rubric_version
        or comparison_model.corpus_hash != statement.corpus_hash
        or comparison_model.configuration_id != statement.configuration_id
        or comparison_model.config_fingerprint != target_report.config_fingerprint
        or comparison_model.agent_configuration_fingerprint
        != target_metadata.agent_configuration_fingerprint
        or comparison_model.target_report_sha256 != statement.target_report_sha256
        or comparison_model.reproduced_report_sha256 != statement.reproduced_report_sha256
        or comparison_model.target_modal_outcomes_sha256 != statement.target_modal_outcomes_sha256
        or comparison_model.reproduced_modal_outcomes_sha256
        != statement.reproduced_modal_outcomes_sha256
        or comparison_model.target_report_bytes_sha256 != target_report_bytes_sha256
        or comparison_model.reproduced_report_bytes_sha256 != reproduced_report_bytes_sha256
        or comparison_model.target_public_bundle_manifest_sha256
        != target_public_bundle_manifest_sha256
        or target_public_bundle_manifest_sha256 != target_baseline.public_bundle_manifest_sha256
        or comparison_model.target_escrow_bundle_manifest_sha256
        != target_baseline.escrow_bundle_manifest_sha256
        or comparison_model.reproduced_public_bundle_manifest_sha256
        != reproduced_public_bundle_manifest_sha256
        or comparison_model.reproduced_escrow_bundle_manifest_sha256
        != statement.reproduced_escrow_bundle_manifest_sha256
        or comparison_model.reproduced_report_signature_sha256 != report_signature.signature_sha256
        or comparison_model.reproduced_report_signature_namespace != report_signature.namespace
        or comparison_model.reproduced_report_signer_identity != report_signature.identity
        or comparison_model.reproduced_report_signing_key_fingerprint
        != report_signature.signing_key_fingerprint
        or comparison_model.reproduced_report_allowed_signers_sha256
        != report_signature.allowed_signers_sha256
        or comparison_model.classification_fields != CLASSIFICATION_FIELDS
        or comparison_model.excluded_run_fields != EXCLUDED_RUN_FIELDS
        or comparison_model.discrepancy_ledger_sha256 != statement.discrepancy_ledger_sha256
        or comparison_model.discrepancy_count != len(statement.discrepancies)
        or paired.seed != _REQUIRED_COMPARISON_SEED
        or paired.overall_interval.bootstrap_samples != _REQUIRED_COMPARISON_SAMPLES
        or paired.overall_interval.confidence_level != _REQUIRED_CONFIDENCE_LEVEL
        or any(
            interval.bootstrap_samples != _REQUIRED_COMPARISON_SAMPLES
            or interval.confidence_level != _REQUIRED_CONFIDENCE_LEVEL
            for interval in paired.family_intervals.values()
        )
    ):
        raise PublicReproductionVerificationError(
            "comparison manifest does not bind the authorized public evidence"
        )
    try:
        verify_paired_comparison(paired, reproduced_report, target_report)
    except BenchmarkComparisonError as exc:
        raise PublicReproductionVerificationError(
            "paired comparison does not recompute from the public reports"
        ) from exc


def _recompute_diff(target: Report, reproduced: Report) -> ReproductionDiffTemplate:
    """Recompute the existing strict structural, modal, and field-difference contract."""
    try:
        return build_reproduction_diff(target, reproduced)
    except ReproductionBuilderError as exc:
        raise PublicReproductionVerificationError(
            "public reports do not form a valid modal-stable reproduction pair"
        ) from exc


def _load_report(content: bytes, *, label: str) -> Report:
    """Parse one report without allowing legacy models to ignore unknown fields."""
    try:
        raw = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicReproductionVerificationError(f"{label} is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise PublicReproductionVerificationError(f"{label} root must be an object")
    _require_known_keys(raw, Report, label=label)
    results = raw.get("results")
    if not isinstance(results, list):
        raise PublicReproductionVerificationError(f"{label} results must be a list")
    for result in results:
        if not isinstance(result, dict):
            raise PublicReproductionVerificationError(f"{label} result must be an object")
        _require_known_keys(result, ScenarioResult, label=label)
        detector_results = result.get("detector_results")
        if not isinstance(detector_results, list):
            raise PublicReproductionVerificationError(f"{label} detector results must be a list")
        for detector in detector_results:
            if not isinstance(detector, dict):
                raise PublicReproductionVerificationError(
                    f"{label} detector result must be an object"
                )
            _require_known_keys(detector, DetectorResult, label=label)
    family_scores = raw.get("family_scores")
    if not isinstance(family_scores, dict):
        raise PublicReproductionVerificationError(f"{label} family scores must be an object")
    for score in family_scores.values():
        if not isinstance(score, dict):
            raise PublicReproductionVerificationError(f"{label} family score must be an object")
        _require_known_keys(score, FamilyScore, label=label)
    judge = raw.get("judge_assisted")
    if judge is not None:
        if not isinstance(judge, dict):
            raise PublicReproductionVerificationError(f"{label} judge block must be an object")
        _require_known_keys(judge, JudgeReport, label=label)
    try:
        report = Report.model_validate(raw)
        verify_report(report)
    except (ValidationError, ReportMismatchError, ValueError) as exc:
        raise PublicReproductionVerificationError(
            f"{label} failed deterministic verification"
        ) from exc
    return report


def _load_public_manifest(
    content: bytes,
    *,
    reproduced_report_bytes: bytes,
) -> EvidenceBundleManifest:
    """Parse and internally verify a canonical public inventory without escrow."""
    try:
        manifest = EvidenceBundleManifest.model_validate_json(content)
    except (ValidationError, ValueError) as exc:
        raise PublicReproductionVerificationError(
            "reproduced public-bundle manifest is invalid"
        ) from exc
    if content != _canonical_model_bytes(manifest):
        raise PublicReproductionVerificationError(
            "reproduced public-bundle manifest is not canonical"
        )
    _verify_public_manifest_shape(manifest, reproduced_report_bytes)
    return manifest


def _verify_public_manifest_shape(
    manifest: EvidenceBundleManifest,
    report_bytes: bytes,
) -> None:
    """Verify public role shape, inventory digest, and exact report membership."""
    if (
        manifest.format_version != BUNDLE_FORMAT_VERSION
        or manifest.bundle_kind is not BundleKind.PUBLIC
        or manifest.leakage_policy_sha256 is None
        or manifest.access_control_notice is not None
        or manifest.protocol_signature_namespace != PROTOCOL_SIGNATURE_NAMESPACE
    ):
        raise PublicReproductionVerificationError(
            "reproduced bundle manifest is not a public evidence inventory"
        )
    _require_sha256(manifest.leakage_policy_sha256, label="public leakage policy hash")
    for digest in (
        manifest.protocol_sha256,
        manifest.protocol_signature_sha256,
        manifest.allowed_signers_sha256,
        manifest.config_sha256,
        manifest.report_sha256,
        manifest.inventory_sha256,
    ):
        _require_sha256(digest, label="public manifest hash")
    if (
        not manifest.protocol_signer_identity
        or manifest.protocol_signer_identity != manifest.protocol_signer_identity.strip()
    ):
        raise PublicReproductionVerificationError(
            "public manifest protocol signer identity is invalid"
        )

    roles: dict[EvidenceRole, list[tuple[str, InventoryFile]]] = {}
    for path, entry in manifest.files.items():
        _require_safe_relative_path(path)
        _require_sha256(entry.sha256, label="public inventory file hash")
        if entry.size < 0:
            raise PublicReproductionVerificationError(
                "public inventory contains an invalid file size"
            )
        roles.setdefault(entry.role, []).append((path, entry))
    for path, role in manifest.directories.items():
        _require_safe_relative_path(path)
        if role not in _CORE_ROLES | {EvidenceRole.LOG}:
            raise PublicReproductionVerificationError(
                "public inventory contains a forbidden directory role"
            )
    if any(role not in _CORE_ROLES | {EvidenceRole.LOG} for role in roles) or any(
        len(roles.get(role, ())) != 1 for role in _CORE_ROLES
    ):
        raise PublicReproductionVerificationError(
            "public inventory does not contain exactly one of every core role"
        )
    if any(
        entry.role is EvidenceRole.LOG and not path.startswith("logs/")
        for path, entry in manifest.files.items()
    ):
        raise PublicReproductionVerificationError(
            "public inventory contains a log outside its public log directory"
        )

    role_hashes = {
        EvidenceRole.PROTOCOL: manifest.protocol_sha256,
        EvidenceRole.PROTOCOL_SIGNATURE: manifest.protocol_signature_sha256,
        EvidenceRole.SIGNER_POLICY: manifest.allowed_signers_sha256,
        EvidenceRole.CONFIG: manifest.config_sha256,
        EvidenceRole.REPORT: manifest.report_sha256,
    }
    for role, expected_hash in role_hashes.items():
        entry = roles[role][0][1]
        if entry.sha256 != expected_hash:
            raise PublicReproductionVerificationError(
                "public inventory core-role hash disagrees with its manifest field"
            )
    report_entry = roles[EvidenceRole.REPORT][0][1]
    if (
        report_entry.sha256 != _sha256(report_bytes)
        or report_entry.size != len(report_bytes)
        or report_entry.executable
    ):
        raise PublicReproductionVerificationError(
            "public inventory does not bind the supplied reproduced report bytes"
        )
    inventory_payload = {
        "files": {
            path: entry.model_dump(mode="json") for path, entry in sorted(manifest.files.items())
        },
        "directories": {path: role.value for path, role in sorted(manifest.directories.items())},
    }
    if manifest.inventory_sha256 != _sha256(_canonical_payload_bytes(inventory_payload)):
        raise PublicReproductionVerificationError("public inventory digest does not recompute")


def _load_comparison_manifest(content: bytes) -> ReproductionComparisonManifest:
    """Parse the exact canonical comparison artifact."""
    try:
        manifest = ReproductionComparisonManifest.model_validate_json(content)
    except (ValidationError, ValueError) as exc:
        raise PublicReproductionVerificationError(
            "reproduction comparison manifest is invalid"
        ) from exc
    if content != _canonical_model_bytes(manifest):
        raise PublicReproductionVerificationError(
            "reproduction comparison manifest is not canonical"
        )
    return manifest


def _load_discrepancy_ledger(content: bytes) -> ReproductionDiscrepancyLedger:
    """Parse the exact canonical report-bound ledger."""
    try:
        ledger = ReproductionDiscrepancyLedger.model_validate_json(content)
    except (ValidationError, ValueError) as exc:
        raise PublicReproductionVerificationError(
            "reproduction discrepancy ledger is invalid"
        ) from exc
    if content != _canonical_payload_bytes(ledger.model_dump(mode="json")):
        raise PublicReproductionVerificationError(
            "reproduction discrepancy ledger is not canonical"
        )
    return ledger


def _verify_report_signature(
    report_bytes: bytes,
    *,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> ArtifactSignatureVerification:
    """Verify OpenSSH against the already-snapshotted reproduced report bytes."""
    try:
        with tempfile.TemporaryDirectory(prefix="stinger-public-reproduction-") as temporary:
            snapshot = Path(temporary) / "report.json"
            snapshot.write_bytes(report_bytes)
            snapshot.chmod(0o600)
            verification = verify_reproduced_report_signature(
                snapshot,
                signature,
                allowed_signers,
                identity,
            )
    except (OSError, ProtocolSignatureError, ValueError) as exc:
        raise PublicReproductionVerificationError(
            "reproduced report signature verification failed"
        ) from exc
    if (
        verification.namespace != REPRODUCED_REPORT_SIGNATURE_NAMESPACE
        or verification.artifact_sha256 != _sha256(report_bytes)
    ):
        raise PublicReproductionVerificationError(
            "reproduced report signature does not bind the verified bytes"
        )
    return verification


def _require_known_keys(
    raw: Mapping[str, object],
    model: type[BaseModel],
    *,
    label: str,
) -> None:
    """Reject keys that legacy report models would otherwise ignore."""
    if not set(raw).issubset(model.model_fields):
        raise PublicReproductionVerificationError(f"{label} contains unknown fields")


def _require_safe_relative_path(value: str) -> None:
    """Reject ambiguous, absolute, or traversal paths in public inventories."""
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
    ):
        raise PublicReproductionVerificationError(
            "public inventory contains an unsafe relative path"
        )


def _read_regular_bytes(path: Path, *, label: str) -> bytes:
    """Read nonempty exact bytes from a regular nonsymlink file without FIFO blocking."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PublicReproductionVerificationError(
            f"{label} must be a readable regular nonsymlink file"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PublicReproductionVerificationError(
                f"{label} must be a readable regular nonsymlink file"
            )
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
        raise PublicReproductionVerificationError(f"{label} must not be empty")
    return content


def _load_public_reproduction_verification_statement(
    content: bytes,
) -> PublicReproductionVerificationStatement:
    """Parse the closed public-gate handoff schema."""
    try:
        raw = json.loads(content)
        if not isinstance(raw, dict):
            raise ValueError("statement root must be an object")
        return PublicReproductionVerificationStatement.model_validate(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise PublicReproductionVerificationError(
            "public reproduction verification statement is invalid"
        ) from exc


def _atomic_create(destination: Path, content: bytes) -> None:
    """Create one private canonical file without following a destination symlink."""
    try:
        parent_metadata = destination.parent.stat(follow_symlinks=False)
    except OSError as exc:
        raise PublicReproductionVerificationError(
            "verification statement output parent is unavailable"
        ) from exc
    if not stat.S_ISDIR(parent_metadata.st_mode) or destination.parent.is_symlink():
        raise PublicReproductionVerificationError(
            "verification statement output parent must be a real directory"
        )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(destination, flags, 0o600)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        with contextlib.suppress(OSError):
            destination.unlink(missing_ok=True)
        raise PublicReproductionVerificationError(
            "verification statement could not be created atomically"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _canonical_model_bytes(model: BaseModel) -> bytes:
    """Serialize one closed public artifact exactly as its builder does."""
    return _canonical_payload_bytes(model.model_dump(mode="json")) + b"\n"


def _canonical_model_sha256(model: BaseModel) -> str:
    """Hash one typed model without a transport newline."""
    return _sha256(_canonical_payload_bytes(model.model_dump(mode="json")))


def _canonical_payload_bytes(payload: object) -> bytes:
    """Serialize JSON without incidental whitespace or key-order dependence."""
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(content: bytes) -> str:
    """Return the exact lowercase SHA-256 digest."""
    return hashlib.sha256(content).hexdigest()


def _require_sha256(value: str, *, label: str) -> None:
    """Require one exact lowercase SHA-256 digest."""
    if _SHA256_PATTERN.fullmatch(value) is None:
        raise PublicReproductionVerificationError(
            f"{label} must be 64 lowercase hexadecimal characters"
        )
