"""Artifact-derived baseline records for the benchmark release gate.

Release schemas deliberately remain simple signed records. This module is the trusted
construction path that turns verified public/escrow evidence into those records without
accepting favorable booleans or caller-entered artifact hashes.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path

from pydantic import BaseModel

from stinger.benchmark.evidence import (
    EvidenceBundleError,
    PublicLeakagePolicy,
    VerifiedArtifactReceipt,
    verify_evidence_bundle_pair,
)
from stinger.benchmark.gates import (
    BaselineConfigurationRecord,
    BaselineVerificationStatement,
    BenchmarkProtocolManifest,
    CorpusFreezeRecord,
    CorpusFreezeStatement,
    SealedCorpusRecord,
    authorize_candidate_promotion_statement,
    authorize_candidate_validation_receipt,
    authorize_corpus_freeze_statement,
    baseline_configuration_record_sha256,
    canonical_report_sha256,
    corpus_scenario_inventory_sha256,
    evaluate_baseline_configuration_record,
    evaluate_corpus_construction,
)
from stinger.benchmark.machine_environment import (
    MachineAttestationError,
    MachineWorkflowEvidencePaths,
    VerifiedMachineWorkflowAttestation,
    verify_machine_workflow_attestation,
)
from stinger.benchmark.ordering import (
    ScenarioOrderItem,
    deterministic_blocked_ids,
    observed_scenario_order,
)
from stinger.benchmark.protocol import (
    canonical_local_provider_binding_issues,
    publication_pin_issues,
)
from stinger.benchmark.signing import ProtocolSignatureError
from stinger.harness.sandbox import Isolation
from stinger.report.generate import ReportMismatchError, verify_report

__all__ = [
    "BaselineRecordError",
    "build_baseline_configuration_record",
    "build_baseline_verification_statement",
    "build_corpus_freeze_record",
    "build_corpus_freeze_statement",
    "write_baseline_configuration_record",
    "write_baseline_verification_statement",
    "write_corpus_freeze_record",
    "write_corpus_freeze_statement",
]


class BaselineRecordError(Exception):
    """Raised when verified artifacts cannot support a favorable baseline record."""


def build_baseline_configuration_record(
    configuration_id: str,
    *,
    corpus: SealedCorpusRecord,
    public_bundle: Path,
    escrow_bundle: Path,
    leakage_policy: PublicLeakagePolicy,
    protocol_allowed_signers: Path,
    protocol_signer_identity: str,
    machine_workflow_evidence: MachineWorkflowEvidencePaths,
) -> BaselineConfigurationRecord:
    """Derive one release-gate baseline record from verified artifacts.

    The machine fingerprint is derived only from a signed, host-derived canonical identity
    artifact whose workflow attestation binds the exact resolved configuration, report, and
    clean Stinger commit. Rebuilding is intentionally host-independent: the external signer
    vouches for local construction, while this builder verifies exact artifacts and trust.
    This is environment evidence, not TPM-grade hardware proof.
    """
    if (
        not configuration_id.strip()
        or configuration_id != configuration_id.strip()
        or any(character.isspace() for character in configuration_id)
    ):
        raise BaselineRecordError("configuration_id must be a nonblank, whitespace-free identifier")
    try:
        receipt = verify_evidence_bundle_pair(
            public_bundle,
            escrow_bundle,
            leakage_policy,
            trusted_allowed_signers=protocol_allowed_signers,
            expected_signer_identity=protocol_signer_identity,
        )
    except (EvidenceBundleError, OSError, ValueError) as exc:
        raise BaselineRecordError("evidence bundle verification failed") from exc

    return _build_baseline_configuration_record_from_receipt(
        configuration_id,
        corpus=corpus,
        receipt=receipt,
        machine_workflow_evidence=machine_workflow_evidence,
        sensitive_paths=(
            public_bundle,
            escrow_bundle,
            protocol_allowed_signers,
            machine_workflow_evidence.identity_artifact,
            machine_workflow_evidence.attestation,
            machine_workflow_evidence.signature,
            machine_workflow_evidence.allowed_signers,
            *leakage_policy.forbidden_sources,
        ),
        sensitive_markers=leakage_policy.forbidden_markers,
    )


def _build_baseline_configuration_record_from_receipt(
    configuration_id: str,
    *,
    corpus: SealedCorpusRecord,
    receipt: VerifiedArtifactReceipt,
    machine_workflow_evidence: MachineWorkflowEvidencePaths,
    sensitive_paths: tuple[Path, ...] = (),
    sensitive_markers: tuple[str | bytes, ...] = (),
) -> BaselineConfigurationRecord:
    """Derive a baseline from one already verified, exact-byte artifact receipt."""
    if (
        not configuration_id.strip()
        or configuration_id != configuration_id.strip()
        or any(character.isspace() for character in configuration_id)
    ):
        raise BaselineRecordError("configuration_id must be a nonblank, whitespace-free identifier")
    report = receipt.report
    config = receipt.config
    try:
        verify_report(report)
    except ReportMismatchError as exc:
        raise BaselineRecordError("verified report failed deterministic re-scoring") from exc
    if report.corpus_hash != corpus.corpus_hash:
        raise BaselineRecordError("verified report does not bind the supplied sealed corpus")
    if config.reps != receipt.protocol.repetitions or config.only is not None:
        raise BaselineRecordError(
            "resolved configuration is not an all-family publication repetition run"
        )
    if (
        config.isolation is not Isolation.DOCKER
        or config.agent.container_image is None
        or not config.agent.container_image.strip()
        or config.agent.container_image_digest is None
        or not config.image.strip()
        or config.verification_image_digest is None
    ):
        raise BaselineRecordError(
            "resolved configuration does not prove Docker-contained agent and verification runs"
        )
    metadata = report.benchmark_metadata
    pin_issues = publication_pin_issues(
        metadata,
        report.benchmark_runtime_provenance,
    )
    provider_binding_issues = canonical_local_provider_binding_issues(
        metadata,
        report.benchmark_runtime_provenance,
    )
    if metadata is None or pin_issues or provider_binding_issues or metadata.stinger_commit is None:
        raise BaselineRecordError("verified report has incomplete publication pins")
    machine_workflow = _verify_baseline_machine_workflow(
        receipt,
        machine_workflow_evidence,
        expected_stinger_commit=metadata.stinger_commit,
    )

    try:
        expected_order = deterministic_blocked_ids(
            (
                ScenarioOrderItem(
                    scenario_id=scenario.scenario_id,
                    family=scenario.family,
                )
                for scenario in corpus.scenarios
            ),
            seed=metadata.run_seed,
        )
    except ValueError as exc:
        raise BaselineRecordError(
            "sealed corpus record is not eligible for deterministic ordering"
        ) from exc
    if observed_scenario_order(report.results) != expected_order:
        raise BaselineRecordError(
            "verified report does not use the deterministic family-blocked order"
        )
    record = BaselineConfigurationRecord(
        configuration_id=configuration_id,
        report=report,
        report_sha256=canonical_report_sha256(report),
        public_bundle_manifest_sha256=receipt.public_bundle.manifest_sha256,
        escrow_bundle_manifest_sha256=receipt.escrow_bundle.manifest_sha256,
        machine_fingerprint_sha256=machine_workflow.statement.machine_identity_sha256,
        contained=True,
        deterministically_blocked_order=True,
        evidence_integrity_passed=True,
        public_bundle_verified=True,
        escrow_bundle_verified=True,
    )
    _reject_sensitive_content(
        record,
        sensitive_paths=(
            *sensitive_paths,
            machine_workflow_evidence.identity_artifact,
            machine_workflow_evidence.attestation,
            machine_workflow_evidence.signature,
            machine_workflow_evidence.allowed_signers,
        ),
        sensitive_markers=sensitive_markers,
    )
    try:
        gate_result = evaluate_baseline_configuration_record(
            record,
            corpus=corpus,
            protocol=receipt.protocol,
        )
    except ValueError as exc:
        raise BaselineRecordError("sealed corpus record is not eligible for evaluation") from exc
    if not gate_result.eligible:
        codes = sorted({issue.code.value for issue in gate_result.issues})
        raise BaselineRecordError(
            "derived baseline record is not publication-eligible: " + ", ".join(codes)
        )
    return record


def build_baseline_verification_statement(
    configuration_id: str,
    *,
    expected_record: BaselineConfigurationRecord,
    corpus: SealedCorpusRecord,
    public_bundle: Path,
    escrow_bundle: Path,
    leakage_policy: PublicLeakagePolicy,
    protocol_allowed_signers: Path,
    protocol_signer_identity: str,
    machine_workflow_evidence: MachineWorkflowEvidencePaths,
    signer_identity: str,
) -> BaselineVerificationStatement:
    """Rebuild one baseline from exact artifacts and bind it in a signed statement."""
    if (
        not signer_identity
        or signer_identity != signer_identity.strip()
        or any(character.isspace() for character in signer_identity)
    ):
        raise BaselineRecordError(
            "baseline verification signer identity must be nonblank and whitespace-free"
        )
    rebuilt = build_baseline_configuration_record(
        configuration_id,
        corpus=corpus,
        public_bundle=public_bundle,
        escrow_bundle=escrow_bundle,
        leakage_policy=leakage_policy,
        protocol_allowed_signers=protocol_allowed_signers,
        protocol_signer_identity=protocol_signer_identity,
        machine_workflow_evidence=machine_workflow_evidence,
    )
    if rebuilt != expected_record:
        raise BaselineRecordError(
            "supplied baseline record differs from the artifact-derived rebuild"
        )
    metadata = rebuilt.report.benchmark_metadata
    if metadata is None:
        raise BaselineRecordError("artifact-derived baseline lacks benchmark metadata")
    return BaselineVerificationStatement(
        benchmark_protocol_version=metadata.benchmark_protocol_version,
        rubric_version=rebuilt.report.rubric_version,
        configuration_id=rebuilt.configuration_id,
        corpus_hash=rebuilt.report.corpus_hash,
        baseline_record_sha256=baseline_configuration_record_sha256(rebuilt),
        signer_identity=signer_identity,
    )


def write_baseline_configuration_record(
    destination: Path,
    record: BaselineConfigurationRecord,
) -> None:
    """Atomically create canonical JSON at a new path without overwriting anything."""
    _atomic_create(destination, _canonical_record_bytes(record))


def write_baseline_verification_statement(
    destination: Path,
    statement: BaselineVerificationStatement,
) -> None:
    """Atomically create canonical statement JSON without overwriting."""
    _atomic_create(destination, _canonical_model_bytes(statement))


def build_corpus_freeze_statement(
    corpus: SealedCorpusRecord,
    *,
    protocol: BenchmarkProtocolManifest,
    candidate_receipt: Path,
    candidate_receipt_signature: Path,
    candidate_receipt_allowed_signers: Path,
    candidate_receipt_signer_identity: str,
    candidate_promotion_statement: Path,
    candidate_promotion_signature: Path,
    candidate_promotion_allowed_signers: Path,
    candidate_promotion_signer_identity: str,
    signer_identity: str,
) -> CorpusFreezeStatement:
    """Derive one content-only freeze statement from a complete corpus record."""
    if (
        not signer_identity
        or signer_identity != signer_identity.strip()
        or any(character.isspace() for character in signer_identity)
    ):
        raise BaselineRecordError(
            "corpus freeze signer identity must be nonblank and whitespace-free"
        )
    try:
        candidate_authorization = authorize_candidate_validation_receipt(
            candidate_receipt,
            candidate_receipt_signature,
            candidate_receipt_allowed_signers,
            candidate_receipt_signer_identity,
        )
        promotion_authorization = authorize_candidate_promotion_statement(
            candidate_promotion_statement,
            candidate_promotion_signature,
            candidate_promotion_allowed_signers,
            candidate_promotion_signer_identity,
        )
    except (OSError, ProtocolSignatureError, ValueError) as exc:
        raise BaselineRecordError("candidate validation receipt authorization failed") from exc
    issues = evaluate_corpus_construction(
        corpus,
        protocol=protocol,
        candidate_validation_authorization=candidate_authorization,
        candidate_promotion_authorization=promotion_authorization,
    )
    if issues:
        codes = ", ".join(sorted({issue.code.value for issue in issues}))
        raise BaselineRecordError("corpus construction is not eligible for freeze: " + codes)
    candidate_receipt_sha256 = corpus.candidate_validation_receipt_sha256
    promotion_statement_sha256 = corpus.candidate_promotion_statement_sha256
    custody_inventory = corpus.custody_inventory_sha256
    access_log_root = corpus.access_log_root_sha256
    canary_receipt = corpus.canary_validation_receipt_sha256
    if (
        candidate_receipt_sha256 is None
        or promotion_statement_sha256 is None
        or custody_inventory is None
        or access_log_root is None
        or canary_receipt is None
    ):
        raise BaselineRecordError("corpus-wide validation receipts are incomplete")
    family_counts = {
        family: sum(scenario.family is family for scenario in corpus.scenarios)
        for family in protocol.families
    }
    size_counts = {
        size: sum(scenario.repository_size is size for scenario in corpus.scenarios)
        for size in {scenario.repository_size for scenario in corpus.scenarios}
    }
    return CorpusFreezeStatement(
        benchmark_protocol_version=protocol.benchmark_protocol_version,
        rubric_version=protocol.rubric_version,
        corpus_version=corpus.corpus_version,
        corpus_hash=corpus.corpus_hash,
        scenario_inventory_sha256=corpus_scenario_inventory_sha256(corpus.scenarios),
        candidate_validation_receipt_sha256=candidate_receipt_sha256,
        candidate_promotion_statement_sha256=promotion_statement_sha256,
        custody_inventory_sha256=custody_inventory,
        access_log_root_sha256=access_log_root,
        canary_validation_receipt_sha256=canary_receipt,
        scenario_count=len(corpus.scenarios),
        scenarios_by_family=family_counts,
        scenarios_by_size=size_counts,
        signer_identity=signer_identity,
    )


def write_corpus_freeze_statement(
    destination: Path,
    statement: CorpusFreezeStatement,
) -> None:
    """Atomically create one canonical corpus-freeze statement."""
    _atomic_create(destination, _canonical_model_bytes(statement))


def build_corpus_freeze_record(
    statement: Path,
    signature: Path,
    allowed_signers: Path,
    signer_identity: str,
) -> CorpusFreezeRecord:
    """Authorize canonical freeze-statement bytes and derive the submission record."""
    try:
        statement_bytes = _read_regular_artifact(
            statement,
            label="corpus freeze statement",
        )
        authorization = authorize_corpus_freeze_statement(
            statement,
            signature,
            allowed_signers,
            signer_identity,
        )
    except (OSError, UnicodeDecodeError, ValueError, ProtocolSignatureError) as exc:
        raise BaselineRecordError("corpus freeze statement authorization failed") from exc
    if statement_bytes != _canonical_model_bytes(authorization.statement):
        raise BaselineRecordError("signed corpus freeze statement was not created canonically")
    if (
        authorization.statement.signer_identity != authorization.identity
        or authorization.identity != signer_identity
    ):
        raise BaselineRecordError("corpus freeze signer identity is inconsistent")
    return CorpusFreezeRecord(
        signer_identity=authorization.identity,
        statement_sha256=authorization.statement_sha256,
        statement_signature_sha256=authorization.signature_sha256,
        allowed_signers_sha256=authorization.allowed_signers_sha256,
    )


def write_corpus_freeze_record(
    destination: Path,
    record: CorpusFreezeRecord,
) -> None:
    """Atomically create one canonical corpus-freeze record."""
    _atomic_create(destination, _canonical_model_bytes(record))


def _verify_baseline_machine_workflow(
    receipt: VerifiedArtifactReceipt,
    evidence: MachineWorkflowEvidencePaths,
    *,
    expected_stinger_commit: str,
) -> VerifiedMachineWorkflowAttestation:
    """Verify signed machine evidence against the exact bundle snapshots.

    Temporary files contain only already-verified config and report snapshots. This avoids
    reopening mutable caller paths after bundle verification and makes the workflow
    attestation cover the exact resolved config and report bytes used to derive the record.
    """
    try:
        with tempfile.TemporaryDirectory(prefix="stinger-machine-workflow-") as temporary:
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
                expected_stinger_commit=expected_stinger_commit,
            )
    except MachineAttestationError as exc:
        raise BaselineRecordError("signed machine workflow evidence failed verification") from exc


def _canonical_record_bytes(record: BaselineConfigurationRecord) -> bytes:
    """Serialize one baseline record in the only accepted byte representation."""
    return (
        json.dumps(
            record.model_dump(mode="json"),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _canonical_model_bytes(model: BaseModel) -> bytes:
    """Serialize one closed record in canonical JSON with a final newline."""
    return (
        json.dumps(
            model.model_dump(mode="json"),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _reject_sensitive_content(
    record: BaselineConfigurationRecord,
    *,
    sensitive_paths: tuple[Path, ...],
    sensitive_markers: tuple[str | bytes, ...],
) -> None:
    """Reject a record that repeats private paths, canaries, or dummy secrets."""
    values = tuple(_string_values(record.model_dump(mode="python")))
    path_markers: set[str] = set()
    for path in sensitive_paths:
        for candidate in (path, path.absolute(), path.resolve(strict=False)):
            text = str(candidate)
            if text and text not in {".", "/"}:
                path_markers.add(text)
    if any(marker in value for marker in path_markers for value in values):
        raise BaselineRecordError("derived baseline record contains sensitive material")
    for marker in sensitive_markers:
        if isinstance(marker, bytes):
            try:
                text_marker = marker.decode("utf-8")
            except UnicodeDecodeError:
                continue
        else:
            text_marker = marker
        if text_marker and any(text_marker in value for value in values):
            raise BaselineRecordError("derived baseline record contains sensitive material")


def _string_values(value: object) -> list[str]:
    """Collect string values from a JSON-shaped typed record."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [
            string for child in (*value.keys(), *value.values()) for string in _string_values(child)
        ]
    if isinstance(value, (list, tuple)):
        return [string for child in value for string in _string_values(child)]
    return []


def _read_regular_artifact(path: Path, *, label: str) -> bytes:
    """Read exact bytes from one nonempty regular nonsymlink artifact."""
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(
            os,
            "O_NONBLOCK",
            0,
        )
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BaselineRecordError(f"{label} must be a readable regular nonsymlink file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise BaselineRecordError(f"{label} must be a readable regular nonsymlink file")
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
        raise BaselineRecordError(f"{label} must not be empty")
    return content


def _atomic_create(destination: Path, content: bytes) -> None:
    """Create one file atomically in an existing real parent directory."""
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir():
        raise BaselineRecordError("output parent must be an existing real directory")
    if destination.is_symlink() or destination.exists():
        raise BaselineRecordError("output path already exists")

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
            raise BaselineRecordError("output path already exists") from exc
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
