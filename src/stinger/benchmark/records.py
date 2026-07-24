"""Artifact-derived baseline records for the benchmark release gate.

Release schemas deliberately remain simple signed records. This module is the trusted
construction path that turns verified public/escrow evidence into those records without
accepting favorable booleans or caller-entered artifact hashes.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path

from stinger.benchmark.evidence import (
    EvidenceBundleError,
    PublicLeakagePolicy,
    verify_evidence_bundle_pair,
)
from stinger.benchmark.gates import (
    BaselineConfigurationRecord,
    ErrorDispositionRecord,
    SealedCorpusRecord,
    canonical_report_sha256,
    evaluate_baseline_configuration_record,
)
from stinger.benchmark.ordering import (
    ScenarioOrderItem,
    deterministic_blocked_ids,
    observed_scenario_order,
)
from stinger.benchmark.protocol import publication_pin_issues
from stinger.harness.sandbox import Isolation
from stinger.models import Outcome, Report
from stinger.report.generate import ReportMismatchError, verify_report

__all__ = [
    "BaselineRecordError",
    "build_baseline_configuration_record",
    "write_baseline_configuration_record",
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
    machine_identity_artifact: Path,
    error_dispositions: tuple[ErrorDispositionRecord, ...] = (),
) -> BaselineConfigurationRecord:
    """Derive one release-gate baseline record from verified artifacts.

    The machine artifact is an out-of-band identity attestation supplied by the operator.
    Its exact bytes are bound here, but Stinger does not claim that an arbitrary file proves
    hardware identity.
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
    if metadata is None or pin_issues:
        raise BaselineRecordError("verified report has incomplete publication pins")

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
    _validate_error_dispositions(error_dispositions, report)

    record = BaselineConfigurationRecord(
        configuration_id=configuration_id,
        report=report,
        report_sha256=canonical_report_sha256(report),
        public_bundle_manifest_sha256=receipt.public_bundle.manifest_sha256,
        escrow_bundle_manifest_sha256=receipt.escrow_bundle.manifest_sha256,
        machine_fingerprint_sha256=_sha256_identity_artifact(machine_identity_artifact),
        contained=True,
        deterministically_blocked_order=True,
        evidence_integrity_passed=True,
        public_bundle_verified=True,
        escrow_bundle_verified=True,
        error_dispositions=error_dispositions,
    )
    _reject_sensitive_content(
        record,
        sensitive_paths=(
            public_bundle,
            escrow_bundle,
            protocol_allowed_signers,
            machine_identity_artifact,
            *leakage_policy.forbidden_sources,
        ),
        sensitive_markers=leakage_policy.forbidden_markers,
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


def write_baseline_configuration_record(
    destination: Path,
    record: BaselineConfigurationRecord,
) -> None:
    """Atomically create canonical JSON at a new path without overwriting anything."""
    _atomic_create(destination, _canonical_record_bytes(record))


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


def _validate_error_dispositions(
    dispositions: tuple[ErrorDispositionRecord, ...],
    report: Report,
) -> None:
    """Require unique disposition keys that name actual ERROR results only."""
    # Kept local rather than accepting the release gate's favorable boolean: the builder
    # rejects malformed records before constructing any output.
    error_keys = {
        (result.scenario_id, result.repetition)
        for result in report.results
        if result.outcome is Outcome.ERROR
    }
    seen: set[tuple[str, int]] = set()
    for disposition in dispositions:
        key = (disposition.scenario_id, disposition.repetition)
        if key in seen:
            raise BaselineRecordError("error dispositions contain a duplicate result key")
        seen.add(key)
        if key not in error_keys:
            raise BaselineRecordError(
                "error disposition does not reference an observed ERROR outcome"
            )
        if disposition.explained and not disposition.explanation.strip():
            raise BaselineRecordError("explained error disposition requires a nonblank explanation")


def _sha256_identity_artifact(path: Path) -> str:
    """Hash exact bytes from a nonempty, regular, nonsymlink identity attestation."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BaselineRecordError(
            "machine identity artifact must be a readable regular nonsymlink file"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise BaselineRecordError(
                "machine identity artifact must be a readable regular nonsymlink file"
            )
        digest = hashlib.sha256()
        byte_count = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            byte_count += len(chunk)
    finally:
        os.close(descriptor)
    if byte_count == 0:
        raise BaselineRecordError("machine identity artifact must not be empty")
    return digest.hexdigest()


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
