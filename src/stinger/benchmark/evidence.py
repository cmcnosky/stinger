"""Deterministic public and escrow evidence bundles for benchmark operation.

This module deliberately does not replace the reproducibility package in
``stinger.report.repro``. A benchmark operator can use that package as the rerunnable
evidence input here, then produce two different disclosure surfaces:

* a public bundle containing the protocol, resolved configuration, report, and only the
  logs explicitly permitted by the caller; and
* an escrow bundle containing those artifacts plus the complete sealed corpus and
  rerunnable evidence.

Public-bundle leakage checks require an explicit :class:`PublicLeakagePolicy`. The policy
names the active sealed sources and supplies every canary and bait-secret value that must
not be published. Only hashes of that policy enter the bundle. Verification therefore needs
the same policy again; silently verifying without the sensitive comparison set would turn
an unavailable check into a favorable result.

Escrow is not encryption. The bundle is an ordinary directory and relies entirely on the
operator's filesystem, storage, and transfer access controls. The manifest and sidecar
hashes detect disagreement and accidental corruption, but are not signatures and cannot
prove authenticity against someone able to rewrite both.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError

from stinger.benchmark.gates import (
    BenchmarkProtocolManifest,
    compiled_benchmark_protocol,
)
from stinger.benchmark.protocol import BenchmarkSplit
from stinger.benchmark.replay import (
    INVOCATION_AGGREGATE_NAME,
    REPRO_EVIDENCE_FORMAT_FILE,
    ClassificationReplayError,
    verify_report_classifications_from_escrow,
)
from stinger.benchmark.signing import (
    PROTOCOL_SIGNATURE_NAMESPACE,
    ProtocolSignatureError,
    ProtocolSignatureVerification,
    verify_protocol_signature,
)
from stinger.config import RunConfig
from stinger.models import Report
from stinger.report.generate import (
    ReportMismatchError,
    load_report,
    verify_report,
)
from stinger.report.repro import SEALED_REPRO_MARKER, build_corpus_lock
from stinger.scenario.loader import ScenarioLoadError, corpus_hash, discover_scenarios

__all__ = [
    "BUNDLE_FORMAT_VERSION",
    "BUNDLE_MANIFEST",
    "BUNDLE_MANIFEST_HASH",
    "ESCROW_NOTICE",
    "BundleKind",
    "EvidenceBundleError",
    "EvidenceBundleManifest",
    "EvidenceBundleReceipt",
    "InventoryFile",
    "PublicLeakagePolicy",
    "VerifiedArtifactReceipt",
    "create_escrow_evidence_bundle",
    "create_public_evidence_bundle",
    "verify_evidence_bundle_pair",
    "verify_escrow_evidence_bundle",
    "verify_public_evidence_bundle",
    "verify_public_evidence_bundle_receipt",
]

BUNDLE_FORMAT_VERSION = "4"
BUNDLE_MANIFEST = "bundle.manifest.json"
BUNDLE_MANIFEST_HASH = "bundle.manifest.sha256"
ESCROW_NOTICE_FILE = "ESCROW_NOTICE.txt"

ESCROW_NOTICE = """STINGER BENCHMARK ESCROW — ACCESS CONTROL REQUIRED

This directory is NOT encrypted. It contains the active sealed corpus, reference
resolutions, and rerunnable evidence. Confidentiality depends entirely on the access
controls of the filesystem, storage service, and transfer channel holding it.

Do not publish or place this directory in a public artifact store. Possession grants access
to benchmark material that can invalidate future measurements.
"""
"""The truthful security notice embedded in every escrow bundle."""

_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ROLE_NAMES = frozenset({"protocol", "config", "report", "log"})
_SENSITIVE_DIRECTORY_NAMES = frozenset(
    {
        "active_corpus",
        "completion_check",
        "corpus",
        "reference",
        "references",
        "seed_repo",
        "sealed_corpus",
    }
)
_INTRINSIC_SECRET_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
)
_SECRET_OPTION_NAME = re.compile(
    r"(?:api[_-]?key|access[_-]?token|auth(?:orization)?|bearer|cookie|credential|"
    r"pass(?:word|wd)?|private[_-]?key|secret)",
    re.IGNORECASE,
)
_SECRET_OPTION_VALUE = re.compile(
    r"(?:"
    r"\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=_-]+|"
    r"\b(?:sk|rk|pk)-[A-Za-z0-9_-]{12,}|"
    r"\b(?:ghp|github_pat|xox[aboprs])-?[A-Za-z0-9_-]{12,}|"
    r"\bAKIA[0-9A-Z]{16}|"
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}|"
    r"\b[A-Za-z0-9+/=_-]{40,}\b"
    r")",
    re.IGNORECASE,
)
_PUBLIC_PATH_REDACTION = Path("<redacted-host-path>")
_SENSITIVE_RAW_CHUNK_BYTES = 64
_SENSITIVE_RAW_CHUNK_STRIDE = 16
_SENSITIVE_TEXT_NGRAM_WORDS = 8
_SENSITIVE_TEXT_NGRAM_MIN_BYTES = 48
_MAX_SENSITIVE_CHUNKS_PER_FILE = 8192
_TEXT_TOKEN_PATTERN = re.compile(r"[^\W_]+(?:[._:/-][^\W_]+)*|_", re.UNICODE)
_PRIVATE_ABSOLUTE_PATH_PATTERNS = (
    re.compile(
        rb"(?<![A-Za-z0-9_.-])/(?:Users|home)/[^\s\"'<>]+",
        re.IGNORECASE,
    ),
    re.compile(
        rb"(?<![A-Za-z0-9_.-])/(?:private/)?(?:var/folders|tmp)/[^\s\"'<>]+",
        re.IGNORECASE,
    ),
    re.compile(
        rb"(?<![A-Za-z0-9_.-])/(?:[^\s\"'<>]+/)*"
        rb"[^/\s\"'<>]*(?:escrow|sealed[-_]?corpus|private[-_]?candidate)"
        rb"[^\s\"'<>]*",
        re.IGNORECASE,
    ),
    re.compile(
        rb"(?<![A-Za-z0-9_.-])[A-Za-z]:[\\/]+Users[\\/]+[^\s\"'<>]+",
        re.IGNORECASE,
    ),
)


class EvidenceBundleError(Exception):
    """Raised when a bundle cannot be created or does not verify fail-closed."""


class BundleKind(StrEnum):
    """The two disclosure surfaces an evidence package may target."""

    PUBLIC = "public"
    ESCROW = "escrow"


class EvidenceRole(StrEnum):
    """The purpose of a payload path recorded in a bundle inventory."""

    PROTOCOL = "protocol"
    PROTOCOL_SIGNATURE = "protocol_signature"
    SIGNER_POLICY = "signer_policy"
    CONFIG = "config"
    REPORT = "report"
    LOG = "log"
    SEALED_CORPUS = "sealed_corpus"
    RERUNNABLE_EVIDENCE = "rerunnable_evidence"
    NOTICE = "notice"


class InventoryFile(BaseModel):
    """One byte-bearing payload file pinned by the bundle manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: EvidenceRole
    sha256: str
    size: int
    executable: bool


class EvidenceBundleManifest(BaseModel):
    """The canonical, deterministic inventory shared by both bundle kinds."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: str
    bundle_kind: BundleKind
    protocol_sha256: str
    protocol_signature_sha256: str
    allowed_signers_sha256: str
    protocol_signer_identity: str
    protocol_signature_namespace: str
    config_sha256: str
    report_sha256: str
    inventory_sha256: str
    leakage_policy_sha256: str | None
    access_control_notice: str | None
    files: dict[str, InventoryFile]
    directories: dict[str, EvidenceRole]


@dataclass(frozen=True)
class PublicLeakagePolicy:
    """Sensitive comparison material required to verify a public bundle.

    ``forbidden_sources`` should include the complete active sealed corpus. It may also
    include any separately stored reference solutions. Every regular file below those
    paths is fingerprinted so an exact file cannot be relabeled as a permitted log.

    ``forbidden_markers`` should include every active corpus canary and every bait-secret
    value. Markers are scanned as raw bytes, so they catch a value embedded in text or a
    binary log. Neither source paths nor marker values are written into the public bundle.
    At least one source and one non-empty marker are required: an absent leakage comparison
    set is an unavailable check, not a pass.
    """

    forbidden_sources: tuple[Path, ...]
    forbidden_markers: tuple[str | bytes, ...]


@dataclass(frozen=True, slots=True)
class EvidenceBundleReceipt:
    """Exact core bytes and typed artifacts retained after bundle verification.

    The ordinary verifier APIs intentionally return only the public manifest. Builders need
    a stronger handoff: they must derive hashes from the exact bytes that survived
    verification, rather than reopening caller-controlled paths later and trusting that the
    files still name the same artifacts.
    """

    bundle_kind: BundleKind
    manifest: EvidenceBundleManifest
    manifest_bytes: bytes
    manifest_sha256: str
    protocol: BenchmarkProtocolManifest
    protocol_bytes: bytes
    protocol_signature_bytes: bytes
    allowed_signers_bytes: bytes
    config: RunConfig
    config_bytes: bytes
    report: Report
    report_bytes: bytes


@dataclass(frozen=True, slots=True)
class VerifiedArtifactReceipt:
    """Cross-bound public and escrow receipts for one benchmark run."""

    public_bundle: EvidenceBundleReceipt
    escrow_bundle: EvidenceBundleReceipt
    protocol: BenchmarkProtocolManifest
    config: RunConfig
    report: Report
    protocol_signature_verification: ProtocolSignatureVerification


@dataclass(frozen=True)
class _LeakageSnapshot:
    """Hashed policy material safe to compare with public payloads."""

    forbidden_file_hashes: frozenset[str]
    forbidden_chunk_hashes: frozenset[str]
    forbidden_markers: tuple[bytes, ...]
    forbidden_path_fragments: tuple[bytes, ...]
    fingerprint: str


@dataclass
class _InventoryBuilder:
    """Mutable inventory used only while one new destination is being assembled."""

    files: dict[str, InventoryFile]
    directories: dict[str, EvidenceRole]


def create_public_evidence_bundle(
    destination: Path,
    *,
    protocol: Path,
    protocol_signature: Path,
    allowed_signers: Path,
    signer_identity: str,
    config: Path,
    report: Path,
    permitted_logs: Mapping[str, Path],
    leakage_policy: PublicLeakagePolicy,
) -> EvidenceBundleManifest:
    """Create a disclosure-safe public benchmark evidence bundle.

    Args:
        destination: New directory to create. Existing paths are refused, including empty
            directories, so stale un-inventoried files can never survive into a bundle.
        protocol: Frozen benchmark protocol artifact.
        protocol_signature: Detached OpenSSH signature over ``protocol``.
        allowed_signers: Verifier-controlled OpenSSH signer trust policy.
        signer_identity: Expected principal in ``allowed_signers``.
        config: Fully resolved agent/run configuration artifact.
        report: Benchmark report artifact.
        permitted_logs: Explicit mapping of bundle-relative log names to individual source
            files. Names are placed below ``logs/`` and may contain safe subdirectories.
        leakage_policy: Active sealed material and marker values to exclude.

    Returns:
        The manifest written to ``destination``.

    Raises:
        EvidenceBundleError: If a source is unsafe or unreadable, the leakage policy is
            incomplete, any payload matches forbidden material, or the destination exists.
    """
    snapshot = _snapshot_policy(leakage_policy)
    core = _core_sources(
        protocol,
        protocol_signature,
        allowed_signers,
        signer_identity,
        config,
        report,
    )
    log_sources = _public_log_sources(permitted_logs)
    sources = (*core, *log_sources)
    _check_destination(destination, [source for _, source, _ in sources])
    public_config = _public_config_bytes(config)
    _scan_public_sources(sources, snapshot, config_override=public_config)

    destination.mkdir(parents=True)
    inventory = _InventoryBuilder(files={}, directories={})
    for relative, source, role in sources:
        if role is EvidenceRole.CONFIG:
            _copy_bytes(public_config, destination, relative, role, False, inventory)
        else:
            _copy_file(source, destination, relative, role, inventory)

    manifest = _build_manifest(
        BundleKind.PUBLIC,
        inventory,
        protocol_signer_identity=signer_identity,
        leakage_policy_sha256=snapshot.fingerprint,
        access_control_notice=None,
    )
    _write_manifest(destination, manifest)
    verify_public_evidence_bundle(
        destination,
        leakage_policy,
        trusted_allowed_signers=allowed_signers,
        expected_signer_identity=signer_identity,
    )
    return manifest


def create_escrow_evidence_bundle(
    destination: Path,
    *,
    protocol: Path,
    protocol_signature: Path,
    allowed_signers: Path,
    signer_identity: str,
    config: Path,
    report: Path,
    sealed_corpus: Path,
    rerunnable_evidence: Path,
) -> EvidenceBundleManifest:
    """Create a full, unencrypted escrow bundle for an independent verifier.

    Args:
        destination: New directory to create.
        protocol: Frozen benchmark protocol artifact.
        protocol_signature: Detached OpenSSH signature over ``protocol``.
        allowed_signers: Verifier-controlled OpenSSH signer trust policy.
        signer_identity: Expected principal in ``allowed_signers``.
        config: Fully resolved agent/run configuration artifact.
        report: Benchmark report artifact.
        sealed_corpus: Complete active corpus directory, including references and held-out
            checks.
        rerunnable_evidence: Complete evidence/reproduction directory required to rerun and
            rescore the measured configuration.

    Returns:
        The manifest written to ``destination``.

    Raises:
        EvidenceBundleError: If any source is missing, empty, symlinked, special, nested
            around the destination, or the destination already exists.

    Security:
        This function does not encrypt. The returned directory contains the answer-bearing
        corpus in ordinary files and MUST be protected by external access controls.
    """
    core = _core_sources(
        protocol,
        protocol_signature,
        allowed_signers,
        signer_identity,
        config,
        report,
    )
    _require_directory(sealed_corpus, "sealed corpus")
    _require_directory(rerunnable_evidence, "rerunnable evidence")
    protocol_model, config_model, report_model = _validate_core_semantics(
        protocol,
        config,
        report,
    )
    _verify_private_escrow_semantics(
        sealed_corpus,
        rerunnable_evidence,
        protocol=protocol_model,
        config=config_model,
        report=report_model,
    )
    all_sources = [source for _, source, _ in core] + [sealed_corpus, rerunnable_evidence]
    _check_destination(destination, all_sources)

    destination.mkdir(parents=True)
    inventory = _InventoryBuilder(files={}, directories={})
    for relative, source, role in core:
        _copy_file(source, destination, relative, role, inventory)
    _copy_tree(
        sealed_corpus,
        destination,
        PurePosixPath("sealed-corpus"),
        EvidenceRole.SEALED_CORPUS,
        inventory,
    )
    _copy_tree(
        rerunnable_evidence,
        destination,
        PurePosixPath("rerunnable-evidence"),
        EvidenceRole.RERUNNABLE_EVIDENCE,
        inventory,
    )
    _copy_bytes(
        ESCROW_NOTICE.encode("utf-8"),
        destination,
        PurePosixPath(ESCROW_NOTICE_FILE),
        EvidenceRole.NOTICE,
        False,
        inventory,
    )

    manifest = _build_manifest(
        BundleKind.ESCROW,
        inventory,
        protocol_signer_identity=signer_identity,
        leakage_policy_sha256=None,
        access_control_notice=ESCROW_NOTICE,
    )
    _write_manifest(destination, manifest)
    verify_escrow_evidence_bundle(
        destination,
        trusted_allowed_signers=allowed_signers,
        expected_signer_identity=signer_identity,
    )
    return manifest


def verify_public_evidence_bundle(
    directory: Path,
    leakage_policy: PublicLeakagePolicy,
    *,
    trusted_allowed_signers: Path,
    expected_signer_identity: str,
) -> EvidenceBundleManifest:
    """Verify public inventory integrity and re-run every leakage safeguard.

    Args:
        directory: Public bundle directory.
        leakage_policy: The same active sensitive comparison set used at creation.
        trusted_allowed_signers: Independently obtained signer trust policy. The copy inside
            the bundle is never trusted merely because it is bundled.
        expected_signer_identity: Independently expected signer principal.

    Returns:
        The verified manifest.

    Raises:
        EvidenceBundleError: On any ambiguity, missing/extra path, hash disagreement,
            policy mismatch, sensitive path, exact forbidden-file match, or marker leak.
    """
    manifest, _ = _verify_public_evidence_bundle_components(
        directory,
        leakage_policy,
        trusted_allowed_signers=trusted_allowed_signers,
        expected_signer_identity=expected_signer_identity,
    )
    return manifest


def _verify_public_evidence_bundle_components(
    directory: Path,
    leakage_policy: PublicLeakagePolicy,
    *,
    trusted_allowed_signers: Path,
    expected_signer_identity: str,
) -> tuple[EvidenceBundleManifest, ProtocolSignatureVerification]:
    """Verify one public bundle and retain its original signature authorization."""
    snapshot = _snapshot_policy(leakage_policy)
    manifest = _load_and_verify_manifest(directory, expected_kind=BundleKind.PUBLIC)
    if manifest.leakage_policy_sha256 != snapshot.fingerprint:
        raise EvidenceBundleError(
            "public bundle leakage policy disagrees with the active verification policy"
        )
    if manifest.access_control_notice is not None:
        raise EvidenceBundleError("public bundle unexpectedly declares an escrow notice")
    _verify_role_shape(manifest, public=True)
    signature_verification = _verify_bundled_protocol_signature(
        directory,
        manifest,
        trusted_allowed_signers=trusted_allowed_signers,
        expected_signer_identity=expected_signer_identity,
    )
    _verify_bundled_core_semantics(directory, manifest)
    _scan_public_bundle(directory, manifest, snapshot)
    return manifest, signature_verification


def verify_public_evidence_bundle_receipt(
    directory: Path,
    leakage_policy: PublicLeakagePolicy,
    *,
    trusted_allowed_signers: Path,
    expected_signer_identity: str,
) -> EvidenceBundleReceipt:
    """Verify a complete public bundle and retain exact core bytes for downstream gates.

    This is the public-only counterpart to :func:`verify_evidence_bundle_pair`. It reruns
    inventory, protocol trust, core semantics, and leakage checks, snapshots the exact
    verified manifest/config/report bytes, then rechecks the inventory so later builders
    never accept a manifest-shaped JSON file as a substitute for the actual bundle.
    """
    manifest, signature_verification = _verify_public_evidence_bundle_components(
        directory,
        leakage_policy,
        trusted_allowed_signers=trusted_allowed_signers,
        expected_signer_identity=expected_signer_identity,
    )
    receipt = _snapshot_verified_bundle(
        directory,
        manifest,
        protocol_signature_verification=signature_verification,
    )
    _verify_actual_inventory(directory, manifest)
    final_manifest = _read_regular_file(directory / BUNDLE_MANIFEST, "bundle manifest")
    if final_manifest != receipt.manifest_bytes:
        raise EvidenceBundleError("public bundle changed during receipt construction")
    return receipt


def verify_escrow_evidence_bundle(
    directory: Path,
    *,
    trusted_allowed_signers: Path,
    expected_signer_identity: str,
) -> EvidenceBundleManifest:
    """Verify escrow inventory integrity and required full-package roles.

    Args:
        directory: Escrow bundle directory.
        trusted_allowed_signers: Independently obtained signer trust policy.
        expected_signer_identity: Independently expected signer principal.

    Returns:
        The verified manifest.

    Raises:
        EvidenceBundleError: On any missing/extra path, hash disagreement, malformed
            manifest, missing full-corpus/evidence role, or untruthful security notice.
    """
    manifest, _ = _verify_escrow_evidence_bundle_components(
        directory,
        trusted_allowed_signers=trusted_allowed_signers,
        expected_signer_identity=expected_signer_identity,
    )
    return manifest


def _verify_escrow_evidence_bundle_components(
    directory: Path,
    *,
    trusted_allowed_signers: Path,
    expected_signer_identity: str,
) -> tuple[EvidenceBundleManifest, ProtocolSignatureVerification]:
    """Verify one escrow bundle and retain its original signature authorization."""
    manifest = _load_and_verify_manifest(directory, expected_kind=BundleKind.ESCROW)
    if manifest.leakage_policy_sha256 is not None:
        raise EvidenceBundleError("escrow bundle unexpectedly declares a public leakage policy")
    if manifest.access_control_notice != ESCROW_NOTICE:
        raise EvidenceBundleError("escrow bundle does not carry the required access-control notice")
    _verify_role_shape(manifest, public=False)
    signature_verification = _verify_bundled_protocol_signature(
        directory,
        manifest,
        trusted_allowed_signers=trusted_allowed_signers,
        expected_signer_identity=expected_signer_identity,
    )
    protocol, config, report = _verify_bundled_core_semantics(directory, manifest)
    # Inventory verification above proves the bytes at one point in time. Replay reads a
    # large tree repeatedly (sealed source, final workdirs, transcripts, typed observations),
    # so reopening the caller-controlled paths directly would reintroduce a check/use race.
    # Copy every role-bound byte through a no-follow descriptor into a verifier-owned
    # snapshot, checking its manifest hash again, and perform all semantic work there.
    with _snapshot_escrow_payloads(directory, manifest) as (
        sealed_corpus,
        rerunnable_evidence,
    ):
        _verify_private_escrow_semantics(
            sealed_corpus,
            rerunnable_evidence,
            protocol=protocol,
            config=config,
            report=report,
        )
    notice = directory / ESCROW_NOTICE_FILE
    if _read_regular_file(notice, "escrow notice") != ESCROW_NOTICE.encode("utf-8"):
        raise EvidenceBundleError("escrow notice file disagrees with the required warning")
    return manifest, signature_verification


def verify_evidence_bundle_pair(
    public_bundle: Path,
    escrow_bundle: Path,
    leakage_policy: PublicLeakagePolicy,
    *,
    trusted_allowed_signers: Path,
    expected_signer_identity: str,
) -> VerifiedArtifactReceipt:
    """Verify and cross-bind one public/escrow pair using exact core snapshots.

    Existing bundle verifiers still own inventory, signature, semantic, leakage, and escrow
    checks. This receipt layer snapshots the verified manifest and core artifacts immediately
    afterwards, checks those bytes against the in-memory manifest, and derives every later
    builder value from the snapshots. A path substitution after verification therefore
    cannot change what a builder records.

    Args:
        public_bundle: Public evidence bundle directory.
        escrow_bundle: Corresponding complete escrow bundle directory.
        leakage_policy: Active public leakage comparison set.
        trusted_allowed_signers: Independently obtained protocol trust policy.
        expected_signer_identity: Independently expected protocol signer.

    Returns:
        Exact-byte receipts cross-bound to the same run.

    Raises:
        EvidenceBundleError: If either bundle fails or the pair disagrees.
    """
    public_manifest, public_signature_verification = _verify_public_evidence_bundle_components(
        public_bundle,
        leakage_policy,
        trusted_allowed_signers=trusted_allowed_signers,
        expected_signer_identity=expected_signer_identity,
    )
    public_receipt = _snapshot_verified_bundle(
        public_bundle,
        public_manifest,
        protocol_signature_verification=public_signature_verification,
    )
    _verify_actual_inventory(public_bundle, public_manifest)
    escrow_manifest, escrow_signature_verification = _verify_escrow_evidence_bundle_components(
        escrow_bundle,
        trusted_allowed_signers=trusted_allowed_signers,
        expected_signer_identity=expected_signer_identity,
    )
    escrow_receipt = _snapshot_verified_bundle(
        escrow_bundle,
        escrow_manifest,
        protocol_signature_verification=escrow_signature_verification,
    )
    _verify_actual_inventory(escrow_bundle, escrow_manifest)
    _verify_leakage_policy_covers_escrow(
        escrow_bundle,
        public_manifest,
        escrow_manifest,
        leakage_policy,
    )

    if public_receipt.protocol_bytes != escrow_receipt.protocol_bytes:
        raise EvidenceBundleError("public and escrow bundles contain different protocols")
    if public_receipt.protocol != escrow_receipt.protocol:
        raise EvidenceBundleError("public and escrow protocol models disagree")
    if public_receipt.protocol_signature_bytes != escrow_receipt.protocol_signature_bytes:
        raise EvidenceBundleError("public and escrow protocol signatures disagree")
    if public_receipt.allowed_signers_bytes != escrow_receipt.allowed_signers_bytes:
        raise EvidenceBundleError("public and escrow protocol trust policies disagree")
    if public_signature_verification != escrow_signature_verification:
        raise EvidenceBundleError("public and escrow protocol signature authorizations disagree")
    if (
        public_receipt.manifest.protocol_signer_identity
        != escrow_receipt.manifest.protocol_signer_identity
    ):
        raise EvidenceBundleError("public and escrow protocol signer identities disagree")
    if public_receipt.report_bytes != escrow_receipt.report_bytes:
        raise EvidenceBundleError("public and escrow report bytes disagree")
    if public_receipt.report != escrow_receipt.report:
        raise EvidenceBundleError("public and escrow typed reports disagree")
    if public_receipt.report.corpus_hash != escrow_receipt.report.corpus_hash:
        raise EvidenceBundleError("public and escrow corpus bindings disagree")
    if public_receipt.config.fingerprint() != escrow_receipt.config.fingerprint():
        raise EvidenceBundleError("public and escrow configuration fingerprints disagree")
    if public_receipt.config.benchmark_metadata() != escrow_receipt.config.benchmark_metadata():
        raise EvidenceBundleError("public and escrow benchmark metadata disagree")

    return VerifiedArtifactReceipt(
        public_bundle=public_receipt,
        escrow_bundle=escrow_receipt,
        protocol=public_receipt.protocol,
        config=escrow_receipt.config,
        report=public_receipt.report,
        protocol_signature_verification=public_signature_verification,
    )


def _verify_leakage_policy_covers_escrow(
    escrow_bundle: Path,
    public_manifest: EvidenceBundleManifest,
    escrow_manifest: EvidenceBundleManifest,
    leakage_policy: PublicLeakagePolicy,
) -> None:
    """Prove the public comparison set covers the paired escrow corpus bytes.

    The public verifier binds its leakage-policy fingerprint, but that policy is supplied
    externally. Without this cross-check, an unrelated dummy directory could satisfy the
    public scan while the paired sealed corpus was never compared. Extra forbidden sources
    remain allowed, so separately stored sensitive material can make the policy stricter.
    """
    external = _snapshot_policy(leakage_policy)
    if external.fingerprint != public_manifest.leakage_policy_sha256:
        raise EvidenceBundleError("public leakage policy changed after bundle verification")
    escrow_hashes: set[str] = set()
    for relative, entry in sorted(escrow_manifest.files.items()):
        under_sealed_corpus = relative.startswith("sealed-corpus/")
        if under_sealed_corpus != (entry.role is EvidenceRole.SEALED_CORPUS):
            raise EvidenceBundleError("escrow sealed-corpus path and inventory role disagree")
        if not under_sealed_corpus:
            continue
        content = _read_regular_file(
            escrow_bundle / relative,
            "escrow sealed-corpus payload",
        )
        if len(content) != entry.size or _sha256(content) != entry.sha256:
            raise EvidenceBundleError("escrow sealed corpus changed after verification")
        escrow_hashes.add(entry.sha256)
    if not escrow_hashes:
        raise EvidenceBundleError("escrow bundle contains no sealed-corpus files")
    if not escrow_hashes.issubset(external.forbidden_file_hashes):
        raise EvidenceBundleError("public leakage policy does not cover the paired escrow corpus")


def _snapshot_verified_bundle(
    directory: Path,
    manifest: EvidenceBundleManifest,
    *,
    protocol_signature_verification: ProtocolSignatureVerification,
) -> EvidenceBundleReceipt:
    """Snapshot exact core bytes and prove they still match the verified manifest."""
    manifest_bytes = _read_regular_file(directory / BUNDLE_MANIFEST, "bundle manifest")
    if manifest_bytes != _manifest_bytes(manifest):
        raise EvidenceBundleError("bundle manifest changed after verification")
    sidecar = _read_regular_file(
        directory / BUNDLE_MANIFEST_HASH,
        "bundle manifest hash",
    )
    if sidecar != f"{_sha256(manifest_bytes)}  {BUNDLE_MANIFEST}\n".encode("ascii"):
        raise EvidenceBundleError("bundle manifest sidecar changed after verification")

    protocol_bytes = _snapshot_role(directory, manifest, EvidenceRole.PROTOCOL)
    signature_bytes = _snapshot_role(
        directory,
        manifest,
        EvidenceRole.PROTOCOL_SIGNATURE,
    )
    allowed_signers_bytes = _snapshot_role(
        directory,
        manifest,
        EvidenceRole.SIGNER_POLICY,
    )
    config_bytes = _snapshot_role(directory, manifest, EvidenceRole.CONFIG)
    report_bytes = _snapshot_role(directory, manifest, EvidenceRole.REPORT)
    protocol, config, report = _validate_core_semantics_bytes(
        protocol_bytes,
        config_bytes,
        report_bytes,
    )
    if (
        protocol_signature_verification.identity != manifest.protocol_signer_identity
        or protocol_signature_verification.namespace != manifest.protocol_signature_namespace
        or protocol_signature_verification.protocol_sha256 != _sha256(protocol_bytes)
        or protocol_signature_verification.signature_sha256 != _sha256(signature_bytes)
        or protocol_signature_verification.allowed_signers_sha256 != _sha256(allowed_signers_bytes)
    ):
        raise EvidenceBundleError(
            "retained protocol signature authorization disagrees with exact bundle bytes"
        )
    return EvidenceBundleReceipt(
        bundle_kind=manifest.bundle_kind,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_sha256=_sha256(manifest_bytes),
        protocol=protocol,
        protocol_bytes=protocol_bytes,
        protocol_signature_bytes=signature_bytes,
        allowed_signers_bytes=allowed_signers_bytes,
        config=config,
        config_bytes=config_bytes,
        report=report,
        report_bytes=report_bytes,
    )


def _snapshot_role(
    directory: Path,
    manifest: EvidenceBundleManifest,
    role: EvidenceRole,
) -> bytes:
    """Read one verified core role and re-bind its exact bytes to the manifest."""
    path = _single_role_path(manifest, role)
    content = _read_regular_file(directory / path, f"bundle {role.value}")
    entry = manifest.files[path]
    if len(content) != entry.size or _sha256(content) != entry.sha256:
        raise EvidenceBundleError(f"bundle {role.value} changed after verification")
    return content


def _core_sources(
    protocol: Path,
    protocol_signature: Path,
    allowed_signers: Path,
    signer_identity: str,
    config: Path,
    report: Path,
) -> tuple[tuple[PurePosixPath, Path, EvidenceRole], ...]:
    """Verify and assign stable destinations to all required core artifacts."""
    try:
        verify_protocol_signature(
            protocol,
            protocol_signature,
            allowed_signers,
            signer_identity,
        )
    except ProtocolSignatureError as exc:
        raise EvidenceBundleError(str(exc)) from exc
    _validate_core_semantics(protocol, config, report)
    sources = (
        (PurePosixPath("protocol") / protocol.name, protocol, EvidenceRole.PROTOCOL),
        (
            PurePosixPath("signature") / protocol_signature.name,
            protocol_signature,
            EvidenceRole.PROTOCOL_SIGNATURE,
        ),
        (
            PurePosixPath("trust") / allowed_signers.name,
            allowed_signers,
            EvidenceRole.SIGNER_POLICY,
        ),
        (PurePosixPath("config") / config.name, config, EvidenceRole.CONFIG),
        (PurePosixPath("report") / report.name, report, EvidenceRole.REPORT),
    )
    for _, source, role in sources:
        _read_regular_file(source, role.value)
    return sources


def _validate_core_semantics(
    protocol: Path,
    config: Path,
    report: Path,
) -> tuple[BenchmarkProtocolManifest, RunConfig, Report]:
    """Parse, verify, and cross-bind the three benchmark claim artifacts.

    Byte hashes prove only that files did not change after bundling. This check proves that
    the files are the artifacts they claim to be and all name the same protocol and
    behavioral configuration.
    """
    return _validate_core_semantics_bytes(
        _read_regular_file(protocol, "benchmark protocol"),
        _read_regular_file(config, "resolved config"),
        _read_regular_file(report, "report"),
    )


def _validate_core_semantics_bytes(
    protocol_content: bytes,
    config_content: bytes,
    report_content: bytes,
) -> tuple[BenchmarkProtocolManifest, RunConfig, Report]:
    """Parse and cross-bind exact protocol, configuration, and report bytes."""
    try:
        raw_protocol = yaml.safe_load(protocol_content.decode("utf-8"))
        if not isinstance(raw_protocol, dict):
            raise ValueError("benchmark protocol root must be a mapping")
        protocol_model = BenchmarkProtocolManifest.model_validate(raw_protocol)
    except (UnicodeDecodeError, ValueError, ValidationError, yaml.YAMLError) as exc:
        raise EvidenceBundleError(f"benchmark protocol is not valid: {exc}") from exc
    expected_protocol = compiled_benchmark_protocol()
    if protocol_model != expected_protocol:
        raise EvidenceBundleError(
            "signed benchmark protocol does not match the frozen Protocol 2 contract"
        )

    config_model = _load_resolved_config_bytes(config_content)
    try:
        report_model = load_report(report_content.decode("utf-8"))
        verify_report(report_model)
    except (UnicodeDecodeError, ReportMismatchError) as exc:
        raise EvidenceBundleError(f"benchmark report does not verify: {exc}") from exc

    if report_model.config_fingerprint != config_model.fingerprint():
        raise EvidenceBundleError(
            "benchmark report config fingerprint disagrees with the resolved configuration"
        )
    metadata = config_model.benchmark_metadata()
    if metadata is None:
        raise EvidenceBundleError("resolved configuration does not opt into a benchmark protocol")
    if report_model.benchmark_metadata != metadata:
        raise EvidenceBundleError(
            "benchmark report metadata disagrees with the resolved configuration"
        )
    if (
        report_model.benchmark_protocol_version != protocol_model.benchmark_protocol_version
        or config_model.benchmark_protocol_version != protocol_model.benchmark_protocol_version
    ):
        raise EvidenceBundleError(
            "protocol, configuration, and report benchmark versions do not agree"
        )
    if report_model.rubric_version != protocol_model.rubric_version:
        raise EvidenceBundleError(
            "benchmark report rubric version disagrees with the signed protocol"
        )
    return protocol_model, config_model, report_model


def _load_resolved_config(path: Path) -> RunConfig:
    """Load a resolved config and verify its embedded self-fingerprint."""
    return _load_resolved_config_bytes(_read_regular_file(path, "resolved config"))


def _load_resolved_config_bytes(content: bytes) -> RunConfig:
    """Load exact resolved-config bytes and verify their embedded fingerprint."""
    try:
        raw = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceBundleError("benchmark configuration must be a resolved JSON object") from exc
    if not isinstance(raw, dict):
        raise EvidenceBundleError("benchmark configuration must be a resolved JSON object")
    embedded = raw.get("config_fingerprint")
    if not isinstance(embedded, str) or _HASH_PATTERN.fullmatch(embedded) is None:
        raise EvidenceBundleError(
            "resolved benchmark configuration is missing its valid config_fingerprint"
        )
    raw.pop("config_fingerprint", None)
    try:
        config = RunConfig.model_validate(raw)
    except ValidationError as exc:
        raise EvidenceBundleError(f"benchmark configuration does not validate: {exc}") from exc
    if embedded != config.fingerprint():
        raise EvidenceBundleError(
            "resolved benchmark configuration's embedded fingerprint is incorrect"
        )
    return config


def _verify_bundled_core_semantics(
    directory: Path,
    manifest: EvidenceBundleManifest,
) -> tuple[BenchmarkProtocolManifest, RunConfig, Report]:
    """Re-run semantic cross-binding against inventory-selected bundled artifacts."""
    return _validate_core_semantics(
        directory / _single_role_path(manifest, EvidenceRole.PROTOCOL),
        directory / _single_role_path(manifest, EvidenceRole.CONFIG),
        directory / _single_role_path(manifest, EvidenceRole.REPORT),
    )


def _public_config_bytes(config_path: Path) -> bytes:
    """Return a semantically identical config with host-only paths removed.

    Corpus, output, baseline, and credential-mount locations are deliberately excluded from
    the behavioral fingerprint. Redacting them therefore preserves the cryptographic binding
    to the report while keeping operator usernames, home paths, and sealed-storage locations
    out of a public artifact. Fields that do affect behavior cannot be silently rewritten:
    secret-looking environment options and fixture/absolute command paths are refused.
    """
    config = _load_resolved_config(config_path)
    for name, value in config.agent.options.items():
        if _SECRET_OPTION_NAME.search(name) or _SECRET_OPTION_VALUE.search(value):
            raise EvidenceBundleError(
                f"agent option {name!r} looks secret-bearing and cannot enter a public bundle"
            )
    if config.agent.fixture is not None:
        raise EvidenceBundleError(
            "recorded-agent fixture paths cannot enter a public benchmark configuration"
        )
    public_argv = (*config.agent.command, *config.agent.version_command)
    if any(_SECRET_OPTION_VALUE.search(part) for part in public_argv):
        raise EvidenceBundleError(
            "agent command/version arguments look secret-bearing and cannot enter a public bundle"
        )
    if any(
        Path(part).is_absolute()
        for part in public_argv
        if "{prompt}" not in part
        and "{reasoning_effort}" not in part
        and "{inference_settings_json}" not in part
    ):
        raise EvidenceBundleError(
            "absolute host paths in agent command/version arguments cannot enter a public "
            "benchmark configuration"
        )

    agent = config.agent.model_copy(
        update={
            "credential_mount": (
                None if config.agent.credential_mount is None else _PUBLIC_PATH_REDACTION
            )
        }
    )
    redacted = config.model_copy(
        update={
            "agent": agent,
            "corpus": _PUBLIC_PATH_REDACTION,
            "output_dir": _PUBLIC_PATH_REDACTION,
            "baseline": None if config.baseline is None else _PUBLIC_PATH_REDACTION,
        }
    )
    if redacted.fingerprint() != config.fingerprint():
        raise EvidenceBundleError(
            "public path redaction changed the behavioral configuration fingerprint"
        )
    return redacted.resolved_json().encode("utf-8")


def _verify_escrow_semantics(
    sealed_corpus: Path,
    rerunnable_evidence: Path,
    *,
    protocol: BenchmarkProtocolManifest,
    config: RunConfig,
    report: Report,
) -> None:
    """Bind escrow payload structure to the core report and actual sealed corpus bytes."""
    try:
        scenarios = discover_scenarios(sealed_corpus)
    except ScenarioLoadError as exc:
        raise EvidenceBundleError(f"escrow sealed corpus does not load: {exc}") from exc
    if not scenarios:
        raise EvidenceBundleError("escrow sealed corpus is empty")
    if any(
        scenario.manifest.benchmark_split is not BenchmarkSplit.SEALED for scenario in scenarios
    ):
        raise EvidenceBundleError("escrow corpus contains a scenario not marked sealed")
    if any(scenario.manifest.cluster_id is None for scenario in scenarios):
        raise EvidenceBundleError("escrow sealed corpus has a scenario without cluster_id")
    actual_corpus_hash = corpus_hash(scenarios)
    if actual_corpus_hash != report.corpus_hash:
        raise EvidenceBundleError("escrow sealed corpus hash disagrees with the benchmark report")
    report_ids = {result.scenario_id for result in report.results}
    scenario_ids = {scenario.id for scenario in scenarios}
    if not report.results or report_ids != scenario_ids:
        raise EvidenceBundleError(
            "escrow report scenario ids do not exactly cover the sealed corpus"
        )
    scenarios_by_id = {scenario.id: scenario for scenario in scenarios}
    for result in report.results:
        scenario = scenarios_by_id[result.scenario_id]
        manifest = scenario.manifest
        if (
            result.family is not manifest.family
            or result.benchmark_split is not manifest.benchmark_split
            or result.scenario_version != manifest.scenario_version
            or result.cluster_id != manifest.cluster_id
        ):
            raise EvidenceBundleError(
                "escrow report scenario metadata disagrees with the sealed corpus"
            )

    _require_directory(rerunnable_evidence, "rerunnable evidence")
    entries = _walk_tree(rerunnable_evidence)
    if not any(not is_directory for _, is_directory in entries):
        raise EvidenceBundleError("rerunnable evidence is empty")
    required_files = (
        "report.json",
        "config.resolved.json",
        "corpus.lock",
        "rubric.version",
        REPRO_EVIDENCE_FORMAT_FILE,
        INVOCATION_AGGREGATE_NAME,
        "benchmark.protocol.version",
        "rerun.sh",
        SEALED_REPRO_MARKER,
    )
    required_bytes = {
        required_name: _read_regular_file(
            rerunnable_evidence / required_name,
            f"rerunnable evidence {required_name}",
        )
        for required_name in required_files
    }
    _require_directory(rerunnable_evidence / "runs", "rerunnable evidence runs")
    if (rerunnable_evidence / "corpus").exists():
        raise EvidenceBundleError(
            "sealed corpus was copied into the ordinary rerunnable evidence package"
        )

    try:
        repro_report = load_report(required_bytes["report.json"].decode("utf-8"))
        verify_report(repro_report)
    except (UnicodeDecodeError, ReportMismatchError) as exc:
        raise EvidenceBundleError(f"rerunnable evidence report does not verify: {exc}") from exc
    if repro_report != report:
        raise EvidenceBundleError(
            "rerunnable evidence report disagrees with the escrow core report"
        )
    repro_config = _load_resolved_config_bytes(required_bytes["config.resolved.json"])
    if (
        repro_config.fingerprint() != config.fingerprint()
        or repro_config.benchmark_metadata() != config.benchmark_metadata()
    ):
        raise EvidenceBundleError(
            "rerunnable evidence configuration disagrees with the escrow core configuration"
        )
    try:
        corpus_lock = required_bytes["corpus.lock"].decode("utf-8")
        rubric_version = required_bytes["rubric.version"].decode("utf-8")
        benchmark_protocol_version = required_bytes["benchmark.protocol.version"].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceBundleError("rerunnable evidence metadata must be valid UTF-8") from exc
    if corpus_lock != build_corpus_lock(scenarios):
        raise EvidenceBundleError(
            "rerunnable evidence corpus.lock disagrees with the actual sealed corpus"
        )
    if rubric_version != protocol.rubric_version + "\n":
        raise EvidenceBundleError("rerunnable evidence rubric.version is incorrect")
    if benchmark_protocol_version != protocol.benchmark_protocol_version + "\n":
        raise EvidenceBundleError("rerunnable evidence benchmark.protocol.version is incorrect")
    for result in report.results:
        for artifact in (result.transcript_path, result.diff_path):
            artifact_path = _safe_relative_path(artifact, "report artifact")
            _read_regular_file(
                rerunnable_evidence / artifact_path.as_posix(),
                f"rerunnable evidence report artifact {artifact!r}",
            )
    try:
        verify_report_classifications_from_escrow(
            sealed_corpus,
            rerunnable_evidence,
            config=config,
            report=report,
        )
    except ClassificationReplayError:
        raise EvidenceBundleError(
            "rerunnable evidence classification replay failed closed (private details withheld)"
        ) from None


def _verify_private_escrow_semantics(
    sealed_corpus: Path,
    rerunnable_evidence: Path,
    *,
    protocol: BenchmarkProtocolManifest,
    config: RunConfig,
    report: Report,
) -> None:
    """Run private semantic checks without exposing sealed identifiers or paths."""
    try:
        _verify_escrow_semantics(
            sealed_corpus,
            rerunnable_evidence,
            protocol=protocol,
            config=config,
            report=report,
        )
    except (EvidenceBundleError, ClassificationReplayError, ScenarioLoadError, OSError):
        raise EvidenceBundleError(
            "escrow private semantic verification failed closed (private details withheld)"
        ) from None


@contextmanager
def _snapshot_escrow_payloads(
    directory: Path,
    manifest: EvidenceBundleManifest,
) -> Iterator[tuple[Path, Path]]:
    """Yield immutable verifier-owned snapshots of both private evidence roles.

    ``_verify_actual_inventory`` rejects symlinks and verifies every hash, but a caller able
    to mutate the bundle could replace a regular file after that pass and before semantic
    replay reopened it.  This helper closes that window: every byte is read through
    ``O_NOFOLLOW``, checked against the already parsed manifest again, and copied into a new
    private temporary tree.  Replay touches only that tree.
    """
    private_roles = {
        EvidenceRole.SEALED_CORPUS,
        EvidenceRole.RERUNNABLE_EVIDENCE,
    }
    with tempfile.TemporaryDirectory(prefix="stinger-escrow-snapshot-") as temporary_name:
        snapshot = Path(temporary_name)
        for relative, role in sorted(manifest.directories.items()):
            if role not in private_roles:
                continue
            target = snapshot / relative
            target.mkdir(parents=True, exist_ok=False)
            target.chmod(0o700)
        for relative, entry in sorted(manifest.files.items()):
            if entry.role not in private_roles:
                continue
            try:
                content = _read_regular_file(
                    directory / relative,
                    "escrow private payload",
                )
            except EvidenceBundleError:
                raise EvidenceBundleError(
                    "escrow private payload could not be snapshotted (private details withheld)"
                ) from None
            if len(content) != entry.size or _sha256(content) != entry.sha256:
                raise EvidenceBundleError(
                    "escrow private payload changed before semantic replay "
                    "(private details withheld)"
                )
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(0o700 if entry.executable else 0o600)

        sealed = snapshot / "sealed-corpus"
        rerunnable = snapshot / "rerunnable-evidence"
        _require_directory(sealed, "snapshotted sealed corpus")
        _require_directory(rerunnable, "snapshotted rerunnable evidence")
        yield sealed, rerunnable


def _public_log_sources(
    permitted_logs: Mapping[str, Path],
) -> tuple[tuple[PurePosixPath, Path, EvidenceRole], ...]:
    """Turn an explicit public-log allowlist into sorted, safe payload destinations."""
    sources: list[tuple[PurePosixPath, Path, EvidenceRole]] = []
    seen: set[str] = set()
    for name, source in sorted(permitted_logs.items()):
        relative = _safe_relative_path(name, "permitted log")
        payload_path = PurePosixPath("logs") / relative
        key = payload_path.as_posix()
        if key in seen:
            raise EvidenceBundleError(f"duplicate permitted log destination {key!r}")
        seen.add(key)
        _read_regular_file(source, f"permitted log {name!r}")
        sources.append((payload_path, source, EvidenceRole.LOG))
    return tuple(sources)


def _safe_relative_path(value: str, label: str) -> PurePosixPath:
    """Return one unambiguous POSIX relative path or fail closed."""
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise EvidenceBundleError(f"{label} path must be non-empty, relative, and traversal-free")
    if "\\" in value:
        raise EvidenceBundleError(f"{label} path must use POSIX separators")
    return path


def _check_destination(destination: Path, sources: Sequence[Path]) -> None:
    """Refuse stale destinations and recursive source/destination layouts."""
    if destination.exists() or destination.is_symlink():
        raise EvidenceBundleError(f"bundle destination already exists: {destination}")
    target = destination.resolve()
    for source in sources:
        resolved = source.resolve()
        if target == resolved or target.is_relative_to(resolved):
            raise EvidenceBundleError(
                f"bundle destination {destination} is inside source {source}; refusing recursion"
            )


def _snapshot_policy(policy: PublicLeakagePolicy) -> _LeakageSnapshot:
    """Hash sensitive roots and markers without exposing their paths or values."""
    if not policy.forbidden_sources:
        raise EvidenceBundleError("public leakage policy must name the active sealed sources")
    if not policy.forbidden_markers:
        raise EvidenceBundleError(
            "public leakage policy must supply active corpus canary and secret markers"
        )

    file_hashes: set[str] = set()
    chunk_hashes: set[str] = set()
    path_fragments: set[bytes] = set()
    sensitive_content: list[bytes] = []
    for source in policy.forbidden_sources:
        if source.is_symlink():
            raise EvidenceBundleError(f"forbidden source must not be a symlink: {source}")
        resolved_source = str(source.resolve()).encode("utf-8")
        if resolved_source:
            path_fragments.add(resolved_source)
        if source.is_file():
            content = _read_regular_file(source, "forbidden source")
            file_hashes.add(_sha256(content))
            chunk_hashes.update(_sensitive_chunk_hashes(content))
            sensitive_content.append(content)
            continue
        _require_directory(source, "forbidden source")
        entries = _walk_tree(source)
        for entry, is_directory in entries:
            if not is_directory:
                content = _read_regular_file(entry, "forbidden source file")
                file_hashes.add(_sha256(content))
                chunk_hashes.update(_sensitive_chunk_hashes(content))
                sensitive_content.append(content)
    if not file_hashes:
        raise EvidenceBundleError("public leakage policy sealed sources contain no files")

    markers: set[bytes] = set()
    for marker in policy.forbidden_markers:
        encoded = marker if isinstance(marker, bytes) else marker.encode("utf-8")
        if not encoded:
            raise EvidenceBundleError("public leakage policy markers must not be empty")
        markers.add(encoded)
    ordered_markers = tuple(sorted(markers))
    missing_markers = [
        index
        for index, marker in enumerate(ordered_markers, start=1)
        if not any(marker in content for content in sensitive_content)
    ]
    if missing_markers:
        raise EvidenceBundleError(
            "public leakage policy marker(s) are not bound to the supplied sealed sources: "
            + ", ".join(str(index) for index in missing_markers)
        )
    payload = {
        "forbidden_file_sha256": sorted(file_hashes),
        "forbidden_chunk_sha256": sorted(chunk_hashes),
        "forbidden_marker_sha256": sorted(_sha256(marker) for marker in ordered_markers),
    }
    fingerprint = _sha256(_canonical_json(payload))
    return _LeakageSnapshot(
        frozenset(file_hashes),
        frozenset(chunk_hashes),
        ordered_markers,
        tuple(sorted(path_fragments)),
        fingerprint,
    )


def _scan_public_sources(
    sources: Sequence[tuple[PurePosixPath, Path, EvidenceRole]],
    snapshot: _LeakageSnapshot,
    *,
    config_override: bytes,
) -> None:
    """Reject sensitive content before a public destination is created."""
    for relative, source, role in sources:
        _check_public_path(relative)
        content = (
            config_override
            if role is EvidenceRole.CONFIG
            else _read_regular_file(source, f"public payload {relative.as_posix()!r}")
        )
        _check_public_content(relative.as_posix(), content, snapshot)


def _scan_public_bundle(
    directory: Path,
    manifest: EvidenceBundleManifest,
    snapshot: _LeakageSnapshot,
) -> None:
    """Re-scan the verified public payload using the active sensitive comparison set."""
    for relative in sorted(manifest.files):
        _check_public_path(PurePosixPath(relative))
        content = _read_regular_file(directory / relative, f"public payload {relative!r}")
        _check_public_content(relative, content, snapshot)


def _check_public_path(path: PurePosixPath) -> None:
    """Reject answer-bearing directory names from the public disclosure surface."""
    for component in path.parts[:-1]:
        normalized = re.sub(r"[^a-z0-9]+", "_", component.casefold()).strip("_")
        if normalized in _SENSITIVE_DIRECTORY_NAMES or normalized.startswith("reference_"):
            raise EvidenceBundleError(
                f"public bundle path {path.as_posix()!r} names sealed corpus/reference material"
            )


def _check_public_content(relative: str, content: bytes, snapshot: _LeakageSnapshot) -> None:
    """Reject sealed near-copies, private paths, active markers, and private keys."""
    if _sha256(content) in snapshot.forbidden_file_hashes:
        raise EvidenceBundleError(
            f"public payload {relative!r} is byte-identical to active sealed material"
        )
    overlap = _sensitive_chunk_hashes(content) & snapshot.forbidden_chunk_hashes
    if overlap:
        raise EvidenceBundleError(
            f"public payload {relative!r} contains a meaningful sealed-material fragment"
        )
    for index, marker in enumerate(snapshot.forbidden_markers, start=1):
        if marker in content:
            raise EvidenceBundleError(
                f"public payload {relative!r} contains forbidden canary/secret marker #{index}"
            )
    if any(fragment in content for fragment in snapshot.forbidden_path_fragments) or any(
        pattern.search(content) is not None for pattern in _PRIVATE_ABSOLUTE_PATH_PATTERNS
    ):
        raise EvidenceBundleError(
            f"public payload {relative!r} contains an absolute private or escrow path"
        )
    if any(marker in content for marker in _INTRINSIC_SECRET_MARKERS):
        raise EvidenceBundleError(
            f"public payload {relative!r} contains recognizable private-key material"
        )


def _sensitive_chunk_hashes(content: bytes) -> set[str]:
    """Return bounded domain-separated hashes of meaningful raw and textual fragments."""
    hashes: set[str] = set()
    if len(content) >= _SENSITIVE_RAW_CHUNK_BYTES:
        positions = list(
            range(
                0,
                len(content) - _SENSITIVE_RAW_CHUNK_BYTES + 1,
                _SENSITIVE_RAW_CHUNK_STRIDE,
            )
        )
        last = len(content) - _SENSITIVE_RAW_CHUNK_BYTES
        if not positions or positions[-1] != last:
            positions.append(last)
        for position in _bounded_positions(positions):
            chunk = content[position : position + _SENSITIVE_RAW_CHUNK_BYTES]
            hashes.add(_sha256(b"stinger-raw-chunk-v1\x00" + chunk))

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return hashes
    tokens = _TEXT_TOKEN_PATTERN.findall(text.casefold())
    if len(tokens) < _SENSITIVE_TEXT_NGRAM_WORDS:
        return hashes
    positions = list(range(0, len(tokens) - _SENSITIVE_TEXT_NGRAM_WORDS + 1))
    for position in _bounded_positions(positions):
        ngram = " ".join(tokens[position : position + _SENSITIVE_TEXT_NGRAM_WORDS]).encode("utf-8")
        if len(ngram) >= _SENSITIVE_TEXT_NGRAM_MIN_BYTES:
            hashes.add(_sha256(b"stinger-text-ngram-v1\x00" + ngram))
    return hashes


def _bounded_positions(positions: list[int]) -> tuple[int, ...]:
    """Select deterministic evenly distributed positions under the per-file bound."""
    if len(positions) <= _MAX_SENSITIVE_CHUNKS_PER_FILE:
        return tuple(positions)
    last = len(positions) - 1
    return tuple(
        positions[index * last // (_MAX_SENSITIVE_CHUNKS_PER_FILE - 1)]
        for index in range(_MAX_SENSITIVE_CHUNKS_PER_FILE)
    )


def _require_directory(path: Path, label: str) -> None:
    """Require a real, non-symlink directory."""
    if path.is_symlink() or not path.is_dir():
        raise EvidenceBundleError(f"{label} must be a real directory: {path}")


def _walk_tree(root: Path) -> list[tuple[Path, bool]]:
    """List a tree deterministically while rejecting symlinks and special files."""
    _require_directory(root, "tree source")
    entries: list[tuple[Path, bool]] = []
    for current, directories, filenames in os.walk(root, followlinks=False):
        directories.sort()
        filenames.sort()
        base = Path(current)
        for name in directories:
            path = base / name
            if path.is_symlink() or not path.is_dir():
                raise EvidenceBundleError(f"tree contains an unsafe directory: {path}")
            entries.append((path, True))
        for name in filenames:
            path = base / name
            if path.is_symlink() or not path.is_file():
                raise EvidenceBundleError(f"tree contains an unsafe file: {path}")
            entries.append((path, False))
    return entries


def _copy_tree(
    source: Path,
    destination: Path,
    relative_root: PurePosixPath,
    role: EvidenceRole,
    inventory: _InventoryBuilder,
) -> None:
    """Copy a complete source tree, including empty directories, into the inventory."""
    _record_directory(destination, relative_root, role, inventory)
    for entry, is_directory in _walk_tree(source):
        relative = relative_root / PurePosixPath(entry.relative_to(source).as_posix())
        if is_directory:
            _record_directory(destination, relative, role, inventory)
        else:
            _copy_file(entry, destination, relative, role, inventory)


def _copy_file(
    source: Path,
    destination: Path,
    relative: PurePosixPath,
    role: EvidenceRole,
    inventory: _InventoryBuilder,
) -> None:
    """Copy one regular file with a deterministic permission mode."""
    content = _read_regular_file(source, role.value)
    executable = bool(source.stat().st_mode & 0o111)
    _copy_bytes(content, destination, relative, role, executable, inventory)


def _copy_bytes(
    content: bytes,
    destination: Path,
    relative: PurePosixPath,
    role: EvidenceRole,
    executable: bool,
    inventory: _InventoryBuilder,
) -> None:
    """Write bytes and pin their digest, size, role, and normalized executable bit."""
    relative_text = relative.as_posix()
    if relative_text in inventory.files or relative_text in inventory.directories:
        raise EvidenceBundleError(f"duplicate bundle payload path {relative_text!r}")
    _record_parent_directories(destination, relative.parent, role, inventory)
    target = destination / relative_text
    target.write_bytes(content)
    target.chmod(0o755 if executable else 0o644)
    inventory.files[relative_text] = InventoryFile(
        role=role,
        sha256=_sha256(content),
        size=len(content),
        executable=executable,
    )


def _record_parent_directories(
    destination: Path,
    relative: PurePosixPath,
    role: EvidenceRole,
    inventory: _InventoryBuilder,
) -> None:
    """Create and inventory every missing payload parent from the root downward."""
    current = PurePosixPath()
    for part in relative.parts:
        current /= part
        _record_directory(destination, current, role, inventory)


def _record_directory(
    destination: Path,
    relative: PurePosixPath,
    role: EvidenceRole,
    inventory: _InventoryBuilder,
) -> None:
    """Create one deterministic directory and record its role."""
    relative_text = relative.as_posix()
    if not relative_text or relative_text == ".":
        return
    existing_role = inventory.directories.get(relative_text)
    if existing_role is not None:
        if existing_role != role:
            raise EvidenceBundleError(
                f"bundle directory {relative_text!r} is shared by incompatible roles"
            )
        return
    if relative_text in inventory.files:
        raise EvidenceBundleError(f"bundle path {relative_text!r} is both a file and directory")
    target = destination / relative_text
    target.mkdir()
    target.chmod(0o755)
    inventory.directories[relative_text] = role


def _build_manifest(
    kind: BundleKind,
    inventory: _InventoryBuilder,
    *,
    protocol_signer_identity: str,
    leakage_policy_sha256: str | None,
    access_control_notice: str | None,
) -> EvidenceBundleManifest:
    """Build a manifest only after the complete payload inventory exists."""
    required = {}
    for role in (
        EvidenceRole.PROTOCOL,
        EvidenceRole.PROTOCOL_SIGNATURE,
        EvidenceRole.SIGNER_POLICY,
        EvidenceRole.CONFIG,
        EvidenceRole.REPORT,
    ):
        matching = [entry for entry in inventory.files.values() if entry.role is role]
        if len(matching) != 1:
            raise EvidenceBundleError(f"bundle must contain exactly one {role.value} artifact")
        required[role] = matching[0].sha256
    files = dict(sorted(inventory.files.items()))
    directories = dict(sorted(inventory.directories.items()))
    return EvidenceBundleManifest(
        format_version=BUNDLE_FORMAT_VERSION,
        bundle_kind=kind,
        protocol_sha256=required[EvidenceRole.PROTOCOL],
        protocol_signature_sha256=required[EvidenceRole.PROTOCOL_SIGNATURE],
        allowed_signers_sha256=required[EvidenceRole.SIGNER_POLICY],
        protocol_signer_identity=protocol_signer_identity,
        protocol_signature_namespace=PROTOCOL_SIGNATURE_NAMESPACE,
        config_sha256=required[EvidenceRole.CONFIG],
        report_sha256=required[EvidenceRole.REPORT],
        inventory_sha256=_inventory_hash(files, directories),
        leakage_policy_sha256=leakage_policy_sha256,
        access_control_notice=access_control_notice,
        files=files,
        directories=directories,
    )


def _write_manifest(directory: Path, manifest: EvidenceBundleManifest) -> None:
    """Write canonical manifest bytes plus their standard sha256 sidecar."""
    encoded = _manifest_bytes(manifest)
    (directory / BUNDLE_MANIFEST).write_bytes(encoded)
    digest = _sha256(encoded)
    (directory / BUNDLE_MANIFEST_HASH).write_text(
        f"{digest}  {BUNDLE_MANIFEST}\n", encoding="ascii"
    )


def _load_and_verify_manifest(
    directory: Path, *, expected_kind: BundleKind
) -> EvidenceBundleManifest:
    """Verify canonical metadata, inventory shape, payload bytes, and top-level hashes."""
    _require_directory(directory, "bundle")
    manifest_path = directory / BUNDLE_MANIFEST
    encoded = _read_regular_file(manifest_path, "bundle manifest")
    sidecar = _read_regular_file(directory / BUNDLE_MANIFEST_HASH, "bundle manifest hash")
    expected_sidecar = f"{_sha256(encoded)}  {BUNDLE_MANIFEST}\n".encode("ascii")
    if sidecar != expected_sidecar:
        raise EvidenceBundleError("bundle manifest hash sidecar disagrees with the manifest")
    try:
        manifest = EvidenceBundleManifest.model_validate_json(encoded)
    except ValidationError as exc:
        raise EvidenceBundleError(f"bundle manifest is invalid: {exc}") from exc
    if encoded != _manifest_bytes(manifest):
        raise EvidenceBundleError("bundle manifest is not in canonical deterministic form")
    if manifest.format_version != BUNDLE_FORMAT_VERSION:
        raise EvidenceBundleError(
            f"bundle format {manifest.format_version!r} is not supported "
            f"(expected {BUNDLE_FORMAT_VERSION!r})"
        )
    if manifest.bundle_kind is not expected_kind:
        raise EvidenceBundleError(
            f"bundle kind is {manifest.bundle_kind.value!r}, expected {expected_kind.value!r}"
        )
    _validate_manifest_digests(manifest)
    _verify_actual_inventory(directory, manifest)
    _verify_required_hashes(manifest)
    return manifest


def _validate_manifest_digests(manifest: EvidenceBundleManifest) -> None:
    """Refuse malformed hashes and impossible byte counts before comparing anything."""
    named = {
        "protocol_sha256": manifest.protocol_sha256,
        "protocol_signature_sha256": manifest.protocol_signature_sha256,
        "allowed_signers_sha256": manifest.allowed_signers_sha256,
        "config_sha256": manifest.config_sha256,
        "report_sha256": manifest.report_sha256,
        "inventory_sha256": manifest.inventory_sha256,
    }
    if manifest.leakage_policy_sha256 is not None:
        named["leakage_policy_sha256"] = manifest.leakage_policy_sha256
    for name, value in named.items():
        if _HASH_PATTERN.fullmatch(value) is None:
            raise EvidenceBundleError(f"bundle manifest {name} is not a sha256 digest")
    for path, entry in manifest.files.items():
        _validate_inventory_path(path)
        if _HASH_PATTERN.fullmatch(entry.sha256) is None:
            raise EvidenceBundleError(f"bundle file {path!r} has an invalid sha256 digest")
        if entry.size < 0:
            raise EvidenceBundleError(f"bundle file {path!r} has a negative size")
    for path in manifest.directories:
        _validate_inventory_path(path)
    if manifest.protocol_signature_namespace != PROTOCOL_SIGNATURE_NAMESPACE:
        raise EvidenceBundleError("bundle protocol signature namespace is unsupported or ambiguous")
    identity = manifest.protocol_signer_identity
    if (
        not identity.strip()
        or identity != identity.strip()
        or any(character.isspace() for character in identity)
    ):
        raise EvidenceBundleError("bundle protocol signer identity is invalid")


def _validate_inventory_path(path: str) -> None:
    """Require canonical, traversal-free POSIX paths in untrusted manifests."""
    parsed = PurePosixPath(path)
    if (
        not path
        or parsed.is_absolute()
        or parsed.as_posix() != path
        or ".." in parsed.parts
        or "." in parsed.parts
        or "\\" in path
    ):
        raise EvidenceBundleError(f"bundle inventory contains unsafe path {path!r}")
    if path in {BUNDLE_MANIFEST, BUNDLE_MANIFEST_HASH}:
        raise EvidenceBundleError(f"bundle metadata path {path!r} must not be payload inventory")


def _verify_actual_inventory(directory: Path, manifest: EvidenceBundleManifest) -> None:
    """Require exact file/directory sets and verify every payload hash, size, and mode."""
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for entry, is_directory in _walk_tree(directory):
        relative = entry.relative_to(directory).as_posix()
        if relative in {BUNDLE_MANIFEST, BUNDLE_MANIFEST_HASH}:
            continue
        if is_directory:
            actual_directories.add(relative)
            continue
        actual_files.add(relative)
        expected = manifest.files.get(relative)
        if expected is None:
            continue
        content = _read_regular_file(entry, f"bundle payload {relative!r}")
        if len(content) != expected.size or _sha256(content) != expected.sha256:
            raise EvidenceBundleError(f"bundle payload hash or size disagrees for {relative!r}")
        executable = bool(entry.stat().st_mode & 0o111)
        if executable != expected.executable:
            raise EvidenceBundleError(f"bundle payload executable mode disagrees for {relative!r}")
    if actual_files != set(manifest.files):
        missing = sorted(set(manifest.files) - actual_files)
        extra = sorted(actual_files - set(manifest.files))
        raise EvidenceBundleError(
            f"bundle file inventory disagrees (missing={missing}, extra={extra})"
        )
    if actual_directories != set(manifest.directories):
        missing = sorted(set(manifest.directories) - actual_directories)
        extra = sorted(actual_directories - set(manifest.directories))
        raise EvidenceBundleError(
            f"bundle directory inventory disagrees (missing={missing}, extra={extra})"
        )
    expected_inventory = _inventory_hash(manifest.files, manifest.directories)
    if manifest.inventory_sha256 != expected_inventory:
        raise EvidenceBundleError("bundle inventory hash disagrees with its file inventory")


def _verify_required_hashes(manifest: EvidenceBundleManifest) -> None:
    """Tie the headline protocol/config/report hashes to their unique inventory files."""
    expected = {
        EvidenceRole.PROTOCOL: manifest.protocol_sha256,
        EvidenceRole.PROTOCOL_SIGNATURE: manifest.protocol_signature_sha256,
        EvidenceRole.SIGNER_POLICY: manifest.allowed_signers_sha256,
        EvidenceRole.CONFIG: manifest.config_sha256,
        EvidenceRole.REPORT: manifest.report_sha256,
    }
    for role, digest in expected.items():
        matching = [entry.sha256 for entry in manifest.files.values() if entry.role is role]
        if matching != [digest]:
            raise EvidenceBundleError(
                f"bundle {role.value} hash disagrees with its inventory artifact"
            )


def _verify_bundled_protocol_signature(
    directory: Path,
    manifest: EvidenceBundleManifest,
    *,
    trusted_allowed_signers: Path,
    expected_signer_identity: str,
) -> ProtocolSignatureVerification:
    """Cryptographically bind the bundled protocol to the declared trusted identity."""
    protocol = _single_role_path(manifest, EvidenceRole.PROTOCOL)
    signature = _single_role_path(manifest, EvidenceRole.PROTOCOL_SIGNATURE)
    bundled_allowed_signers = _single_role_path(manifest, EvidenceRole.SIGNER_POLICY)
    if manifest.protocol_signer_identity != expected_signer_identity:
        raise EvidenceBundleError(
            "bundle protocol signer identity disagrees with independently expected identity"
        )
    try:
        verification = verify_protocol_signature(
            directory / protocol,
            directory / signature,
            trusted_allowed_signers,
            expected_signer_identity,
            namespace=manifest.protocol_signature_namespace,
        )
    except ProtocolSignatureError as exc:
        raise EvidenceBundleError(str(exc)) from exc
    if (
        verification.protocol_sha256 != manifest.protocol_sha256
        or verification.signature_sha256 != manifest.protocol_signature_sha256
        or verification.allowed_signers_sha256 != manifest.allowed_signers_sha256
    ):
        raise EvidenceBundleError(
            "verified protocol signature artifacts disagree with bundle headline hashes"
        )
    bundled_trust = _read_regular_file(
        directory / bundled_allowed_signers,
        "bundled allowed signers",
    )
    if _sha256(bundled_trust) != verification.allowed_signers_sha256:
        raise EvidenceBundleError(
            "bundled signer policy disagrees with independently trusted signer policy"
        )
    return verification


def _single_role_path(manifest: EvidenceBundleManifest, role: EvidenceRole) -> str:
    """Return the one file carrying a required evidence role."""
    matches = [path for path, entry in manifest.files.items() if entry.role is role]
    if len(matches) != 1:
        raise EvidenceBundleError(f"bundle must contain exactly one {role.value} artifact")
    return matches[0]


def _verify_role_shape(manifest: EvidenceBundleManifest, *, public: bool) -> None:
    """Refuse role substitution that could hide sealed files under an allowed label."""
    file_roles = {entry.role for entry in manifest.files.values()}
    directory_roles = set(manifest.directories.values())
    roles = file_roles | directory_roles
    core = {
        EvidenceRole.PROTOCOL,
        EvidenceRole.PROTOCOL_SIGNATURE,
        EvidenceRole.SIGNER_POLICY,
        EvidenceRole.CONFIG,
        EvidenceRole.REPORT,
    }
    if public:
        allowed = core | {EvidenceRole.LOG}
        forbidden = roles - allowed
        if forbidden:
            raise EvidenceBundleError(
                "public bundle contains forbidden payload role(s): "
                + ", ".join(sorted(role.value for role in forbidden))
            )
        for path, entry in manifest.files.items():
            if entry.role is EvidenceRole.LOG and not path.startswith("logs/"):
                raise EvidenceBundleError(f"public log lies outside logs/: {path!r}")
        return

    required = core | {
        EvidenceRole.SEALED_CORPUS,
        EvidenceRole.RERUNNABLE_EVIDENCE,
        EvidenceRole.NOTICE,
    }
    missing = required - roles
    if missing:
        raise EvidenceBundleError(
            "escrow bundle is incomplete; missing role(s): "
            + ", ".join(sorted(role.value for role in missing))
        )
    if roles - required:
        raise EvidenceBundleError("escrow bundle contains an unknown payload role")


def _inventory_hash(
    files: Mapping[str, InventoryFile], directories: Mapping[str, EvidenceRole]
) -> str:
    """Hash the complete payload layout independently of the enclosing manifest."""
    payload = {
        "files": {path: entry.model_dump(mode="json") for path, entry in sorted(files.items())},
        "directories": {path: role.value for path, role in sorted(directories.items())},
    }
    return _sha256(_canonical_json(payload))


def _manifest_bytes(manifest: EvidenceBundleManifest) -> bytes:
    """Canonical newline-terminated JSON for byte-for-byte deterministic manifests."""
    return _canonical_json(manifest.model_dump(mode="json")) + b"\n"


def _canonical_json(value: object) -> bytes:
    """Serialize a JSON-compatible value with stable keys and no incidental whitespace."""
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def _read_regular_file(path: Path, label: str) -> bytes:
    """Read one descriptor-validated regular file without a check/use path race."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceBundleError(f"{label} must be a real regular file: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceBundleError(f"{label} must be a real regular file: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _sha256(content: bytes) -> str:
    """Return a lowercase sha256 hex digest."""
    return hashlib.sha256(content).hexdigest()
