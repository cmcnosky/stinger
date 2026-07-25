"""Artifact-derived baseline-verification trust and release-gate tests."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

import stinger.benchmark.records as records_module
from stinger import BENCHMARK_PROTOCOL_VERSION, RUBRIC_VERSION
from stinger.benchmark.evidence import PublicLeakagePolicy
from stinger.benchmark.gates import (
    BaselineConfigurationRecord,
    BaselineVerificationStatement,
    BenchmarkGateReport,
    BenchmarkReleaseSubmission,
    PilotEvidenceRecord,
    PublicationIssueCode,
    ReleaseEvidenceRecord,
    SealedCorpusRecord,
    authorize_baseline_verification_statement,
    baseline_configuration_record_sha256,
    compiled_benchmark_protocol,
    evaluate_benchmark_release,
)
from stinger.benchmark.machine_environment import MachineWorkflowEvidencePaths
from stinger.benchmark.protocol import BenchmarkRunMetadata
from stinger.benchmark.records import (
    BaselineRecordError,
    build_baseline_verification_statement,
    write_baseline_verification_statement,
)
from stinger.benchmark.signing import (
    BASELINE_VERIFICATION_SIGNATURE_NAMESPACE,
    ProtocolSignatureError,
    sign_baseline_verification_statement,
    sign_protocol,
)
from stinger.models import Report

IDENTITY = "baseline-verifier@example.test"


@dataclass(frozen=True, slots=True)
class SignedBaselineStatement:
    """One exact baseline statement and its ephemeral SSH authority."""

    statement: BaselineVerificationStatement
    path: Path
    signature: Path
    private_key: Path
    allowed_signers: Path


@dataclass(frozen=True, slots=True)
class BaselineFixture:
    """Small typed baseline inputs for statement and release-gate tests."""

    record: BaselineConfigurationRecord
    corpus: SealedCorpusRecord
    public_bundle: Path
    escrow_bundle: Path
    policy: PublicLeakagePolicy
    allowed_signers: Path
    machine_identity: Path


@pytest.fixture
def baseline_fixture(tmp_path: Path) -> BaselineFixture:
    """Create a small exact typed baseline without running statistical fixtures."""
    corpus_hash = "a" * 64
    report = Report(
        rubric_version=RUBRIC_VERSION,
        corpus_hash=corpus_hash,
        config_fingerprint="b" * 64,
        generated_at="2026-07-25T00:00:00Z",
        results=[],
        family_scores={},
        overall_integrity_rate=None,
        partial=True,
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        benchmark_metadata=BenchmarkRunMetadata(),
    )
    record = BaselineConfigurationRecord(
        configuration_id="synthetic-baseline",
        report=report,
        report_sha256="c" * 64,
        public_bundle_manifest_sha256="d" * 64,
        escrow_bundle_manifest_sha256="e" * 64,
        machine_fingerprint_sha256="f" * 64,
        contained=True,
        deterministically_blocked_order=True,
        evidence_integrity_passed=True,
        public_bundle_verified=True,
        escrow_bundle_verified=True,
    )
    corpus = SealedCorpusRecord(
        corpus_version="1.0.0",
        corpus_hash=corpus_hash,
        scenarios=(),
    )
    public_bundle = tmp_path / "public-bundle"
    escrow_bundle = tmp_path / "escrow-bundle"
    sensitive_source = tmp_path / "sealed-corpus"
    allowed_signers = tmp_path / "protocol.allowed-signers"
    machine_identity = tmp_path / "machine.identity"
    for path in (
        public_bundle,
        escrow_bundle,
        sensitive_source,
    ):
        path.mkdir()
    allowed_signers.write_text("synthetic trust fixture\n", encoding="utf-8")
    machine_identity.write_text("synthetic machine identity\n", encoding="utf-8")
    return BaselineFixture(
        record=record,
        corpus=corpus,
        public_bundle=public_bundle,
        escrow_bundle=escrow_bundle,
        policy=PublicLeakagePolicy(
            forbidden_sources=(sensitive_source,),
            forbidden_markers=("STINGER-SYNTHETIC-MARKER",),
        ),
        allowed_signers=allowed_signers,
        machine_identity=machine_identity,
    )


@pytest.fixture
def signed_baseline_statement(
    tmp_path: Path,
    baseline_fixture: BaselineFixture,
) -> SignedBaselineStatement:
    """Sign an exact statement with a real ephemeral Ed25519 identity."""
    statement = _statement(baseline_fixture)
    path = tmp_path / "baseline-verification.json"
    write_baseline_verification_statement(path, statement)
    private_key, allowed_signers = _new_signing_identity(
        tmp_path,
        label="trusted-baseline-verifier",
        identity=IDENTITY,
    )
    signature = sign_baseline_verification_statement(path, private_key)
    return SignedBaselineStatement(
        statement=statement,
        path=path,
        signature=signature,
        private_key=private_key,
        allowed_signers=allowed_signers,
    )


def test_statement_is_derived_from_and_binds_the_exact_baseline_artifacts(
    baseline_fixture: BaselineFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The statement binds the exact record returned by the verified-artifact builder."""
    observed: dict[str, object] = {}

    def artifact_builder(
        configuration_id: str,
        **kwargs: object,
    ) -> BaselineConfigurationRecord:
        observed["configuration_id"] = configuration_id
        observed.update(kwargs)
        return baseline_fixture.record

    monkeypatch.setattr(
        records_module,
        "build_baseline_configuration_record",
        artifact_builder,
    )
    statement = _build_statement(baseline_fixture)
    protocol = compiled_benchmark_protocol()

    assert statement.benchmark_protocol_version == protocol.benchmark_protocol_version
    assert statement.rubric_version == protocol.rubric_version
    assert statement.configuration_id == baseline_fixture.record.configuration_id
    assert statement.corpus_hash == baseline_fixture.corpus.corpus_hash
    assert statement.baseline_record_sha256 == baseline_configuration_record_sha256(
        baseline_fixture.record
    )
    assert statement.signer_identity == IDENTITY
    assert observed == {
        "configuration_id": baseline_fixture.record.configuration_id,
        "corpus": baseline_fixture.corpus,
        "public_bundle": baseline_fixture.public_bundle,
        "escrow_bundle": baseline_fixture.escrow_bundle,
        "leakage_policy": baseline_fixture.policy,
        "protocol_allowed_signers": baseline_fixture.allowed_signers,
        "protocol_signer_identity": "baseline-builder@example.test",
        "machine_workflow_evidence": _machine_workflow_evidence(baseline_fixture),
    }

    altered = baseline_fixture.record.model_copy(update={"public_bundle_manifest_sha256": "f" * 64})
    with pytest.raises(
        BaselineRecordError,
        match="differs from the artifact-derived rebuild",
    ):
        build_baseline_verification_statement(
            altered.configuration_id,
            expected_record=altered,
            corpus=baseline_fixture.corpus,
            public_bundle=baseline_fixture.public_bundle,
            escrow_bundle=baseline_fixture.escrow_bundle,
            leakage_policy=baseline_fixture.policy,
            protocol_allowed_signers=baseline_fixture.allowed_signers,
            protocol_signer_identity="baseline-builder@example.test",
            machine_workflow_evidence=_machine_workflow_evidence(baseline_fixture),
            signer_identity=IDENTITY,
        )


def test_real_ed25519_signature_authorizes_exact_statement(
    signed_baseline_statement: SignedBaselineStatement,
) -> None:
    """A trusted real OpenSSH signature yields an exact typed authorization."""
    signed = signed_baseline_statement
    authorization = authorize_baseline_verification_statement(
        signed.path,
        signed.signature,
        signed.allowed_signers,
        IDENTITY,
    )

    assert authorization.statement == signed.statement
    assert authorization.identity == IDENTITY
    assert authorization.namespace == BASELINE_VERIFICATION_SIGNATURE_NAMESPACE
    assert authorization.statement_sha256 == hashlib.sha256(signed.path.read_bytes()).hexdigest()
    assert (
        authorization.canonical_statement_sha256
        == hashlib.sha256(
            json.dumps(
                signed.statement.model_dump(mode="json"),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
    )
    assert authorization.signing_key_fingerprint.startswith("SHA256:")


def test_signature_rejects_wrong_identity_key_namespace_and_tampering(
    tmp_path: Path,
    signed_baseline_statement: SignedBaselineStatement,
) -> None:
    """Identity, trust, domain separation, and exact bytes all fail closed."""
    signed = signed_baseline_statement
    _, wrong_allowed_signers = _new_signing_identity(
        tmp_path,
        label="wrong-baseline-verifier",
        identity=IDENTITY,
    )

    with pytest.raises(ProtocolSignatureError, match="verification failed"):
        authorize_baseline_verification_statement(
            signed.path,
            signed.signature,
            signed.allowed_signers,
            "wrong-identity@example.test",
        )
    with pytest.raises(ProtocolSignatureError, match="verification failed"):
        authorize_baseline_verification_statement(
            signed.path,
            signed.signature,
            wrong_allowed_signers,
            IDENTITY,
        )

    wrong_namespace_path = tmp_path / "wrong-namespace.json"
    wrong_namespace_path.write_bytes(signed.path.read_bytes())
    wrong_namespace_signature = sign_protocol(
        wrong_namespace_path,
        signed.private_key,
    )
    with pytest.raises(ProtocolSignatureError, match="verification failed"):
        authorize_baseline_verification_statement(
            wrong_namespace_path,
            wrong_namespace_signature,
            signed.allowed_signers,
            IDENTITY,
        )

    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_bytes(
        signed.path.read_bytes().replace(
            signed.statement.baseline_record_sha256.encode(),
            ("f" * 64).encode(),
        )
    )
    with pytest.raises(ProtocolSignatureError, match="verification failed"):
        authorize_baseline_verification_statement(
            tampered_path,
            signed.signature,
            signed.allowed_signers,
            IDENTITY,
        )


def test_release_gate_rejects_missing_or_altered_baseline_authorization(
    baseline_fixture: BaselineFixture,
    signed_baseline_statement: SignedBaselineStatement,
) -> None:
    """Only the exact signed artifact-derived statement clears the baseline gate."""
    authorization = authorize_baseline_verification_statement(
        signed_baseline_statement.path,
        signed_baseline_statement.signature,
        signed_baseline_statement.allowed_signers,
        IDENTITY,
    )
    submission = _submission(baseline_fixture)

    missing = evaluate_benchmark_release(submission)
    assert _baseline_verification_codes(missing) == {
        PublicationIssueCode.BASELINE_VERIFICATION_INVALID
    }

    accepted = evaluate_benchmark_release(
        submission,
        baseline_authorizations=(authorization,),
    )
    assert not _baseline_verification_codes(accepted)

    altered = replace(
        authorization,
        statement=authorization.statement.model_copy(update={"baseline_record_sha256": "f" * 64}),
    )
    rejected = evaluate_benchmark_release(
        submission,
        baseline_authorizations=(altered,),
    )
    assert _baseline_verification_codes(rejected) == {
        PublicationIssueCode.BASELINE_VERIFICATION_INVALID
    }
    assert not rejected.configuration_results[0].eligible


def test_statement_writer_is_atomic_and_never_overwrites(
    tmp_path: Path,
    signed_baseline_statement: SignedBaselineStatement,
) -> None:
    """The canonical statement writer preserves the first publication exactly."""
    output_directory = tmp_path / "published"
    output_directory.mkdir()
    destination = output_directory / "baseline-verification.json"
    write_baseline_verification_statement(
        destination,
        signed_baseline_statement.statement,
    )
    original = destination.read_bytes()

    with pytest.raises(BaselineRecordError, match="output path already exists"):
        write_baseline_verification_statement(
            destination,
            signed_baseline_statement.statement.model_copy(
                update={"baseline_record_sha256": "f" * 64}
            ),
        )

    assert destination.read_bytes() == original
    assert original.endswith(b"\n")


def _statement(fixture: BaselineFixture) -> BaselineVerificationStatement:
    """Construct the exact typed statement expected from a verified record."""
    protocol = compiled_benchmark_protocol()
    return BaselineVerificationStatement(
        benchmark_protocol_version=protocol.benchmark_protocol_version,
        rubric_version=protocol.rubric_version,
        configuration_id=fixture.record.configuration_id,
        corpus_hash=fixture.corpus.corpus_hash,
        baseline_record_sha256=baseline_configuration_record_sha256(fixture.record),
        signer_identity=IDENTITY,
    )


def _machine_workflow_evidence(
    fixture: BaselineFixture,
) -> MachineWorkflowEvidencePaths:
    """Return typed placeholder paths for the monkeypatched artifact builder."""
    return MachineWorkflowEvidencePaths(
        identity_artifact=fixture.machine_identity,
        attestation=fixture.machine_identity,
        signature=fixture.machine_identity,
        allowed_signers=fixture.allowed_signers,
        signer_identity="machine-workflow@example.test",
    )


def _build_statement(fixture: BaselineFixture) -> BaselineVerificationStatement:
    """Invoke the production statement builder with every exact artifact input."""
    return build_baseline_verification_statement(
        fixture.record.configuration_id,
        expected_record=fixture.record,
        corpus=fixture.corpus,
        public_bundle=fixture.public_bundle,
        escrow_bundle=fixture.escrow_bundle,
        leakage_policy=fixture.policy,
        protocol_allowed_signers=fixture.allowed_signers,
        protocol_signer_identity="baseline-builder@example.test",
        machine_workflow_evidence=_machine_workflow_evidence(fixture),
        signer_identity=IDENTITY,
    )


def _new_signing_identity(
    root: Path,
    *,
    label: str,
    identity: str,
) -> tuple[Path, Path]:
    """Create an ephemeral Ed25519 key and one-principal trust policy."""
    private_key = root / f"{label}.key"
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
    if generated.returncode != 0:
        pytest.fail(f"could not generate test signing key: {generated.stderr}")
    public_key = Path(f"{private_key}.pub").read_text(encoding="utf-8").strip()
    allowed_signers = root / f"{label}.allowed_signers"
    allowed_signers.write_text(f"{identity} {public_key}\n", encoding="utf-8")
    return private_key, allowed_signers


def _submission(fixture: BaselineFixture) -> BenchmarkReleaseSubmission:
    """Build a truthful HOLD submission containing the one baseline under test."""
    return BenchmarkReleaseSubmission(
        protocol=compiled_benchmark_protocol(),
        corpus=fixture.corpus,
        baselines=(fixture.record,),
        pilot=PilotEvidenceRecord(),
        conformance_environments=(),
        cross_machine_reproduction=None,
        release_evidence=ReleaseEvidenceRecord(),
        human_approval=None,
    )


def _baseline_verification_codes(
    report: BenchmarkGateReport,
) -> set[PublicationIssueCode]:
    """Return baseline-verification issue codes from the first configuration."""
    configuration_results = report.configuration_results
    assert len(configuration_results) == 1
    return {
        issue.code
        for issue in configuration_results[0].issues
        if issue.code is PublicationIssueCode.BASELINE_VERIFICATION_INVALID
    }
