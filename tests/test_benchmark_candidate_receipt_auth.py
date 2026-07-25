"""Detached authorization and release-gate binding for candidate receipts."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from stinger import BENCHMARK_PROTOCOL_VERSION, RUBRIC_VERSION
from stinger.benchmark.gates import (
    BenchmarkReleaseSubmission,
    CandidateValidationReceipt,
    CorpusScenarioRecord,
    PilotEvidenceRecord,
    PublicationIssueCode,
    ReleaseEvidenceRecord,
    RepositorySize,
    SealedCorpusRecord,
    authorize_candidate_validation_receipt,
    candidate_scenario_identity_inventory_sha256,
    candidate_validation_inventory_sha256,
    compiled_benchmark_protocol,
    evaluate_benchmark_release,
)
from stinger.benchmark.protocol import BenchmarkSplit
from stinger.benchmark.signing import (
    CANDIDATE_VALIDATION_SIGNATURE_NAMESPACE,
    ProtocolSignatureError,
    sign_candidate_validation_receipt,
    sign_protocol,
)
from stinger.benchmark.verification_image import (
    APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
    canonical_verification_image_policy_sha256,
    compiled_verification_image_policy,
)
from stinger.models import Family, Outcome

IDENTITY = "candidate-validator@example.test"


def _digest(*parts: object) -> str:
    """Return a deterministic sha256 digest for synthetic evidence."""
    encoded = "\0".join(str(part) for part in parts).encode()
    return hashlib.sha256(encoded).hexdigest()


def _new_signing_identity(
    root: Path,
    *,
    label: str,
    identity: str = IDENTITY,
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


def _synthetic_scenarios() -> tuple[CorpusScenarioRecord, ...]:
    """Build the exact 120-scenario identity and validation inventory."""
    scenarios: list[CorpusScenarioRecord] = []
    for family in Family:
        for index in range(24):
            if index < 8:
                repository_size = RepositorySize.SMALL
            elif index < 16:
                repository_size = RepositorySize.MEDIUM
            else:
                repository_size = RepositorySize.LARGER_MULTI_MODULE
            scenario_id = f"{family.value}-candidate-{index + 1:02d}"
            scenarios.append(
                CorpusScenarioRecord(
                    scenario_id=scenario_id,
                    family=family,
                    repository_size=repository_size,
                    benchmark_split=BenchmarkSplit.SEALED,
                    scenario_version="1.0.0",
                    cluster_id=f"{family.value.lower()}.cluster-{index + 1:02d}",
                    expected_honest_outcome=Outcome.HONEST,
                    scenario_artifact_sha256=_digest(scenario_id, "scenario"),
                    machine_validation_receipt_sha256=_digest(scenario_id, "validation"),
                    provenance_receipt_sha256=_digest(scenario_id, "provenance"),
                    containment_receipt_sha256=_digest(scenario_id, "containment"),
                    dummy_safety_receipt_sha256=_digest(scenario_id, "dummy-safety"),
                )
            )
    return tuple(scenarios)


def _candidate_receipt(
    scenarios: tuple[CorpusScenarioRecord, ...],
) -> CandidateValidationReceipt:
    """Construct a path-free receipt exactly bound to the synthetic corpus inventory."""
    return CandidateValidationReceipt(
        format_version="1",
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        rubric_version=RUBRIC_VERSION,
        corpus_version="1.0.0",
        signer_identity=IDENTITY,
        stinger_commit="a" * 40,
        validation_contract="stinger-scenario-validity-v1-docker",
        verification_image_id=APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
        verification_image_policy_sha256=(
            canonical_verification_image_policy_sha256(compiled_verification_image_policy())
        ),
        docker_client_sha256=_digest("docker-client"),
        docker_runtime_fingerprint_sha256=_digest("docker-runtime"),
        repository_size_source="signed-private-metadata-v1",
        candidate_corpus_hash=_digest("candidate-corpus"),
        source_snapshot_sha256=_digest("source-snapshot"),
        private_metadata_sha256=_digest("private-metadata"),
        scenario_identity_inventory_sha256=(
            candidate_scenario_identity_inventory_sha256(scenarios)
        ),
        validation_inventory_sha256=candidate_validation_inventory_sha256(scenarios),
        canary_inventory_sha256=_digest("canary-inventory"),
        access_log_root_sha256=_digest("access-log-root"),
        custody_ledger_mode="cooperative-hash-chain",
        scenario_count=120,
        scenarios_by_family={family: 24 for family in Family},
        scenarios_by_family_and_size={
            family: {repository_size: 8 for repository_size in RepositorySize} for family in Family
        },
        unique_cluster_count=120,
        machine_validation_count=120,
        canary_count=120,
        access_log_event_count=3,
    )


def _write_receipt(path: Path, receipt: CandidateValidationReceipt) -> None:
    """Write stable JSON bytes suitable for detached signing."""
    path.write_text(receipt.model_dump_json(indent=2) + "\n", encoding="utf-8")


def _submission(corpus: SealedCorpusRecord) -> BenchmarkReleaseSubmission:
    """Build a truthful HOLD submission around one synthetic corpus."""
    return BenchmarkReleaseSubmission(
        protocol=compiled_benchmark_protocol(),
        corpus=corpus,
        baselines=(),
        pilot=PilotEvidenceRecord(),
        conformance_environments=(),
        cross_machine_reproduction=None,
        release_evidence=ReleaseEvidenceRecord(),
        human_approval=None,
    )


def test_candidate_receipt_authorizes_exact_signed_bytes(tmp_path: Path) -> None:
    """An exact receipt signed by the trusted identity yields typed authorization."""
    scenarios = _synthetic_scenarios()
    receipt = _candidate_receipt(scenarios)
    receipt_path = tmp_path / "candidate-receipt.json"
    _write_receipt(receipt_path, receipt)
    private_key, allowed_signers = _new_signing_identity(tmp_path, label="candidate")

    signature = sign_candidate_validation_receipt(receipt_path, private_key)
    authorization = authorize_candidate_validation_receipt(
        receipt_path,
        signature,
        allowed_signers,
        IDENTITY,
    )

    assert authorization.receipt == receipt
    assert authorization.identity == IDENTITY
    assert authorization.namespace == CANDIDATE_VALIDATION_SIGNATURE_NAMESPACE
    assert authorization.receipt_sha256 == hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    assert len(authorization.canonical_receipt_sha256) == 64
    assert len(authorization.signature_sha256) == 64
    assert len(authorization.allowed_signers_sha256) == 64
    assert authorization.signing_key_fingerprint.startswith("SHA256:")


def test_candidate_receipt_rejects_wrong_identity_key_namespace_and_tamper(
    tmp_path: Path,
) -> None:
    """Identity, trust key, signature domain, and exact bytes all fail closed."""
    scenarios = _synthetic_scenarios()
    receipt = _candidate_receipt(scenarios)
    receipt_path = tmp_path / "candidate-receipt.json"
    original_bytes = receipt.model_dump_json(indent=2).encode() + b"\n"
    receipt_path.write_bytes(original_bytes)
    private_key, allowed_signers = _new_signing_identity(tmp_path, label="candidate")
    _, wrong_allowed_signers = _new_signing_identity(tmp_path, label="wrong-key")
    signature = sign_candidate_validation_receipt(receipt_path, private_key)

    with pytest.raises(ProtocolSignatureError, match="verification failed"):
        authorize_candidate_validation_receipt(
            receipt_path,
            signature,
            allowed_signers,
            "wrong-identity@example.test",
        )
    with pytest.raises(ProtocolSignatureError, match="verification failed"):
        authorize_candidate_validation_receipt(
            receipt_path,
            signature,
            wrong_allowed_signers,
            IDENTITY,
        )

    wrong_namespace_path = tmp_path / "wrong-namespace.json"
    wrong_namespace_path.write_bytes(original_bytes)
    wrong_namespace_signature = sign_protocol(wrong_namespace_path, private_key)
    with pytest.raises(ProtocolSignatureError, match="verification failed"):
        authorize_candidate_validation_receipt(
            wrong_namespace_path,
            wrong_namespace_signature,
            allowed_signers,
            IDENTITY,
        )

    receipt_path.write_bytes(
        original_bytes.replace(b'"scenario_count": 120', b'"scenario_count": 119')
    )
    with pytest.raises(ProtocolSignatureError, match="verification failed"):
        authorize_candidate_validation_receipt(
            receipt_path,
            signature,
            allowed_signers,
            IDENTITY,
        )


def test_release_gate_requires_candidate_authorization_bound_to_sealed_inventory(
    tmp_path: Path,
) -> None:
    """Candidate identity is receipt-bound; sealed validation continuity belongs to promotion."""
    scenarios = _synthetic_scenarios()
    receipt = _candidate_receipt(scenarios)
    receipt_path = tmp_path / "candidate-receipt.json"
    _write_receipt(receipt_path, receipt)
    private_key, allowed_signers = _new_signing_identity(tmp_path, label="candidate")
    signature = sign_candidate_validation_receipt(receipt_path, private_key)
    authorization = authorize_candidate_validation_receipt(
        receipt_path,
        signature,
        allowed_signers,
        IDENTITY,
    )
    corpus = SealedCorpusRecord(
        corpus_version="1.0.0",
        corpus_hash=_digest("sealed-corpus"),
        scenarios=scenarios,
        candidate_validation_receipt_sha256=authorization.receipt_sha256,
        custody_inventory_sha256=_digest("sealed-custody"),
        access_log_root_sha256=_digest("sealed-access-log"),
        canary_validation_receipt_sha256=receipt.canary_inventory_sha256,
    )

    accepted = evaluate_benchmark_release(
        _submission(corpus),
        candidate_validation_authorization=authorization,
    )
    accepted_codes = {issue.code for issue in accepted.issues}
    assert PublicationIssueCode.CORPUS_CANDIDATE_VALIDATION_RECEIPT_INVALID not in accepted_codes
    assert not accepted.publishable

    missing = evaluate_benchmark_release(_submission(corpus))
    assert PublicationIssueCode.CORPUS_CANDIDATE_VALIDATION_RECEIPT_INVALID in {
        issue.code for issue in missing.issues
    }

    changed_scenarios = list(scenarios)
    changed_scenarios[0] = changed_scenarios[0].model_copy(
        update={"machine_validation_receipt_sha256": _digest("different-validation")}
    )
    mismatched_corpus = corpus.model_copy(update={"scenarios": tuple(changed_scenarios)})
    mismatched = evaluate_benchmark_release(
        _submission(mismatched_corpus),
        candidate_validation_authorization=authorization,
    )
    mismatched_codes = {issue.code for issue in mismatched.issues}
    assert PublicationIssueCode.CORPUS_CANDIDATE_VALIDATION_RECEIPT_INVALID not in mismatched_codes
    assert PublicationIssueCode.CORPUS_CANDIDATE_PROMOTION_INVALID in mismatched_codes
