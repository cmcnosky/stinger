"""Public-only verification of signed cross-machine reproduction evidence."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from stinger import BENCHMARK_PROTOCOL_VERSION
from stinger.benchmark.comparison import build_paired_comparison
from stinger.benchmark.credential_broker import CredentialBrokerConfiguration
from stinger.benchmark.evidence import (
    BUNDLE_FORMAT_VERSION,
    BUNDLE_MANIFEST,
    BundleKind,
    EvidenceBundleManifest,
    EvidenceRole,
    InventoryFile,
    PublicLeakagePolicy,
    create_public_evidence_bundle,
)
from stinger.benchmark.gates import (
    BaselineConfigurationRecord,
    CrossMachineReproductionStatement,
    VerifiedCrossMachineReproductionAuthorization,
    authorize_reproduction_statement,
    canonical_report_sha256,
    reproduction_discrepancy_ledger_sha256,
    reproduction_modal_outcomes_sha256,
)
from stinger.benchmark.protocol import (
    BenchmarkRuntimeProvenance,
    BenchmarkSplit,
    CredentialIsolationRuntimeProvenance,
    ProviderId,
)
from stinger.benchmark.reproduction import (
    CLASSIFICATION_FIELDS,
    EXCLUDED_RUN_FIELDS,
    ReproductionComparisonManifest,
    build_reproduction_diff,
)
from stinger.benchmark.reproduction_verification import (
    PublicReproductionVerificationError,
    VerifiedPublicReproductionReceipt,
    authorize_public_reproduction_verification_statement,
    build_public_reproduction_verification_statement,
    verify_public_reproduction,
    write_public_reproduction_verification_statement,
)
from stinger.benchmark.signing import (
    PROTOCOL_SIGNATURE_NAMESPACE,
    sign_protocol,
    sign_public_reproduction_verification_statement,
    sign_reproduced_report,
    sign_reproduction_statement,
    verify_reproduced_report_signature,
)
from stinger.benchmark.verification_image import (
    APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
    canonical_verification_image_policy_sha256,
    compiled_verification_image_policy,
)
from stinger.config import AgentConfig, RunConfig
from stinger.docker_runtime import DOCKER_RUNTIME_CLAIM_BOUNDARY
from stinger.harness.sandbox import Isolation
from stinger.models import DetectorResult, Family, Outcome, Report, ScenarioResult
from stinger.report.generate import build_report, render_json

_AGENT_DIGEST = f"sha256:{'a' * 64}"
_VERIFICATION_DIGEST = APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID
_STINGER_COMMIT = "c" * 40
_EVALUATOR_IDENTITY = "independent-evaluator@example.test"
_CONFIGURATION_ID = "synthetic-openai-1"
_PROTOCOL_SIGNER_IDENTITY = "protocol-operator@example.test"
ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class PublicReproductionArtifacts:
    """One complete synthetic public reproduction proof."""

    authorization: VerifiedCrossMachineReproductionAuthorization
    evaluator_private_key: Path
    baseline: BaselineConfigurationRecord
    target_report: Path
    target_public_bundle: Path
    public_bundle: Path
    public_manifest: Path
    reproduced_report: Path
    report_signature: Path
    allowed_signers: Path
    protocol_allowed_signers: Path
    leakage_policy: PublicLeakagePolicy
    comparison_manifest: Path
    discrepancy_ledger: Path
    wrong_report_signature: Path


def _sha256(content: bytes) -> str:
    """Return the exact lowercase SHA-256 digest."""
    return hashlib.sha256(content).hexdigest()


def _canonical_payload_bytes(payload: object) -> bytes:
    """Serialize the builder's canonical JSON payload."""
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonical_model_bytes(model: object) -> bytes:
    """Serialize one Pydantic model exactly as reproduction builders do."""
    assert hasattr(model, "model_dump")
    return _canonical_payload_bytes(model.model_dump(mode="json")) + b"\n"


def _new_signing_identity(
    root: Path,
    *,
    label: str,
    identity: str,
) -> tuple[Path, Path]:
    """Create one ephemeral Ed25519 key and explicit one-principal trust policy."""
    private_key = root / label
    generated = subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)],
        capture_output=True,
        check=False,
        text=True,
    )
    if generated.returncode != 0:
        pytest.fail(f"could not generate test signing key: {generated.stderr}")
    public_key = private_key.with_suffix(".pub").read_text(encoding="utf-8").strip()
    allowed_signers = root / f"{label}.allowed_signers"
    allowed_signers.write_text(f"{identity} {public_key}\n", encoding="utf-8")
    return private_key, allowed_signers


def _run_config(root: Path) -> RunConfig:
    """Create one publication-pinned synthetic configuration."""
    return RunConfig(
        agent=AgentConfig(
            adapter="codex",
            model="synthetic-model",
            provider=ProviderId.OPENAI,
            cli_version="1.0.0",
            reasoning_effort="high",
            inference_settings={"temperature": 0.0},
            api_key_env="OPENAI_API_KEY",
            container_image="synthetic-agent:1",
            container_image_digest=_AGENT_DIGEST,
            credential_broker=CredentialBrokerConfiguration(
                image="synthetic-runner:1",
                image_digest=_VERIFICATION_DIGEST,
            ),
        ),
        corpus=root / "sealed-corpus",
        output_dir=root / "output",
        reps=5,
        isolation=Isolation.DOCKER,
        image="synthetic-runner:1",
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        stinger_commit=_STINGER_COMMIT,
        verification_image_digest=_VERIFICATION_DIGEST,
        run_seed=17,
    )


def _runtime(config: RunConfig) -> BenchmarkRuntimeProvenance:
    """Mirror every publication pin with mechanically observed synthetic provenance."""
    metadata = config.benchmark_metadata()
    assert metadata is not None
    credential_identities = config._credential_isolation_identities()
    assert credential_identities is not None
    (
        credential_policy_sha256,
        broker_configuration_sha256,
        allowed_destination_inventory_sha256,
        agent_projection_inventory_sha256,
        broker_source_inventory_sha256,
    ) = credential_identities
    assert metadata.credential_broker_image_digest is not None
    return BenchmarkRuntimeProvenance(
        requested_provider=metadata.provider,
        requested_model_id=metadata.model_id,
        stinger_commit=metadata.stinger_commit,
        agent_cli_version=metadata.agent_cli_version,
        agent_container_image_id=metadata.agent_container_digest,
        verification_image_id=metadata.verification_image_digest,
        verification_image_policy_sha256=(
            canonical_verification_image_policy_sha256(compiled_verification_image_policy())
        ),
        resolved_agent_invocation=("codex", "--model", "synthetic-model"),
        resolved_version_invocation=("codex", "--version"),
        reasoning_effort=metadata.reasoning_effort,
        inference_settings=metadata.inference_settings,
        docker_client_sha256="d" * 64,
        docker_runtime_fingerprint_sha256="e" * 64,
        docker_runtime_claim_boundary=DOCKER_RUNTIME_CLAIM_BOUNDARY,
        resolved_environment_names=("OPENAI_API_KEY",),
        credential_isolation=CredentialIsolationRuntimeProvenance(
            policy_sha256=credential_policy_sha256,
            broker_configuration_sha256=broker_configuration_sha256,
            allowed_destination_inventory_sha256=allowed_destination_inventory_sha256,
            agent_projection_inventory_sha256=agent_projection_inventory_sha256,
            broker_source_inventory_sha256=broker_source_inventory_sha256,
            broker_image_id=metadata.credential_broker_image_digest,
            docker_runtime_fingerprint_sha256="e" * 64,
            verified=True,
        ),
        verified=True,
    )


def _publication_report(
    config: RunConfig,
    *,
    generated_at: str,
    reproduced: bool,
) -> Report:
    """Build five-family, five-repetition reports differing only in run-specific fields."""
    results = [
        ScenarioResult(
            scenario_id=f"{family.value}-PUBLIC-01",
            family=family,
            outcome=(
                Outcome.CHEATED
                if reproduced and family is Family.T and repetition == 0
                else Outcome.HONEST
            ),
            detector_results=(
                [
                    DetectorResult(
                        detector="synthetic-reproduction-check",
                        fired=True,
                        evidence="synthetic classification evidence",
                    )
                ]
                if reproduced and family is Family.T and repetition == 0
                else []
            ),
            goal_met=True,
            agent_claimed_done=True,
            transcript_path=(
                f"{'reproduced' if reproduced else 'target'}/"
                f"{family.value}/{repetition}/transcript.txt"
            ),
            diff_path=(
                f"{'reproduced' if reproduced else 'target'}/{family.value}/{repetition}/after.diff"
            ),
            duration_s=1.25 if reproduced else 1.0,
            repetition=repetition,
            benchmark_split=BenchmarkSplit.SEALED,
            scenario_version="1.0.0",
            cluster_id=f"{family.value.lower()}.public-cluster-01",
        )
        for family in Family
        for repetition in range(5)
    ]
    metadata = config.benchmark_metadata()
    assert metadata is not None
    return build_report(
        results,
        corpus_hash="d" * 64,
        config_fingerprint=config.fingerprint(),
        generated_at=generated_at,
        benchmark_metadata=metadata,
        benchmark_runtime_provenance=_runtime(config),
        bootstrap_samples=10_000,
    )


def _public_manifest(report_bytes: bytes) -> EvidenceBundleManifest:
    """Create a canonical public inventory binding the exact reproduced report bytes."""
    payloads = {
        "protocol/protocol.yaml": (EvidenceRole.PROTOCOL, b"protocol-v2\n"),
        "signature/protocol.yaml.sig": (
            EvidenceRole.PROTOCOL_SIGNATURE,
            b"synthetic-protocol-signature\n",
        ),
        "trust/allowed_signers": (
            EvidenceRole.SIGNER_POLICY,
            b"synthetic-protocol-trust\n",
        ),
        "config/config.resolved.json": (
            EvidenceRole.CONFIG,
            b'{"synthetic":"config"}\n',
        ),
        "report/report.json": (EvidenceRole.REPORT, report_bytes),
    }
    files = {
        path: InventoryFile(
            role=role,
            sha256=_sha256(content),
            size=len(content),
            executable=False,
        )
        for path, (role, content) in payloads.items()
    }
    directories = {
        "config": EvidenceRole.CONFIG,
        "protocol": EvidenceRole.PROTOCOL,
        "report": EvidenceRole.REPORT,
        "signature": EvidenceRole.PROTOCOL_SIGNATURE,
        "trust": EvidenceRole.SIGNER_POLICY,
    }
    inventory = {
        "files": {path: entry.model_dump(mode="json") for path, entry in sorted(files.items())},
        "directories": {path: role.value for path, role in sorted(directories.items())},
    }
    return EvidenceBundleManifest(
        format_version=BUNDLE_FORMAT_VERSION,
        bundle_kind=BundleKind.PUBLIC,
        protocol_sha256=files["protocol/protocol.yaml"].sha256,
        protocol_signature_sha256=files["signature/protocol.yaml.sig"].sha256,
        allowed_signers_sha256=files["trust/allowed_signers"].sha256,
        protocol_signer_identity="protocol-operator@example.test",
        protocol_signature_namespace=PROTOCOL_SIGNATURE_NAMESPACE,
        config_sha256=files["config/config.resolved.json"].sha256,
        report_sha256=files["report/report.json"].sha256,
        inventory_sha256=_sha256(_canonical_payload_bytes(inventory)),
        leakage_policy_sha256="e" * 64,
        access_control_notice=None,
        files=files,
        directories=directories,
    )


@pytest.fixture(scope="module")
def public_reproduction_artifacts(
    tmp_path_factory: pytest.TempPathFactory,
) -> PublicReproductionArtifacts:
    """Build one complete public proof and reuse its 10,000-draw comparison."""
    root = tmp_path_factory.mktemp("public-reproduction")
    config = _run_config(root)
    target = _publication_report(
        config,
        generated_at="2026-07-24T00:00:00+00:00",
        reproduced=False,
    )
    reproduced = _publication_report(
        config,
        generated_at="2026-07-25T00:00:00+00:00",
        reproduced=True,
    )
    target_path = root / "target-report.json"
    reproduced_path = root / "reproduced-report.json"
    target_bytes = render_json(target).encode("utf-8")
    reproduced_bytes = render_json(reproduced).encode("utf-8")
    target_path.write_bytes(target_bytes)
    reproduced_path.write_bytes(reproduced_bytes)

    evaluator_key, evaluator_allowed_signers = _new_signing_identity(
        root,
        label="evaluator-key",
        identity=_EVALUATOR_IDENTITY,
    )
    report_signature = sign_reproduced_report(reproduced_path, evaluator_key)
    report_verification = verify_reproduced_report_signature(
        reproduced_path,
        report_signature,
        evaluator_allowed_signers,
        _EVALUATOR_IDENTITY,
    )

    protocol = root / "protocol.yaml"
    protocol.write_bytes((ROOT / "benchmark" / "protocol.yaml").read_bytes())
    protocol_key, protocol_allowed_signers = _new_signing_identity(
        root,
        label="protocol-key",
        identity=_PROTOCOL_SIGNER_IDENTITY,
    )
    protocol_signature = sign_protocol(protocol, protocol_key)
    config_path = root / "config.resolved.json"
    config_path.write_text(config.resolved_json(), encoding="utf-8")
    forbidden_source = root / "active-sealed-material"
    forbidden_source.mkdir()
    forbidden_marker = b"STINGER-SYNTHETIC-PRIVATE-CANARY"
    (forbidden_source / "sealed-item.bin").write_bytes(forbidden_marker)
    leakage_policy = PublicLeakagePolicy(
        forbidden_sources=(forbidden_source,),
        forbidden_markers=(forbidden_marker,),
    )
    target_public_bundle = root / "target-public-bundle"
    create_public_evidence_bundle(
        target_public_bundle,
        protocol=protocol,
        protocol_signature=protocol_signature,
        allowed_signers=protocol_allowed_signers,
        signer_identity=_PROTOCOL_SIGNER_IDENTITY,
        config=config_path,
        report=target_path,
        permitted_logs={},
        leakage_policy=leakage_policy,
    )
    target_manifest_bytes = (target_public_bundle / BUNDLE_MANIFEST).read_bytes()
    public_bundle = root / "reproduced-public-bundle"
    create_public_evidence_bundle(
        public_bundle,
        protocol=protocol,
        protocol_signature=protocol_signature,
        allowed_signers=protocol_allowed_signers,
        signer_identity=_PROTOCOL_SIGNER_IDENTITY,
        config=config_path,
        report=reproduced_path,
        permitted_logs={},
        leakage_policy=leakage_policy,
    )
    manifest_path = public_bundle / BUNDLE_MANIFEST
    manifest_bytes = manifest_path.read_bytes()

    target_public_manifest_hash = _sha256(target_manifest_bytes)
    target_escrow_manifest_hash = "2" * 64
    reproduced_escrow_manifest_hash = "3" * 64
    target_machine_hash = "4" * 64
    reproduced_machine_hash = "5" * 64
    baseline = BaselineConfigurationRecord(
        configuration_id=_CONFIGURATION_ID,
        report=target,
        report_sha256=canonical_report_sha256(target),
        public_bundle_manifest_sha256=target_public_manifest_hash,
        escrow_bundle_manifest_sha256=target_escrow_manifest_hash,
        machine_fingerprint_sha256=target_machine_hash,
        contained=True,
        deterministically_blocked_order=True,
        evidence_integrity_passed=True,
        public_bundle_verified=True,
        escrow_bundle_verified=True,
    )

    diff = build_reproduction_diff(target, reproduced)
    ordered_discrepancies = tuple(
        sorted(
            diff.discrepancies,
            key=lambda item: (
                item.scenario_id,
                item.repetition,
                item.field,
                item.discrepancy_id,
            ),
        )
    )
    ledger_payload = {
        "target_report_sha256": diff.target_report_sha256,
        "reproduced_report_sha256": diff.reproduced_report_sha256,
        "discrepancies": [item.model_dump(mode="json") for item in ordered_discrepancies],
    }
    ledger_bytes = _canonical_payload_bytes(ledger_payload)
    ledger_path = root / "discrepancy-ledger.json"
    ledger_path.write_bytes(ledger_bytes)
    ledger_hash = reproduction_discrepancy_ledger_sha256(
        diff.discrepancies,
        target_report_sha256=diff.target_report_sha256,
        reproduced_report_sha256=diff.reproduced_report_sha256,
    )
    assert ledger_hash == _sha256(ledger_bytes)

    paired = build_paired_comparison(
        reproduced,
        target,
        samples=10_000,
        seed=0,
        confidence_level=0.95,
    )
    metadata = target.benchmark_metadata
    assert metadata is not None
    assert metadata.agent_configuration_fingerprint is not None
    comparison = ReproductionComparisonManifest(
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        rubric_version=target.rubric_version,
        corpus_hash=target.corpus_hash,
        configuration_id=_CONFIGURATION_ID,
        config_fingerprint=target.config_fingerprint,
        agent_configuration_fingerprint=metadata.agent_configuration_fingerprint,
        target_report_sha256=diff.target_report_sha256,
        reproduced_report_sha256=diff.reproduced_report_sha256,
        target_modal_outcomes_sha256=diff.target_modal_outcomes_sha256,
        reproduced_modal_outcomes_sha256=diff.reproduced_modal_outcomes_sha256,
        target_report_bytes_sha256=_sha256(target_bytes),
        reproduced_report_bytes_sha256=_sha256(reproduced_bytes),
        target_public_bundle_manifest_sha256=target_public_manifest_hash,
        target_escrow_bundle_manifest_sha256=target_escrow_manifest_hash,
        reproduced_public_bundle_manifest_sha256=_sha256(manifest_bytes),
        reproduced_escrow_bundle_manifest_sha256=reproduced_escrow_manifest_hash,
        reproduced_report_signature_sha256=report_verification.signature_sha256,
        reproduced_report_signature_namespace=report_verification.namespace,
        reproduced_report_signer_identity=report_verification.identity,
        reproduced_report_signing_key_fingerprint=(report_verification.signing_key_fingerprint),
        reproduced_report_allowed_signers_sha256=(report_verification.allowed_signers_sha256),
        classification_fields=CLASSIFICATION_FIELDS,
        excluded_run_fields=EXCLUDED_RUN_FIELDS,
        discrepancy_ledger_sha256=ledger_hash,
        discrepancy_count=len(diff.discrepancies),
        paired_comparison=paired,
    )
    comparison_path = root / "comparison.manifest.json"
    comparison_bytes = _canonical_model_bytes(comparison)
    comparison_path.write_bytes(comparison_bytes)

    statement = CrossMachineReproductionStatement(
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        evaluator_id="synthetic-independent-evaluator",
        signer_identity=_EVALUATOR_IDENTITY,
        configuration_id=_CONFIGURATION_ID,
        corpus_hash=target.corpus_hash,
        target_report_sha256=canonical_report_sha256(target),
        target_config_fingerprint=target.config_fingerprint,
        target_agent_configuration_fingerprint=(metadata.agent_configuration_fingerprint),
        target_public_bundle_manifest_sha256=target_public_manifest_hash,
        target_escrow_bundle_manifest_sha256=target_escrow_manifest_hash,
        target_machine_fingerprint_sha256=target_machine_hash,
        reproduced_report_sha256=canonical_report_sha256(reproduced),
        reproduced_report_signature_sha256=report_verification.signature_sha256,
        reproduced_report_signature_namespace=report_verification.namespace,
        reproduced_report_signer_identity=report_verification.identity,
        reproduced_report_signing_key_fingerprint=(report_verification.signing_key_fingerprint),
        reproduced_report_allowed_signers_sha256=(report_verification.allowed_signers_sha256),
        reproduced_public_bundle_manifest_sha256=_sha256(manifest_bytes),
        reproduced_escrow_bundle_manifest_sha256=reproduced_escrow_manifest_hash,
        reproduced_machine_fingerprint_sha256=reproduced_machine_hash,
        reproduced_config_fingerprint=reproduced.config_fingerprint,
        reproduced_agent_configuration_fingerprint=(metadata.agent_configuration_fingerprint),
        comparison_manifest_sha256=_sha256(comparison_bytes),
        discrepancy_ledger_sha256=ledger_hash,
        target_modal_outcomes_sha256=reproduction_modal_outcomes_sha256(target),
        reproduced_modal_outcomes_sha256=reproduction_modal_outcomes_sha256(reproduced),
        completed_families=tuple(Family),
        scenario_count=len(Family),
        repetitions=5,
        discrepancies=diff.discrepancies,
    )
    statement_path = root / "reproduction-statement.json"
    statement_path.write_bytes(_canonical_model_bytes(statement))
    statement_signature = sign_reproduction_statement(statement_path, evaluator_key)
    authorization = authorize_reproduction_statement(
        statement_path,
        statement_signature,
        evaluator_allowed_signers,
        _EVALUATOR_IDENTITY,
    )

    attacker_root = root / "attacker"
    attacker_root.mkdir()
    attacker_report = attacker_root / "report.json"
    shutil.copyfile(reproduced_path, attacker_report)
    attacker_key, _ = _new_signing_identity(
        attacker_root,
        label="attacker-key",
        identity=_EVALUATOR_IDENTITY,
    )
    wrong_report_signature = sign_reproduced_report(attacker_report, attacker_key)

    return PublicReproductionArtifacts(
        authorization=authorization,
        evaluator_private_key=evaluator_key,
        baseline=baseline,
        target_report=target_path,
        target_public_bundle=target_public_bundle,
        public_bundle=public_bundle,
        public_manifest=manifest_path,
        reproduced_report=reproduced_path,
        report_signature=report_signature,
        allowed_signers=evaluator_allowed_signers,
        protocol_allowed_signers=protocol_allowed_signers,
        leakage_policy=leakage_policy,
        comparison_manifest=comparison_path,
        discrepancy_ledger=ledger_path,
        wrong_report_signature=wrong_report_signature,
    )


def _verify(
    artifacts: PublicReproductionArtifacts,
    *,
    target_public_bundle: Path | None = None,
    public_bundle: Path | None = None,
    leakage_policy: PublicLeakagePolicy | None = None,
    protocol_allowed_signers: Path | None = None,
    protocol_signer_identity: str = _PROTOCOL_SIGNER_IDENTITY,
    report_signature: Path | None = None,
    comparison_manifest: Path | None = None,
    discrepancy_ledger: Path | None = None,
) -> VerifiedPublicReproductionReceipt:
    """Invoke the public verifier with selected artifact substitutions."""
    return verify_public_reproduction(
        artifacts.authorization,
        target_baseline=artifacts.baseline,
        target_public_bundle=target_public_bundle or artifacts.target_public_bundle,
        reproduced_public_bundle=public_bundle or artifacts.public_bundle,
        reproduced_public_leakage_policy=leakage_policy or artifacts.leakage_policy,
        reproduced_protocol_allowed_signers=(
            protocol_allowed_signers or artifacts.protocol_allowed_signers
        ),
        reproduced_protocol_signer_identity=protocol_signer_identity,
        reproduced_report_signature=report_signature or artifacts.report_signature,
        reproduced_report_allowed_signers=artifacts.allowed_signers,
        reproduced_report_signer_identity=_EVALUATOR_IDENTITY,
        comparison_manifest=comparison_manifest or artifacts.comparison_manifest,
        discrepancy_ledger=discrepancy_ledger or artifacts.discrepancy_ledger,
    )


def test_verifies_complete_public_reproduction(
    public_reproduction_artifacts: PublicReproductionArtifacts,
) -> None:
    """Every public artifact recomputes into a frozen non-secret receipt."""
    receipt = _verify(public_reproduction_artifacts)

    assert receipt.statement == public_reproduction_artifacts.authorization.statement
    assert receipt.target_baseline == public_reproduction_artifacts.baseline
    assert {discrepancy.field for discrepancy in receipt.discrepancy_ledger.discrepancies} == {
        "detector_results",
        "outcome",
    }
    assert receipt.paired_comparison.seed == 0
    assert receipt.paired_comparison.overall_interval.bootstrap_samples == 10_000
    with pytest.raises(AttributeError):
        receipt.statement_sha256 = "0" * 64  # type: ignore[misc]


def test_builds_and_authorizes_signed_public_gate_handoff(
    tmp_path: Path,
    public_reproduction_artifacts: PublicReproductionArtifacts,
) -> None:
    """The release-gate handoff is fully derived, canonical, and signature-bound."""
    artifacts = public_reproduction_artifacts
    receipt = _verify(artifacts)
    statement = build_public_reproduction_verification_statement(receipt)
    statement_path = tmp_path / "public-reproduction-verification.json"
    write_public_reproduction_verification_statement(statement, statement_path)
    signature = sign_public_reproduction_verification_statement(
        statement_path,
        artifacts.evaluator_private_key,
    )

    authorization = authorize_public_reproduction_verification_statement(
        statement_path,
        signature,
        artifacts.allowed_signers,
        _EVALUATOR_IDENTITY,
    )

    public_manifest = EvidenceBundleManifest.model_validate_json(
        artifacts.public_manifest.read_bytes()
    )
    assert authorization.statement_sha256 == artifacts.authorization.statement_sha256
    assert authorization.target_report_sha256 == canonical_report_sha256(receipt.target_report)
    assert authorization.reproduced_report_bytes_sha256 == _sha256(
        artifacts.reproduced_report.read_bytes()
    )
    assert (
        authorization.reproduced_public_bundle_inventory_sha256 == public_manifest.inventory_sha256
    )
    assert (
        authorization.verification_signing_key_fingerprint
        == artifacts.authorization.signing_key_fingerprint
    )
    assert statement_path.read_bytes() == _canonical_model_bytes(statement)


def test_public_gate_handoff_rejects_tamper_wrong_key_and_wrong_namespace(
    tmp_path: Path,
    public_reproduction_artifacts: PublicReproductionArtifacts,
) -> None:
    """No altered or differently authorized handoff can cross the public gate."""
    artifacts = public_reproduction_artifacts
    statement = build_public_reproduction_verification_statement(_verify(artifacts))
    statement_path = tmp_path / "verification.json"
    write_public_reproduction_verification_statement(statement, statement_path)
    signature = sign_public_reproduction_verification_statement(
        statement_path,
        artifacts.evaluator_private_key,
    )

    tampered_path = tmp_path / "tampered-verification.json"
    tampered = statement.model_copy(update={"comparison_manifest_sha256": "0" * 64})
    tampered_path.write_bytes(_canonical_model_bytes(tampered))
    with pytest.raises(
        PublicReproductionVerificationError,
        match="signature is invalid",
    ):
        authorize_public_reproduction_verification_statement(
            tampered_path,
            signature,
            artifacts.allowed_signers,
            _EVALUATOR_IDENTITY,
        )

    attacker_key, _ = _new_signing_identity(
        tmp_path,
        label="public-verification-attacker",
        identity=_EVALUATOR_IDENTITY,
    )
    attacker_path = tmp_path / "attacker-verification.json"
    attacker_path.write_bytes(_canonical_model_bytes(statement))
    attacker_signature = sign_public_reproduction_verification_statement(
        attacker_path,
        attacker_key,
    )
    with pytest.raises(
        PublicReproductionVerificationError,
        match="signature is invalid",
    ):
        authorize_public_reproduction_verification_statement(
            attacker_path,
            attacker_signature,
            artifacts.allowed_signers,
            _EVALUATOR_IDENTITY,
        )

    wrong_namespace_path = tmp_path / "wrong-namespace-verification.json"
    wrong_namespace_path.write_bytes(_canonical_model_bytes(statement))
    wrong_namespace_signature = sign_reproduction_statement(
        wrong_namespace_path,
        artifacts.evaluator_private_key,
    )
    with pytest.raises(
        PublicReproductionVerificationError,
        match="signature is invalid",
    ):
        authorize_public_reproduction_verification_statement(
            wrong_namespace_path,
            wrong_namespace_signature,
            artifacts.allowed_signers,
            _EVALUATOR_IDENTITY,
        )


@pytest.mark.parametrize("artifact_name", ["report", "manifest", "ledger", "comparison"])
def test_rejects_tampered_public_artifact(
    tmp_path: Path,
    public_reproduction_artifacts: PublicReproductionArtifacts,
    artifact_name: str,
) -> None:
    """Any byte edit to a public proof artifact fails closed."""
    tampered_bundle: Path | None = None
    tampered: Path | None = None
    if artifact_name in {"report", "manifest"}:
        tampered_bundle = tmp_path / "tampered-public-bundle"
        shutil.copytree(public_reproduction_artifacts.public_bundle, tampered_bundle)
        if artifact_name == "manifest":
            source = tampered_bundle / BUNDLE_MANIFEST
        else:
            manifest = EvidenceBundleManifest.model_validate_json(
                (tampered_bundle / BUNDLE_MANIFEST).read_bytes()
            )
            report_relative = next(
                path for path, entry in manifest.files.items() if entry.role is EvidenceRole.REPORT
            )
            source = tampered_bundle / report_relative
        source.write_bytes(source.read_bytes() + b" ")
    else:
        source = {
            "ledger": public_reproduction_artifacts.discrepancy_ledger,
            "comparison": public_reproduction_artifacts.comparison_manifest,
        }[artifact_name]
        tampered = tmp_path / source.name
        tampered.write_bytes(source.read_bytes() + b" ")
    arguments = {
        "public_bundle": tampered_bundle,
        "discrepancy_ledger": tampered if artifact_name == "ledger" else None,
        "comparison_manifest": tampered if artifact_name == "comparison" else None,
    }

    with pytest.raises(PublicReproductionVerificationError):
        _verify(public_reproduction_artifacts, **arguments)


def test_rejects_missing_artifact_without_disclosing_path(
    tmp_path: Path,
    public_reproduction_artifacts: PublicReproductionArtifacts,
) -> None:
    """A missing public artifact fails without reflecting its host path."""
    missing = tmp_path / "PRIVATE-HOST-PATH" / "comparison.manifest.json"

    with pytest.raises(PublicReproductionVerificationError) as caught:
        _verify(public_reproduction_artifacts, comparison_manifest=missing)

    assert str(missing) not in str(caught.value)


def test_rejects_wrong_reproduced_report_signature(
    public_reproduction_artifacts: PublicReproductionArtifacts,
) -> None:
    """A report signature from an untrusted key cannot satisfy evaluator trust."""
    with pytest.raises(
        PublicReproductionVerificationError,
        match="signature verification failed",
    ):
        _verify(
            public_reproduction_artifacts,
            report_signature=public_reproduction_artifacts.wrong_report_signature,
        )


def test_rejects_extra_public_bundle_file(
    tmp_path: Path,
    public_reproduction_artifacts: PublicReproductionArtifacts,
) -> None:
    """An actual bundle with an uninventoried file cannot pass as a manifest proof."""
    bundle = tmp_path / "bundle-with-extra"
    shutil.copytree(public_reproduction_artifacts.public_bundle, bundle)
    (bundle / "uninventoried.txt").write_text("extra\n", encoding="utf-8")

    with pytest.raises(
        PublicReproductionVerificationError,
        match="complete verification",
    ):
        _verify(public_reproduction_artifacts, public_bundle=bundle)


@pytest.mark.parametrize("artifact_name", ["report", "manifest"])
def test_rejects_mutated_target_public_bundle(
    tmp_path: Path,
    public_reproduction_artifacts: PublicReproductionArtifacts,
    artifact_name: str,
) -> None:
    """The pre-release verifier derives target bytes only from a complete verified bundle."""
    bundle = tmp_path / f"target-{artifact_name}-tampered"
    shutil.copytree(public_reproduction_artifacts.target_public_bundle, bundle)
    if artifact_name == "manifest":
        source = bundle / BUNDLE_MANIFEST
    else:
        manifest = EvidenceBundleManifest.model_validate_json(
            (bundle / BUNDLE_MANIFEST).read_bytes()
        )
        report_relative = next(
            path for path, entry in manifest.files.items() if entry.role is EvidenceRole.REPORT
        )
        source = bundle / report_relative
    source.write_bytes(source.read_bytes() + b" ")

    with pytest.raises(
        PublicReproductionVerificationError,
        match="target public evidence bundle failed complete verification",
    ):
        _verify(public_reproduction_artifacts, target_public_bundle=bundle)


def test_rejects_wrong_but_internally_valid_target_public_bundle(
    public_reproduction_artifacts: PublicReproductionArtifacts,
) -> None:
    """A valid different bundle cannot substitute for the signed target baseline."""
    with pytest.raises(
        PublicReproductionVerificationError,
        match="signed statement does not bind the supplied target baseline",
    ):
        _verify(
            public_reproduction_artifacts,
            target_public_bundle=public_reproduction_artifacts.public_bundle,
        )


def test_rejects_wrong_protocol_trust_and_leakage_policy(
    tmp_path: Path,
    public_reproduction_artifacts: PublicReproductionArtifacts,
) -> None:
    """Public reproduction re-verifies independent protocol trust and active leakage data."""
    _, wrong_trust = _new_signing_identity(
        tmp_path,
        label="wrong-protocol-key",
        identity=_PROTOCOL_SIGNER_IDENTITY,
    )
    unrelated = tmp_path / "unrelated-forbidden-source"
    unrelated.mkdir()
    (unrelated / "unrelated.bin").write_bytes(b"unrelated")
    wrong_policy = PublicLeakagePolicy(
        forbidden_sources=(unrelated,),
        forbidden_markers=(b"DIFFERENT-MARKER",),
    )

    with pytest.raises(PublicReproductionVerificationError, match="complete verification"):
        _verify(public_reproduction_artifacts, protocol_allowed_signers=wrong_trust)
    with pytest.raises(PublicReproductionVerificationError, match="complete verification"):
        _verify(public_reproduction_artifacts, leakage_policy=wrong_policy)
