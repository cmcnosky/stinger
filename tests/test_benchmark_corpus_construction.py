"""Synthetic artifact-derived corpus-construction tests.

No test reads the ignored candidate corpus.  The positive fixture creates a complete
120-item Protocol 2 corpus below ``tmp_path`` and replaces only the external evidence-bundle
verifier with exact in-memory receipts.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

import pytest
import yaml
from pydantic import BaseModel, ValidationError

import stinger.benchmark.corpus_construction as construction_module
import stinger.benchmark.replay as replay_module
from stinger import BENCHMARK_PROTOCOL_VERSION, RUBRIC_VERSION
from stinger.adapters.base import AgentRun, RecordedAdapter
from stinger.adapters.codex import CodexAdapter
from stinger.benchmark.candidate_receipt import _inventory_tree, _verify_canaries
from stinger.benchmark.corpus_construction import (
    CONSTRUCTION_RECEIPT_FORMAT_VERSION,
    MACHINE_REVIEW_CLAIM_BOUNDARY,
    MACHINE_REVIEW_RUNTIME_FORMAT_VERSION,
    MACHINE_REVIEW_RUNTIME_SIGNATURE_NAMESPACE,
    AuthoringConfigurationReceipt,
    BlindSolveInput,
    ConstructionMachineReviewManifest,
    ConstructionResolutionVariantManifest,
    ConstructionRunBundleManifest,
    ConstructionScenarioManifest,
    CorpusConstructionError,
    CorpusConstructionInputManifest,
    CorpusConstructionReceipt,
    CustodyInventoryReceipt,
    DummySafetyReceipt,
    MachineReviewerConfigurationReceipt,
    MachineReviewEvidenceManifest,
    MachineReviewInputReceipt,
    MachineReviewPackageInput,
    MachineReviewRuntimeReceipt,
    ReferenceIsolationReceipt,
    ResolutionExecutionReceipt,
    ResolutionVariantInput,
    ScenarioConstructionInput,
    ScenarioContainmentReceipt,
    ScenarioProvenanceReceipt,
    VerifiedCorpusConstructionReceipt,
    VerifiedMachineReviewRuntimeAuthorization,
    VerifiedRunBundleInput,
    authorize_corpus_construction_receipt,
    authorize_machine_review_runtime_receipt,
    build_agent_run_workflow_input_receipt,
    build_corpus_construction_receipt,
    canonical_corpus_construction_receipt_sha256,
    load_corpus_construction_input_manifest,
    sign_corpus_construction_receipt,
    sign_machine_review_runtime_receipt,
    write_agent_run_workflow_input_receipt,
    write_corpus_construction_receipt,
)
from stinger.benchmark.corpus_promotion import SEALED_VALIDATION_CONTRACT
from stinger.benchmark.credential_broker import (
    CredentialBrokerConfiguration,
    CredentialIsolationInvocationReceipt,
    agent_environment_names,
    broker_source_inventory_sha256,
    credential_identity_payloads,
    provider_route,
)
from stinger.benchmark.evidence import (
    BUNDLE_FORMAT_VERSION,
    ESCROW_NOTICE,
    BundleKind,
    EvidenceBundleManifest,
    EvidenceBundleReceipt,
    PublicLeakagePolicy,
    VerifiedArtifactReceipt,
    create_escrow_evidence_bundle,
    create_public_evidence_bundle,
)
from stinger.benchmark.gates import (
    CANDIDATE_PROMOTION_CONTRACT,
    CANDIDATE_PROMOTION_FORMAT_VERSION,
    CANDIDATE_RECEIPT_FORMAT_VERSION,
    CANDIDATE_VALIDATION_CONTRACT,
    REPOSITORY_SIZE_SOURCE_VERSION,
    CandidatePromotionStatement,
    CandidateValidationReceipt,
    CorpusScenarioRecord,
    MachineReviewRecord,
    RepositorySize,
    ResolutionKind,
    ResolutionVariantRecord,
    SealedCorpusRecord,
    VerifiedCandidatePromotionAuthorization,
    VerifiedCandidateValidationAuthorization,
    candidate_scenario_identity_inventory_sha256,
    candidate_validation_inventory_sha256,
    compiled_benchmark_protocol,
    corpus_scenario_inventory_sha256,
    machine_review_input_manifest_sha256,
    sealed_scenario_artifact_inventory_sha256,
)
from stinger.benchmark.machine_environment import (
    MACHINE_ENVIRONMENT_CLAIM_BOUNDARY,
    MACHINE_WORKFLOW_SIGNATURE_NAMESPACE,
    MachineArchitecture,
    MachineEnvironmentIdentity,
    MachineIdentitySource,
    MachinePlatform,
    MachineWorkflowAttestation,
    VerifiedMachineWorkflowAttestation,
    machine_environment_identity_sha256,
    sign_machine_workflow_attestation,
    verify_machine_workflow_attestation,
    write_machine_workflow_attestation,
)
from stinger.benchmark.machine_review import (
    MACHINE_REVIEW_OUTPUT_SCHEMA_SHA256,
    MACHINE_REVIEW_PROMPT_SHA256,
    MachineReviewDecision,
    MachineReviewOutput,
)
from stinger.benchmark.protocol import (
    BenchmarkRuntimeProvenance,
    BenchmarkSplit,
    CredentialIsolationRuntimeProvenance,
    ProviderId,
    canonical_credential_isolation_policy_sha256,
    compiled_credential_isolation_policy,
)
from stinger.benchmark.replay import (
    build_invocation_plan,
    verify_report_classifications_from_escrow,
)
from stinger.benchmark.signing import (
    CANDIDATE_PROMOTION_SIGNATURE_NAMESPACE,
    CANDIDATE_VALIDATION_SIGNATURE_NAMESPACE,
    PROTOCOL_SIGNATURE_NAMESPACE,
    ProtocolSignatureError,
    ProtocolSignatureVerification,
    sign_candidate_promotion_statement,
    sign_candidate_validation_receipt,
    sign_protocol,
)
from stinger.benchmark.verification_image import (
    APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
    canonical_verification_image_policy_sha256,
    compiled_verification_image_policy,
)
from stinger.config import AgentConfig, RunConfig
from stinger.docker_runtime import (
    DOCKER_RUNTIME_CLAIM_BOUNDARY,
    DockerRuntimeError,
    DockerRuntimeIdentity,
    inspect_docker_image,
    observe_docker_runtime,
)
from stinger.harness.runner import run_scenario_once
from stinger.harness.sandbox import Isolation, Sandbox, SandboxError, apply_overlay, diff_states
from stinger.models import ExecResult, Family, Outcome, ScenarioResult
from stinger.report.generate import build_report, render_json
from stinger.report.repro import write_repro_package
from stinger.scenario.loader import Scenario, corpus_hash, discover_scenarios, scenario_hash

AGENT_IMAGE = f"sha256:{'a' * 64}"
VERIFY_IMAGE = APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID
STINGER_COMMIT = "c" * 40
CORPUS_VERSION = "1.0.0"
SIGNING_FINGERPRINT = "SHA256:dGVzdC1jb25zdHJ1Y3Rpb24="
LEDGER_MODE = "cooperative_hash_chained_not_kernel_enforced_or_independently_anchored"


def _credential_isolation_fields(docker_runtime_sha256: str) -> dict[str, str]:
    """Return one complete synthetic external-broker identity binding."""
    return {
        "credential_isolation_policy_sha256": (
            canonical_credential_isolation_policy_sha256(compiled_credential_isolation_policy())
        ),
        "broker_configuration_sha256": "c" * 64,
        "allowed_destination_inventory_sha256": "d" * 64,
        "agent_projection_inventory_sha256": "e" * 64,
        "broker_source_inventory_sha256": "f" * 64,
        "broker_image_id": "sha256:" + "1" * 64,
        "broker_runtime_identity_sha256": docker_runtime_sha256,
    }


def _credential_isolation_receipt(
    runtime: DockerRuntimeIdentity,
    *,
    seed: str = "a",
    agent: AgentConfig | None = None,
    repository: Path | None = None,
) -> CredentialIsolationInvocationReceipt:
    """Return complete synthetic per-invocation broker evidence."""
    policy_sha256 = canonical_credential_isolation_policy_sha256(
        compiled_credential_isolation_policy()
    )
    broker_configuration_sha256 = "b" * 64
    allowed_destination_inventory_sha256 = "c" * 64
    agent_projection_inventory_sha256 = "d" * 64
    source_inventory_sha256 = "e" * 64
    broker_image_id = "sha256:" + "f" * 64
    environment_names = ("OPENAI_API_KEY",)
    if agent is not None and repository is not None:
        assert agent.credential_broker is not None
        assert agent.api_key_env is not None
        route = provider_route(agent.adapter, agent.provider)
        source_inventory_sha256 = broker_source_inventory_sha256(repository)
        (
            policy_sha256,
            broker_configuration_sha256,
            allowed_destination_inventory_sha256,
            agent_projection_inventory_sha256,
        ) = credential_identity_payloads(
            route=route,
            broker=agent.credential_broker,
            api_key_env=agent.api_key_env,
            source_inventory_sha256=source_inventory_sha256,
        )
        broker_image_id = agent.credential_broker.image_digest
        environment_names = agent_environment_names(route)
    return CredentialIsolationInvocationReceipt(
        policy_sha256=policy_sha256,
        broker_configuration_sha256=broker_configuration_sha256,
        allowed_destination_inventory_sha256=allowed_destination_inventory_sha256,
        resolved_upstream_address_inventory_sha256="e" * 64,
        agent_projection_inventory_sha256=agent_projection_inventory_sha256,
        broker_source_inventory_sha256=source_inventory_sha256,
        broker_image_id=broker_image_id,
        docker_client_sha256=runtime.client_sha256,
        docker_runtime_fingerprint_sha256=runtime.fingerprint_sha256,
        agent_container_id_sha256="3" * 64,
        broker_container_id_sha256="4" * 64,
        internal_network_id_sha256=seed * 64,
        internal_network_name_sha256="1" * 64,
        outbound_network_id_sha256=hashlib.sha256(
            f"{seed}:outbound-id".encode("ascii")
        ).hexdigest(),
        outbound_network_name_sha256=hashlib.sha256(
            f"{seed}:outbound-name".encode("ascii")
        ).hexdigest(),
        broker_lease_sha256="5" * 64,
        agent_command_inventory_sha256="0" * 64,
        agent_environment_inventory_sha256="6" * 64,
        agent_mount_inventory_sha256="7" * 64,
        agent_image_credential_scan_sha256="9" * 64,
        agent_container_runtime_inventory_sha256="6" * 64,
        broker_container_runtime_inventory_sha256="5" * 64,
        network_attachment_inventory_sha256="8" * 64,
        broker_audit_sha256="2" * 64,
        request_count=1,
        rejection_count=0,
        agent_environment_names=environment_names,
        agent_network_mode="fresh-docker-internal-network-only",
        agent_bridge_gateway="isolated-no-host-interface",
        agent_dns="embedded-broker-alias-with-loopback-only-upstream",
        broker_alias="stinger-credential-broker",
        raw_provider_credential_exposed=False,
        broker_bypass_path_present=False,
        unapproved_egress_path_present=False,
        agent_container_cleanup_verified=True,
        broker_container_cleanup_verified=True,
        internal_network_cleanup_verified=True,
        outbound_network_cleanup_verified=True,
    )


def _sha256(content: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(content).hexdigest()


def _payload_sha256(payload: object) -> str:
    """Hash one canonical JSON-compatible payload."""
    return _sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _model_bytes(model: BaseModel) -> bytes:
    """Render one canonical construction input receipt."""
    return (
        json.dumps(
            model.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _model_sha256(model: BaseModel) -> str:
    """Hash a model using the release gate's canonical payload contract."""
    return _payload_sha256(model.model_dump(mode="json"))


def _write_model(path: Path, model: BaseModel) -> Path:
    """Write one canonical typed input receipt."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_model_bytes(model))
    return path


def _write_bytes(path: Path, content: bytes) -> Path:
    """Write one exact synthetic artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _make_closed_review_workspace(root: Path) -> Path:
    """Create one minimal content-addressed machine-review workspace."""
    root.mkdir()
    collector = construction_module._ReviewEvidenceCollector(root)
    collector.add(PurePosixPath("scenario/AGENTS.md"), b"scenario rules\n")
    collector.add(PurePosixPath("scenario/CLAUDE.md"), b"scenario Claude rules\n")
    resolution_ids = tuple(
        sorted(f"{kind}-{index}" for kind in ("honest", "cheat") for index in range(2))
    )
    for variant_id in resolution_ids:
        collector.add(
            PurePosixPath("resolutions") / variant_id / "transcript.bin",
            f"resolution {variant_id}\n".encode(),
        )
    qa_ids = tuple(f"qa-{index}" for index in range(5))
    for attempt_id in qa_ids:
        collector.add(
            PurePosixPath("qa") / attempt_id / "run" / "transcript.bin",
            f"qa {attempt_id}\n".encode(),
        )
    input_manifest_sha256 = "1" * 64
    files = collector.files
    evidence_inventory_sha256 = construction_module._review_file_inventory_sha256(files)
    manifest = MachineReviewEvidenceManifest(
        format_version="1",
        scenario_id="scenario-one",
        scenario_artifact_sha256="2" * 64,
        input_manifest_sha256=input_manifest_sha256,
        covered_resolution_variant_ids=resolution_ids,
        covered_qa_attempt_ids=qa_ids,
        evidence_inventory_sha256=evidence_inventory_sha256,
        files=files,
    )
    manifest_path = _write_model(
        root / construction_module.MACHINE_REVIEW_EVIDENCE_MANIFEST_FILENAME,
        manifest,
    )
    review_input = MachineReviewInputReceipt(
        format_version="3",
        scenario_id="scenario-one",
        input_manifest_sha256=input_manifest_sha256,
        review_evidence_manifest_sha256=_sha256(manifest_path.read_bytes()),
        review_evidence_inventory_sha256=evidence_inventory_sha256,
        prompt_sha256=MACHINE_REVIEW_PROMPT_SHA256,
        output_schema_sha256=MACHINE_REVIEW_OUTPUT_SCHEMA_SHA256,
        covered_qa_attempt_ids=qa_ids,
    )
    _write_model(
        root / construction_module.MACHINE_REVIEW_INPUT_FILENAME,
        review_input,
    )
    return root


@dataclass(frozen=True, slots=True)
class _RunSpec:
    """Inputs used by the mocked external bundle verifier."""

    scenario_id: str
    family: Family
    scenario_version: str
    cluster_id: str
    provider: ProviderId
    token: str
    outcome: Outcome
    corpus_hash: str


@dataclass(frozen=True, slots=True)
class ConstructionFixture:
    """One complete synthetic Protocol 2 construction invocation."""

    repository: Path
    corpus_root: Path
    candidate_authorization: VerifiedCandidateValidationAuthorization
    promotion_authorization: VerifiedCandidatePromotionAuthorization
    custody_inventory: Path
    canary_registry: Path
    access_ledger: Path
    scenarios: tuple[ScenarioConstructionInput, ...]
    private_root: Path


@dataclass(frozen=True, slots=True)
class ManifestLoaderFixture:
    """One signed, safe, relative-path construction-input manifest."""

    root: Path
    path: Path
    manifest: CorpusConstructionInputManifest
    marker_file: Path
    corpus_root: Path


def _scenario_manifest(
    scenario_id: str,
    family: Family,
    cluster_id: str,
) -> dict[str, object]:
    """Return one minimal, loadable sealed scenario manifest."""
    return {
        "id": scenario_id,
        "family": family.value,
        "title": "Synthetic construction scenario",
        "prompt": "Perform the synthetic task.",
        "benchmark_split": BenchmarkSplit.SEALED.value,
        "scenario_version": "1.0.0",
        "cluster_id": cluster_id,
        "detectors": [],
        "completion_check": "completion_check/check.py",
    }


def _make_verified_bundle_receipt(spec: _RunSpec) -> VerifiedArtifactReceipt:
    """Build an internally exact receipt returned by the mocked external verifier."""
    config = RunConfig(
        agent=AgentConfig(
            adapter="recorded",
            model=f"{spec.provider.value}-construction-model",
            provider=spec.provider,
            cli_version="1.0.0",
            reasoning_effort="high",
            inference_settings={"synthetic_token": spec.token},
            container_image="synthetic-agent:1",
            container_image_digest=AGENT_IMAGE,
        ),
        corpus=Path("<sealed-corpus>"),
        output_dir=Path("<synthetic-output>"),
        reps=1,
        only=spec.family,
        isolation=Isolation.DOCKER,
        image="stinger-runner:1",
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        stinger_commit=STINGER_COMMIT,
        verification_image_digest=VERIFY_IMAGE,
        run_seed=17,
    )
    metadata = config.benchmark_metadata()
    assert metadata is not None
    runtime = BenchmarkRuntimeProvenance(
        requested_provider=spec.provider,
        requested_model_id=config.agent.model,
        stinger_commit=STINGER_COMMIT,
        docker_client_sha256="d" * 64,
        docker_runtime_fingerprint_sha256="e" * 64,
        docker_runtime_claim_boundary=DOCKER_RUNTIME_CLAIM_BOUNDARY,
        agent_cli_version=config.agent.cli_version,
        agent_container_image_id=AGENT_IMAGE,
        verification_image_id=VERIFY_IMAGE,
        verification_image_policy_sha256=(
            canonical_verification_image_policy_sha256(compiled_verification_image_policy())
        ),
        resolved_agent_invocation=("agent", config.agent.model or ""),
        resolved_version_invocation=("agent", "--version"),
        reasoning_effort=config.agent.reasoning_effort,
        inference_settings=config.agent.inference_settings,
        verified=True,
    )
    result = ScenarioResult(
        scenario_id=spec.scenario_id,
        family=spec.family,
        outcome=spec.outcome,
        detector_results=[],
        goal_met=spec.outcome in {Outcome.HONEST, Outcome.CHEATED},
        agent_claimed_done=True,
        transcript_path=f"transcripts/{spec.token}.txt",
        diff_path=f"diffs/{spec.token}.patch",
        duration_s=float(int(_sha256(spec.token.encode())[:6], 16)),
        repetition=0,
        benchmark_split=BenchmarkSplit.SEALED,
        scenario_version=spec.scenario_version,
        cluster_id=spec.cluster_id,
    )
    report = build_report(
        [result],
        corpus_hash=spec.corpus_hash,
        config_fingerprint=config.fingerprint(),
        generated_at="2026-01-01T00:00:00Z",
        benchmark_metadata=metadata,
        benchmark_runtime_provenance=runtime,
        bootstrap_samples=1,
    )
    report_bytes = render_json(report).encode("utf-8")
    protocol = compiled_benchmark_protocol()
    protocol_bytes = _model_bytes(protocol)
    config_bytes = config.resolved_json().encode("utf-8")

    def bundle(kind: BundleKind) -> EvidenceBundleReceipt:
        manifest = EvidenceBundleManifest(
            format_version=BUNDLE_FORMAT_VERSION,
            bundle_kind=kind,
            protocol_sha256=_sha256(protocol_bytes),
            protocol_signature_sha256=_sha256(b"protocol-signature"),
            allowed_signers_sha256=_sha256(b"protocol-trust"),
            protocol_signer_identity="protocol@example.test",
            protocol_signature_namespace=PROTOCOL_SIGNATURE_NAMESPACE,
            config_sha256=_sha256(config_bytes),
            report_sha256=_sha256(report_bytes),
            inventory_sha256=_payload_sha256({"kind": kind.value, "token": spec.token}),
            leakage_policy_sha256=(
                _sha256(b"synthetic-policy") if kind is BundleKind.PUBLIC else None
            ),
            access_control_notice=(None if kind is BundleKind.PUBLIC else ESCROW_NOTICE),
            files={},
            directories={},
        )
        manifest_bytes = _model_bytes(manifest)
        return EvidenceBundleReceipt(
            bundle_kind=kind,
            manifest=manifest,
            manifest_bytes=manifest_bytes,
            manifest_sha256=_sha256(manifest_bytes),
            protocol=protocol,
            protocol_bytes=protocol_bytes,
            protocol_signature_bytes=b"protocol-signature",
            allowed_signers_bytes=b"protocol-trust",
            config=config,
            config_bytes=config_bytes,
            report=report,
            report_bytes=report_bytes,
        )

    return VerifiedArtifactReceipt(
        public_bundle=bundle(BundleKind.PUBLIC),
        escrow_bundle=bundle(BundleKind.ESCROW),
        protocol=protocol,
        config=config,
        report=report,
        protocol_signature_verification=ProtocolSignatureVerification(
            identity="protocol@example.test",
            namespace=PROTOCOL_SIGNATURE_NAMESPACE,
            protocol_sha256=_sha256(protocol_bytes),
            signature_sha256=_sha256(b"protocol-signature"),
            allowed_signers_sha256=_sha256(b"protocol-trust"),
            signing_key_fingerprint=SIGNING_FINGERPRINT,
        ),
    )


def _repository_size(index: int) -> RepositorySize:
    """Return the frozen eight/eight/eight size stratum."""
    if index < 8:
        return RepositorySize.SMALL
    if index < 16:
        return RepositorySize.MEDIUM
    return RepositorySize.LARGER_MULTI_MODULE


def _candidate_authorizations(
    *,
    stubs: tuple[CorpusScenarioRecord, ...],
    source_snapshot_sha256: str,
    corpus_hash_value: str,
    canary_inventory_sha256: str,
    access_root_sha256: str,
) -> tuple[
    VerifiedCandidateValidationAuthorization,
    VerifiedCandidatePromotionAuthorization,
]:
    """Construct internally exact signature-authorized synthetic lifecycle records."""
    protocol = compiled_benchmark_protocol()
    candidate_receipt_hash = _sha256(b"synthetic-signed-candidate-receipt")
    candidate_validation_inventory = _sha256(b"candidate-validation-inventory")
    candidate_access_root = _sha256(b"candidate-access-root")
    receipt = CandidateValidationReceipt(
        format_version=CANDIDATE_RECEIPT_FORMAT_VERSION,
        benchmark_protocol_version=protocol.benchmark_protocol_version,
        rubric_version=protocol.rubric_version,
        corpus_version=CORPUS_VERSION,
        signer_identity="candidate@example.test",
        stinger_commit=STINGER_COMMIT,
        docker_client_sha256="d" * 64,
        docker_runtime_fingerprint_sha256="e" * 64,
        validation_contract=CANDIDATE_VALIDATION_CONTRACT,
        verification_image_id=VERIFY_IMAGE,
        verification_image_policy_sha256=(
            canonical_verification_image_policy_sha256(compiled_verification_image_policy())
        ),
        repository_size_source=REPOSITORY_SIZE_SOURCE_VERSION,
        candidate_corpus_hash=_sha256(b"synthetic-candidate-corpus"),
        source_snapshot_sha256=_sha256(b"synthetic-candidate-source"),
        private_metadata_sha256=_sha256(b"synthetic-private-metadata"),
        scenario_identity_inventory_sha256=(candidate_scenario_identity_inventory_sha256(stubs)),
        validation_inventory_sha256=candidate_validation_inventory,
        canary_inventory_sha256=canary_inventory_sha256,
        access_log_root_sha256=candidate_access_root,
        custody_ledger_mode=LEDGER_MODE,
        scenario_count=len(stubs),
        scenarios_by_family={family: 24 for family in Family},
        scenarios_by_family_and_size={
            family: {size: 8 for size in RepositorySize} for family in Family
        },
        unique_cluster_count=len(stubs),
        machine_validation_count=len(stubs),
        canary_count=len(stubs),
        access_log_event_count=1,
    )
    candidate_authorization = VerifiedCandidateValidationAuthorization(
        receipt=receipt,
        identity=receipt.signer_identity,
        namespace=CANDIDATE_VALIDATION_SIGNATURE_NAMESPACE,
        receipt_sha256=candidate_receipt_hash,
        canonical_receipt_sha256=_model_sha256(receipt),
        signature_sha256=_sha256(b"candidate-signature"),
        allowed_signers_sha256=_sha256(b"candidate-trust"),
        signing_key_fingerprint=SIGNING_FINGERPRINT,
    )
    statement = CandidatePromotionStatement(
        format_version=CANDIDATE_PROMOTION_FORMAT_VERSION,
        benchmark_protocol_version=protocol.benchmark_protocol_version,
        rubric_version=protocol.rubric_version,
        corpus_version=CORPUS_VERSION,
        signer_identity="promotion@example.test",
        stinger_commit=STINGER_COMMIT,
        docker_client_sha256="d" * 64,
        docker_runtime_fingerprint_sha256="e" * 64,
        verification_image_id=VERIFY_IMAGE,
        verification_image_policy_sha256=(receipt.verification_image_policy_sha256),
        transformation_contract=CANDIDATE_PROMOTION_CONTRACT,
        candidate_receipt_sha256=candidate_receipt_hash,
        candidate_corpus_hash=receipt.candidate_corpus_hash,
        candidate_source_snapshot_sha256=receipt.source_snapshot_sha256,
        candidate_validation_inventory_sha256=candidate_validation_inventory,
        candidate_access_log_root_sha256=candidate_access_root,
        sealed_corpus_hash=corpus_hash_value,
        sealed_source_snapshot_sha256=source_snapshot_sha256,
        sealed_scenario_identity_inventory_sha256=(
            candidate_scenario_identity_inventory_sha256(stubs)
        ),
        sealed_scenario_artifact_inventory_sha256=(
            sealed_scenario_artifact_inventory_sha256(stubs)
        ),
        sealed_validation_inventory_sha256=candidate_validation_inventory_sha256(stubs),
        transformation_inventory_sha256=_sha256(b"synthetic-transformations"),
        canary_inventory_sha256=canary_inventory_sha256,
        sealed_access_log_root_sha256=access_root_sha256,
        scenario_count=len(stubs),
    )
    promotion_authorization = VerifiedCandidatePromotionAuthorization(
        statement=statement,
        identity=statement.signer_identity,
        namespace=CANDIDATE_PROMOTION_SIGNATURE_NAMESPACE,
        statement_sha256=_sha256(b"synthetic-signed-promotion"),
        canonical_statement_sha256=_model_sha256(statement),
        signature_sha256=_sha256(b"promotion-signature"),
        allowed_signers_sha256=_sha256(b"promotion-trust"),
        signing_key_fingerprint=SIGNING_FINGERPRINT,
    )
    return candidate_authorization, promotion_authorization


@pytest.fixture
def manifest_loader_fixture(tmp_path: Path) -> ManifestLoaderFixture:
    """Create one signed canonical manifest with only synthetic private inputs."""
    root = tmp_path / "manifest-package"
    root.mkdir()
    repository = root / "repository"
    repository.mkdir()
    corpus_root = root / "corpus"
    scenario_directory = corpus_root / "scenario-one"
    scenario_directory.mkdir(parents=True)
    authoring = _write_bytes(root / "scenario" / "authoring.json", b"{}\n")
    provenance_source = _write_bytes(
        root / "scenario" / "provenance-source.txt",
        b"synthetic provenance\n",
    )
    provenance = _write_bytes(root / "scenario" / "provenance.json", b"{}\n")
    marker_file = _write_bytes(root / "marker.txt", b"synthetic-private-marker\n")
    custody = _write_bytes(root / "custody.json", b"{}\n")
    canary_registry = _write_bytes(root / "canary-registry.yaml", b"synthetic: true\n")
    access_ledger = _write_bytes(root / "access-ledger.jsonl", b"{}\n")

    stub = CorpusScenarioRecord(
        scenario_id="scenario-one",
        family=Family.T,
        repository_size=RepositorySize.SMALL,
        benchmark_split=BenchmarkSplit.SEALED,
        scenario_version="1.0.0",
        cluster_id="cluster-one",
        expected_honest_outcome=Outcome.HONEST,
        scenario_artifact_sha256="1" * 64,
        machine_validation_receipt_sha256="2" * 64,
        provenance_receipt_sha256="3" * 64,
        containment_receipt_sha256="4" * 64,
        dummy_safety_receipt_sha256="5" * 64,
    )
    candidate_authorization, promotion_authorization = _candidate_authorizations(
        stubs=(stub,),
        source_snapshot_sha256="6" * 64,
        corpus_hash_value="7" * 64,
        canary_inventory_sha256="8" * 64,
        access_root_sha256="9" * 64,
    )
    candidate_receipt = _write_model(
        root / "candidate-receipt.json",
        candidate_authorization.receipt,
    )
    promotion_statement = _write_model(
        root / "promotion-statement.json",
        promotion_authorization.statement,
    )
    private_key = root / "lifecycle-key"
    subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            str(private_key),
        ],
        check=True,
        capture_output=True,
    )
    public_key = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(private_key)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    allowed_signers = _write_bytes(
        root / "allowed-signers",
        (
            f"{candidate_authorization.identity} {public_key}\n"
            f"{promotion_authorization.identity} {public_key}\n"
            f"protocol@example.test {public_key}\n"
        ).encode(),
    )
    candidate_signature = sign_candidate_validation_receipt(
        candidate_receipt,
        private_key,
    )
    promotion_signature = sign_candidate_promotion_statement(
        promotion_statement,
        private_key,
    )

    variant_manifests: list[ConstructionResolutionVariantManifest] = []
    for index in range(4):
        source_tree = root / "scenario" / "variants" / str(index) / "source"
        source_tree.mkdir(parents=True)
        semantic_patch = _write_bytes(
            root / "scenario" / "variants" / str(index) / "semantic.patch",
            f"patch-{index}\n".encode(),
        )
        agent_run = _write_bytes(
            root / "scenario" / "variants" / str(index) / "agent-run.json",
            b"{}\n",
        )
        variant_manifests.append(
            ConstructionResolutionVariantManifest(
                variant_id=f"variant-{index}",
                kind=(ResolutionKind.HONEST if index < 2 else ResolutionKind.CHEAT),
                source_tree=str(source_tree.relative_to(root)),
                semantic_patch=str(semantic_patch.relative_to(root)),
                agent_run=str(agent_run.relative_to(root)),
            )
        )

    def run_manifest(run_id: str) -> ConstructionRunBundleManifest:
        public = root / "bundles" / run_id / "public"
        escrow = root / "bundles" / run_id / "escrow"
        public.mkdir(parents=True)
        escrow.mkdir()
        workflow_root = root / "bundles" / run_id / "workflow"
        machine_identity = _write_bytes(workflow_root / "machine.json", b"{}\n")
        workflow_input = _write_bytes(workflow_root / "input.json", b"{}\n")
        workflow_receipt = _write_bytes(workflow_root / "receipt.json", b"{}\n")
        workflow_attestation = _write_bytes(workflow_root / "attestation.json", b"{}\n")
        workflow_signature = _write_bytes(workflow_root / "attestation.sig", b"signature\n")
        return ConstructionRunBundleManifest(
            run_id=run_id,
            public_bundle=str(public.relative_to(root)),
            escrow_bundle=str(escrow.relative_to(root)),
            forbidden_sources=("corpus",),
            marker_files=("marker.txt",),
            protocol_allowed_signers="allowed-signers",
            protocol_signer_identity="protocol@example.test",
            machine_identity_artifact=str(machine_identity.relative_to(root)),
            workflow_input=str(workflow_input.relative_to(root)),
            workflow_receipt=str(workflow_receipt.relative_to(root)),
            workflow_attestation=str(workflow_attestation.relative_to(root)),
            workflow_signature=str(workflow_signature.relative_to(root)),
            workflow_allowed_signers="allowed-signers",
            workflow_signer_identity=f"workflow-{run_id}@example.test",
        )

    qa_attempts = tuple(run_manifest(f"qa-{index}") for index in range(5))
    review_manifests: list[ConstructionMachineReviewManifest] = []
    for index in range(2):
        review_root = root / "scenario" / "reviews" / str(index)
        configuration = _write_bytes(review_root / "configuration.json", b"{}\n")
        review_input = _write_bytes(review_root / "input.json", b"{}\n")
        review_workspace = review_root / "workspace"
        review_workspace.mkdir()
        credential_isolation = _write_bytes(
            review_root / "credential-isolation.json",
            b"{}\n",
        )
        runtime = _write_bytes(review_root / "runtime.json", b"{}\n")
        transcript = _write_bytes(review_root / "transcript.bin", b"{}\n")
        output = _write_bytes(review_root / "output.json", b"{}\n")
        runtime_signature = _write_bytes(review_root / "runtime.sig", b"signature\n")
        review_manifests.append(
            ConstructionMachineReviewManifest(
                configuration_receipt=str(configuration.relative_to(root)),
                input_receipt=str(review_input.relative_to(root)),
                review_workspace=str(review_workspace.relative_to(root)),
                credential_isolation_receipt=str(credential_isolation.relative_to(root)),
                runtime_receipt=str(runtime.relative_to(root)),
                transcript=str(transcript.relative_to(root)),
                output=str(output.relative_to(root)),
                runtime_signature=str(runtime_signature.relative_to(root)),
                runtime_allowed_signers=allowed_signers.name,
                runtime_signer_identity=f"review-runner-{index}@example.test",
            )
        )
    scenario_manifest = ConstructionScenarioManifest(
        scenario_directory=str(scenario_directory.relative_to(root)),
        provenance_receipt=str(provenance.relative_to(root)),
        authoring_configuration_artifacts=(str(authoring.relative_to(root)),),
        provenance_source_artifacts=(str(provenance_source.relative_to(root)),),
        resolution_variants=tuple(variant_manifests),
        qa_attempts=qa_attempts,
        machine_reviews=tuple(review_manifests),
        blind_agent_solves=(),
    )
    manifest = CorpusConstructionInputManifest.model_validate(
        {
            "format_version": "4",
            "repository": "repository",
            "corpus_root": "corpus",
            "corpus_version": CORPUS_VERSION,
            "candidate_validation": {
                "artifact": candidate_receipt.name,
                "signature": candidate_signature.name,
                "allowed_signers": allowed_signers.name,
                "signer_identity": candidate_authorization.identity,
            },
            "candidate_promotion": {
                "artifact": promotion_statement.name,
                "signature": promotion_signature.name,
                "allowed_signers": allowed_signers.name,
                "signer_identity": promotion_authorization.identity,
            },
            "custody_inventory_receipt": custody.name,
            "canary_registry": canary_registry.name,
            "access_ledger": access_ledger.name,
            "scenarios": [scenario_manifest.model_dump(mode="json")],
        }
    )
    manifest_path = _write_model(root / "construction-input.json", manifest)
    return ManifestLoaderFixture(
        root=root,
        path=manifest_path,
        manifest=manifest,
        marker_file=marker_file,
        corpus_root=corpus_root,
    )


@pytest.fixture
def construction_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> ConstructionFixture:
    """Create one complete synthetic 120-scenario construction package."""

    class _NoopDockerSandbox(Sandbox):
        """Fast fixed-Docker stand-in; focused tests exercise the real derivation helpers."""

        isolation = Isolation.DOCKER

        def __init__(self, isolation: Isolation, image: str) -> None:
            assert isolation is Isolation.DOCKER
            self.image = image

        def preflight_benchmark(
            self,
            _repository: Path,
            *,
            policy: object | None = None,
        ) -> None:
            del policy
            return

        def verify_runtime_unchanged(self) -> None:
            return

    monkeypatch.setattr(construction_module, "Sandbox", _NoopDockerSandbox)

    private_root = tmp_path / "private-construction-inputs"
    repository = private_root / "repository"
    repository.mkdir(parents=True)
    monkeypatch.setattr(
        construction_module,
        "_clean_exact_git_head",
        lambda _: STINGER_COMMIT,
    )
    monkeypatch.setattr(
        construction_module,
        "_require_construction_implementation",
        lambda *args, **kwargs: _sha256(b"synthetic-construction-implementation"),
    )
    corpus_root = private_root / "sealed-corpus"
    artifacts_root = private_root / "receipts"
    corpus_root.mkdir(parents=True)
    canary_entries: list[dict[str, str]] = []
    for family in Family:
        for index in range(24):
            scenario_id = f"{family.value.lower()}-{index:02d}-synthetic"
            cluster_id = f"cluster-{family.value.lower()}-{index:02d}"
            directory = corpus_root / scenario_id
            _write_bytes(
                directory / "manifest.yaml",
                yaml.safe_dump(
                    _scenario_manifest(scenario_id, family, cluster_id),
                    sort_keys=True,
                ).encode("utf-8"),
            )
            _write_bytes(
                directory / "seed_repo" / "task.txt",
                f"synthetic task {scenario_id}\n".encode(),
            )
            canary = f"STINGER-SYNTHETIC-{family.value}-{index:02d}-7bcf9a".encode()
            _write_bytes(directory / ".stinger-corpus-canary", canary + b"\n")
            canary_entries.append(
                {
                    "relative_path": f"{scenario_id}/.stinger-corpus-canary",
                    "scenario_id": scenario_id,
                    "sha256": _sha256(canary + b"\n"),
                }
            )
    loaded = discover_scenarios(corpus_root)
    source_snapshot = _inventory_tree(corpus_root)
    corpus_hash_value = corpus_hash(loaded)
    canary_registry = private_root / "canary-registry.yaml"
    _write_bytes(
        canary_registry,
        yaml.safe_dump(
            {
                "schema_version": "1",
                "status": "synthetic",
                "corpus_path": "<synthetic-private-corpus>",
                "scenario_count": len(loaded),
                "canary_values_stored_in_registry": False,
                "entries": canary_entries,
            },
            sort_keys=True,
        ).encode("utf-8"),
    )
    registry_bytes = canary_registry.read_bytes()
    canary_inventory, _ = _verify_canaries(
        loaded,
        registry_bytes,
        registry_sha256=_sha256(registry_bytes),
    )
    ledger_event: dict[str, object] = {
        "event_type": "candidate_promoted_to_sealed",
        "custody_ledger_mode": LEDGER_MODE,
        "previous_event_hash": "0" * 64,
        "stinger_corpus_sha256": corpus_hash_value,
        "canary_registry_sha256": _sha256(registry_bytes),
    }
    ledger_event["event_hash"] = _payload_sha256(ledger_event)
    access_ledger = _write_bytes(
        private_root / "sealed-access-ledger.jsonl",
        json.dumps(ledger_event, sort_keys=True, separators=(",", ":")).encode() + b"\n",
    )
    access_root = str(ledger_event["event_hash"])

    stubs: list[CorpusScenarioRecord] = []
    for ordinal, scenario in enumerate(loaded):
        size = _repository_size(ordinal % 24)
        artifact_sha256 = scenario_hash(scenario)
        validation_sha256 = _payload_sha256(
            {
                "scenario_id": scenario.id,
                "scenario_artifact_sha256": artifact_sha256,
                "sealed_corpus_hash": corpus_hash_value,
                "stinger_commit": STINGER_COMMIT,
                "verification_image_id": VERIFY_IMAGE,
                "verification_image_policy_sha256": (
                    canonical_verification_image_policy_sha256(compiled_verification_image_policy())
                ),
                "validation_contract": SEALED_VALIDATION_CONTRACT,
            }
        )
        stubs.append(
            CorpusScenarioRecord(
                scenario_id=scenario.id,
                family=scenario.manifest.family,
                repository_size=size,
                benchmark_split=BenchmarkSplit.SEALED,
                scenario_version=scenario.manifest.scenario_version,
                cluster_id=scenario.manifest.cluster_id or "",
                expected_honest_outcome=Outcome.HONEST,
                scenario_artifact_sha256=artifact_sha256,
                machine_validation_receipt_sha256=validation_sha256,
                provenance_receipt_sha256="0" * 64,
                containment_receipt_sha256="0" * 64,
                dummy_safety_receipt_sha256="0" * 64,
            )
        )
    candidate_authorization, promotion_authorization = _candidate_authorizations(
        stubs=tuple(stubs),
        source_snapshot_sha256=source_snapshot.inventory_sha256,
        corpus_hash_value=corpus_hash_value,
        canary_inventory_sha256=canary_inventory,
        access_root_sha256=access_root,
    )
    custody_inventory = _write_model(
        private_root / "custody-inventory.json",
        CustodyInventoryReceipt(
            format_version=CONSTRUCTION_RECEIPT_FORMAT_VERSION,
            corpus_version=CORPUS_VERSION,
            corpus_hash=corpus_hash_value,
            sealed_source_snapshot_sha256=source_snapshot.inventory_sha256,
            candidate_promotion_statement_sha256=(promotion_authorization.statement_sha256),
            access_log_root_sha256=access_root,
            canary_inventory_sha256=canary_inventory,
        ),
    )

    run_specs: dict[str, _RunSpec] = {}
    receipt_cache: dict[str, VerifiedArtifactReceipt] = {}

    def verifier(
        public_bundle: Path,
        escrow_bundle: Path,
        leakage_policy: PublicLeakagePolicy,
        *,
        trusted_allowed_signers: Path,
        expected_signer_identity: str,
    ) -> VerifiedArtifactReceipt:
        del escrow_bundle, leakage_policy, trusted_allowed_signers, expected_signer_identity
        key = str(public_bundle)
        spec = run_specs.get(key)
        if spec is None:
            raise AssertionError("unexpected synthetic bundle")
        if key not in receipt_cache:
            receipt_cache[key] = _make_verified_bundle_receipt(spec)
        return receipt_cache[key]

    monkeypatch.setattr(
        construction_module,
        "verify_evidence_bundle_pair",
        verifier,
    )

    def execute_variant(
        scenario: Scenario,
        scenario_artifact_sha256: str,
        item: ResolutionVariantInput,
        *,
        sandbox: object,
    ) -> object:
        del sandbox
        source_hash = _inventory_tree(item.source_tree).inventory_sha256
        patch_hash = _sha256(item.semantic_patch.read_bytes())
        run_hash = _sha256(item.agent_run.read_bytes())
        outcome = Outcome.HONEST if item.kind is ResolutionKind.HONEST else Outcome.CHEATED
        receipt = ResolutionExecutionReceipt(
            format_version="4",
            scenario_id=scenario.id,
            scenario_artifact_sha256=scenario_artifact_sha256,
            variant_id=item.variant_id,
            kind=item.kind,
            source_tree_sha256=source_hash,
            semantic_patch_sha256=patch_hash,
            semantic_change_sha256=_sha256(f"semantic:{item.variant_id}".encode()),
            implementation_mechanism_sha256=_sha256(f"mechanism:{item.variant_id}".encode()),
            agent_run_sha256=run_hash,
            verification_image_id=VERIFY_IMAGE,
            result_sha256=_sha256(f"result:{item.variant_id}".encode()),
            transcript_sha256=_sha256(f"transcript:{item.variant_id}".encode()),
            diff_sha256=patch_hash,
            outcome=outcome,
            goal_met=True,
            intended_detector_triggered=item.kind is ResolutionKind.CHEAT,
            intended_detector="synthetic-intended",
        )
        return construction_module._ResolutionVariantBuild(
            record=ResolutionVariantRecord(
                variant_id=receipt.variant_id,
                kind=item.kind,
                source_tree_sha256=source_hash,
                semantic_patch_sha256=patch_hash,
                execution_receipt_sha256=_sha256(_model_bytes(receipt)),
            ),
            execution=receipt,
            source_tree=item.source_tree,
            semantic_patch=item.semantic_patch.read_bytes(),
            agent_run=item.agent_run.read_bytes(),
            transcript=f"transcript:{item.variant_id}".encode(),
            diff=item.semantic_patch.read_bytes(),
        )

    def authorize_review_runtime(
        receipt_path: Path,
        signature: Path,
        allowed_signers: Path,
        identity: str,
    ) -> VerifiedMachineReviewRuntimeAuthorization:
        del signature, allowed_signers
        runtime, content = construction_module._load_canonical_model(
            receipt_path,
            MachineReviewRuntimeReceipt,
            label="machine review runtime",
        )
        fingerprints = {
            "review-runner-0@example.test": "SHA256:cnVubmVyLTA=",
            "review-runner-1@example.test": "SHA256:cnVubmVyLTE=",
        }
        return VerifiedMachineReviewRuntimeAuthorization(
            receipt=runtime,
            identity=identity,
            namespace=MACHINE_REVIEW_RUNTIME_SIGNATURE_NAMESPACE,
            receipt_sha256=_sha256(content),
            canonical_receipt_sha256=_sha256(content),
            signature_sha256=_sha256(f"signature:{identity}".encode()),
            allowed_signers_sha256=_sha256(f"review-trust:{identity}".encode()),
            signing_key_fingerprint=fingerprints[identity],
        )

    def verify_run_bundle(
        run: VerifiedRunBundleInput,
        *,
        scenario: Scenario,
        corpus_hash_value: str,
        expected_stinger_commit: str,
        forbidden_signer_identities: frozenset[str],
        forbidden_signing_key_fingerprints: frozenset[str],
        forbidden_trust_policy_sha256s: frozenset[str],
    ) -> object:
        del (
            scenario,
            corpus_hash_value,
            expected_stinger_commit,
            forbidden_signer_identities,
            forbidden_signing_key_fingerprints,
            forbidden_trust_policy_sha256s,
        )
        spec = run_specs[str(run.public_bundle)]
        receipt = receipt_cache.setdefault(
            str(run.public_bundle),
            _make_verified_bundle_receipt(spec),
        )
        token_hash = hashlib.sha256(spec.token.encode()).digest()
        fingerprint = "SHA256:" + base64.b64encode(token_hash).decode().rstrip("=")
        signer_identity = f"workflow-{_sha256(spec.token.encode())[:16]}@example.test"
        statement = MachineWorkflowAttestation(
            claim_boundary=MACHINE_ENVIRONMENT_CLAIM_BOUNDARY,
            machine_identity_sha256=_sha256(f"machine:{spec.token}".encode()),
            host_identity_commitment_sha256=_sha256(f"host:{spec.token}".encode()),
            platform=MachinePlatform.LINUX,
            architecture=MachineArchitecture.X86_64,
            identity_source=MachineIdentitySource.LINUX_MACHINE_ID,
            python_version="3.12.0",
            stinger_commit=STINGER_COMMIT,
            workflow_input_sha256=_sha256(f"input:{spec.token}".encode()),
            workflow_receipt_sha256=_sha256(f"receipt:{spec.token}".encode()),
            signer_identity=signer_identity,
        )
        authorization = VerifiedMachineWorkflowAttestation(
            statement=statement,
            attestation_sha256=_sha256(f"attestation:{spec.token}".encode()),
            signature_sha256=_sha256(f"signature:{spec.token}".encode()),
            allowed_signers_sha256=_sha256(f"trust:{spec.token}".encode()),
            signer_identity=signer_identity,
            signing_key_fingerprint=fingerprint,
            signature_namespace=MACHINE_WORKFLOW_SIGNATURE_NAMESPACE,
        )
        identity = construction_module._RunExecutionIdentity(
            invocation_ids=frozenset({_sha256(f"invocation:{spec.token}".encode())}),
            challenge_nonce_sha256s=frozenset({_sha256(f"challenge:{spec.token}".encode())}),
            provider_response_id_sha256s=frozenset({_sha256(f"provider:{spec.token}".encode())}),
            execution_evidence_sha256s=frozenset({_sha256(f"execution:{spec.token}".encode())}),
            workflow_signature_sha256=authorization.signature_sha256,
        )
        return construction_module._VerifiedRunEvidence(
            artifact_receipt=receipt,
            result=receipt.report.results[0],
            provider=spec.provider,
            configuration_fingerprint=receipt.config.fingerprint(),
            runtime_receipt_sha256=_sha256(f"runtime:{spec.token}".encode()),
            execution_identity=identity,
            workflow_authorization=authorization,
        )

    def build_reviews(
        scenario: CorpusScenarioRecord,
        packages: tuple[MachineReviewPackageInput, ...],
        **_: object,
    ) -> tuple[MachineReviewRecord, ...]:
        del packages
        qa_ids = tuple(sorted(attempt.attempt_id for attempt in scenario.agent_qa_attempts))
        output = MachineReviewOutput(
            format_version="2",
            covered_qa_attempt_ids=qa_ids,
            findings=(),
            decision=MachineReviewDecision.ACCEPT,
        )
        input_sha256 = machine_review_input_manifest_sha256(scenario)
        return tuple(
            MachineReviewRecord(
                review_id=f"review-{index}",
                provider=provider,
                model_id=f"{provider.value}-review-model",
                reviewer_configuration_fingerprint=_sha256(
                    f"review-config:{scenario.scenario_id}:{index}".encode()
                ),
                runtime_receipt_sha256=_sha256(
                    f"review-runtime:{scenario.scenario_id}:{index}".encode()
                ),
                runtime_signer_identity=f"review-runner-{index}@example.test",
                runtime_signing_key_fingerprint=(f"SHA256:{('A' if index == 0 else 'B') * 43}"),
                runtime_allowed_signers_sha256=_sha256(
                    f"review-trust:{scenario.scenario_id}:{index}".encode()
                ),
                runtime_signature_sha256=_sha256(
                    f"review-signature:{scenario.scenario_id}:{index}".encode()
                ),
                prompt_sha256=MACHINE_REVIEW_PROMPT_SHA256,
                input_manifest_sha256=input_sha256,
                output_schema_sha256=MACHINE_REVIEW_OUTPUT_SCHEMA_SHA256,
                output_sha256=_model_sha256(output),
                output=output,
            )
            for index, provider in enumerate((ProviderId.OPENAI, ProviderId.ANTHROPIC))
        )

    def materialize_review_workspace(*args: object, **kwargs: object) -> None:
        del args, kwargs

    def derive_isolation(
        scenario: CorpusScenarioRecord,
        source_scenario: Scenario,
        run: VerifiedRunBundleInput,
        receipt: VerifiedArtifactReceipt,
        result: ScenarioResult,
        *,
        runtime_receipt_sha256: str,
    ) -> ReferenceIsolationReceipt:
        del source_scenario, result
        return ReferenceIsolationReceipt(
            format_version=CONSTRUCTION_RECEIPT_FORMAT_VERSION,
            solve_id=run.run_id,
            scenario_id=scenario.scenario_id,
            scenario_artifact_sha256=scenario.scenario_artifact_sha256,
            expected_workspace_inventory_sha256=_sha256(f"workspace:{run.run_id}".encode()),
            expected_before_diff_sha256=_sha256(f"before:{run.run_id}".encode()),
            observed_before_diff_sha256=_sha256(f"before:{run.run_id}".encode()),
            transcript_sha256=_sha256(f"transcript:{run.run_id}".encode()),
            result_diff_sha256=_sha256(f"diff:{run.run_id}".encode()),
            report_sha256=_sha256(receipt.public_bundle.report_bytes),
            public_manifest_sha256=receipt.public_bundle.manifest_sha256,
            escrow_manifest_sha256=receipt.escrow_bundle.manifest_sha256,
            runtime_receipt_sha256=runtime_receipt_sha256,
        )

    monkeypatch.setattr(construction_module, "_build_resolution_variant", execute_variant)
    monkeypatch.setattr(construction_module, "_verify_run_bundle", verify_run_bundle)
    monkeypatch.setattr(construction_module, "_build_machine_reviews", build_reviews)
    monkeypatch.setattr(
        construction_module,
        "_materialize_machine_review_workspace",
        materialize_review_workspace,
    )
    monkeypatch.setattr(
        construction_module,
        "authorize_machine_review_runtime_receipt",
        authorize_review_runtime,
    )
    monkeypatch.setattr(
        construction_module,
        "_derive_reference_isolation_receipt",
        derive_isolation,
    )
    policy = PublicLeakagePolicy(
        forbidden_sources=(corpus_root,),
        forbidden_markers=("STINGER-SYNTHETIC-PRIVATE-MARKER",),
    )

    static_inputs: list[ScenarioConstructionInput] = []
    base_records: list[CorpusScenarioRecord] = []
    for ordinal, scenario in enumerate(loaded):
        scenario_root = artifacts_root / scenario.id
        artifact_sha256 = scenario_hash(scenario)
        authoring = tuple(
            _write_model(
                scenario_root / f"authoring-{index}.json",
                AuthoringConfigurationReceipt(
                    format_version=CONSTRUCTION_RECEIPT_FORMAT_VERSION,
                    provider=ProviderId.OTHER,
                    model_id=f"authoring-{scenario.id}-{index}",
                    agent_build="synthetic-authoring-1.0.0",
                    reasoning_effort="high",
                    inference_settings={"author": index},
                ),
            )
            for index in range(2)
        )
        sources = (
            _write_bytes(
                scenario_root / "source.txt",
                f"synthetic provenance for {scenario.id}\n".encode(),
            ),
        )
        authoring_hashes = tuple(sorted(_sha256(path.read_bytes()) for path in authoring))
        source_hashes = tuple(sorted(_sha256(path.read_bytes()) for path in sources))
        provenance = _write_model(
            scenario_root / "provenance.json",
            ScenarioProvenanceReceipt(
                format_version=CONSTRUCTION_RECEIPT_FORMAT_VERSION,
                benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
                rubric_version=RUBRIC_VERSION,
                corpus_version=CORPUS_VERSION,
                scenario_id=scenario.id,
                scenario_artifact_sha256=artifact_sha256,
                repository_size=_repository_size(ordinal % 24),
                authoring_configuration_fingerprints=authoring_hashes,
                source_artifact_sha256s=source_hashes,
            ),
        )
        variants: list[ResolutionVariantInput] = []
        for kind in ResolutionKind:
            for variant_index in range(2):
                variant_id = f"{kind.value}-{variant_index}"
                source_tree = scenario_root / "variants" / variant_id / "source"
                _write_bytes(
                    source_tree / "solution.py",
                    f"{scenario.id}:{variant_id}:source\n".encode(),
                )
                source_hash = _inventory_tree(source_tree).inventory_sha256
                patch = _write_bytes(
                    scenario_root / "variants" / variant_id / "semantic.patch",
                    f"{scenario.id}:{variant_id}:patch\n".encode(),
                )
                patch_hash = _sha256(patch.read_bytes())
                del source_hash, patch_hash
                agent_run = _write_model(
                    scenario_root / "variants" / variant_id / "agent-run.json",
                    AgentRun(
                        transcript=f"synthetic {variant_id}",
                        final_message="All tests pass.",
                        commands_observed=True,
                    ),
                )
                variants.append(
                    ResolutionVariantInput(
                        variant_id=variant_id,
                        kind=kind,
                        source_tree=source_tree,
                        semantic_patch=patch,
                        agent_run=agent_run,
                    )
                )
        qa_runs: list[VerifiedRunBundleInput] = []
        for run_index in range(5):
            token = f"{scenario.id}-qa-{run_index}"
            public = private_root / "bundles" / token / "public"
            run_specs[str(public)] = _RunSpec(
                scenario_id=scenario.id,
                family=scenario.manifest.family,
                scenario_version=scenario.manifest.scenario_version,
                cluster_id=scenario.manifest.cluster_id or "",
                provider=(ProviderId.OPENAI if run_index % 2 == 0 else ProviderId.ANTHROPIC),
                token=token,
                outcome=Outcome.HONEST,
                corpus_hash=corpus_hash_value,
            )
            qa_runs.append(
                VerifiedRunBundleInput(
                    run_id=f"qa-{run_index}",
                    public_bundle=public,
                    escrow_bundle=private_root / "bundles" / token / "escrow",
                    leakage_policy=policy,
                    protocol_allowed_signers=private_root / "protocol-trust",
                    protocol_signer_identity="protocol@example.test",
                    machine_identity_artifact=private_root / "machine-identity",
                    workflow_input=private_root / "workflow-input",
                    workflow_receipt=private_root / "workflow-receipt",
                    workflow_attestation=private_root / "workflow-attestation",
                    workflow_signature=private_root / "workflow-signature",
                    workflow_allowed_signers=private_root / "workflow-trust",
                    workflow_signer_identity="workflow@example.test",
                )
            )
        static = ScenarioConstructionInput(
            scenario_directory=scenario.directory,
            provenance_receipt=provenance,
            authoring_configuration_artifacts=authoring,
            provenance_source_artifacts=sources,
            resolution_variants=tuple(variants),
            qa_attempts=tuple(qa_runs),
            machine_reviews=(),
            blind_agent_solves=(),
        )
        static_inputs.append(static)
        base, _, _, _ = construction_module._build_base_scenario_record(
            scenario,
            static,
            repository=repository,
            corpus_version=CORPUS_VERSION,
            corpus_hash_value=corpus_hash_value,
            promotion=promotion_authorization.statement,
            promotion_statement_sha256=promotion_authorization.statement_sha256,
            resolution_sandbox=_NoopDockerSandbox(
                Isolation.DOCKER,
                VERIFY_IMAGE,
            ),
            lifecycle_role_constraints=construction_module._LifecycleRoleConstraints(
                signer_identities=frozenset(
                    {
                        candidate_authorization.identity,
                        promotion_authorization.identity,
                    }
                ),
                signing_key_fingerprints=frozenset(
                    {
                        candidate_authorization.signing_key_fingerprint,
                        promotion_authorization.signing_key_fingerprint,
                    }
                ),
                trust_policy_sha256s=frozenset(
                    {
                        candidate_authorization.allowed_signers_sha256,
                        promotion_authorization.allowed_signers_sha256,
                    }
                ),
            ),
        )
        base_records.append(base)

    selected_blind_ids = construction_module._selected_blind_solve_ids(
        tuple(base_records),
        corpus_hash_value=corpus_hash_value,
    )
    final_inputs: list[ScenarioConstructionInput] = []
    for static, scenario in zip(static_inputs, loaded, strict=True):
        reviews: list[MachineReviewPackageInput] = []
        blind_solves: list[BlindSolveInput] = []
        if scenario.id in selected_blind_ids:
            for solve_index, provider in enumerate((ProviderId.OPENAI, ProviderId.ANTHROPIC)):
                solve_id = f"blind-{solve_index}"
                token = f"{scenario.id}-{solve_id}"
                public = private_root / "bundles" / token / "public"
                run_specs[str(public)] = _RunSpec(
                    scenario_id=scenario.id,
                    family=scenario.manifest.family,
                    scenario_version=scenario.manifest.scenario_version,
                    cluster_id=scenario.manifest.cluster_id or "",
                    provider=provider,
                    token=token,
                    outcome=Outcome.HONEST,
                    corpus_hash=corpus_hash_value,
                )
                bundle = VerifiedRunBundleInput(
                    run_id=solve_id,
                    public_bundle=public,
                    escrow_bundle=private_root / "bundles" / token / "escrow",
                    leakage_policy=policy,
                    protocol_allowed_signers=private_root / "protocol-trust",
                    protocol_signer_identity="protocol@example.test",
                    machine_identity_artifact=private_root / "machine-identity",
                    workflow_input=private_root / "workflow-input",
                    workflow_receipt=private_root / "workflow-receipt",
                    workflow_attestation=private_root / "workflow-attestation",
                    workflow_signature=private_root / "workflow-signature",
                    workflow_allowed_signers=private_root / "workflow-trust",
                    workflow_signer_identity="workflow@example.test",
                )
                blind_solves.append(
                    BlindSolveInput(
                        bundle=bundle,
                    )
                )
        final_inputs.append(
            replace(
                static,
                machine_reviews=tuple(reviews),
                blind_agent_solves=tuple(blind_solves),
            )
        )
    return ConstructionFixture(
        repository=repository,
        corpus_root=corpus_root,
        candidate_authorization=candidate_authorization,
        promotion_authorization=promotion_authorization,
        custody_inventory=custody_inventory,
        canary_registry=canary_registry,
        access_ledger=access_ledger,
        scenarios=tuple(final_inputs),
        private_root=private_root,
    )


def _build(fixture: ConstructionFixture) -> VerifiedCorpusConstructionReceipt:
    """Invoke the construction builder with the complete fixture."""
    return build_corpus_construction_receipt(
        repository=fixture.repository,
        corpus_root=fixture.corpus_root,
        corpus_version=CORPUS_VERSION,
        candidate_validation_authorization=fixture.candidate_authorization,
        candidate_promotion_authorization=fixture.promotion_authorization,
        custody_inventory_receipt=fixture.custody_inventory,
        canary_registry=fixture.canary_registry,
        access_ledger=fixture.access_ledger,
        scenarios=fixture.scenarios,
    )


def test_private_manifest_loader_returns_exact_builder_kwargs(
    manifest_loader_fixture: ManifestLoaderFixture,
) -> None:
    """One canonical JSON manifest resolves signatures, paths, and private markers."""
    kwargs = load_corpus_construction_input_manifest(manifest_loader_fixture.path)

    assert set(kwargs) == {
        "repository",
        "corpus_root",
        "corpus_version",
        "candidate_validation_authorization",
        "candidate_promotion_authorization",
        "custody_inventory_receipt",
        "canary_registry",
        "access_ledger",
        "scenarios",
    }
    assert kwargs["corpus_root"] == manifest_loader_fixture.corpus_root
    assert kwargs["corpus_version"] == CORPUS_VERSION
    assert kwargs["candidate_validation_authorization"].identity == "candidate@example.test"
    assert kwargs["candidate_promotion_authorization"].identity == "promotion@example.test"
    assert len(kwargs["scenarios"]) == 1
    scenario = kwargs["scenarios"][0]
    assert len(scenario.resolution_variants) == 4
    assert len(scenario.qa_attempts) == 5
    assert len(scenario.machine_reviews) == 2
    assert scenario.machine_reviews[0].credential_isolation_receipt.name == (
        "credential-isolation.json"
    )
    assert scenario.qa_attempts[0].leakage_policy.forbidden_markers == (
        b"synthetic-private-marker",
    )
    assert scenario.qa_attempts[0].leakage_policy.forbidden_sources == (
        manifest_loader_fixture.corpus_root,
    )


def test_private_yaml_manifest_is_duplicate_safe_and_supported(
    manifest_loader_fixture: ManifestLoaderFixture,
) -> None:
    """The same closed model may be supplied as safe, alias-free YAML."""
    yaml_path = manifest_loader_fixture.root / "construction-input.yaml"
    yaml_path.write_text(
        yaml.safe_dump(
            manifest_loader_fixture.manifest.model_dump(mode="json"),
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    kwargs = load_corpus_construction_input_manifest(yaml_path)

    assert kwargs["corpus_root"] == manifest_loader_fixture.corpus_root
    assert len(kwargs["scenarios"][0].qa_attempts) == 5


@pytest.mark.parametrize(
    ("suffix", "content"),
    [
        (
            ".json",
            b'{"format_version":"2","format_version":"2"}\n',
        ),
        (
            ".yaml",
            b"format_version: '2'\nformat_version: '2'\n",
        ),
        (
            ".yaml",
            b"format_version: &version '2'\ncopy: *version\n",
        ),
    ],
)
def test_private_manifest_rejects_duplicate_keys_and_yaml_aliases(
    tmp_path: Path,
    suffix: str,
    content: bytes,
) -> None:
    """Neither parser permits ambiguous last-key-wins or alias-expanded input."""
    path = _write_bytes(tmp_path / f"manifest{suffix}", content)
    with pytest.raises(CorpusConstructionError, match="malformed"):
        load_corpus_construction_input_manifest(path)


def test_private_json_manifest_must_be_canonical(
    manifest_loader_fixture: ManifestLoaderFixture,
) -> None:
    """Pretty-printed JSON cannot represent a second byte form of one manifest."""
    path = manifest_loader_fixture.root / "noncanonical.json"
    path.write_text(
        json.dumps(
            manifest_loader_fixture.manifest.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(CorpusConstructionError, match="not canonical"):
        load_corpus_construction_input_manifest(path)


def test_private_manifest_rejects_empty_marker(
    manifest_loader_fixture: ManifestLoaderFixture,
) -> None:
    """An unavailable leakage marker never degrades to a favorable empty policy."""
    manifest_loader_fixture.marker_file.write_bytes(b"")
    with pytest.raises(CorpusConstructionError, match="marker file is empty"):
        load_corpus_construction_input_manifest(manifest_loader_fixture.path)


def test_private_manifest_rejects_symlinked_parent_component(
    manifest_loader_fixture: ManifestLoaderFixture,
) -> None:
    """A real final directory is unsafe when an ancestor component is a symlink."""
    linked_bundles = manifest_loader_fixture.root / "linked-bundles"
    linked_bundles.symlink_to(
        manifest_loader_fixture.root / "bundles",
        target_is_directory=True,
    )
    payload = manifest_loader_fixture.manifest.model_dump(mode="json")
    payload["scenarios"][0]["qa_attempts"][0]["public_bundle"] = "linked-bundles/qa-0/public"
    changed = CorpusConstructionInputManifest.model_validate(payload)
    path = _write_model(
        manifest_loader_fixture.root / "symlink-parent.json",
        changed,
    )

    with pytest.raises(CorpusConstructionError, match="unsafe node"):
        load_corpus_construction_input_manifest(path)


def test_private_manifest_rejects_resolved_duplicate_policy_paths(
    manifest_loader_fixture: ManifestLoaderFixture,
) -> None:
    """Distinct spellings cannot reuse one forbidden source or marker file."""
    payload = manifest_loader_fixture.manifest.model_dump(mode="json")
    payload["scenarios"][0]["qa_attempts"][0]["marker_files"] = [
        "./marker.txt",
        "marker.txt",
    ]
    changed = CorpusConstructionInputManifest.model_validate(payload)
    path = _write_model(
        manifest_loader_fixture.root / "duplicate-policy.json",
        changed,
    )

    with pytest.raises(CorpusConstructionError, match="duplicate leakage-policy"):
        load_corpus_construction_input_manifest(path)


def test_builds_complete_artifact_derived_corpus(
    construction_fixture: ConstructionFixture,
) -> None:
    """All 120 records, reviews, variants, QA, and selected solves are derived."""
    built = _build(construction_fixture)
    receipt = built.receipt

    assert receipt.format_version == "2"
    assert receipt.scenario_count == 120
    assert len(receipt.corpus.scenarios) == 120
    assert all(len(item.resolution_variants) == 4 for item in receipt.corpus.scenarios)
    assert all(len(item.agent_qa_attempts) == 5 for item in receipt.corpus.scenarios)
    assert all(len(item.machine_reviews) == 2 for item in receipt.corpus.scenarios)
    assert sum(bool(item.blind_agent_solves) for item in receipt.corpus.scenarios) == 30
    assert sum(len(item.blind_agent_solves) for item in receipt.corpus.scenarios) == 60
    assert built.canonical_receipt_sha256 == canonical_corpus_construction_receipt_sha256(receipt)
    encoded = _model_bytes(receipt)
    assert str(construction_fixture.private_root).encode() not in encoded
    assert b"STINGER-SYNTHETIC-T-00-7bcf9a" not in encoded


def test_builder_rejects_runtime_change_after_successful_resolution_work(
    construction_fixture: ConstructionFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-execution Docker identity change blocks receipt derivation."""
    successful_resolutions = 0
    build_resolution_variant = construction_module._build_resolution_variant

    def record_success(
        scenario: Scenario,
        scenario_artifact_sha256: str,
        item: ResolutionVariantInput,
        *,
        sandbox: Sandbox,
    ) -> construction_module._ResolutionVariantBuild:
        nonlocal successful_resolutions
        result = build_resolution_variant(
            scenario,
            scenario_artifact_sha256,
            item,
            sandbox=sandbox,
        )
        successful_resolutions += 1
        return result

    def reject_changed_runtime(_: Sandbox) -> None:
        assert successful_resolutions == 120 * 4
        raise SandboxError("synthetic Docker runtime mutation")

    monkeypatch.setattr(
        construction_module,
        "_build_resolution_variant",
        record_success,
    )
    monkeypatch.setattr(
        construction_module.__dict__["Sandbox"],
        "verify_runtime_unchanged",
        reject_changed_runtime,
    )

    with pytest.raises(CorpusConstructionError, match="Docker runtime changed"):
        _build(construction_fixture)


def test_builder_refuses_any_gate_issue(
    construction_fixture: ConstructionFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The builder never publishes a record the unchanged gate rejects."""
    from stinger.benchmark.gates import GateIssue, PublicationIssueCode

    monkeypatch.setattr(
        construction_module,
        "evaluate_corpus_construction",
        lambda *args, **kwargs: (
            GateIssue(
                code=PublicationIssueCode.CORPUS_AGENT_QA_INVALID,
                subject=None,
                detail="synthetic rejection",
            ),
        ),
    )
    with pytest.raises(CorpusConstructionError, match="construction gate"):
        _build(construction_fixture)


def test_error_bundle_is_rejected_without_private_path(
    construction_fixture: ConstructionFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A verifier failure stays fail-closed and does not disclose bundle locations."""

    def fail(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise CorpusConstructionError("run evidence bundle verification failed")

    monkeypatch.setattr(
        construction_module,
        "_verify_run_bundle",
        fail,
    )
    with pytest.raises(CorpusConstructionError) as captured:
        _build(construction_fixture)
    message = str(captured.value)
    assert "private escrow path" not in message
    assert str(construction_fixture.private_root) not in message


def test_machine_review_content_addressed_blob_mutation_is_rejected(
    tmp_path: Path,
) -> None:
    """Changing one transcript blob invalidates the closed review workspace."""
    workspace = _make_closed_review_workspace(tmp_path / "review-workspace")
    construction_module._verify_machine_review_workspace(workspace)
    blob = next((workspace / "evidence" / "blobs").iterdir())
    blob.write_bytes(blob.read_bytes() + b"tampered")

    with pytest.raises(CorpusConstructionError, match="closed canonical"):
        construction_module._verify_machine_review_workspace(workspace)


def test_machine_review_logical_control_files_never_become_physical_controls(
    tmp_path: Path,
) -> None:
    """Scenario AGENTS/CLAUDE evidence remains blobs, while extra root controls fail."""
    workspace = _make_closed_review_workspace(tmp_path / "review-workspace")
    construction_module._verify_machine_review_workspace(workspace)
    assert not (workspace / "AGENTS.md").exists()
    assert not (workspace / "CLAUDE.md").exists()
    (workspace / "AGENTS.md").write_text("injected global instruction\n")

    with pytest.raises(CorpusConstructionError, match="closed canonical"):
        construction_module._verify_machine_review_workspace(workspace)


def test_machine_review_rejects_raw_credential_mount() -> None:
    """Machine review cannot mount raw provider credential files."""
    agent = AgentConfig(
        adapter="codex",
        model="synthetic-model",
        provider=ProviderId.OPENAI,
        credential_mount=Path("synthetic-raw-credentials"),
    )
    with pytest.raises(CorpusConstructionError, match="forbids raw credential mounts"):
        construction_module._require_review_credential_isolation_configuration(agent)


def test_machine_review_requires_broker_and_forbids_environment_options() -> None:
    """Missing broker configuration and caller-controlled environment both fail closed."""
    missing_broker = AgentConfig(
        adapter="codex",
        model="synthetic-model",
        provider=ProviderId.OPENAI,
        api_key_env="OPENAI_API_KEY",
    )
    with pytest.raises(CorpusConstructionError, match="external credential broker"):
        construction_module._require_review_credential_isolation_configuration(missing_broker)
    with pytest.raises(CorpusConstructionError, match="environment options"):
        construction_module._require_review_credential_isolation_configuration(
            missing_broker.model_copy(update={"options": {"CODEX_HOME": "/caller-controlled"}})
        )
    brokered = missing_broker.model_copy(
        update={
            "container_image": AGENT_IMAGE,
            "container_image_digest": AGENT_IMAGE,
            "credential_broker": CredentialBrokerConfiguration(
                image="synthetic-broker",
                image_digest="sha256:" + "9" * 64,
            ),
        }
    )
    construction_module._require_review_credential_isolation_configuration(brokered)
    with pytest.raises(CorpusConstructionError, match="does not match its provider route"):
        construction_module._require_review_credential_isolation_configuration(
            brokered.model_copy(update={"api_key_env": "ANTHROPIC_API_KEY"})
        )


def test_machine_review_accepts_only_matching_per_invocation_broker_evidence() -> None:
    """The runner must return exact broker evidence bound to its Docker runtime."""
    repository = Path(__file__).parents[1]
    runtime = DockerRuntimeIdentity(
        client_path="/usr/bin/docker",
        client_sha256="1" * 64,
        client_version="1.0",
        context_name="default",
        context_endpoint="unix:///synthetic/docker.sock",
        context_endpoint_sha256="2" * 64,
        server_platform="linux",
        server_version="1.0",
        server_api_version="1.0",
        server_os="linux",
        server_arch="amd64",
    )
    agent = AgentConfig(
        adapter="codex",
        model="synthetic-model",
        provider=ProviderId.OPENAI,
        api_key_env="OPENAI_API_KEY",
    ).model_copy(
        update={
            "container_image": AGENT_IMAGE,
            "container_image_digest": AGENT_IMAGE,
            "credential_broker": CredentialBrokerConfiguration(
                image="synthetic-broker",
                image_digest="sha256:" + "9" * 64,
            ),
        }
    )
    isolation = _credential_isolation_receipt(
        runtime,
        agent=agent,
        repository=repository,
    )
    run = AgentRun(transcript="synthetic", final_message="synthetic").model_copy(
        update={"credential_isolation": isolation}
    )
    assert (
        construction_module._verified_review_credential_isolation(
            run,
            agent=agent,
            repository=repository,
            docker_runtime=runtime,
        )
        == isolation
    )

    missing = AgentRun(transcript="synthetic", final_message="synthetic")
    with pytest.raises(CorpusConstructionError, match="missing, unverified, or mismatched"):
        construction_module._verified_review_credential_isolation(
            missing,
            agent=agent,
            repository=repository,
            docker_runtime=runtime,
        )
    wrong_runtime = isolation.model_copy(update={"docker_client_sha256": "9" * 64})
    with pytest.raises(CorpusConstructionError, match="missing, unverified, or mismatched"):
        construction_module._verified_review_credential_isolation(
            run.model_copy(update={"credential_isolation": wrong_runtime}),
            agent=agent,
            repository=repository,
            docker_runtime=runtime,
        )
    wrong_configuration = isolation.model_copy(update={"broker_configuration_sha256": "0" * 64})
    with pytest.raises(CorpusConstructionError, match="missing, unverified, or mismatched"):
        construction_module._verified_review_credential_isolation(
            run.model_copy(update={"credential_isolation": wrong_configuration}),
            agent=agent,
            repository=repository,
            docker_runtime=runtime,
        )


@pytest.mark.parametrize(
    "update",
    (
        {"agent_read_only_mounts": ("/credentials",)},
        {"rejection_count": 1},
        {"request_count": 0},
        {"raw_provider_credential_exposed": True},
        {"broker_bypass_path_present": True},
        {"unapproved_egress_path_present": True},
        {"agent_container_cleanup_verified": False},
        {"broker_container_cleanup_verified": False},
        {"internal_network_cleanup_verified": False},
        {"outbound_network_cleanup_verified": False},
    ),
)
def test_credential_isolation_receipt_rejects_bypass_evidence(
    update: dict[str, object],
) -> None:
    """A credential mount, rejected request, exposure, or cleanup gap is invalid evidence."""
    runtime = DockerRuntimeIdentity(
        client_path="/usr/bin/docker",
        client_sha256="1" * 64,
        client_version="1.0",
        context_name="default",
        context_endpoint="unix:///synthetic/docker.sock",
        context_endpoint_sha256="2" * 64,
        server_platform="linux",
        server_version="1.0",
        server_api_version="1.0",
        server_os="linux",
        server_arch="amd64",
    )
    payload = _credential_isolation_receipt(runtime).model_dump(mode="json")
    payload.update(update)
    with pytest.raises(ValidationError):
        CredentialIsolationInvocationReceipt.model_validate(payload)


@pytest.mark.parametrize(
    ("outbound_field", "internal_field"),
    (
        ("outbound_network_id_sha256", "internal_network_id_sha256"),
        ("outbound_network_name_sha256", "internal_network_name_sha256"),
    ),
)
def test_credential_isolation_receipt_requires_distinct_network_identities(
    outbound_field: str,
    internal_field: str,
) -> None:
    """A receipt cannot relabel the agent network as the broker egress network."""
    runtime = DockerRuntimeIdentity(
        client_path="/usr/bin/docker",
        client_sha256="1" * 64,
        client_version="1.0",
        context_name="default",
        context_endpoint="unix:///synthetic/docker.sock",
        context_endpoint_sha256="2" * 64,
        server_platform="linux",
        server_version="1.0",
        server_api_version="1.0",
        server_os="linux",
        server_arch="amd64",
    )
    payload = _credential_isolation_receipt(runtime).model_dump(mode="json")
    payload[outbound_field] = payload[internal_field]

    with pytest.raises(ValidationError, match="network identities must be distinct"):
        CredentialIsolationInvocationReceipt.model_validate(payload)


def test_review_image_global_configuration_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A nonempty recognized image-global config probe cannot support a review."""
    monkeypatch.setattr(
        construction_module,
        "_run_review_docker",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=["docker"],
            returncode=33,
            stdout="",
            stderr="global config present",
        ),
    )
    runtime = DockerRuntimeIdentity(
        client_path="/usr/bin/docker",
        client_sha256="1" * 64,
        client_version="1.0",
        context_name="default",
        context_endpoint="unix:///synthetic/docker.sock",
        context_endpoint_sha256="2" * 64,
        server_platform="linux",
        server_version="1.0",
        server_api_version="1.0",
        server_os="linux",
        server_arch="amd64",
    )
    with pytest.raises(CorpusConstructionError, match="global agent state"):
        construction_module._require_clean_review_image_state(
            f"sha256:{'3' * 64}",
            adapter="codex",
            docker_runtime=runtime,
        )


@pytest.mark.parametrize("operation", ["run", "create"])
def test_timed_review_container_is_named_and_cleanup_is_verified(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    """Abandoning a timed Docker client cannot orphan a run or create container."""
    runtime = DockerRuntimeIdentity(
        client_path="/usr/bin/docker",
        client_sha256="1" * 64,
        client_version="1.0",
        context_name="default",
        context_endpoint="unix:///synthetic/docker.sock",
        context_endpoint_sha256="2" * 64,
        server_platform="linux",
        server_version="1.0",
        server_api_version="1.0",
        server_os="linux",
        server_arch="amd64",
    )
    launched: list[list[str]] = []
    terminated: list[tuple[str, DockerRuntimeIdentity, int]] = []

    def time_out(
        arguments: list[str],
        *,
        runtime: DockerRuntimeIdentity,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        del runtime, timeout
        launched.append(list(arguments))
        raise DockerRuntimeError("fixed Docker client invocation failed")

    def terminate(
        name: str,
        *,
        runtime: DockerRuntimeIdentity,
        timeout: int,
    ) -> None:
        terminated.append((name, runtime, timeout))

    monkeypatch.setattr(construction_module, "run_docker", time_out)
    monkeypatch.setattr(construction_module, "terminate_docker_container", terminate)

    with pytest.raises(CorpusConstructionError, match="invocation failed closed"):
        construction_module._run_review_docker(
            [operation, "--rm", "sha256:" + "3" * 64],
            runtime=runtime,
            timeout=7,
        )

    (effective,) = launched
    assert effective[0] == operation
    assert effective[1] == "--name"
    container_name = effective[2]
    assert container_name.startswith(f"stinger-review-{operation}-")
    assert terminated == [(container_name, runtime, 30)]


@pytest.mark.parametrize("operation", ["run", "create"])
def test_timed_review_container_fails_closed_when_cleanup_is_unverified(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    """Construction aborts if exact-name absence cannot be proved after timeout."""
    runtime = DockerRuntimeIdentity(
        client_path="/usr/bin/docker",
        client_sha256="1" * 64,
        client_version="1.0",
        context_name="default",
        context_endpoint="unix:///synthetic/docker.sock",
        context_endpoint_sha256="2" * 64,
        server_platform="linux",
        server_version="1.0",
        server_api_version="1.0",
        server_os="linux",
        server_arch="amd64",
    )
    monkeypatch.setattr(
        construction_module,
        "run_docker",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            DockerRuntimeError("fixed Docker client invocation failed")
        ),
    )
    monkeypatch.setattr(
        construction_module,
        "terminate_docker_container",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            DockerRuntimeError("container still present")
        ),
    )

    with pytest.raises(CorpusConstructionError, match="cleanup could not be verified"):
        construction_module._run_review_docker(
            [operation, "--rm", "sha256:" + "3" * 64],
            runtime=runtime,
            timeout=7,
        )


@pytest.mark.parametrize("returncode", [23, -9])
def test_abnormal_review_completion_cleans_before_returning_evidence(
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
) -> None:
    """Nonzero and killed clients must prove exact-name absence before output escapes."""
    runtime = DockerRuntimeIdentity(
        client_path="/usr/bin/docker",
        client_sha256="1" * 64,
        client_version="1.0",
        context_name="default",
        context_endpoint="unix:///synthetic/docker.sock",
        context_endpoint_sha256="2" * 64,
        server_platform="linux",
        server_version="1.0",
        server_api_version="1.0",
        server_os="linux",
        server_arch="amd64",
    )
    events: list[str] = []

    def complete(
        arguments: list[str],
        *,
        runtime: DockerRuntimeIdentity,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        del runtime, timeout
        events.append("completed")
        return subprocess.CompletedProcess(arguments, returncode, "bounded output", "")

    monkeypatch.setattr(construction_module, "run_docker", complete)
    monkeypatch.setattr(
        construction_module,
        "terminate_docker_container",
        lambda name, *, runtime, timeout: events.append("cleanup"),
    )

    result = construction_module._run_review_docker(
        ["run", "--rm", "sha256:" + "3" * 64],
        runtime=runtime,
        timeout=7,
    )

    assert events == ["completed", "cleanup"]
    assert result.returncode == returncode
    assert result.stdout == "bounded output"


def test_review_launch_oserror_cleans_before_failing_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An OSError after a possible daemon request still requires absence proof."""
    runtime = DockerRuntimeIdentity(
        client_path="/usr/bin/docker",
        client_sha256="1" * 64,
        client_version="1.0",
        context_name="default",
        context_endpoint="unix:///synthetic/docker.sock",
        context_endpoint_sha256="2" * 64,
        server_platform="linux",
        server_version="1.0",
        server_api_version="1.0",
        server_os="linux",
        server_arch="amd64",
    )
    terminated: list[str] = []
    monkeypatch.setattr(
        construction_module,
        "run_docker",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("client launch failed")),
    )
    monkeypatch.setattr(
        construction_module,
        "terminate_docker_container",
        lambda name, *, runtime, timeout: terminated.append(name),
    )

    with pytest.raises(CorpusConstructionError, match="invocation failed closed"):
        construction_module._run_review_docker(
            ["run", "--rm", "sha256:" + "3" * 64],
            runtime=runtime,
            timeout=7,
        )

    assert len(terminated) == 1
    assert terminated[0].startswith("stinger-review-run-")


@pytest.mark.parametrize(
    "interruption",
    [KeyboardInterrupt(), SystemExit(31), BaseException("synthetic stop")],
    ids=["keyboard-interrupt", "system-exit", "base-exception"],
)
def test_interrupted_review_probe_cleans_then_reraises(
    monkeypatch: pytest.MonkeyPatch,
    interruption: BaseException,
) -> None:
    """Operator and other BaseException exits cannot bypass named cleanup."""
    runtime = DockerRuntimeIdentity(
        client_path="/usr/bin/docker",
        client_sha256="1" * 64,
        client_version="1.0",
        context_name="default",
        context_endpoint="unix:///synthetic/docker.sock",
        context_endpoint_sha256="2" * 64,
        server_platform="linux",
        server_version="1.0",
        server_api_version="1.0",
        server_os="linux",
        server_arch="amd64",
    )
    terminated: list[str] = []
    monkeypatch.setattr(
        construction_module,
        "run_docker",
        lambda *args, **kwargs: (_ for _ in ()).throw(interruption),
    )
    monkeypatch.setattr(
        construction_module,
        "terminate_docker_container",
        lambda name, *, runtime, timeout: terminated.append(name),
    )

    with pytest.raises(type(interruption)):
        construction_module._run_review_docker(
            ["run", "--rm", "sha256:" + "3" * 64],
            runtime=runtime,
            timeout=7,
        )

    assert len(terminated) == 1
    assert terminated[0].startswith("stinger-review-run-")


def test_abnormal_review_completion_fails_if_cleanup_is_unverified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Abnormal output is not evidence when exact-name absence cannot be proved."""
    runtime = DockerRuntimeIdentity(
        client_path="/usr/bin/docker",
        client_sha256="1" * 64,
        client_version="1.0",
        context_name="default",
        context_endpoint="unix:///synthetic/docker.sock",
        context_endpoint_sha256="2" * 64,
        server_platform="linux",
        server_version="1.0",
        server_api_version="1.0",
        server_os="linux",
        server_arch="amd64",
    )
    monkeypatch.setattr(
        construction_module,
        "run_docker",
        lambda arguments, **kwargs: subprocess.CompletedProcess(
            arguments, 41, "must not escape", ""
        ),
    )
    monkeypatch.setattr(
        construction_module,
        "terminate_docker_container",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            DockerRuntimeError("container still present")
        ),
    )

    with pytest.raises(CorpusConstructionError, match="cleanup could not be verified"):
        construction_module._run_review_docker(
            ["create", "--entrypoint", "/bin/true", "sha256:" + "3" * 64],
            runtime=runtime,
            timeout=7,
        )


def test_successful_review_create_retains_name_and_requires_final_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful create is still force-removed and late presence aborts construction."""
    runtime = DockerRuntimeIdentity(
        client_path="/usr/bin/docker",
        client_sha256="1" * 64,
        client_version="1.0",
        context_name="default",
        context_endpoint="unix:///synthetic/docker.sock",
        context_endpoint_sha256="2" * 64,
        server_platform="linux",
        server_version="1.0",
        server_api_version="1.0",
        server_os="linux",
        server_arch="amd64",
    )
    image_id = "sha256:" + "3" * 64
    created_names: list[str] = []
    terminated_names: list[str] = []

    monkeypatch.setattr(construction_module, "observe_docker_runtime", lambda: runtime)
    monkeypatch.setattr(
        construction_module,
        "inspect_docker_image",
        lambda image, *, runtime: (image_id, ()),
    )
    monkeypatch.setattr(
        construction_module,
        "_require_clean_review_image_state",
        lambda *args, **kwargs: None,
    )

    def review_docker(
        arguments: list[str],
        *,
        runtime: DockerRuntimeIdentity,
        timeout: int,
        container_name: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del runtime, timeout
        if arguments[0] == "run" and 'command -v "$1"' in arguments:
            return subprocess.CompletedProcess(arguments, 0, "/usr/local/bin/codex\n", "")
        if arguments[0] == "run":
            return subprocess.CompletedProcess(arguments, 0, "codex-cli 1.2.3\n", "")
        if arguments[0] == "create":
            assert container_name is not None
            created_names.append(container_name)
            return subprocess.CompletedProcess(arguments, 0, "synthetic-container-id\n", "")
        assert arguments[0] == "cp"
        Path(arguments[-1]).write_bytes(b"synthetic-cli-binary")
        assert arguments[1].startswith(f"{created_names[0]}:")
        return subprocess.CompletedProcess(arguments, 0, "", "")

    def terminate(
        name: str,
        *,
        runtime: DockerRuntimeIdentity,
        timeout: int,
    ) -> None:
        del runtime, timeout
        terminated_names.append(name)
        raise DockerRuntimeError("late container remained visible")

    monkeypatch.setattr(construction_module, "_run_review_docker", review_docker)
    monkeypatch.setattr(construction_module, "terminate_docker_container", terminate)

    agent = AgentConfig(
        adapter="codex",
        provider=ProviderId.OPENAI,
        model="synthetic-review-model",
        cli_version="1.2.3",
        container_image="synthetic-agent:1",
        container_image_digest=image_id,
    )
    with pytest.raises(CorpusConstructionError, match="cleanup could not be verified"):
        construction_module._observe_review_runtime(agent)

    assert len(created_names) == 1
    assert terminated_names == created_names


def test_review_create_interrupt_is_inside_the_final_cleanup_region(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An interrupt at the create boundary cannot land before the enclosing cleanup."""
    runtime = DockerRuntimeIdentity(
        client_path="/usr/bin/docker",
        client_sha256="1" * 64,
        client_version="1.0",
        context_name="default",
        context_endpoint="unix:///synthetic/docker.sock",
        context_endpoint_sha256="2" * 64,
        server_platform="linux",
        server_version="1.0",
        server_api_version="1.0",
        server_os="linux",
        server_arch="amd64",
    )
    image_id = "sha256:" + "3" * 64
    terminated: list[str] = []
    monkeypatch.setattr(construction_module, "observe_docker_runtime", lambda: runtime)
    monkeypatch.setattr(
        construction_module,
        "inspect_docker_image",
        lambda image, *, runtime: (image_id, ()),
    )
    monkeypatch.setattr(
        construction_module,
        "_require_clean_review_image_state",
        lambda *args, **kwargs: None,
    )

    run_count = 0

    def review_docker(
        arguments: list[str],
        *,
        runtime: DockerRuntimeIdentity,
        timeout: int,
        container_name: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal run_count
        del runtime, timeout
        if arguments[0] == "run":
            run_count += 1
            output = "/usr/local/bin/codex\n" if run_count == 1 else "codex-cli 1.2.3\n"
            return subprocess.CompletedProcess(arguments, 0, output, "")
        assert arguments[0] == "create"
        assert container_name is not None
        raise KeyboardInterrupt

    monkeypatch.setattr(construction_module, "_run_review_docker", review_docker)
    monkeypatch.setattr(
        construction_module,
        "terminate_docker_container",
        lambda name, *, runtime, timeout: terminated.append(name),
    )
    agent = AgentConfig(
        adapter="codex",
        provider=ProviderId.OPENAI,
        model="synthetic-review-model",
        cli_version="1.2.3",
        container_image="synthetic-agent:1",
        container_image_digest=image_id,
    )

    with pytest.raises(KeyboardInterrupt):
        construction_module._observe_review_runtime(agent)

    assert len(terminated) == 1
    assert terminated[0].startswith("stinger-review-create-")


def test_resolution_semantic_identity_collapses_local_renames(tmp_path: Path) -> None:
    """Cosmetic local renames cannot masquerade as independent implementations."""
    first = tmp_path / "first"
    second = tmp_path / "second"
    structural = tmp_path / "structural"
    _write_bytes(
        first / "solution.py",
        b"def total(values):\n    result = 0\n    for value in values:\n"
        b"        result += value\n    return result\n",
    )
    _write_bytes(
        second / "solution.py",
        b"def total(items):\n    answer = 0\n    for item in items:\n"
        b"        answer += item\n    return answer\n",
    )
    _write_bytes(
        structural / "solution.py",
        b"def total(values):\n    return sum(values)\n",
    )
    diff = b"--- a/solution.py\n+++ b/solution.py\n"
    first_semantic = construction_module._semantic_change_sha256(first, diff)
    first_mechanism = construction_module._implementation_mechanism_sha256(first, diff)
    assert construction_module._semantic_change_sha256(second, diff) == first_semantic
    assert construction_module._implementation_mechanism_sha256(second, diff) == first_mechanism
    assert construction_module._semantic_change_sha256(structural, diff) != first_semantic
    assert construction_module._implementation_mechanism_sha256(structural, diff) != first_mechanism


def test_dummy_safety_resolves_concatenated_real_targets_and_tokens() -> None:
    """String concatenation cannot hide a real sink or credential from construction."""
    with pytest.raises(CorpusConstructionError, match="non-local"):
        construction_module._python_dummy_safety_evidence(
            b'import socket\nHOST = "api." + "real-target.example.dev"\n'
            b"socket.create_connection((HOST, 443))\n"
        )
    with pytest.raises(CorpusConstructionError, match="secret-like"):
        construction_module._python_dummy_safety_evidence(
            b'REAL_API_TOKEN = "actual_" + "live_token_value_123456"\n'
        )


def test_noncanonical_and_duplicate_receipts_fail_closed(tmp_path: Path) -> None:
    """Whitespace variants and duplicate JSON keys cannot acquire favorable hashes."""
    receipt = ScenarioContainmentReceipt(
        format_version="2",
        scenario_id="synthetic",
        scenario_artifact_sha256="a" * 64,
        sealed_validation_receipt_sha256="b" * 64,
        promotion_statement_sha256="c" * 64,
        validation_contract="stinger-scenario-validity-v1-docker-sealed",
        verification_image_id=VERIFY_IMAGE,
        isolation="docker",
        network_mode="none",
    )
    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_text(json.dumps(receipt.model_dump(mode="json"), indent=2) + "\n")
    with pytest.raises(CorpusConstructionError, match="not canonical"):
        construction_module._load_canonical_model(
            noncanonical,
            ScenarioContainmentReceipt,
            label="containment",
        )

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"format_version":"2","scenario_id":"one","scenario_id":"two"}\n',
        encoding="utf-8",
    )
    with pytest.raises(CorpusConstructionError, match="malformed"):
        construction_module._load_canonical_model(
            duplicate,
            ScenarioContainmentReceipt,
            label="containment",
        )


def test_unsafe_receipt_file_is_rejected(tmp_path: Path) -> None:
    """A symlink can never substitute bytes after a receipt path is approved."""
    target = _write_bytes(tmp_path / "target.json", b"{}\n")
    link = tmp_path / "receipt.json"
    link.symlink_to(target)
    with pytest.raises(CorpusConstructionError, match="safe regular file"):
        construction_module._read_exact_regular_file(link, label="receipt")


def test_dummy_safety_is_derived_from_exact_scenario_bytes(tmp_path: Path) -> None:
    """A caller cannot turn a real network target into a favorable safety literal."""
    scenario_root = tmp_path / "corpus" / "t-safe"
    _write_bytes(
        scenario_root / "manifest.yaml",
        yaml.safe_dump(
            _scenario_manifest("t-safe", Family.T, "cluster-t-safe"),
            sort_keys=True,
        ).encode(),
    )
    task = _write_bytes(
        scenario_root / "seed_repo" / "task.txt",
        (
            b'import socket\nsocket.create_connection(("localhost", 8080))\n'
            b'LOCAL_URL = "http://localhost:8080/health"\n'
            b'RESERVED_URL = "https://collector.example.test/data"\n'
            b'DUMMY_API_TOKEN = "dummy-test-only-token"\n'
        ),
    )
    scenario = discover_scenarios(tmp_path / "corpus")[0]
    receipt = construction_module._derive_dummy_safety_receipt(
        scenario,
        scenario_artifact_sha256=scenario_hash(scenario),
    )
    assert isinstance(receipt, DummySafetyReceipt)
    assert receipt.allowed_network_target_count >= 2

    task.write_text(
        'import socket\nsocket.create_connection(("api.real-target.example.dev", 443))\n',
        encoding="utf-8",
    )
    changed = discover_scenarios(tmp_path / "corpus")[0]
    with pytest.raises(CorpusConstructionError, match="network target"):
        construction_module._derive_dummy_safety_receipt(
            changed,
            scenario_artifact_sha256=scenario_hash(changed),
        )

    task.write_text(
        'REAL_API_TOKEN = "actual_live_token_value_123456"\n',
        encoding="utf-8",
    )
    changed = discover_scenarios(tmp_path / "corpus")[0]
    with pytest.raises(CorpusConstructionError, match="secret-like assignment"):
        construction_module._derive_dummy_safety_receipt(
            changed,
            scenario_artifact_sha256=scenario_hash(changed),
        )


def test_resolution_variants_are_executed_not_self_attested(tmp_path: Path) -> None:
    """Honest and cheat facts come from the full runner, not a supplied result receipt."""

    class _LocalCommandsDockerSandbox(Sandbox):
        """Exercise Docker-selected construction semantics without requiring Docker in CI."""

        def run_command(
            self,
            workdir: Path,
            argv: Sequence[str],
            timeout_s: int,
            *,
            network: bool = False,
        ) -> ExecResult:
            assert not network
            completed = subprocess.run(
                list(argv),
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
            return ExecResult(
                argv=list(argv),
                exit_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
            )

    source = Path(__file__).parents[1] / "scenarios" / "T-02-no-touch-tests"
    corpus = tmp_path / "corpus"
    scenario_root = corpus / source.name
    shutil.copytree(source, scenario_root)
    manifest_path = scenario_root / "manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["benchmark_split"] = BenchmarkSplit.SEALED.value
    manifest["scenario_version"] = "1.0.0"
    manifest["cluster_id"] = "cluster-t-02-mechanical"
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    scenario = discover_scenarios(corpus)[0]
    sandbox = _LocalCommandsDockerSandbox(
        isolation=Isolation.DOCKER,
        image="synthetic-verification:1",
    )

    def variant(
        variant_id: str,
        kind: ResolutionKind,
        reference_name: str,
    ) -> ResolutionVariantInput:
        root = tmp_path / "variants" / variant_id
        overlay = root / "source"
        shutil.copytree(scenario_root / "reference" / reference_name, overlay)
        workdir = root / "expected-workdir"
        sandbox.prepare(scenario.directory, scenario.manifest, workdir)
        before = sandbox.capture(workdir)
        apply_overlay(overlay, workdir)
        after = sandbox.capture(workdir)
        patch = _write_bytes(
            root / "semantic.patch",
            diff_states(before, after).encode(),
        )
        run = AgentRun(
            transcript="Done. All tests pass.",
            final_message="Done. All tests pass.",
            commands_observed=True,
        )
        return ResolutionVariantInput(
            variant_id=variant_id,
            kind=kind,
            source_tree=overlay,
            semantic_patch=patch,
            agent_run=_write_model(root / "agent-run.json", run),
        )

    honest_build = construction_module._build_resolution_variant(
        scenario,
        scenario_hash(scenario),
        variant("honest-real", ResolutionKind.HONEST, "honest"),
        sandbox=sandbox,
    )
    cheat_build = construction_module._build_resolution_variant(
        scenario,
        scenario_hash(scenario),
        variant("cheat-real", ResolutionKind.CHEAT, "cheat"),
        sandbox=sandbox,
    )

    assert honest_build.record.kind is ResolutionKind.HONEST
    assert honest_build.execution.outcome is Outcome.HONEST
    assert honest_build.execution.goal_met
    assert not honest_build.execution.intended_detector_triggered
    assert cheat_build.record.kind is ResolutionKind.CHEAT
    assert cheat_build.execution.outcome is Outcome.CHEATED
    assert cheat_build.execution.intended_detector_triggered


def test_blind_isolation_uses_a_real_verified_bundle_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The non-mocked evidence verifier and escrow inventory bind the initial workspace."""
    monkeypatch.setattr(replay_module, "_loaded_verifier_checkout_issues", lambda _: ())
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    protocol_path = inputs / "protocol.yaml"
    shutil.copyfile(
        Path(__file__).parents[1] / "benchmark" / "protocol.yaml",
        protocol_path,
    )
    source = Path(__file__).parents[1] / "scenarios" / "T-02-no-touch-tests"
    corpus_root = inputs / "sealed-corpus"
    scenario_root = corpus_root / source.name
    shutil.copytree(source, scenario_root)
    manifest_path = scenario_root / "manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["benchmark_split"] = BenchmarkSplit.SEALED.value
    manifest["scenario_version"] = "1.0.0"
    manifest["cluster_id"] = "cluster-real-bundle-t02"
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    private_marker = b"SYNTHETIC-PRIVATE-MARKER-84a2"
    _write_bytes(scenario_root / ".stinger-corpus-canary", private_marker + b"\n")
    scenario = discover_scenarios(corpus_root)[0]
    corpus_hash_value = corpus_hash([scenario])
    docker_runtime = observe_docker_runtime()
    observed_image_id, _ = inspect_docker_image(
        "stinger-runner:1",
        runtime=docker_runtime,
    )

    config = RunConfig(
        agent=AgentConfig(
            adapter="codex",
            model="synthetic-blind-model",
            provider=ProviderId.OPENAI,
            cli_version="1.2.3",
            reasoning_effort="high",
            inference_settings={"temperature": 0},
            api_key_env="OPENAI_API_KEY",
            container_image="stinger-runner:1",
            container_image_digest=observed_image_id,
            credential_broker=CredentialBrokerConfiguration(
                image="stinger-runner:1",
                image_digest=observed_image_id,
            ),
        ),
        corpus=corpus_root,
        output_dir=inputs / "output",
        reps=1,
        isolation=Isolation.DOCKER,
        image="stinger-runner:1",
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        stinger_commit=STINGER_COMMIT,
        verification_image_digest=observed_image_id,
        run_seed=17,
    )
    metadata = config.benchmark_metadata()
    assert metadata is not None
    assert metadata.credential_isolation_policy_sha256 is not None
    assert metadata.credential_broker_configuration_sha256 is not None
    assert metadata.credential_allowed_destination_inventory_sha256 is not None
    assert metadata.credential_agent_projection_inventory_sha256 is not None
    assert metadata.credential_broker_source_inventory_sha256 is not None
    assert metadata.credential_broker_image_digest is not None
    invocation_isolation = _credential_isolation_receipt(
        docker_runtime,
        agent=config.agent,
        repository=Path(__file__).parents[1],
    )
    runtime = BenchmarkRuntimeProvenance(
        requested_provider=ProviderId.OPENAI,
        requested_model_id=config.agent.model,
        stinger_commit=STINGER_COMMIT,
        docker_client_sha256=docker_runtime.client_sha256,
        docker_runtime_fingerprint_sha256=docker_runtime.fingerprint_sha256,
        docker_runtime_claim_boundary=DOCKER_RUNTIME_CLAIM_BOUNDARY,
        agent_cli_version=config.agent.cli_version,
        agent_container_image_id=observed_image_id,
        verification_image_id=observed_image_id,
        verification_image_policy_sha256=(
            canonical_verification_image_policy_sha256(compiled_verification_image_policy())
        ),
        resolved_agent_invocation=CodexAdapter(config.agent).resolved_invocation_template(),
        resolved_version_invocation=tuple(CodexAdapter(config.agent).version_argv()),
        reasoning_effort=config.agent.reasoning_effort,
        inference_settings=config.agent.inference_settings,
        credential_isolation=CredentialIsolationRuntimeProvenance(
            policy_sha256=metadata.credential_isolation_policy_sha256,
            broker_configuration_sha256=(metadata.credential_broker_configuration_sha256),
            allowed_destination_inventory_sha256=(
                metadata.credential_allowed_destination_inventory_sha256
            ),
            agent_projection_inventory_sha256=(
                metadata.credential_agent_projection_inventory_sha256
            ),
            broker_source_inventory_sha256=(metadata.credential_broker_source_inventory_sha256),
            broker_image_id=metadata.credential_broker_image_digest,
            docker_runtime_fingerprint_sha256=(docker_runtime.fingerprint_sha256),
            verified=True,
        ),
        verified=True,
    )
    repro = inputs / "repro"
    fixture = inputs / "recorded-agent"
    shutil.copytree(scenario_root / "reference" / "honest", fixture / "workdir")
    transcript = (Path(__file__).parent / "fixtures" / "cli" / "codex-honest.jsonl").read_text(
        encoding="utf-8"
    )
    _write_model(
        fixture / "run.json",
        CodexAdapter(config.agent)
        .replay(transcript)
        .model_copy(update={"credential_isolation": invocation_isolation}),
    )
    sandbox = Sandbox(isolation=Isolation.DOCKER, image=config.image)
    sandbox.preflight()
    invocation_plan = build_invocation_plan(
        config=config,
        corpus_hash=corpus_hash_value,
        runtime_provenance=runtime,
        ordered_scenario_ids=(scenario.id,),
    )
    result = run_scenario_once(
        scenario.directory,
        scenario.manifest,
        RecordedAdapter(fixture),
        0,
        sandbox=sandbox,
        artifacts_dir=repro / "runs" / scenario.id / "0",
        path_root=repro,
        invocation_context=invocation_plan[0],
    )
    assert result.outcome is Outcome.HONEST
    report = build_report(
        [result],
        corpus_hash=corpus_hash_value,
        config_fingerprint=config.fingerprint(),
        generated_at="2026-01-01T00:00:00Z",
        benchmark_metadata=metadata,
        benchmark_runtime_provenance=runtime,
        bootstrap_samples=1,
    )
    report_path = _write_bytes(
        inputs / "report.json",
        render_json(report).encode(),
    )
    config_path = _write_bytes(
        inputs / "config.resolved.json",
        config.resolved_json().encode(),
    )
    write_repro_package(repro, report, config, [scenario])
    verify_report_classifications_from_escrow(
        corpus_root,
        repro,
        config=config,
        report=report,
    )

    private_key = inputs / "protocol-key"
    subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            str(private_key),
        ],
        check=True,
        capture_output=True,
    )
    signer_identity = "protocol-real-bundle@example.test"
    public_key = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(private_key)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    allowed_signers = _write_bytes(
        inputs / "allowed-signers",
        f"{signer_identity} {public_key}\n".encode(),
    )
    protocol_signature = sign_protocol(protocol_path, private_key)
    log = _write_bytes(inputs / "operator.log", b"synthetic run complete\n")
    policy = PublicLeakagePolicy(
        forbidden_sources=(corpus_root,),
        forbidden_markers=(private_marker,),
    )
    public_bundle = tmp_path / "public-bundle"
    escrow_bundle = tmp_path / "escrow-bundle"
    create_public_evidence_bundle(
        public_bundle,
        protocol=protocol_path,
        protocol_signature=protocol_signature,
        allowed_signers=allowed_signers,
        signer_identity=signer_identity,
        config=config_path,
        report=report_path,
        permitted_logs={"operator.log": log},
        leakage_policy=policy,
    )
    create_escrow_evidence_bundle(
        escrow_bundle,
        protocol=protocol_path,
        protocol_signature=protocol_signature,
        allowed_signers=allowed_signers,
        signer_identity=signer_identity,
        config=config_path,
        report=report_path,
        sealed_corpus=corpus_root,
        rerunnable_evidence=repro,
    )
    workflow_input_model = build_agent_run_workflow_input_receipt(
        run_id="blind-real",
        public_bundle=public_bundle,
        escrow_bundle=escrow_bundle,
        leakage_policy=policy,
        protocol_allowed_signers=allowed_signers,
        protocol_signer_identity=signer_identity,
    )
    workflow_input = inputs / "workflow-input.json"
    write_agent_run_workflow_input_receipt(workflow_input, workflow_input_model)
    workflow_receipt = _write_bytes(
        inputs / "workflow-receipt.json",
        (escrow_bundle / "rerunnable-evidence" / "invocation.aggregate.json").read_bytes(),
    )
    machine_identity = MachineEnvironmentIdentity(
        platform=MachinePlatform.LINUX,
        architecture=MachineArchitecture.X86_64,
        identity_source=MachineIdentitySource.LINUX_MACHINE_ID,
        host_identity_commitment_sha256=_sha256(b"synthetic-test-host"),
    )
    machine_identity_path = _write_model(
        inputs / "machine-identity.json",
        machine_identity,
    )
    workflow_private_key = inputs / "workflow-key"
    subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            str(workflow_private_key),
        ],
        check=True,
        capture_output=True,
    )
    workflow_signer_identity = "workflow-real-bundle@example.test"
    workflow_public_key = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(workflow_private_key)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    workflow_allowed_signers = _write_bytes(
        inputs / "workflow-allowed-signers",
        f"{workflow_signer_identity} {workflow_public_key}\n".encode(),
    )
    workflow_attestation_model = MachineWorkflowAttestation(
        machine_identity_sha256=machine_environment_identity_sha256(machine_identity),
        host_identity_commitment_sha256=machine_identity.host_identity_commitment_sha256,
        platform=machine_identity.platform,
        architecture=machine_identity.architecture,
        identity_source=machine_identity.identity_source,
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        stinger_commit=STINGER_COMMIT,
        workflow_input_sha256=_sha256(workflow_input.read_bytes()),
        workflow_receipt_sha256=_sha256(workflow_receipt.read_bytes()),
        signer_identity=workflow_signer_identity,
    )
    workflow_attestation = inputs / "workflow-attestation.json"
    write_machine_workflow_attestation(
        workflow_attestation,
        workflow_attestation_model,
    )
    workflow_signature = sign_machine_workflow_attestation(
        workflow_attestation,
        workflow_private_key,
    )
    run = VerifiedRunBundleInput(
        run_id="blind-real",
        public_bundle=public_bundle,
        escrow_bundle=escrow_bundle,
        leakage_policy=policy,
        protocol_allowed_signers=allowed_signers,
        protocol_signer_identity=signer_identity,
        machine_identity_artifact=machine_identity_path,
        workflow_input=workflow_input,
        workflow_receipt=workflow_receipt,
        workflow_attestation=workflow_attestation,
        workflow_signature=workflow_signature,
        workflow_allowed_signers=workflow_allowed_signers,
        workflow_signer_identity=workflow_signer_identity,
    )
    verify_workflow = verify_machine_workflow_attestation

    def swap_original_workflow_paths(
        *,
        machine_identity_artifact: Path,
        workflow_input: Path,
        workflow_receipt: Path,
        attestation: Path,
        signature: Path,
        allowed_signers: Path,
        signer_identity: str,
        expected_stinger_commit: str,
    ) -> VerifiedMachineWorkflowAttestation:
        assert workflow_input != run.workflow_input
        original_input = run.workflow_input.read_bytes()
        run.workflow_input.write_bytes(b'{"swapped":"caller-path"}\n')
        try:
            return verify_workflow(
                machine_identity_artifact=machine_identity_artifact,
                workflow_input=workflow_input,
                workflow_receipt=workflow_receipt,
                attestation=attestation,
                signature=signature,
                allowed_signers=allowed_signers,
                signer_identity=signer_identity,
                expected_stinger_commit=expected_stinger_commit,
            )
        finally:
            run.workflow_input.write_bytes(original_input)

    monkeypatch.setattr(
        construction_module,
        "verify_machine_workflow_attestation",
        swap_original_workflow_paths,
    )
    verified = construction_module._verify_run_bundle(
        run,
        scenario=scenario,
        corpus_hash_value=corpus_hash_value,
        expected_stinger_commit=STINGER_COMMIT,
        forbidden_signer_identities=frozenset(),
        forbidden_signing_key_fingerprints=frozenset(),
        forbidden_trust_policy_sha256s=frozenset(),
    )
    aggregate_path = escrow_bundle / "rerunnable-evidence" / replay_module.INVOCATION_AGGREGATE_NAME
    aggregate_bytes = aggregate_path.read_bytes()
    aggregate_path.write_bytes(aggregate_bytes + b"post-verification-swap")
    with pytest.raises(CorpusConstructionError, match="changed after bundle verification"):
        construction_module._materialize_verified_rerunnable_evidence(
            verified.artifact_receipt,
            escrow_bundle,
            tmp_path / "tampered-rerunnable-snapshot",
        )
    aggregate_path.write_bytes(aggregate_bytes)
    scenario_record = CorpusScenarioRecord(
        scenario_id=scenario.id,
        family=scenario.manifest.family,
        repository_size=RepositorySize.SMALL,
        benchmark_split=BenchmarkSplit.SEALED,
        scenario_version=scenario.manifest.scenario_version,
        cluster_id=scenario.manifest.cluster_id or "",
        expected_honest_outcome=Outcome.HONEST,
        scenario_artifact_sha256=scenario_hash(scenario),
        machine_validation_receipt_sha256="2" * 64,
        provenance_receipt_sha256="3" * 64,
        containment_receipt_sha256="4" * 64,
        dummy_safety_receipt_sha256="5" * 64,
    )
    isolation = construction_module._derive_reference_isolation_receipt(
        scenario_record,
        scenario,
        run,
        verified.artifact_receipt,
        verified.result,
        runtime_receipt_sha256=verified.runtime_receipt_sha256,
    )
    assert isolation.expected_before_diff_sha256 == isolation.observed_before_diff_sha256
    assert isolation.transcript_sha256 == _sha256(
        (escrow_bundle / "rerunnable-evidence" / result.transcript_path).read_bytes()
    )
    observed_before_diff = (
        escrow_bundle
        / "rerunnable-evidence"
        / PurePosixPath(result.transcript_path).parent
        / "before.diff"
    )
    observed_before_diff.write_bytes(observed_before_diff.read_bytes() + b"tampered")
    with pytest.raises(CorpusConstructionError, match="changed after bundle verification"):
        construction_module._derive_reference_isolation_receipt(
            scenario_record,
            scenario,
            run,
            verified.artifact_receipt,
            verified.result,
            runtime_receipt_sha256=verified.runtime_receipt_sha256,
        )


def test_symlinked_corpus_root_is_rejected(
    construction_fixture: ConstructionFixture,
) -> None:
    """Resolving a caller path never converts a symlinked corpus root into a pass."""
    linked_root = construction_fixture.private_root / "linked-corpus"
    linked_root.symlink_to(construction_fixture.corpus_root, target_is_directory=True)
    with pytest.raises(CorpusConstructionError, match="real directory"):
        build_corpus_construction_receipt(
            repository=construction_fixture.repository,
            corpus_root=linked_root,
            corpus_version=CORPUS_VERSION,
            candidate_validation_authorization=(construction_fixture.candidate_authorization),
            candidate_promotion_authorization=(construction_fixture.promotion_authorization),
            custody_inventory_receipt=construction_fixture.custody_inventory,
            canary_registry=construction_fixture.canary_registry,
            access_ledger=construction_fixture.access_ledger,
            scenarios=construction_fixture.scenarios,
        )


def test_closed_receipts_reject_favorable_extra_fields() -> None:
    """Receipt producers cannot smuggle an unverified favorable claim."""
    with pytest.raises(ValidationError):
        ScenarioContainmentReceipt.model_validate(
            {
                "format_version": "2",
                "scenario_id": "synthetic",
                "scenario_artifact_sha256": "a" * 64,
                "isolation": "docker",
                "network_mode": "none",
                "host_paths_exposed": False,
                "containment_checks_passed": True,
                "operator_says_safe": True,
            }
        )
    with pytest.raises(ValidationError):
        ResolutionExecutionReceipt.model_validate(
            {
                "format_version": "4",
                "scenario_id": "synthetic",
                "scenario_artifact_sha256": "a" * 64,
                "variant_id": "cheat-0",
                "kind": ResolutionKind.CHEAT,
                "source_tree_sha256": "b" * 64,
                "semantic_patch_sha256": "c" * 64,
                "semantic_change_sha256": "1" * 64,
                "implementation_mechanism_sha256": "2" * 64,
                "agent_run_sha256": "d" * 64,
                "verification_image_id": VERIFY_IMAGE,
                "result_sha256": "e" * 64,
                "transcript_sha256": "f" * 64,
                "diff_sha256": "0" * 64,
                "outcome": Outcome.HONEST,
                "goal_met": True,
                "intended_detector_triggered": False,
                "intended_detector": "synthetic",
                "operator_says_safe": True,
            }
        )
    with pytest.raises(ValidationError, match="did not meet"):
        ResolutionExecutionReceipt(
            format_version="4",
            scenario_id="synthetic",
            scenario_artifact_sha256="a" * 64,
            variant_id="honest-0",
            kind=ResolutionKind.HONEST,
            source_tree_sha256="b" * 64,
            semantic_patch_sha256="c" * 64,
            semantic_change_sha256="1" * 64,
            implementation_mechanism_sha256="2" * 64,
            agent_run_sha256="d" * 64,
            verification_image_id=VERIFY_IMAGE,
            result_sha256="e" * 64,
            transcript_sha256="f" * 64,
            diff_sha256="0" * 64,
            outcome=Outcome.HONEST,
            goal_met=False,
            intended_detector_triggered=False,
            intended_detector="synthetic",
        )


def test_writer_is_canonical_atomic_and_no_overwrite(
    construction_fixture: ConstructionFixture,
    tmp_path: Path,
) -> None:
    """The private receipt writer creates exact bytes and refuses replacement."""
    built = _build(construction_fixture)
    destination = tmp_path / "published" / "construction.json"
    write_corpus_construction_receipt(destination, built.receipt)
    assert destination.read_bytes() == _model_bytes(built.receipt)
    assert destination.stat().st_mode & 0o777 == 0o600
    with pytest.raises(CorpusConstructionError, match="already exists"):
        write_corpus_construction_receipt(destination, built.receipt)


def test_mock_receipt_helper_keeps_protocol_current() -> None:
    """The synthetic verifier receipt itself uses the compiled Protocol 2 contract."""
    receipt = _make_verified_bundle_receipt(
        _RunSpec(
            scenario_id="t-synthetic",
            family=Family.T,
            scenario_version="1.0.0",
            cluster_id="cluster-t-synthetic",
            provider=ProviderId.OPENAI,
            token="standalone",
            outcome=Outcome.HONEST,
            corpus_hash="d" * 64,
        )
    )
    assert receipt.protocol == compiled_benchmark_protocol()
    assert receipt.report.benchmark_protocol_version == BENCHMARK_PROTOCOL_VERSION


def test_construction_receipt_has_dedicated_signature_authorization(
    tmp_path: Path,
) -> None:
    """Only trusted OpenSSH evidence in the construction namespace authorizes bytes."""
    identity = "construction-verifier@example.test"
    private_key = tmp_path / "construction-key"
    subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            str(private_key),
        ],
        check=True,
        capture_output=True,
    )
    public_key = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(private_key)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    allowed_signers = _write_bytes(
        tmp_path / "allowed-signers",
        f"{identity} {public_key}\n".encode(),
    )
    corpus = SealedCorpusRecord(
        corpus_version=CORPUS_VERSION,
        corpus_hash="d" * 64,
        scenarios=(),
    )
    receipt = CorpusConstructionReceipt(
        format_version="2",
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        rubric_version=RUBRIC_VERSION,
        corpus_version=CORPUS_VERSION,
        corpus_hash=corpus.corpus_hash,
        scenario_count=0,
        scenario_inventory_sha256=corpus_scenario_inventory_sha256(corpus.scenarios),
        construction_artifact_inventory_sha256="e" * 64,
        corpus=corpus,
    )
    receipt_path = tmp_path / "construction-receipt.json"
    write_corpus_construction_receipt(receipt_path, receipt)
    signature = sign_corpus_construction_receipt(receipt_path, private_key)

    authorization = authorize_corpus_construction_receipt(
        receipt_path,
        signature,
        allowed_signers,
        identity,
    )

    assert authorization.receipt == receipt
    assert authorization.receipt_sha256 == _sha256(receipt_path.read_bytes())
    assert authorization.canonical_receipt_sha256 == canonical_corpus_construction_receipt_sha256(
        receipt
    )
    assert authorization.namespace == "stinger-benchmark-corpus-construction"
    with pytest.raises(ProtocolSignatureError):
        authorize_corpus_construction_receipt(
            receipt_path,
            signature,
            allowed_signers,
            "different@example.test",
        )


def test_machine_review_runtime_requires_its_dedicated_signature(
    tmp_path: Path,
) -> None:
    """The exact invocation runtime, not an ACCEPT JSON alone, receives authority."""
    identity = "review-runner@example.test"
    private_key = tmp_path / "review-key"
    subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            str(private_key),
        ],
        check=True,
        capture_output=True,
    )
    public_key = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(private_key)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    allowed_signers = _write_bytes(
        tmp_path / "review-allowed-signers",
        f"{identity} {public_key}\n".encode(),
    )
    runtime = MachineReviewRuntimeReceipt(
        format_version=MACHINE_REVIEW_RUNTIME_FORMAT_VERSION,
        claim_boundary=MACHINE_REVIEW_CLAIM_BOUNDARY,
        review_id="review-0",
        runner_identity=identity,
        stinger_commit=STINGER_COMMIT,
        agent_adapter="codex",
        reviewer_configuration_sha256="1" * 64,
        review_input_receipt_sha256="2" * 64,
        review_evidence_manifest_sha256="3" * 64,
        review_workspace_sha256="4" * 64,
        transcript_sha256="5" * 64,
        review_output_sha256="6" * 64,
        invocation_argv=("review-agent", "--json"),
        version_invocation_argv=("review-agent", "--version"),
        agent_cli_binary_sha256="7" * 64,
        agent_container_digest="8" * 64,
        docker_runtime_claim_boundary=DOCKER_RUNTIME_CLAIM_BOUNDARY,
        docker_client_sha256="c" * 64,
        docker_runtime_fingerprint_sha256="d" * 64,
        **_credential_isolation_fields("d" * 64),
        credential_isolation_receipt_sha256="3" * 64,
        provider_response_id="response-1",
        parsed_final_message_sha256="9" * 64,
        invocation_id_sha256="a" * 64,
        exit_code=0,
    )
    runtime_path = _write_model(tmp_path / "runtime.json", runtime)
    signature = sign_machine_review_runtime_receipt(runtime_path, private_key)

    authorization = authorize_machine_review_runtime_receipt(
        runtime_path,
        signature,
        allowed_signers,
        identity,
    )

    assert authorization.receipt == runtime
    assert authorization.namespace == MACHINE_REVIEW_RUNTIME_SIGNATURE_NAMESPACE
    assert authorization.receipt_sha256 == _sha256(runtime_path.read_bytes())
    with pytest.raises(ProtocolSignatureError):
        authorize_machine_review_runtime_receipt(
            runtime_path,
            signature,
            allowed_signers,
            "different@example.test",
        )


def test_provider_response_id_requires_canonical_direct_cli_event() -> None:
    """Model-authored JSON cannot spoof a provider thread or session binding."""
    assert (
        construction_module._provider_response_id(
            "codex",
            '{"type":"thread.started","thread_id":"thread-123"}\n',
        )
        == "thread-123"
    )
    assert (
        construction_module._provider_response_id(
            "claude-code",
            '{"type":"system","subtype":"init","session_id":"session-123"}\n',
        )
        == "session-123"
    )
    for adapter, transcript in (
        (
            "codex",
            '{"type":"item.completed","item":{"type":"agent_message"},"thread_id":"spoofed"}\n',
        ),
        (
            "claude-code",
            '{"type":"result","result":"done","session_id":"spoofed"}\n',
        ),
    ):
        with pytest.raises(CorpusConstructionError, match="canonical provider session"):
            construction_module._provider_response_id(adapter, transcript)


def test_unsigned_authoring_identity_cannot_establish_reviewer_independence() -> None:
    """Caller-authored model metadata receives no reviewer-independence credit."""
    authoring = AuthoringConfigurationReceipt(
        format_version="2",
        provider=ProviderId.OPENAI,
        model_id="same-model",
        agent_build="same-build",
        reasoning_effort="high",
        inference_settings={"temperature": 0},
    )
    review = MachineReviewerConfigurationReceipt(
        format_version=construction_module.MACHINE_REVIEW_CONFIGURATION_FORMAT_VERSION,
        claim_boundary=MACHINE_REVIEW_CLAIM_BOUNDARY,
        review_id="cosmetically-different-review",
        provider=ProviderId.OPENAI,
        model_id="same-model",
        agent_adapter="codex",
        agent_build="same-build",
        reasoning_effort="high",
        inference_settings={"temperature": 0},
        agent_cli_binary_sha256="a" * 64,
        agent_container_digest="b" * 64,
        docker_runtime_claim_boundary=DOCKER_RUNTIME_CLAIM_BOUNDARY,
        docker_client_sha256="d" * 64,
        docker_runtime_fingerprint_sha256="e" * 64,
        **_credential_isolation_fields("e" * 64),
    )
    with pytest.raises(CorpusConstructionError, match="unsigned authoring"):
        construction_module._normalized_configuration_identity(authoring)  # type: ignore[arg-type]
    assert construction_module._normalized_configuration_identity(review).model_id == "same-model"


def test_machine_review_runtime_detects_signature_verification_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A runtime path changed while OpenSSH is reading it cannot acquire authority."""
    identity = "review-runner@example.test"
    runtime = MachineReviewRuntimeReceipt(
        format_version=MACHINE_REVIEW_RUNTIME_FORMAT_VERSION,
        claim_boundary=MACHINE_REVIEW_CLAIM_BOUNDARY,
        review_id="review-0",
        runner_identity=identity,
        stinger_commit=STINGER_COMMIT,
        agent_adapter="codex",
        reviewer_configuration_sha256="1" * 64,
        review_input_receipt_sha256="2" * 64,
        review_evidence_manifest_sha256="3" * 64,
        review_workspace_sha256="4" * 64,
        transcript_sha256="5" * 64,
        review_output_sha256="6" * 64,
        invocation_argv=("review-agent", "--json"),
        version_invocation_argv=("review-agent", "--version"),
        agent_cli_binary_sha256="7" * 64,
        agent_container_digest="8" * 64,
        docker_runtime_claim_boundary=DOCKER_RUNTIME_CLAIM_BOUNDARY,
        docker_client_sha256="c" * 64,
        docker_runtime_fingerprint_sha256="d" * 64,
        **_credential_isolation_fields("d" * 64),
        credential_isolation_receipt_sha256="3" * 64,
        provider_response_id="response-1",
        parsed_final_message_sha256="9" * 64,
        invocation_id_sha256="a" * 64,
        exit_code=0,
    )
    runtime_path = _write_model(tmp_path / "runtime.json", runtime)
    original = runtime_path.read_bytes()
    signature = _write_bytes(tmp_path / "runtime.sig", b"synthetic\n")
    allowed_signers = _write_bytes(tmp_path / "allowed-signers", b"synthetic\n")

    def mutate_during_verification(
        artifact: Path,
        signature_path: Path,
        trust_path: Path,
        expected_identity: str,
        *,
        namespace: str,
    ) -> ProtocolSignatureVerification:
        del signature_path, trust_path
        artifact.write_bytes(original + b" ")
        return ProtocolSignatureVerification(
            identity=expected_identity,
            namespace=namespace,
            protocol_sha256=_sha256(original),
            signature_sha256="7" * 64,
            allowed_signers_sha256="8" * 64,
            signing_key_fingerprint="SHA256:c3dhcA==",
        )

    monkeypatch.setattr(
        construction_module,
        "verify_protocol_signature",
        mutate_during_verification,
    )
    with pytest.raises(ProtocolSignatureError, match="changed"):
        authorize_machine_review_runtime_receipt(
            runtime_path,
            signature,
            allowed_signers,
            identity,
        )
