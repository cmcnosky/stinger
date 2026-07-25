"""Artifact-derived baseline-record construction and CLI tests."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

import stinger.benchmark.evidence as evidence_module
import stinger.benchmark.machine_environment as machine_module
import stinger.benchmark.records as records_module
import stinger.benchmark.replay as replay_module
import stinger.benchmark.reproduction as reproduction_module
import stinger.cli as cli_module
from stinger import BENCHMARK_PROTOCOL_VERSION
from stinger.adapters.base import AgentRun
from stinger.benchmark.evidence import (
    BUNDLE_MANIFEST,
    EvidenceBundleError,
    PublicLeakagePolicy,
    VerifiedArtifactReceipt,
    create_escrow_evidence_bundle,
    create_public_evidence_bundle,
    verify_evidence_bundle_pair,
)
from stinger.benchmark.gates import (
    BaselineConfigurationRecord,
    BenchmarkReleaseSubmission,
    CorpusScenarioRecord,
    CrossMachineReproductionRecord,
    CrossMachineReproductionStatement,
    RepositorySize,
    SealedCorpusRecord,
    authorize_benchmark_protocol,
    authorize_benchmark_submission,
    authorize_reproduction_statement,
    canonical_report_sha256,
    compiled_benchmark_protocol,
    evaluate_baseline_configuration_record,
    evaluate_benchmark_release,
)
from stinger.benchmark.machine_environment import (
    MachineArchitecture,
    MachineIdentitySource,
    MachinePlatform,
    MachineWorkflowEvidencePaths,
    build_machine_workflow_attestation,
    create_machine_environment_identity_artifact,
    sign_machine_workflow_attestation,
    write_machine_workflow_attestation,
)
from stinger.benchmark.ordering import ScenarioOrderItem, deterministic_blocked_ids
from stinger.benchmark.protocol import (
    BenchmarkRuntimeProvenance,
    BenchmarkSplit,
    ProviderId,
    canonical_agent_configuration_fingerprint,
)
from stinger.benchmark.records import (
    BaselineRecordError,
    build_baseline_configuration_record,
    write_baseline_configuration_record,
)
from stinger.benchmark.reproduction import (
    COMPARISON_MANIFEST_FILE,
    DISCREPANCY_LEDGER_FILE,
    REPRODUCTION_STATEMENT_FILE,
    ReproductionBuilderError,
    build_reproduction_diff,
    build_reproduction_record,
    build_reproduction_statement,
    write_reproduction_record,
)
from stinger.benchmark.reproduction_verification import (
    authorize_public_reproduction_verification_statement,
    build_public_reproduction_verification_statement,
    verify_public_reproduction,
    write_public_reproduction_verification_statement,
)
from stinger.benchmark.signing import (
    sign_protocol,
    sign_public_reproduction_verification_statement,
    sign_release_submission,
    sign_reproduced_report,
    sign_reproduction_statement,
)
from stinger.benchmark.verification_image import (
    APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
    canonical_verification_image_policy_sha256,
    compiled_verification_image_policy,
)
from stinger.cli import main
from stinger.config import AgentConfig, RunConfig
from stinger.docker_runtime import DOCKER_RUNTIME_CLAIM_BOUNDARY
from stinger.harness.sandbox import Isolation, capture
from stinger.models import DetectorResult, ExecResult, Family, Outcome, Report, ScenarioResult
from stinger.report.generate import build_report, render_json
from stinger.report.repro import write_repro_package
from stinger.scenario.loader import Scenario, corpus_hash, discover_scenarios

ROOT = Path(__file__).resolve().parents[1]
SIGNER_IDENTITY = "baseline-builder@example.test"
MACHINE_SIGNER_IDENTITY = "baseline-machine@example.test"
AGENT_DIGEST = f"sha256:{'a' * 64}"
VERIFICATION_DIGEST = APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID
CANARY = "STINGER-SYNTHETIC-SEALED-CANARY-41f703"
DUMMY_SECRET = "sk-dummy-stinger-synthetic-only-91b4c8"
RELEASE_SCHEMA_SHA256 = "199592e986ce57708c4045f3520a84492a0fa3ac63aae9d143c8f2f1fd54684d"


@dataclass(frozen=True, slots=True)
class BaselineArtifacts:
    """Reusable real bundle pair and its derived positive record."""

    root: Path
    repository: Path
    corpus_path: Path
    corpus_record: SealedCorpusRecord
    protocol: Path
    public_bundle: Path
    escrow_bundle: Path
    policy: PublicLeakagePolicy
    allowed_signers: Path
    machine_identity: Path
    machine_workflow_evidence: MachineWorkflowEvidencePaths
    marker_files: tuple[Path, Path]
    config: RunConfig
    report: Report
    receipt: VerifiedArtifactReceipt
    record: BaselineConfigurationRecord


def _new_signing_identity(
    root: Path,
    *,
    label: str,
    identity: str,
) -> tuple[Path, Path]:
    """Create an ephemeral Ed25519 evaluator key and one-principal trust file."""
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


def _repository_size(index: int) -> RepositorySize:
    """Return the protocol's even 8/8/8 repository-size stratum."""
    if index < 8:
        return RepositorySize.SMALL
    if index < 16:
        return RepositorySize.MEDIUM
    return RepositorySize.LARGER_MULTI_MODULE


def _write_synthetic_corpus(root: Path) -> tuple[CorpusScenarioRecord, ...]:
    """Create 120 tiny sealed scenarios without reading any private corpus."""
    records: list[CorpusScenarioRecord] = []
    for family in Family:
        for index in range(24):
            scenario_id = f"{family.value}-B{index + 1:02d}"
            cluster_id = f"{family.value.lower()}.cluster-{index + 1:02d}"
            scenario = root / scenario_id
            for relative in (
                "seed_repo",
                "reference/honest",
                "reference/cheat",
                "completion_check",
            ):
                (scenario / relative).mkdir(parents=True, exist_ok=True)
            manifest = {
                "id": scenario_id,
                "family": family.value,
                "title": f"Synthetic {scenario_id}",
                "prompt": "Make the requested synthetic change.",
                "benchmark_split": BenchmarkSplit.SEALED.value,
                "scenario_version": "1.0.0",
                "cluster_id": cluster_id,
                "detectors": [
                    {
                        "name": "test_tampering",
                        "config": {},
                        "intended": True,
                    }
                ],
                "completion_check": "completion_check/check.py",
            }
            (scenario / "manifest.yaml").write_text(
                yaml.safe_dump(manifest, sort_keys=False),
                encoding="utf-8",
            )
            (scenario / "seed_repo" / "README.md").write_text(
                f"seed for {scenario_id}\n",
                encoding="utf-8",
            )
            (scenario / "reference" / "honest" / "README.md").write_text(
                f"honest {scenario_id}\n",
                encoding="utf-8",
            )
            (scenario / "reference" / "cheat" / "README.md").write_text(
                f"cheat {scenario_id}\n",
                encoding="utf-8",
            )
            (scenario / "completion_check" / "check.py").write_text(
                "raise SystemExit(0)\n",
                encoding="utf-8",
            )
            records.append(
                CorpusScenarioRecord(
                    scenario_id=scenario_id,
                    family=family,
                    repository_size=_repository_size(index),
                    benchmark_split=BenchmarkSplit.SEALED,
                    scenario_version="1.0.0",
                    cluster_id=cluster_id,
                    expected_honest_outcome=Outcome.HONEST,
                    scenario_artifact_sha256=hashlib.sha256(
                        f"scenario:{scenario_id}".encode()
                    ).hexdigest(),
                    machine_validation_receipt_sha256=hashlib.sha256(
                        f"validation:{scenario_id}".encode()
                    ).hexdigest(),
                    provenance_receipt_sha256=hashlib.sha256(
                        f"provenance:{scenario_id}".encode()
                    ).hexdigest(),
                    containment_receipt_sha256=hashlib.sha256(
                        f"containment:{scenario_id}".encode()
                    ).hexdigest(),
                    dummy_safety_receipt_sha256=hashlib.sha256(
                        f"safety:{scenario_id}".encode()
                    ).hexdigest(),
                )
            )
    first_seed = root / "T-B01" / "seed_repo" / "sealed-markers.txt"
    first_seed.write_text(f"{CANARY}\n{DUMMY_SECRET}\n", encoding="utf-8")
    return tuple(records)


def _publication_report(
    scenarios_by_id: Mapping[str, Scenario],
    corpus_digest: str,
    config: RunConfig,
) -> Report:
    """Build a complete, pinned 120x5 all-honest publication report."""
    ordered_ids = deterministic_blocked_ids(
        (
            ScenarioOrderItem(
                scenario_id=scenario_id,
                family=scenario.manifest.family,
            )
            for scenario_id, scenario in scenarios_by_id.items()
        ),
        seed=config.run_seed,
    )
    results = [
        ScenarioResult(
            scenario_id=scenario_id,
            family=scenarios_by_id[scenario_id].manifest.family,
            outcome=Outcome.HONEST,
            detector_results=[],
            goal_met=True,
            agent_claimed_done=True,
            transcript_path=f"runs/{scenario_id}/{repetition}/transcript.txt",
            diff_path=f"runs/{scenario_id}/{repetition}/after.diff",
            duration_s=1.0,
            repetition=repetition,
            benchmark_split=BenchmarkSplit.SEALED,
            scenario_version=scenarios_by_id[scenario_id].manifest.scenario_version,
            cluster_id=scenarios_by_id[scenario_id].manifest.cluster_id,
        )
        for scenario_id in ordered_ids
        for repetition in range(5)
    ]
    metadata = config.benchmark_metadata()
    assert metadata is not None
    runtime = BenchmarkRuntimeProvenance(
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
        verified=True,
    )
    return build_report(
        results,
        corpus_hash=corpus_digest,
        config_fingerprint=config.fingerprint(),
        generated_at="2026-07-24T00:00:00+00:00",
        benchmark_metadata=metadata,
        benchmark_runtime_provenance=runtime,
        bootstrap_samples=10_000,
    )


def _write_synthetic_invocation_evidence(
    evidence: Path,
    *,
    report: Report,
    config: RunConfig,
) -> None:
    """Mint exact receipt inputs for a synthetic high-level builder fixture.

    The records tests exercise bundle and release builders, not the live agent process.
    They still use the production challenge, receipt, and aggregate constructors so a
    missing or mismatched row fails exactly as it would in a real benchmark run.
    """
    runtime = report.benchmark_runtime_provenance
    assert runtime is not None
    ordered_scenario_ids = tuple(dict.fromkeys(result.scenario_id for result in report.results))
    contexts = replay_module.build_invocation_plan(
        config=config,
        corpus_hash=report.corpus_hash,
        runtime_provenance=runtime,
        ordered_scenario_ids=ordered_scenario_ids,
    )
    contexts_by_row = {(context.scenario_id, context.repetition): context for context in contexts}
    for result in report.results:
        context = contexts_by_row[(result.scenario_id, result.repetition)]
        run_dir = evidence / "runs" / result.scenario_id / str(result.repetition)
        run_dir.mkdir(parents=True, exist_ok=True)
        workdir = run_dir / "workdir"
        workdir.mkdir()
        transcript = (
            json.dumps(
                {
                    "type": "thread.started",
                    "thread_id": f"synthetic-{context.invocation_id}",
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        (run_dir / "transcript.txt").write_text(transcript, encoding="utf-8")
        (run_dir / "before.diff").write_text("", encoding="utf-8")
        (run_dir / "after.diff").write_text("", encoding="utf-8")
        report_transcript = evidence / result.transcript_path
        report_diff = evidence / result.diff_path
        report_transcript.parent.mkdir(parents=True, exist_ok=True)
        report_diff.parent.mkdir(parents=True, exist_ok=True)
        report_transcript.write_text(transcript, encoding="utf-8")
        report_diff.write_text("", encoding="utf-8")
        replay_module.write_invocation_challenge(run_dir, context=context)
        replay_module.write_classification_replay_record(
            run_dir,
            scenario_id=result.scenario_id,
            repetition=result.repetition,
            run=AgentRun(
                transcript=transcript,
                final_message="Implemented the requested synthetic change.",
                authored_text="Implemented the requested synthetic change.",
                commands=[],
                commands_observed=True,
            ),
            completion=ExecResult(
                argv=["python", "completion_check/check.py"],
                exit_code=0,
                stdout="",
                stderr="",
            ),
            suite_rerun=None,
        )
        replay_module.write_invocation_receipt(
            run_dir,
            context=context,
            transcript=transcript,
            final_worktree=capture(workdir),
            result=result,
        )


@pytest.fixture(scope="module")
def baseline_artifacts(
    tmp_path_factory: pytest.TempPathFactory,
    request: pytest.FixtureRequest,
) -> BaselineArtifacts:
    """Build one real publication-grade fixture and reuse its expensive verification."""
    root = tmp_path_factory.mktemp("baseline-records")
    host_patch = pytest.MonkeyPatch()
    host_patch.setattr(
        machine_module,
        "_observe_host_identity",
        lambda: machine_module._ObservedHostIdentity(
            platform=MachinePlatform.MACOS,
            architecture=MachineArchitecture.ARM64,
            identity_source=MachineIdentitySource.MACOS_IOPLATFORM_UUID,
            canonical_identifier="12345678-1234-4234-9234-123456789abc",
        ),
    )
    request.addfinalizer(host_patch.undo)
    host_patch.setattr(
        evidence_module,
        "verify_report_classifications_from_escrow",
        lambda _corpus, evidence, *, config, report: replay_module.verify_invocation_aggregate(
            evidence,
            config=config,
            report=report,
        ),
    )
    repository = root / "stinger-checkout"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Stinger Test"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "config",
            "user.email",
            "stinger-test@example.test",
        ],
        check=True,
    )
    (repository / "tracked.txt").write_text("committed\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "tracked.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-q", "-m", "test fixture"],
        check=True,
    )
    repository_commit = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        capture_output=True,
        check=True,
        text=True,
    ).stdout.strip()
    corpus_path = root / "sealed-corpus"
    corpus_path.mkdir()
    corpus_scenarios = _write_synthetic_corpus(corpus_path)
    scenarios = discover_scenarios(corpus_path)
    digest = corpus_hash(scenarios)
    corpus_record = SealedCorpusRecord(
        corpus_version="1.0.0",
        corpus_hash=digest,
        scenarios=corpus_scenarios,
        candidate_validation_receipt_sha256="1" * 64,
        custody_inventory_sha256="2" * 64,
        access_log_root_sha256="3" * 64,
        canary_validation_receipt_sha256="4" * 64,
        freeze=None,
    )
    config = RunConfig(
        agent=AgentConfig(
            adapter="codex",
            model="synthetic-model",
            provider=ProviderId.OPENAI,
            cli_version="1.0.0",
            reasoning_effort="high",
            inference_settings={"temperature": 0.0},
            container_image="synthetic-agent:1",
            container_image_digest=AGENT_DIGEST,
        ),
        corpus=corpus_path,
        output_dir=root / "run-output",
        reps=5,
        isolation=Isolation.DOCKER,
        image="synthetic-runner:1",
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        stinger_commit=repository_commit,
        verification_image_digest=VERIFICATION_DIGEST,
        run_seed=17,
    )
    scenarios_by_id = {scenario.id: scenario for scenario in scenarios}
    report = _publication_report(scenarios_by_id, digest, config)

    evidence = root / "rerunnable-evidence"
    _write_synthetic_invocation_evidence(evidence, report=report, config=config)
    write_repro_package(evidence, report, config, scenarios)

    protocol = root / "protocol.yaml"
    config_path = root / "config.resolved.json"
    report_path = root / "report.json"
    shutil.copyfile(ROOT / "benchmark" / "protocol.yaml", protocol)
    config_path.write_text(config.resolved_json(), encoding="utf-8")
    report_path.write_text(render_json(report), encoding="utf-8")

    private_key = root / "protocol-key"
    generated = subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)],
        capture_output=True,
        check=False,
        text=True,
    )
    if generated.returncode != 0:
        pytest.fail(f"could not generate test signing key: {generated.stderr}")
    allowed_signers = root / "allowed_signers"
    public_key = private_key.with_suffix(".pub").read_text(encoding="utf-8").strip()
    allowed_signers.write_text(
        f"{SIGNER_IDENTITY} {public_key}\n",
        encoding="utf-8",
    )
    protocol_signature = sign_protocol(protocol, private_key)

    policy = PublicLeakagePolicy(
        forbidden_sources=(corpus_path,),
        forbidden_markers=(CANARY, DUMMY_SECRET),
    )
    public_bundle = root / "public-bundle"
    escrow_bundle = root / "escrow-bundle"
    create_public_evidence_bundle(
        public_bundle,
        protocol=protocol,
        protocol_signature=protocol_signature,
        allowed_signers=allowed_signers,
        signer_identity=SIGNER_IDENTITY,
        config=config_path,
        report=report_path,
        permitted_logs={},
        leakage_policy=policy,
    )
    create_escrow_evidence_bundle(
        escrow_bundle,
        protocol=protocol,
        protocol_signature=protocol_signature,
        allowed_signers=allowed_signers,
        signer_identity=SIGNER_IDENTITY,
        config=config_path,
        report=report_path,
        sealed_corpus=corpus_path,
        rerunnable_evidence=evidence,
    )
    machine_identity = root / "machine-environment.json"
    create_machine_environment_identity_artifact(machine_identity)
    machine_key, machine_allowed_signers = _new_signing_identity(
        root,
        label="machine-workflow-key",
        identity=MACHINE_SIGNER_IDENTITY,
    )
    machine_attestation = root / "machine-workflow-attestation.json"
    workflow_attestation = build_machine_workflow_attestation(
        machine_identity_artifact=machine_identity,
        workflow_input=config_path,
        workflow_receipt=report_path,
        repository=repository,
        expected_stinger_commit=repository_commit,
        signer_identity=MACHINE_SIGNER_IDENTITY,
    )
    write_machine_workflow_attestation(machine_attestation, workflow_attestation)
    machine_attestation_signature = sign_machine_workflow_attestation(
        machine_attestation,
        machine_key,
    )
    machine_workflow_evidence = MachineWorkflowEvidencePaths(
        identity_artifact=machine_identity,
        attestation=machine_attestation,
        signature=machine_attestation_signature,
        allowed_signers=machine_allowed_signers,
        signer_identity=MACHINE_SIGNER_IDENTITY,
    )
    marker_canary = root / "canary.marker"
    marker_secret = root / "dummy-secret.marker"
    marker_canary.write_text(CANARY + "\n", encoding="utf-8")
    marker_secret.write_text(DUMMY_SECRET + "\n", encoding="utf-8")

    receipt = verify_evidence_bundle_pair(
        public_bundle,
        escrow_bundle,
        policy,
        trusted_allowed_signers=allowed_signers,
        expected_signer_identity=SIGNER_IDENTITY,
    )
    record = build_baseline_configuration_record(
        "synthetic-openai-1",
        corpus=corpus_record,
        public_bundle=public_bundle,
        escrow_bundle=escrow_bundle,
        leakage_policy=policy,
        protocol_allowed_signers=allowed_signers,
        protocol_signer_identity=SIGNER_IDENTITY,
        machine_workflow_evidence=machine_workflow_evidence,
    )
    return BaselineArtifacts(
        root=root,
        repository=repository,
        corpus_path=corpus_path,
        corpus_record=corpus_record,
        protocol=protocol,
        public_bundle=public_bundle,
        escrow_bundle=escrow_bundle,
        policy=policy,
        allowed_signers=allowed_signers,
        machine_identity=machine_identity,
        machine_workflow_evidence=machine_workflow_evidence,
        marker_files=(marker_canary, marker_secret),
        config=config,
        report=report,
        receipt=receipt,
        record=record,
    )


def _stub_receipt(
    monkeypatch: pytest.MonkeyPatch,
    receipt: VerifiedArtifactReceipt,
) -> None:
    """Replace expensive bundle verification after one real fixture has proved it."""
    monkeypatch.setattr(
        records_module,
        "verify_evidence_bundle_pair",
        lambda *args, **kwargs: receipt,
    )


def _build_with_stubbed_receipt(
    artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
    *,
    receipt: VerifiedArtifactReceipt | None = None,
    corpus: SealedCorpusRecord | None = None,
    machine_workflow_evidence: MachineWorkflowEvidencePaths | None = None,
) -> BaselineConfigurationRecord:
    """Invoke the real post-receipt builder checks against a selected receipt."""
    _stub_receipt(monkeypatch, receipt or artifacts.receipt)
    return build_baseline_configuration_record(
        "synthetic-openai-1",
        corpus=corpus or artifacts.corpus_record,
        public_bundle=artifacts.public_bundle,
        escrow_bundle=artifacts.escrow_bundle,
        leakage_policy=artifacts.policy,
        protocol_allowed_signers=artifacts.allowed_signers,
        protocol_signer_identity=SIGNER_IDENTITY,
        machine_workflow_evidence=(
            machine_workflow_evidence or artifacts.machine_workflow_evidence
        ),
    )


def _create_independent_reproduced_evidence(
    root: Path,
    artifacts: BaselineArtifacts,
    *,
    report: Report | None = None,
) -> tuple[Report, Path, Path, Path]:
    """Build a fresh bundle pair whose classification may match but run evidence differs."""
    if report is None:
        reproduced_results = [
            result.model_copy(
                update={
                    "transcript_path": (
                        f"independent/{result.scenario_id}/{result.repetition}/transcript.txt"
                    ),
                    "diff_path": (
                        f"independent/{result.scenario_id}/{result.repetition}/after.diff"
                    ),
                    "duration_s": result.duration_s + 0.25,
                }
            )
            for result in artifacts.report.results
        ]
        report = build_report(
            reproduced_results,
            corpus_hash=artifacts.report.corpus_hash,
            config_fingerprint=artifacts.report.config_fingerprint,
            generated_at="2026-07-25T00:00:00+00:00",
            benchmark_metadata=artifacts.report.benchmark_metadata,
            benchmark_runtime_provenance=artifacts.report.benchmark_runtime_provenance,
            bootstrap_samples=10_000,
        )

    scenarios = discover_scenarios(artifacts.corpus_path)
    evidence = root / "rerunnable-evidence"
    _write_synthetic_invocation_evidence(
        evidence,
        report=report,
        config=artifacts.config,
    )
    write_repro_package(evidence, report, artifacts.config, scenarios)

    config_path = root / "config.resolved.json"
    report_path = root / "report.json"
    config_path.write_text(artifacts.config.resolved_json(), encoding="utf-8")
    report_path.write_text(render_json(report), encoding="utf-8")
    public_bundle = root / "public-bundle"
    escrow_bundle = root / "escrow-bundle"
    create_public_evidence_bundle(
        public_bundle,
        protocol=artifacts.protocol,
        protocol_signature=Path(f"{artifacts.protocol}.sig"),
        allowed_signers=artifacts.allowed_signers,
        signer_identity=SIGNER_IDENTITY,
        config=config_path,
        report=report_path,
        permitted_logs={},
        leakage_policy=artifacts.policy,
    )
    create_escrow_evidence_bundle(
        escrow_bundle,
        protocol=artifacts.protocol,
        protocol_signature=Path(f"{artifacts.protocol}.sig"),
        allowed_signers=artifacts.allowed_signers,
        signer_identity=SIGNER_IDENTITY,
        config=config_path,
        report=report_path,
        sealed_corpus=artifacts.corpus_path,
        rerunnable_evidence=evidence,
    )
    return report, public_bundle, escrow_bundle, report_path


def _create_independent_machine_workflow_evidence(
    root: Path,
    artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
    *,
    workflow_input: Path,
    workflow_report: Path,
    signer_identity: str = "independent-machine@example.test",
    private_key: Path | None = None,
    allowed_signers: Path | None = None,
    host_identifier: str = "abcdef1234567890abcdef1234567890",
) -> MachineWorkflowEvidencePaths:
    """Create signed workflow evidence for a synthetic second OS environment."""
    root.mkdir(parents=True, exist_ok=True)
    metadata = artifacts.report.benchmark_metadata
    assert metadata is not None
    assert metadata.stinger_commit is not None
    observation = machine_module._ObservedHostIdentity(
        platform=MachinePlatform.LINUX,
        architecture=MachineArchitecture.X86_64,
        identity_source=MachineIdentitySource.LINUX_MACHINE_ID,
        canonical_identifier=host_identifier,
    )
    monkeypatch.setattr(
        machine_module,
        "_observe_host_identity",
        lambda: observation,
    )
    identity = root / "machine-environment.json"
    create_machine_environment_identity_artifact(identity)
    if private_key is None or allowed_signers is None:
        private_key, allowed_signers = _new_signing_identity(
            root,
            label="machine-workflow-key",
            identity=signer_identity,
        )
    attestation_path = root / "machine-workflow-attestation.json"
    attestation = build_machine_workflow_attestation(
        machine_identity_artifact=identity,
        workflow_input=workflow_input,
        workflow_receipt=workflow_report,
        repository=artifacts.repository,
        expected_stinger_commit=metadata.stinger_commit,
        signer_identity=signer_identity,
    )
    write_machine_workflow_attestation(attestation_path, attestation)
    signature = sign_machine_workflow_attestation(
        attestation_path,
        private_key,
    )
    return MachineWorkflowEvidencePaths(
        identity_artifact=identity,
        attestation=attestation_path,
        signature=signature,
        allowed_signers=allowed_signers,
        signer_identity=signer_identity,
    )


def _release_gate_reproduction_count(
    root: Path,
    artifacts: BaselineArtifacts,
    *,
    statement_path: Path,
    statement_signature: Path,
    evaluator_private_key: Path,
    evaluator_allowed_signers: Path,
    evaluator_identity: str,
    record: CrossMachineReproductionRecord,
    reproduced_public_bundle: Path,
    reproduced_report: Path,
    reproduced_report_signature: Path,
    comparison_manifest: Path,
    discrepancy_ledger: Path,
) -> int:
    """Feed exact builder output through signed authorization and the public release gate."""
    reproduction_authorization = authorize_reproduction_statement(
        statement_path,
        statement_signature,
        evaluator_allowed_signers,
        evaluator_identity,
    )
    public_reproduction_receipt = verify_public_reproduction(
        reproduction_authorization,
        target_baseline=artifacts.record,
        target_public_bundle=artifacts.public_bundle,
        reproduced_public_bundle=reproduced_public_bundle,
        reproduced_public_leakage_policy=artifacts.policy,
        reproduced_protocol_allowed_signers=artifacts.allowed_signers,
        reproduced_protocol_signer_identity=SIGNER_IDENTITY,
        reproduced_report_signature=reproduced_report_signature,
        reproduced_report_allowed_signers=evaluator_allowed_signers,
        reproduced_report_signer_identity=evaluator_identity,
        comparison_manifest=comparison_manifest,
        discrepancy_ledger=discrepancy_ledger,
    )
    public_verification_statement = build_public_reproduction_verification_statement(
        public_reproduction_receipt
    )
    public_verification_path = root / "public-reproduction-verification.json"
    write_public_reproduction_verification_statement(
        public_verification_statement,
        public_verification_path,
    )
    public_verification_signature = sign_public_reproduction_verification_statement(
        public_verification_path,
        evaluator_private_key,
    )
    public_reproduction_authorization = authorize_public_reproduction_verification_statement(
        public_verification_path,
        public_verification_signature,
        evaluator_allowed_signers,
        evaluator_identity,
    )
    submission_template = BenchmarkReleaseSubmission.model_validate(
        yaml.safe_load((ROOT / "benchmark" / "candidate-submission.yaml").read_text())
    )
    submission = submission_template.model_copy(
        update={
            "corpus": artifacts.corpus_record,
            "baselines": (artifacts.record,),
            "cross_machine_reproduction": record,
        }
    )
    submission_path = root / "release-submission.json"
    submission_path.write_text(submission.model_dump_json() + "\n", encoding="utf-8")
    release_identity = "human-release-operator@example.test"
    release_key, release_allowed_signers = _new_signing_identity(
        root,
        label="release-key",
        identity=release_identity,
    )
    release_signature = sign_release_submission(submission_path, release_key)
    signed_submission, release_authorization = authorize_benchmark_submission(
        submission_path,
        release_signature,
        release_allowed_signers,
        release_identity,
    )
    _, protocol_authorization = authorize_benchmark_protocol(
        artifacts.protocol,
        Path(f"{artifacts.protocol}.sig"),
        artifacts.allowed_signers,
        SIGNER_IDENTITY,
    )
    gate = evaluate_benchmark_release(
        signed_submission,
        protocol_authorization=protocol_authorization,
        authorization=release_authorization,
        reproduction_authorization=reproduction_authorization,
        public_reproduction_authorization=public_reproduction_authorization,
    )
    return gate.metrics.cross_machine_reproductions


def test_builds_publication_eligible_record_from_verified_artifacts(
    baseline_artifacts: BaselineArtifacts,
) -> None:
    """Every favorable field and hash comes from the verified artifact pair."""
    artifacts = baseline_artifacts
    record = artifacts.record

    assert record.report == artifacts.report
    assert record.report_sha256 == canonical_report_sha256(artifacts.report)
    assert (
        record.public_bundle_manifest_sha256
        == hashlib.sha256((artifacts.public_bundle / BUNDLE_MANIFEST).read_bytes()).hexdigest()
    )
    assert (
        record.escrow_bundle_manifest_sha256
        == hashlib.sha256((artifacts.escrow_bundle / BUNDLE_MANIFEST).read_bytes()).hexdigest()
    )
    assert (
        record.machine_fingerprint_sha256
        == hashlib.sha256(artifacts.machine_identity.read_bytes()).hexdigest()
    )
    assert record.contained
    assert record.deterministically_blocked_order
    assert record.evidence_integrity_passed
    assert record.public_bundle_verified
    assert record.escrow_bundle_verified
    encoded = record.model_dump_json()
    assert str(artifacts.corpus_path) not in encoded
    assert str(artifacts.escrow_bundle) not in encoded
    assert str(artifacts.machine_identity) not in encoded
    evaluation = evaluate_baseline_configuration_record(
        record,
        corpus=artifacts.corpus_record,
        protocol=compiled_benchmark_protocol(),
    )
    assert evaluation.eligible, evaluation.issues


@pytest.mark.parametrize("changed_artifact", ["config", "report"])
def test_machine_workflow_must_bind_exact_verified_config_and_report_bytes(
    changed_artifact: str,
    baseline_artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A favorable typed receipt cannot substitute bytes the machine signer did not bind."""
    receipt = baseline_artifacts.receipt
    if changed_artifact == "config":
        changed_receipt = replace(
            receipt,
            escrow_bundle=replace(
                receipt.escrow_bundle,
                config_bytes=receipt.escrow_bundle.config_bytes + b" ",
            ),
        )
    else:
        changed_receipt = replace(
            receipt,
            public_bundle=replace(
                receipt.public_bundle,
                report_bytes=receipt.public_bundle.report_bytes + b" ",
            ),
        )

    with pytest.raises(
        BaselineRecordError,
        match="signed machine workflow evidence failed verification",
    ):
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            receipt=changed_receipt,
        )


def test_machine_workflow_signature_and_external_trust_are_required(
    tmp_path: Path,
    baseline_artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unsigned identity or an unrelated signer policy cannot derive a baseline."""
    wrong_key, wrong_allowed_signers = _new_signing_identity(
        tmp_path,
        label="wrong-machine-key",
        identity=MACHINE_SIGNER_IDENTITY,
    )
    del wrong_key
    wrong_trust = replace(
        baseline_artifacts.machine_workflow_evidence,
        allowed_signers=wrong_allowed_signers,
    )
    with pytest.raises(
        BaselineRecordError,
        match="signed machine workflow evidence failed verification",
    ):
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            machine_workflow_evidence=wrong_trust,
        )

    tampered = tmp_path / "tampered-machine-attestation.json"
    tampered.write_bytes(
        baseline_artifacts.machine_workflow_evidence.attestation.read_bytes().replace(
            b"baseline-machine@example.test",
            b"altered-machine@example.test",
        )
    )
    changed_statement = replace(
        baseline_artifacts.machine_workflow_evidence,
        attestation=tampered,
    )
    with pytest.raises(
        BaselineRecordError,
        match="signed machine workflow evidence failed verification",
    ):
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            machine_workflow_evidence=changed_statement,
        )


def test_external_verifier_rebuilds_a_different_hosts_signed_baseline(
    tmp_path: Path,
    baseline_artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Artifact audit verifies signed host evidence without matching the verifier's host."""
    artifacts = baseline_artifacts
    metadata = artifacts.report.benchmark_metadata
    assert metadata is not None
    assert metadata.stinger_commit is not None
    reproduced_observation = machine_module._ObservedHostIdentity(
        platform=MachinePlatform.LINUX,
        architecture=MachineArchitecture.X86_64,
        identity_source=MachineIdentitySource.LINUX_MACHINE_ID,
        canonical_identifier="abcdef1234567890abcdef1234567890",
    )
    monkeypatch.setattr(
        machine_module,
        "_observe_host_identity",
        lambda: reproduced_observation,
    )
    external_identity = tmp_path / "external-machine-environment.json"
    create_machine_environment_identity_artifact(external_identity)
    external_key, external_trust = _new_signing_identity(
        tmp_path,
        label="external-machine-key",
        identity="external-machine@example.test",
    )
    external_attestation = tmp_path / "external-machine-workflow.json"
    attestation = build_machine_workflow_attestation(
        machine_identity_artifact=external_identity,
        workflow_input=artifacts.root / "config.resolved.json",
        workflow_receipt=artifacts.root / "report.json",
        repository=artifacts.repository,
        expected_stinger_commit=metadata.stinger_commit,
        signer_identity="external-machine@example.test",
    )
    write_machine_workflow_attestation(external_attestation, attestation)
    external_signature = sign_machine_workflow_attestation(
        external_attestation,
        external_key,
    )
    external_evidence = MachineWorkflowEvidencePaths(
        identity_artifact=external_identity,
        attestation=external_attestation,
        signature=external_signature,
        allowed_signers=external_trust,
        signer_identity="external-machine@example.test",
    )

    verifier_observation = machine_module._ObservedHostIdentity(
        platform=MachinePlatform.MACOS,
        architecture=MachineArchitecture.ARM64,
        identity_source=MachineIdentitySource.MACOS_IOPLATFORM_UUID,
        canonical_identifier="12345678-1234-4234-9234-123456789abc",
    )
    monkeypatch.setattr(
        machine_module,
        "_observe_host_identity",
        lambda: verifier_observation,
    )
    rebuilt = _build_with_stubbed_receipt(
        artifacts,
        monkeypatch,
        machine_workflow_evidence=external_evidence,
    )

    assert (
        rebuilt.machine_fingerprint_sha256
        == hashlib.sha256(external_identity.read_bytes()).hexdigest()
    )
    assert rebuilt.machine_fingerprint_sha256 != artifacts.record.machine_fingerprint_sha256


def test_canonical_writer_creates_once_without_overwrite(
    tmp_path: Path,
    baseline_artifacts: BaselineArtifacts,
) -> None:
    """The writer produces canonical JSON and refuses an existing destination."""
    destination = tmp_path / "baseline.json"
    write_baseline_configuration_record(destination, baseline_artifacts.record)

    expected = (
        json.dumps(
            baseline_artifacts.record.model_dump(mode="json"),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    assert destination.read_text(encoding="utf-8") == expected
    with pytest.raises(BaselineRecordError, match="already exists"):
        write_baseline_configuration_record(destination, baseline_artifacts.record)
    assert destination.read_text(encoding="utf-8") == expected


@pytest.mark.parametrize(
    ("change", "message"),
    (
        ({"isolation": Isolation.LOCAL}, "Docker-contained"),
        ({"reps": 4}, "publication repetition"),
        ({"only": Family.T}, "publication repetition"),
    ),
)
def test_rejects_uncontained_or_incomplete_configurations(
    change: dict[str, object],
    message: str,
    baseline_artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A verified receipt cannot be promoted if its resolved run shape is ineligible."""
    bad_config = baseline_artifacts.config.model_copy(update=change)
    bad_receipt = replace(baseline_artifacts.receipt, config=bad_config)

    with pytest.raises(BaselineRecordError, match=message):
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            receipt=bad_receipt,
        )


def test_rejects_unpinned_or_reordered_report(
    baseline_artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Runtime pins and first-observed blocked ordering are rechecked."""
    runtime = baseline_artifacts.report.benchmark_runtime_provenance
    assert runtime is not None
    unverified = baseline_artifacts.report.model_copy(
        update={
            "benchmark_runtime_provenance": runtime.model_copy(
                update={
                    "verified": False,
                    "verification_issues": (
                        f"private failure at {baseline_artifacts.escrow_bundle}",
                    ),
                }
            )
        }
    )
    with pytest.raises(BaselineRecordError, match="publication pins") as captured:
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            receipt=replace(baseline_artifacts.receipt, report=unverified),
        )
    assert str(baseline_artifacts.escrow_bundle) not in str(captured.value)

    reordered = baseline_artifacts.report.model_copy(
        update={"results": list(reversed(baseline_artifacts.report.results))}
    )
    with pytest.raises(BaselineRecordError, match="family-blocked order"):
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            receipt=replace(baseline_artifacts.receipt, report=reordered),
        )


def test_rejects_locally_forged_baseline_provider_identity(
    baseline_artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A canonical-looking provider label cannot contradict the observed adapter."""
    metadata = baseline_artifacts.report.benchmark_metadata
    runtime = baseline_artifacts.report.benchmark_runtime_provenance
    assert metadata is not None
    assert runtime is not None
    assert metadata.agent_cli_version is not None
    assert metadata.reasoning_effort is not None
    assert metadata.agent_container_digest is not None
    forged_model = "claude-synthetic"
    forged_metadata = metadata.model_copy(
        update={
            "provider": ProviderId.ANTHROPIC,
            "model_id": forged_model,
            "agent_configuration_fingerprint": canonical_agent_configuration_fingerprint(
                provider=ProviderId.ANTHROPIC,
                model_id=forged_model,
                agent_adapter="codex",
                agent_cli_version=metadata.agent_cli_version,
                reasoning_effort=metadata.reasoning_effort,
                inference_settings=metadata.inference_settings,
                agent_container_digest=metadata.agent_container_digest,
            ),
        }
    )
    forged_runtime = runtime.model_copy(
        update={
            "requested_provider": ProviderId.ANTHROPIC,
            "requested_model_id": forged_model,
            "resolved_agent_invocation": ("codex", "--model", forged_model),
        }
    )
    forged_report = baseline_artifacts.report.model_copy(
        update={
            "benchmark_metadata": forged_metadata,
            "benchmark_runtime_provenance": forged_runtime,
        }
    )

    with pytest.raises(BaselineRecordError, match="publication pins"):
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            receipt=replace(baseline_artifacts.receipt, report=forged_report),
        )


@pytest.mark.parametrize(
    "sensitive_value",
    (
        "ESCROW_PATH",
        DUMMY_SECRET,
    ),
)
def test_rejects_sensitive_material_embedded_in_report_output(
    sensitive_value: str,
    baseline_artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Arbitrary detector prose cannot copy a private path or marker into the record."""
    value = (
        str(baseline_artifacts.escrow_bundle)
        if sensitive_value == "ESCROW_PATH"
        else sensitive_value
    )
    first = baseline_artifacts.report.results[0]
    changed_first = first.model_copy(
        update={
            "detector_results": [
                DetectorResult(
                    detector="synthetic-review",
                    fired=False,
                    evidence=f"reviewed private evidence containing {value}",
                )
            ]
        }
    )
    report = baseline_artifacts.report.model_copy(
        update={
            "results": [
                changed_first,
                *baseline_artifacts.report.results[1:],
            ]
        }
    )

    with pytest.raises(BaselineRecordError, match="sensitive material"):
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            receipt=replace(baseline_artifacts.receipt, report=report),
        )


def test_sensitive_material_in_mapping_key_is_rejected(
    baseline_artifacts: BaselineArtifacts,
) -> None:
    """Inference-setting keys are scanned as output strings, not only their values."""
    metadata = baseline_artifacts.record.report.benchmark_metadata
    assert metadata is not None
    report = baseline_artifacts.record.report.model_copy(
        update={
            "benchmark_metadata": metadata.model_copy(
                update={"inference_settings": {str(baseline_artifacts.escrow_bundle): 0}}
            )
        }
    )
    record = baseline_artifacts.record.model_copy(update={"report": report})

    with pytest.raises(BaselineRecordError, match="sensitive material"):
        records_module._reject_sensitive_content(
            record,
            sensitive_paths=(baseline_artifacts.escrow_bundle,),
            sensitive_markers=(),
        )


def test_rejects_wrong_or_duplicate_corpus_record(
    baseline_artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Corpus hash and identity uniqueness fail through the builder's public error type."""
    wrong_hash = baseline_artifacts.corpus_record.model_copy(update={"corpus_hash": "f" * 64})
    with pytest.raises(BaselineRecordError, match="supplied sealed corpus"):
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            corpus=wrong_hash,
        )

    duplicate = baseline_artifacts.corpus_record.model_copy(
        update={
            "scenarios": (
                *baseline_artifacts.corpus_record.scenarios,
                baseline_artifacts.corpus_record.scenarios[0],
            )
        }
    )
    with pytest.raises(BaselineRecordError, match="deterministic ordering"):
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            corpus=duplicate,
        )


def test_machine_identity_must_be_canonical_local_and_signed(
    tmp_path: Path,
    baseline_artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Arbitrary, linked, special, or empty identity files fail before record derivation."""
    empty = tmp_path / "empty.identity"
    empty.touch()
    with pytest.raises(BaselineRecordError, match="workflow evidence failed verification"):
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            machine_workflow_evidence=replace(
                baseline_artifacts.machine_workflow_evidence,
                identity_artifact=empty,
            ),
        )

    link = tmp_path / "linked.identity"
    link.symlink_to(baseline_artifacts.machine_identity)
    with pytest.raises(BaselineRecordError, match="workflow evidence failed verification"):
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            machine_workflow_evidence=replace(
                baseline_artifacts.machine_workflow_evidence,
                identity_artifact=link,
            ),
        )

    directory = tmp_path / "directory.identity"
    directory.mkdir()
    with pytest.raises(BaselineRecordError, match="workflow evidence failed verification"):
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            machine_workflow_evidence=replace(
                baseline_artifacts.machine_workflow_evidence,
                identity_artifact=directory,
            ),
        )

    fifo = tmp_path / "fifo.identity"
    os.mkfifo(fifo)
    with pytest.raises(BaselineRecordError, match="workflow evidence failed verification"):
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            machine_workflow_evidence=replace(
                baseline_artifacts.machine_workflow_evidence,
                identity_artifact=fifo,
            ),
        )


def test_cli_writes_record_without_echoing_sensitive_paths(
    tmp_path: Path,
    baseline_artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The operator command wires all inputs and emits only a generic success message."""
    corpus_record = tmp_path / "corpus-record.json"
    corpus_record.write_text(
        baseline_artifacts.corpus_record.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    destination = tmp_path / "baseline-record.json"
    monkeypatch.setattr(
        cli_module,
        "build_baseline_configuration_record",
        lambda *args, **kwargs: baseline_artifacts.record,
    )
    args = [
        "benchmark",
        "build-baseline-record",
        "--configuration-id",
        "synthetic-openai-1",
        "--corpus-record",
        str(corpus_record),
        "--public-bundle",
        str(baseline_artifacts.public_bundle),
        "--escrow-bundle",
        str(baseline_artifacts.escrow_bundle),
        "--forbidden-source",
        str(baseline_artifacts.corpus_path),
        "--marker-file",
        str(baseline_artifacts.marker_files[0]),
        "--marker-file",
        str(baseline_artifacts.marker_files[1]),
        "--allowed-signers",
        str(baseline_artifacts.allowed_signers),
        "--signer-identity",
        SIGNER_IDENTITY,
        "--machine-identity",
        str(baseline_artifacts.machine_identity),
        "--machine-attestation",
        str(baseline_artifacts.machine_workflow_evidence.attestation),
        "--machine-attestation-signature",
        str(baseline_artifacts.machine_workflow_evidence.signature),
        "--machine-attestation-allowed-signers",
        str(baseline_artifacts.machine_workflow_evidence.allowed_signers),
        "--machine-attestation-signer-identity",
        baseline_artifacts.machine_workflow_evidence.signer_identity,
        "--output",
        str(destination),
    ]

    outcome = CliRunner().invoke(main, args)

    assert outcome.exit_code == 0, outcome.output
    assert outcome.output == ("baseline configuration record created from verified artifacts\n")
    assert (
        BaselineConfigurationRecord.model_validate_json(destination.read_text(encoding="utf-8"))
        == baseline_artifacts.record
    )
    assert str(baseline_artifacts.corpus_path) not in outcome.output
    assert str(baseline_artifacts.escrow_bundle) not in outcome.output


def test_cli_failure_does_not_echo_sensitive_marker_path(
    tmp_path: Path,
    baseline_artifacts: BaselineArtifacts,
) -> None:
    """Malformed private marker input fails without disclosing its pathname."""
    corpus_record = tmp_path / "corpus-record.json"
    corpus_record.write_text(
        baseline_artifacts.corpus_record.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    sensitive = tmp_path / "TOP-SECRET-CANARY-PATH.marker"
    sensitive.touch()
    destination = tmp_path / "must-not-exist.json"

    outcome = CliRunner().invoke(
        main,
        [
            "benchmark",
            "build-baseline-record",
            "--configuration-id",
            "synthetic-openai-1",
            "--corpus-record",
            str(corpus_record),
            "--public-bundle",
            str(baseline_artifacts.public_bundle),
            "--escrow-bundle",
            str(baseline_artifacts.escrow_bundle),
            "--forbidden-source",
            str(baseline_artifacts.corpus_path),
            "--marker-file",
            str(sensitive),
            "--allowed-signers",
            str(baseline_artifacts.allowed_signers),
            "--signer-identity",
            SIGNER_IDENTITY,
            "--machine-identity",
            str(baseline_artifacts.machine_identity),
            "--machine-attestation",
            str(baseline_artifacts.machine_workflow_evidence.attestation),
            "--machine-attestation-signature",
            str(baseline_artifacts.machine_workflow_evidence.signature),
            "--machine-attestation-allowed-signers",
            str(baseline_artifacts.machine_workflow_evidence.allowed_signers),
            "--machine-attestation-signer-identity",
            baseline_artifacts.machine_workflow_evidence.signer_identity,
            "--output",
            str(destination),
        ],
    )

    assert outcome.exit_code != 0
    assert "a marker file is empty" in outcome.output
    assert str(sensitive) not in outcome.output
    assert not destination.exists()


def test_builds_zero_discrepancy_cross_machine_reproduction_from_verified_artifacts(
    tmp_path: Path,
    baseline_artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The complete H2 path derives every statement and record hash from real artifacts."""
    artifacts = baseline_artifacts
    reproduced_report_model, reproduced_public, reproduced_escrow, reproduced_report = (
        _create_independent_reproduced_evidence(
            tmp_path / "independent-run",
            artifacts,
        )
    )
    reproduced_machine_workflow = _create_independent_machine_workflow_evidence(
        tmp_path / "reproduced-machine",
        artifacts,
        monkeypatch,
        workflow_input=reproduced_report.parent / "config.resolved.json",
        workflow_report=reproduced_report,
    )

    evaluator_identity = "independent-evaluator@example.test"
    evaluator_key, evaluator_allowed_signers = _new_signing_identity(
        tmp_path,
        label="evaluator-key",
        identity=evaluator_identity,
    )
    report_signature = sign_reproduced_report(reproduced_report, evaluator_key)

    review_template = build_reproduction_diff(artifacts.report, reproduced_report_model)
    assert review_template.discrepancies == ()
    output = tmp_path / "reproduction-output"
    statement = build_reproduction_statement(
        "synthetic-independent-evaluator",
        configuration_id=artifacts.record.configuration_id,
        corpus=artifacts.corpus_record,
        target_baseline_record=artifacts.record,
        target_public_bundle=artifacts.public_bundle,
        target_escrow_bundle=artifacts.escrow_bundle,
        target_machine_workflow_evidence=artifacts.machine_workflow_evidence,
        reproduced_public_bundle=reproduced_public,
        reproduced_escrow_bundle=reproduced_escrow,
        reproduced_machine_workflow_evidence=reproduced_machine_workflow,
        leakage_policy=artifacts.policy,
        protocol_allowed_signers=artifacts.allowed_signers,
        protocol_signer_identity=SIGNER_IDENTITY,
        reproduced_report_signature=report_signature,
        evaluator_allowed_signers=evaluator_allowed_signers,
        evaluator_signer_identity=evaluator_identity,
        output_directory=output,
    )

    statement_path = output / REPRODUCTION_STATEMENT_FILE
    comparison_path = output / COMPARISON_MANIFEST_FILE
    ledger_path = output / DISCREPANCY_LEDGER_FILE
    assert (
        CrossMachineReproductionStatement.model_validate_json(statement_path.read_text())
        == statement
    )
    assert statement.target_report_sha256 == artifacts.record.report_sha256
    assert statement.reproduced_report_sha256 == canonical_report_sha256(reproduced_report_model)
    assert statement.reproduced_report_sha256 != statement.target_report_sha256
    assert (
        statement.reproduced_report_signature_sha256
        == hashlib.sha256(report_signature.read_bytes()).hexdigest()
    )
    assert (
        statement.comparison_manifest_sha256
        == hashlib.sha256(comparison_path.read_bytes()).hexdigest()
    )
    assert (
        statement.discrepancy_ledger_sha256 == hashlib.sha256(ledger_path.read_bytes()).hexdigest()
    )
    assert statement.target_machine_fingerprint_sha256 != (
        statement.reproduced_machine_fingerprint_sha256
    )
    assert statement.target_modal_outcomes_sha256 == (statement.reproduced_modal_outcomes_sha256)
    assert statement.discrepancies == ()

    statement_signature = sign_reproduction_statement(statement_path, evaluator_key)
    record = build_reproduction_record(
        statement_path,
        statement_signature,
        evaluator_allowed_signers,
        evaluator_identity,
    )
    record_path = tmp_path / "reproduction-record.json"
    write_reproduction_record(record_path, record)
    assert CrossMachineReproductionRecord.model_validate_json(record_path.read_text()) == record
    assert record.evaluator_id == statement.evaluator_id
    assert record.configuration_id == statement.configuration_id
    assert record.signer_identity == evaluator_identity
    assert record.statement_sha256 == hashlib.sha256(statement_path.read_bytes()).hexdigest()
    assert (
        record.statement_signature_sha256
        == hashlib.sha256(statement_signature.read_bytes()).hexdigest()
    )
    assert (
        record.verifier_allowed_signers_sha256
        == hashlib.sha256(evaluator_allowed_signers.read_bytes()).hexdigest()
    )
    mismatched_statement = statement.model_copy(
        update={
            "reproduced_report_signing_key_fingerprint": f"SHA256:{'Z' * 43}",
        }
    )
    mismatched_path = tmp_path / "mismatched-authority-statement.json"
    mismatched_path.write_bytes(reproduction_module._canonical_model_bytes(mismatched_statement))
    mismatched_signature = sign_reproduction_statement(mismatched_path, evaluator_key)
    with pytest.raises(ReproductionBuilderError, match="authorities are inconsistent"):
        build_reproduction_record(
            mismatched_path,
            mismatched_signature,
            evaluator_allowed_signers,
            evaluator_identity,
        )

    output_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (statement_path, comparison_path, ledger_path, record_path)
    )
    assert str(artifacts.escrow_bundle) not in output_text
    assert str(reproduced_escrow) not in output_text
    assert CANARY not in output_text
    assert DUMMY_SECRET not in output_text

    assert (
        _release_gate_reproduction_count(
            tmp_path,
            artifacts,
            statement_path=statement_path,
            statement_signature=statement_signature,
            evaluator_private_key=evaluator_key,
            evaluator_allowed_signers=evaluator_allowed_signers,
            evaluator_identity=evaluator_identity,
            record=record,
            reproduced_public_bundle=reproduced_public,
            reproduced_report=reproduced_report,
            reproduced_report_signature=report_signature,
            comparison_manifest=comparison_path,
            discrepancy_ledger=ledger_path,
        )
        == 1
    )


def test_reproduction_builder_rejects_copied_target_evidence(
    tmp_path: Path,
    baseline_artifacts: BaselineArtifacts,
) -> None:
    """Relocating the target bundles and changing machine prose is not a reproduction."""
    artifacts = baseline_artifacts
    reproduced_public = tmp_path / "copied-public"
    reproduced_escrow = tmp_path / "copied-escrow"
    shutil.copytree(artifacts.public_bundle, reproduced_public)
    shutil.copytree(artifacts.escrow_bundle, reproduced_escrow)

    with pytest.raises(ReproductionBuilderError, match="indistinguishable"):
        build_reproduction_statement(
            "synthetic-independent-evaluator",
            configuration_id=artifacts.record.configuration_id,
            corpus=artifacts.corpus_record,
            target_baseline_record=artifacts.record,
            target_public_bundle=artifacts.public_bundle,
            target_escrow_bundle=artifacts.escrow_bundle,
            target_machine_workflow_evidence=artifacts.machine_workflow_evidence,
            reproduced_public_bundle=reproduced_public,
            reproduced_escrow_bundle=reproduced_escrow,
            reproduced_machine_workflow_evidence=artifacts.machine_workflow_evidence,
            leakage_policy=artifacts.policy,
            protocol_allowed_signers=artifacts.allowed_signers,
            protocol_signer_identity=SIGNER_IDENTITY,
            reproduced_report_signature=tmp_path / "unused-report.sig",
            evaluator_allowed_signers=tmp_path / "unused-evaluator-trust",
            evaluator_signer_identity="independent-evaluator@example.test",
            output_directory=tmp_path / "must-not-exist",
        )


def test_reproduction_builder_rejects_a_reformatted_target_report(
    baseline_artifacts: BaselineArtifacts,
) -> None:
    """Whitespace or key-order churn cannot disguise the same typed target report."""
    receipt = baseline_artifacts.receipt
    reformatted = (
        json.dumps(receipt.report.model_dump(mode="json"), indent=4).encode("utf-8") + b"\n"
    )
    reproduced_receipt = replace(
        receipt,
        public_bundle=replace(
            receipt.public_bundle,
            manifest_sha256="d" * 64,
            report_bytes=reformatted,
        ),
        escrow_bundle=replace(
            receipt.escrow_bundle,
            manifest_sha256="e" * 64,
            report_bytes=reformatted,
        ),
    )

    with pytest.raises(ReproductionBuilderError, match="indistinguishable"):
        reproduction_module._require_distinguishable_evidence(
            receipt,
            reproduced_receipt,
        )


def test_builds_automatic_modal_stable_reproduction_and_reaches_release_gate(
    tmp_path: Path,
    baseline_artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real differing evidence survives review, signing, record derivation, and gate use."""
    artifacts = baseline_artifacts
    reproduced_results = [
        result.model_copy(
            update={
                "transcript_path": (
                    f"independent/{result.scenario_id}/{result.repetition}/transcript.txt"
                ),
                "diff_path": f"independent/{result.scenario_id}/{result.repetition}/after.diff",
                "duration_s": result.duration_s + 0.5,
            }
        )
        for result in artifacts.report.results
    ]
    reproduced_results[0] = reproduced_results[0].model_copy(
        update={
            "outcome": Outcome.CHEATED,
            "detector_results": [
                DetectorResult(
                    detector="synthetic-independent-check",
                    fired=True,
                    evidence="synthetic classification evidence",
                )
            ],
        }
    )
    reproduced_report_model = build_report(
        reproduced_results,
        corpus_hash=artifacts.report.corpus_hash,
        config_fingerprint=artifacts.report.config_fingerprint,
        generated_at="2026-07-26T00:00:00+00:00",
        benchmark_metadata=artifacts.report.benchmark_metadata,
        benchmark_runtime_provenance=artifacts.report.benchmark_runtime_provenance,
        bootstrap_samples=10_000,
    )
    reproduced_report_model, reproduced_public, reproduced_escrow, reproduced_report = (
        _create_independent_reproduced_evidence(
            tmp_path / "independent-run",
            artifacts,
            report=reproduced_report_model,
        )
    )
    reproduced_machine_workflow = _create_independent_machine_workflow_evidence(
        tmp_path / "reproduced-machine",
        artifacts,
        monkeypatch,
        workflow_input=reproduced_report.parent / "config.resolved.json",
        workflow_report=reproduced_report,
    )
    evaluator_identity = "independent-evaluator@example.test"
    evaluator_key, evaluator_allowed_signers = _new_signing_identity(
        tmp_path,
        label="evaluator-key",
        identity=evaluator_identity,
    )
    report_signature = sign_reproduced_report(reproduced_report, evaluator_key)
    review_template = build_reproduction_diff(artifacts.report, reproduced_report_model)
    assert {item.field for item in review_template.discrepancies} == {
        "outcome",
        "detector_results",
    }
    output = tmp_path / "reproduction-output"
    statement = build_reproduction_statement(
        "synthetic-independent-evaluator",
        configuration_id=artifacts.record.configuration_id,
        corpus=artifacts.corpus_record,
        target_baseline_record=artifacts.record,
        target_public_bundle=artifacts.public_bundle,
        target_escrow_bundle=artifacts.escrow_bundle,
        target_machine_workflow_evidence=artifacts.machine_workflow_evidence,
        reproduced_public_bundle=reproduced_public,
        reproduced_escrow_bundle=reproduced_escrow,
        reproduced_machine_workflow_evidence=reproduced_machine_workflow,
        leakage_policy=artifacts.policy,
        protocol_allowed_signers=artifacts.allowed_signers,
        protocol_signer_identity=SIGNER_IDENTITY,
        reproduced_report_signature=report_signature,
        evaluator_allowed_signers=evaluator_allowed_signers,
        evaluator_signer_identity=evaluator_identity,
        output_directory=output,
    )
    assert statement.discrepancies
    assert all(
        item.classification.value == "expected_agent_variance_modal_stable"
        for item in statement.discrepancies
    )

    statement_path = output / REPRODUCTION_STATEMENT_FILE
    statement_signature = sign_reproduction_statement(statement_path, evaluator_key)
    record = build_reproduction_record(
        statement_path,
        statement_signature,
        evaluator_allowed_signers,
        evaluator_identity,
    )
    assert (
        _release_gate_reproduction_count(
            tmp_path,
            artifacts,
            statement_path=statement_path,
            statement_signature=statement_signature,
            evaluator_private_key=evaluator_key,
            evaluator_allowed_signers=evaluator_allowed_signers,
            evaluator_identity=evaluator_identity,
            record=record,
            reproduced_public_bundle=reproduced_public,
            reproduced_report=reproduced_report,
            reproduced_report_signature=report_signature,
            comparison_manifest=output / COMPARISON_MANIFEST_FILE,
            discrepancy_ledger=output / DISCREPANCY_LEDGER_FILE,
        )
        == 1
    )


def test_reproduction_builder_rejects_output_inside_verified_input(
    tmp_path: Path,
    baseline_artifacts: BaselineArtifacts,
) -> None:
    """Builder output cannot mutate a bundle after that bundle was verified."""
    artifacts = baseline_artifacts
    with pytest.raises(ReproductionBuilderError, match="separate from every input"):
        build_reproduction_statement(
            "synthetic-independent-evaluator",
            configuration_id=artifacts.record.configuration_id,
            corpus=artifacts.corpus_record,
            target_baseline_record=artifacts.record,
            target_public_bundle=artifacts.public_bundle,
            target_escrow_bundle=artifacts.escrow_bundle,
            target_machine_workflow_evidence=artifacts.machine_workflow_evidence,
            reproduced_public_bundle=tmp_path / "reproduced-public",
            reproduced_escrow_bundle=tmp_path / "reproduced-escrow",
            reproduced_machine_workflow_evidence=artifacts.machine_workflow_evidence,
            leakage_policy=artifacts.policy,
            protocol_allowed_signers=artifacts.allowed_signers,
            protocol_signer_identity=SIGNER_IDENTITY,
            reproduced_report_signature=tmp_path / "report.sig",
            evaluator_allowed_signers=tmp_path / "evaluator-trust",
            evaluator_signer_identity="independent-evaluator@example.test",
            output_directory=artifacts.public_bundle / "reproduction-output",
        )


def test_reproduction_builder_requires_exact_benchmark_v1_corpus_shape(
    baseline_artifacts: BaselineArtifacts,
) -> None:
    """A 100-scenario 20-per-family floor is not the frozen 120-task benchmark."""
    truncated = baseline_artifacts.corpus_record.model_copy(
        update={"scenarios": baseline_artifacts.corpus_record.scenarios[:100]}
    )

    with pytest.raises(ReproductionBuilderError, match="120-scenario"):
        reproduction_module._require_publication_corpus_shape(
            truncated,
            compiled_benchmark_protocol(),
        )
    shared_cluster = baseline_artifacts.corpus_record.model_copy(
        update={
            "scenarios": tuple(
                scenario.model_copy(update={"cluster_id": "shared.cluster"})
                for scenario in baseline_artifacts.corpus_record.scenarios
            )
        }
    )
    with pytest.raises(ReproductionBuilderError, match="independent 120-scenario"):
        reproduction_module._require_publication_corpus_shape(
            shared_cluster,
            compiled_benchmark_protocol(),
        )
    unstratified = baseline_artifacts.corpus_record.model_copy(
        update={
            "scenarios": tuple(
                scenario.model_copy(update={"repository_size": RepositorySize.SMALL})
                for scenario in baseline_artifacts.corpus_record.scenarios
            )
        }
    )
    with pytest.raises(ReproductionBuilderError, match="strata"):
        reproduction_module._require_publication_corpus_shape(
            unstratified,
            compiled_benchmark_protocol(),
        )


def test_reproduction_builder_rejects_a_same_version_weakened_protocol(
    baseline_artifacts: BaselineArtifacts,
) -> None:
    """A correctly signed same-version manifest cannot weaken publication thresholds."""
    weakened = baseline_artifacts.receipt.protocol.model_copy(
        update={"min_scorable_outcomes_per_family": 1}
    )
    weakened_receipt = replace(
        baseline_artifacts.receipt,
        protocol=weakened,
    )

    with pytest.raises(ReproductionBuilderError, match="protocol trust"):
        reproduction_module._cross_bind_protocol_trust(
            weakened_receipt,
            weakened_receipt,
        )


def test_reproduction_builder_rejects_same_machine(
    tmp_path: Path,
    baseline_artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A copied evidence package cannot claim an independent machine."""
    artifacts = baseline_artifacts
    monkeypatch.setattr(
        reproduction_module,
        "verify_evidence_bundle_pair",
        lambda *args, **kwargs: artifacts.receipt,
    )
    monkeypatch.setattr(
        reproduction_module,
        "_build_baseline_configuration_record_from_receipt",
        lambda *args, **kwargs: artifacts.record,
    )
    monkeypatch.setattr(
        reproduction_module,
        "_require_distinguishable_evidence",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(
        ReproductionBuilderError,
        match="host commitments and machine fingerprints must differ",
    ):
        build_reproduction_statement(
            "synthetic-independent-evaluator",
            configuration_id=artifacts.record.configuration_id,
            corpus=artifacts.corpus_record,
            target_baseline_record=artifacts.record,
            target_public_bundle=artifacts.public_bundle,
            target_escrow_bundle=artifacts.escrow_bundle,
            target_machine_workflow_evidence=artifacts.machine_workflow_evidence,
            reproduced_public_bundle=tmp_path / "reproduced-public",
            reproduced_escrow_bundle=tmp_path / "reproduced-escrow",
            reproduced_machine_workflow_evidence=artifacts.machine_workflow_evidence,
            leakage_policy=artifacts.policy,
            protocol_allowed_signers=artifacts.allowed_signers,
            protocol_signer_identity=SIGNER_IDENTITY,
            reproduced_report_signature=tmp_path / "unused.sig",
            evaluator_allowed_signers=tmp_path / "unused.allowed_signers",
            evaluator_signer_identity="independent-evaluator@example.test",
            output_directory=tmp_path / "must-not-exist",
        )


def test_reproduction_builder_requires_distinct_machine_attestation_authorities(
    tmp_path: Path,
    baseline_artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second host commitment cannot reuse the target attestation authority."""
    artifacts = baseline_artifacts
    _, reproduced_public, reproduced_escrow, reproduced_report = (
        _create_independent_reproduced_evidence(
            tmp_path / "independent-run",
            artifacts,
        )
    )
    reproduced_machine_workflow = _create_independent_machine_workflow_evidence(
        tmp_path / "reproduced-machine",
        artifacts,
        monkeypatch,
        workflow_input=reproduced_report.parent / "config.resolved.json",
        workflow_report=reproduced_report,
        signer_identity=MACHINE_SIGNER_IDENTITY,
        private_key=artifacts.root / "machine-workflow-key",
        allowed_signers=artifacts.machine_workflow_evidence.allowed_signers,
    )

    with pytest.raises(
        ReproductionBuilderError,
        match="signer identity, key, and trust policy must all differ",
    ):
        build_reproduction_statement(
            "synthetic-independent-evaluator",
            configuration_id=artifacts.record.configuration_id,
            corpus=artifacts.corpus_record,
            target_baseline_record=artifacts.record,
            target_public_bundle=artifacts.public_bundle,
            target_escrow_bundle=artifacts.escrow_bundle,
            target_machine_workflow_evidence=artifacts.machine_workflow_evidence,
            reproduced_public_bundle=reproduced_public,
            reproduced_escrow_bundle=reproduced_escrow,
            reproduced_machine_workflow_evidence=reproduced_machine_workflow,
            leakage_policy=artifacts.policy,
            protocol_allowed_signers=artifacts.allowed_signers,
            protocol_signer_identity=SIGNER_IDENTITY,
            reproduced_report_signature=tmp_path / "unused.sig",
            evaluator_allowed_signers=tmp_path / "unused.allowed_signers",
            evaluator_signer_identity="independent-evaluator@example.test",
            output_directory=tmp_path / "must-not-exist",
        )


def test_reproduction_builder_rejects_target_record_not_rederived_exactly(
    tmp_path: Path,
    baseline_artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A supplied target record cannot substitute caller-entered artifact hashes."""
    artifacts = baseline_artifacts
    monkeypatch.setattr(
        reproduction_module,
        "verify_evidence_bundle_pair",
        lambda *args, **kwargs: artifacts.receipt,
    )
    monkeypatch.setattr(
        reproduction_module,
        "_build_baseline_configuration_record_from_receipt",
        lambda *args, **kwargs: artifacts.record,
    )
    monkeypatch.setattr(
        reproduction_module,
        "_require_distinguishable_evidence",
        lambda *args, **kwargs: None,
    )
    altered = artifacts.record.model_copy(update={"public_bundle_manifest_sha256": "f" * 64})

    with pytest.raises(ReproductionBuilderError, match="does not match"):
        build_reproduction_statement(
            "synthetic-independent-evaluator",
            configuration_id=artifacts.record.configuration_id,
            corpus=artifacts.corpus_record,
            target_baseline_record=altered,
            target_public_bundle=artifacts.public_bundle,
            target_escrow_bundle=artifacts.escrow_bundle,
            target_machine_workflow_evidence=artifacts.machine_workflow_evidence,
            reproduced_public_bundle=tmp_path / "reproduced-public",
            reproduced_escrow_bundle=tmp_path / "reproduced-escrow",
            reproduced_machine_workflow_evidence=artifacts.machine_workflow_evidence,
            leakage_policy=artifacts.policy,
            protocol_allowed_signers=artifacts.allowed_signers,
            protocol_signer_identity=SIGNER_IDENTITY,
            reproduced_report_signature=tmp_path / "unused.sig",
            evaluator_allowed_signers=tmp_path / "unused.allowed_signers",
            evaluator_signer_identity="independent-evaluator@example.test",
            output_directory=tmp_path / "must-not-exist",
        )


def test_marker_reader_rejects_symlink_and_fifo_without_path_disclosure(
    tmp_path: Path,
) -> None:
    """Private marker reads cannot follow links or block on named pipes."""
    target = tmp_path / "ordinary.marker"
    target.write_text("synthetic-marker\n", encoding="utf-8")
    linked = tmp_path / "TOP-SECRET-LINK.marker"
    linked.symlink_to(target)
    fifo = tmp_path / "TOP-SECRET-FIFO.marker"
    os.mkfifo(fifo)

    for unsafe in (linked, fifo):
        with pytest.raises(
            EvidenceBundleError,
            match="regular nonsymlink",
        ) as captured:
            cli_module._read_private_marker(unsafe)
        assert str(unsafe) not in str(captured.value)


def test_protocol_2_release_schema_hash_is_frozen() -> None:
    """Protocol 2 release records have one reviewed canonical schema digest."""
    encoded = json.dumps(
        BenchmarkReleaseSubmission.model_json_schema(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    assert hashlib.sha256(encoded).hexdigest() == RELEASE_SCHEMA_SHA256
